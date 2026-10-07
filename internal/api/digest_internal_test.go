package api

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

type sentMail struct {
	to            []string
	subject, body string
}

func newDigestServer(t *testing.T, hour int, fail error) (*Server, store.Store, *[]sentMail) {
	t.Helper()
	key, err := vault.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(key)
	if err != nil {
		t.Fatal(err)
	}
	st := memstore.New()
	resolver, err := auth.NewResolver(st, "k", "")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(st, v, resolver, nil, Options{
		ShareSMTPAddr: "relay.invalid:25", ShareSMTPFrom: "pam@example.com",
		DigestTo: []string{"soc@example.com"}, DigestHour: hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	var sent []sentMail
	srv.digest.send = func(to []string, subject, body string) error {
		sent = append(sent, sentMail{to, subject, body})
		return fail
	}
	return srv, st, &sent
}

func countAction(t *testing.T, st store.Store, action string) int {
	t.Helper()
	events, err := st.ListAudit(context.Background(), 500)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range events {
		if e.Action == action {
			n++
		}
	}
	return n
}

// TestDigestPass proves the daily digest (Phase 277): nothing before the
// configured hour; at it, one mail covering the last 24 hours — counting the
// connection and the critical connection seeded "now" — audited
// report.digest_sent with its day; and no second mail that day, because the
// high-water mark is read back from the trail.
func TestDigestPass(t *testing.T) {
	ctx := context.Background()
	// Pick "now" an hour ahead of the real clock, and that hour as the
	// digest hour, so the window [hour-24h, hour) holds events stamped now.
	now := time.Now().UTC().Add(time.Hour)
	srv, st, sent := newDigestServer(t, now.Hour(), nil)
	for _, e := range []store.AuditEvent{
		{Actor: "alice", Action: "session.start", Detail: "target:core-db host:\"10.0.0.9\":22 cred_user:root mode:interactive"},
		{Actor: "alice", Action: "target.critical_connect", Detail: "target:core-db protocol:ssh cred_user:root"},
	} {
		if err := st.AppendAudit(ctx, &e); err != nil {
			t.Fatal(err)
		}
	}

	if now.Hour() > 0 && srv.digestPass(ctx, now.Add(-time.Hour)) {
		t.Fatal("a digest went out before its hour")
	}
	if !srv.digestPass(ctx, now) {
		t.Fatal("the digest was due and did not go out")
	}
	if len(*sent) != 1 || (*sent)[0].to[0] != "soc@example.com" ||
		!strings.Contains((*sent)[0].subject, "1 connections, 1 to critical targets") ||
		!strings.Contains((*sent)[0].body, "alice -> core-db (ssh)") {
		t.Fatalf("mail = %+v", *sent)
	}
	day := now.Format(time.DateOnly)
	last, err := st.LatestAuditByAction(ctx, "report.digest_sent")
	if err != nil || last == nil || last.Actor != digestActor || !strings.Contains(last.Detail, "day:"+day+" recipients:1 connections:1") {
		t.Fatalf("digest_sent row = %+v err %v", last, err)
	}
	if srv.digestPass(ctx, now.Add(10*time.Minute)) || len(*sent) != 1 {
		t.Fatalf("a second digest went out the same day: %d mails", len(*sent))
	}
}

// TestDigestRetry proves a failed send is audited once and retried an hour
// later, not on every five-minute tick.
func TestDigestRetry(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 7, 6, 0, 0, 0, time.UTC)
	srv, st, sent := newDigestServer(t, 6, errors.New("relay down"))
	if srv.digestPass(ctx, now) || countAction(t, st, "report.digest_failed") != 1 {
		t.Fatal("a failed send must report false and audit report.digest_failed once")
	}
	if srv.digestPass(ctx, now.Add(digestTick)); len(*sent) != 1 {
		t.Fatalf("retried inside the back-off: %d attempts", len(*sent))
	}
	srv.digest.send = func(to []string, subject, body string) error {
		*sent = append(*sent, sentMail{to, subject, body})
		return nil
	}
	if !srv.digestPass(ctx, now.Add(digestRetry)) || len(*sent) != 2 {
		t.Fatalf("not retried after the back-off: %d attempts", len(*sent))
	}
}
