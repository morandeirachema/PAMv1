package auditfwd_test

// auditfwd_test.go exercises the SIEM forwarder against a real in-process syslog
// listener (UDP), so the wire path — format, framing, cursor advance — is proven
// end to end, not mocked.

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/auditfwd"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// udpSink listens on a loopback UDP port and returns its address plus a channel of
// received message strings.
func udpSink(t *testing.T) (string, <-chan string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	msgs := make(chan string, 64)
	go func() {
		buf := make([]byte, 8192)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			msgs <- string(buf[:n])
		}
	}()
	return pc.LocalAddr().String(), msgs
}

// collect drains up to want messages from ch within the timeout.
func collect(t *testing.T, ch <-chan string, want int) []string {
	t.Helper()
	var got []string
	deadline := time.After(3 * time.Second)
	for len(got) < want {
		select {
		case m := <-ch:
			got = append(got, m)
		case <-deadline:
			t.Fatalf("received %d/%d forwarded messages", len(got), want)
		}
	}
	return got
}

func seedAudit(t *testing.T, st store.Store, actions ...string) {
	t.Helper()
	for _, a := range actions {
		if err := st.AppendAudit(context.Background(), &store.AuditEvent{Actor: "alice", Action: a, Detail: "target:web-01"}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestForwardRFC5424 proves new audit events are forwarded as RFC 5424 syslog and
// that the cursor advances so a second flush sends nothing.
func TestForwardRFC5424(t *testing.T) {
	addr, sink := udpSink(t)
	st := memstore.New()

	fwd, err := auditfwd.New(st, auditfwd.Config{Network: "udp", Addr: addr, Format: auditfwd.FormatRFC5424})
	if err != nil {
		t.Fatal(err)
	}
	// A fresh forwarder starts "from now": nothing is sent before events exist.
	if err := fwd.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	seedAudit(t, st, "target.create", "credential.reveal")
	if err := fwd.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := collect(t, sink, 2)
	joined := strings.Join(got, "\n")
	for _, want := range []string{"<110>1", "target.create", "credential.reveal", "actor=alice"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("forwarded syslog missing %q:\n%s", want, joined)
		}
	}

	// The cursor advanced: a second flush with no new events sends nothing.
	if err := fwd.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-sink:
		t.Fatalf("second flush re-sent an already-forwarded event: %q", m)
	case <-time.After(300 * time.Millisecond):
	}
}

// TestForwardCEF proves the ArcSight CEF format.
func TestForwardCEF(t *testing.T) {
	addr, sink := udpSink(t)
	st := memstore.New()
	fwd, err := auditfwd.New(st, auditfwd.Config{Network: "udp", Addr: addr, Format: auditfwd.FormatCEF})
	if err != nil {
		t.Fatal(err)
	}
	fwd.Flush(context.Background()) // set the cursor to "now"
	seedAudit(t, st, "session.kill")
	if err := fwd.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	m := collect(t, sink, 1)[0]
	for _, want := range []string{"CEF:0|pamv1|", "|session.kill|", "suser=alice"} {
		if !strings.Contains(m, want) {
			t.Fatalf("CEF record missing %q: %q", want, m)
		}
	}
}

// TestForwardResumesFromCursor proves a new forwarder resumes from the persisted
// cursor rather than replaying history (a restart does not double-send).
func TestForwardResumesFromCursor(t *testing.T) {
	addr, sink := udpSink(t)
	st := memstore.New()
	seedAudit(t, st, "a.one", "a.two")

	// First forwarder: initializes the cursor to "now" (2 pre-existing events), so
	// they are NOT replayed; then a new event is forwarded.
	f1, _ := auditfwd.New(st, auditfwd.Config{Network: "udp", Addr: addr, Format: auditfwd.FormatRFC5424})
	if err := f1.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	seedAudit(t, st, "a.three")
	if err := f1.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m := collect(t, sink, 1)[0]; !strings.Contains(m, "a.three") {
		t.Fatalf("want the new event, got %q", m)
	}

	// A second forwarder (a "restarted" process) shares the store's persisted
	// cursor and must not re-send a.three.
	f2, _ := auditfwd.New(st, auditfwd.Config{Network: "udp", Addr: addr, Format: auditfwd.FormatRFC5424})
	if err := f2.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-sink:
		t.Fatalf("restarted forwarder replayed an already-sent event: %q", m)
	case <-time.After(300 * time.Millisecond):
	}
}

// TestForwardRejectsBadConfig covers the constructor's validation.
func TestForwardRejectsBadConfig(t *testing.T) {
	st := memstore.New()
	if _, err := auditfwd.New(st, auditfwd.Config{Network: "udp"}); err == nil {
		t.Fatal("missing Addr must be rejected")
	}
	if _, err := auditfwd.New(st, auditfwd.Config{Network: "sctp", Addr: "x:1"}); err == nil {
		t.Fatal("bad network must be rejected")
	}
	if _, err := auditfwd.New(st, auditfwd.Config{Network: "tcp", Addr: "x:1", Format: "xml"}); err == nil {
		t.Fatal("bad format must be rejected")
	}
}
