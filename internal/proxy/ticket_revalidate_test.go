package proxy_test

// ticket_revalidate_test.go proves the Phase 60 gate on the flagship path: an
// SSH session whose admitting access request carries a change ticket the ITSM
// no longer accepts is refused — through the proxy, against a real upstream,
// with nothing about the approval itself having changed.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/ticket"
)

// TestProxyRevalidatesTicketAtConnect is the end-to-end proof on the SSH path.
// The same approved request admits a session while the change is open and stops
// admitting one the moment the ITSM cancels the change; re-opening it admits
// again, which is what shows the refusal came from the ticket rather than from
// the approval being spent.
func TestProxyRevalidatesTicketAtConnect(t *testing.T) {
	var valid atomic.Bool
	valid.Store(true)
	var calls atomic.Int32
	itsm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		calls.Add(1)
		if valid.Load() && b["ticket"] == "CHG1234" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(itsm.Close)
	tv, err := ticket.New(`^CHG[0-9]{3,}$`, ticket.NewWebhook(itsm.URL, nil))
	if err != nil {
		t.Fatal(err)
	}

	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	target := seedTarget(t, st, v, host, port)
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
		RequireApproval: true, TicketCheck: tv,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)

	// An approved, unexpired, ticketed request for the proxy actor.
	if err := st.CreateAccessRequest(context.Background(), &store.AccessRequest{
		Requester: "bootstrap-admin", TargetID: target.ID, Status: "approved",
		ExpiresAt: time.Now().Add(time.Hour), Ticket: "CHG1234",
	}); err != nil {
		t.Fatal(err)
	}

	// While the change is open, the session runs and the credential is injected
	// (the upstream accepts only the vaulted secret).
	client, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("auth should pass: %v", err)
	}
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session must be allowed while the change is open: %v", err)
	}
	out, err := sess.Output("run")
	if err != nil || string(out) != targetOutput {
		t.Fatalf("exec through the proxy: out=%q err=%v", out, err)
	}
	sess.Close()
	client.Close()
	if calls.Load() == 0 {
		t.Fatal("the ITSM must be consulted at connect time")
	}

	// The change is cancelled. The approval row is untouched.
	valid.Store(false)
	client2, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("auth should still pass — the refusal belongs to the session gate: %v", err)
	}
	if s2, err := client2.NewSession(); err == nil {
		s2.Close()
		client2.Close()
		t.Fatal("a session whose ticket the ITSM no longer accepts must be refused")
	}
	client2.Close()
	assertAuditContains(t, st, "access.ticket_revoked", "CHG1234")
	assertAuditContains(t, st, "access.denied", "reason:ticket-not-valid")

	// Re-opening the change admits again: the approval was never spent.
	valid.Store(true)
	client3, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("auth should pass: %v", err)
	}
	defer client3.Close()
	sess3, err := client3.NewSession()
	if err != nil {
		t.Fatalf("session must be allowed once the change is re-opened: %v", err)
	}
	defer sess3.Close()
	if out, err := sess3.Output("run"); err != nil || string(out) != targetOutput {
		t.Fatalf("exec after re-opening: out=%q err=%v", out, err)
	}
}

// TestProxyUnreachableITSMRefusesConnect proves the fail-closed half on the
// session path: an ITSM that cannot be reached refuses the session rather than
// admitting it. A gate that opens when it cannot do its job is not a gate.
func TestProxyUnreachableITSMRefusesConnect(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := dead.URL
	dead.Close() // nothing is listening any more
	tv, err := ticket.New("", ticket.NewWebhook(url, nil))
	if err != nil {
		t.Fatal(err)
	}

	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	target := seedTarget(t, st, v, host, port)
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
		RequireApproval: true, TicketCheck: tv,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)

	if err := st.CreateAccessRequest(context.Background(), &store.AccessRequest{
		Requester: "bootstrap-admin", TargetID: target.ID, Status: "approved",
		ExpiresAt: time.Now().Add(time.Hour), Ticket: "CHG1234",
	}); err != nil {
		t.Fatal(err)
	}

	client, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("auth should pass: %v", err)
	}
	defer client.Close()
	if sess, err := client.NewSession(); err == nil {
		sess.Close()
		t.Fatal("an unreachable ITSM must refuse the session, not admit it")
	}
	assertAuditContains(t, st, "access.denied", "reason:ticket-not-valid")
}
