package proxy_test

import (
	"bufio"
	"io"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// lineRead is one asynchronous bufio.Reader.ReadString('\n') result.
type lineRead struct {
	line string
	err  error
}

// readLineAsync starts a single blocking line read on its own goroutine and
// returns a channel it sends the one result to — never calling anything
// test-related itself, since a goroutine other than the test's own must
// never call t.Fatal (the testing package requires FailNow-family calls to
// come from the test's own goroutine). Every assertion on the result happens
// back in the caller, which IS the test goroutine.
func readLineAsync(r *bufio.Reader) <-chan lineRead {
	ch := make(chan lineRead, 1)
	go func() {
		line, err := r.ReadString('\n')
		ch <- lineRead{line, err}
	}()
	return ch
}

// TestSuspendFreezesInputThenResumeDelivers proves the core Phase 122
// guarantee end to end against a real upstream, not just the mux in
// isolation (already proven in internal/session/share_test.go): once a
// session's ShareRegistry entry is Suspended, keystrokes typed by the
// PRIMARY operator do not reach the target — no echo arrives — and once
// Resumed, they arrive intact, in order, exactly as typed. The operator's
// own connection, not a joiner's, is what a real "freeze this operator's
// input" call targets, so this test exercises that path directly.
func TestSuspendFreezesInputThenResumeDelivers(t *testing.T) {
	host, port := startEchoUpstream(t, upstreamUser, upstreamSecret)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)

	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	reg, hub, shares := session.NewRegistry(), session.NewHub(), session.NewShareRegistry()
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
		Sessions: reg, Live: hub, Shares: shares,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)

	client, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	in, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("shell: %v", err)
	}

	sid := waitForSession(t, reg)
	r := bufio.NewReader(out)

	// Baseline: before any suspend, a normal keystroke echoes back.
	if _, err := io.WriteString(in, "before\n"); err != nil {
		t.Fatalf("write before suspend: %v", err)
	}
	select {
	case res := <-readLineAsync(r):
		if res.err != nil && res.err != io.EOF {
			t.Fatalf("baseline read: %v", res.err)
		}
		if res.line != "before\n" {
			t.Fatalf("baseline echo = %q, want %q", res.line, "before\n")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the baseline echo")
	}

	if !shares.Suspend(sid) {
		t.Fatal("Suspend reported false for a live session")
	}

	// While suspended, a keystroke must NOT reach the target — no echo
	// arrives within a bounded wait. This is a genuine absence check, not
	// just "didn't see it yet": the upstream is a synchronous echo, so any
	// delivery at all would show up well inside this window.
	if _, err := io.WriteString(in, "frozen\n"); err != nil {
		t.Fatalf("write while suspended: %v", err)
	}
	pending := readLineAsync(r)
	select {
	case res := <-pending:
		t.Fatalf("received %q (err %v) while suspended — input was not frozen", res.line, res.err)
	case <-time.After(300 * time.Millisecond):
		// correct: nothing arrived
	}

	if !shares.Resume(sid) {
		t.Fatal("Resume reported false for a live session")
	}

	// The frozen keystroke was HELD, not dropped — the same pending read
	// (started before Resume) now completes with it.
	select {
	case res := <-pending:
		if res.err != nil && res.err != io.EOF {
			t.Fatalf("post-resume read: %v", res.err)
		}
		if res.line != "frozen\n" {
			t.Fatalf("post-resume echo = %q, want the held %q", res.line, "frozen\n")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("resume did not deliver the held keystroke — it was dropped, not frozen")
	}

	if _, err := io.WriteString(in, "after\n"); err != nil {
		t.Fatalf("write after resume: %v", err)
	}
	select {
	case res := <-readLineAsync(r):
		if res.err != nil && res.err != io.EOF {
			t.Fatalf("post-resume read: %v", res.err)
		}
		if res.line != "after\n" {
			t.Fatalf("post-resume echo = %q, want %q", res.line, "after\n")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the post-resume echo")
	}
}

// TestSuspendUnknownSessionReportsFalse proves suspend/resume against a
// session id that was never live (or already ended) is a clean false, not a
// panic — the same "unknown is inert" contract ShareRegistry's other methods
// already give the API handlers that call them.
func TestSuspendUnknownSessionReportsFalse(t *testing.T) {
	shares := session.NewShareRegistry()
	if shares.Suspend("no-such-session") {
		t.Fatal("Suspend on an unknown session id returned true")
	}
	if shares.Resume("no-such-session") {
		t.Fatal("Resume on an unknown session id returned true")
	}
}
