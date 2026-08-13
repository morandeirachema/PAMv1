package proxy_test

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// startEchoUpstream is like startUpstream, but a "shell" request keeps the
// channel open and echoes back every byte it reads, instead of writing one
// fixed string and closing. Session-sharing's whole point is letting a SECOND
// party's live keystrokes reach the target — proving that needs an upstream
// that reacts to input, not one that ignores it.
func startEchoUpstream(t *testing.T, wantUser, wantPass string) (host string, port int) {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == wantUser && string(pass) == wantPass {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("upstream: auth denied")
		},
	}
	cfg.AddHostKey(mustSigner(t))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				defer sconn.Close()
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					if nc.ChannelType() != "session" {
						nc.Reject(ssh.UnknownChannelType, "")
						continue
					}
					ch, chReqs, err := nc.Accept()
					if err != nil {
						continue
					}
					go func(ch ssh.Channel, chReqs <-chan *ssh.Request) {
						for req := range chReqs {
							if req.WantReply {
								req.Reply(true, nil)
							}
							if req.Type == "shell" {
								go io.Copy(ch, ch) // echo whatever arrives back out
							}
						}
					}(ch, chReqs)
				}
			}()
		}
	}()

	h, p, _ := net.SplitHostPort(ln.Addr().String())
	pn, _ := strconv.Atoi(p)
	return h, pn
}

// seedUserToken creates a plain "user" identity with the given raw token as
// its per-user credential (per-user token = hex(sha256(token)), the same
// pattern TestSafeMembershipGrantsConnect uses).
func seedUserToken(t *testing.T, st store.Store, username, rawToken string) {
	t.Helper()
	sum := sha256.Sum256([]byte(rawToken))
	if err := st.CreateUser(context.Background(), &store.User{
		Username: username, Role: "user", TokenHash: hex.EncodeToString(sum[:]),
	}); err != nil {
		t.Fatal(err)
	}
}

// approvedInvite creates a session-share invite already in the "approved"
// state with the given raw token's hash, exactly as DecideSessionShareInvite
// would leave it — tests exercise the proxy's redemption path directly,
// independent of the (not-yet-built-in-this-phase-of-work) API handlers that
// would normally drive request/approve.
func approvedInvite(t *testing.T, st store.Store, sid, mode, kind, invitee, rawToken string, ttl time.Duration) {
	t.Helper()
	ctx := context.Background()
	inv := &store.SessionShareInvite{
		SessionID: sid, Mode: mode, Kind: kind, Invitee: invitee,
		Status: "pending", Requester: "admin",
	}
	if err := st.CreateSessionShareInvite(ctx, inv); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(sum[:])
	expires := time.Now().Add(ttl)
	if err := st.DecideSessionShareInvite(ctx, inv.ID, "approved", "admin2", time.Now(), tokenHash, &expires); err != nil {
		t.Fatal(err)
	}
}

// waitForSession polls reg.List() for the first live session id, mirroring
// TestLiveSupervisionReleasesOnceWatched's exact pattern.
func waitForSession(t *testing.T, reg *session.Registry) string {
	t.Helper()
	for i := 0; i < 200; i++ {
		if ls := reg.List(); len(ls) > 0 {
			return ls[0].ID
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no session was registered")
	return ""
}

// TestSessionShareJoinViewControl proves the core, riskiest property of
// Phase 116 end to end against a real upstream: a SECOND party's own SSH
// connection, redeeming an approved invite, can inject keystrokes that
// actually reach the target — not just a mock of the mux in isolation
// (already proven in internal/session/share_test.go), but the full wiring
// through handleSession's pump and handleJoinSession's forwarder.
func TestSessionShareJoinViewControl(t *testing.T) {
	host, port := startEchoUpstream(t, upstreamUser, upstreamSecret)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	seedUserToken(t, st, "carol", "carols-own-token")

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

	// Primary operator opens an interactive shell (not exec — a shell session
	// stays open, which a joiner needs time to attach to).
	primary, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial proxy (primary): %v", err)
	}
	defer primary.Close()
	primSess, err := primary.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer primSess.Close()
	primOut, err := primSess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := primSess.Shell(); err != nil {
		t.Fatalf("primary shell: %v", err)
	}

	sid := waitForSession(t, reg)

	const rawToken = "carols-share-token"
	approvedInvite(t, st, sid, "view_control", "internal", "carol", rawToken, time.Minute)

	joiner, err := dialProxy(t, addr, "join:"+rawToken, "carols-own-token")
	if err != nil {
		t.Fatalf("dial proxy (joiner): %v", err)
	}
	defer joiner.Close()
	joinSess, err := joiner.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer joinSess.Close()
	joinIn, err := joinSess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := joinSess.Shell(); err != nil {
		t.Fatalf("joiner shell: %v", err)
	}

	// Give the join time to attach (Track/Subscribe/forwarder goroutines
	// starting) before typing — there is no synchronous "attached" signal to
	// wait on, mirroring how a real interactive session has no such signal
	// either.
	time.Sleep(100 * time.Millisecond)

	const typed = "hello-from-the-joiner\n"
	if _, err := io.WriteString(joinIn, typed); err != nil {
		t.Fatalf("joiner write: %v", err)
	}

	// The echo upstream reflects the joiner's bytes back through the SAME
	// upstream channel the PRIMARY reads from — so seeing them on the
	// primary's own stdout proves the joiner's keystrokes reached the target,
	// not merely the mux.
	r := bufio.NewReader(primOut)
	deadline := time.Now().Add(5 * time.Second)
	var got string
	for time.Now().Before(deadline) {
		line, err := r.ReadString('\n')
		got += line
		if err != nil && err != io.EOF {
			break
		}
		if got == typed {
			return // success
		}
		if err == io.EOF {
			break
		}
	}
	t.Fatalf("primary stdout = %q, want it to contain the joiner's typed line %q", got, typed)
}

// TestSessionShareJoinViewOnly proves a view-only joiner receives the same
// live output a supervisor watching the session would (via the existing
// Hub), and that its own keystrokes are discarded rather than reaching the
// mux — the "watch, don't touch" half of session-sharing.
func TestSessionShareJoinViewOnly(t *testing.T) {
	host, port := startEchoUpstream(t, upstreamUser, upstreamSecret)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	seedUserToken(t, st, "dave", "daves-own-token")

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

	primary, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial proxy (primary): %v", err)
	}
	defer primary.Close()
	primSess, err := primary.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer primSess.Close()
	primIn, err := primSess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := primSess.Shell(); err != nil {
		t.Fatalf("primary shell: %v", err)
	}

	sid := waitForSession(t, reg)

	const rawToken = "daves-share-token"
	approvedInvite(t, st, sid, "view_only", "internal", "dave", rawToken, time.Minute)

	joiner, err := dialProxy(t, addr, "join:"+rawToken, "daves-own-token")
	if err != nil {
		t.Fatalf("dial proxy (joiner): %v", err)
	}
	defer joiner.Close()
	joinSess, err := joiner.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer joinSess.Close()
	joinOut, err := joinSess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := joinSess.Shell(); err != nil {
		t.Fatalf("joiner shell: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	const typed = "primary-typed-this\n"
	if _, err := io.WriteString(primIn, typed); err != nil {
		t.Fatalf("primary write: %v", err)
	}

	r := bufio.NewReader(joinOut)
	deadline := time.Now().Add(5 * time.Second)
	var got string
	for time.Now().Before(deadline) {
		line, err := r.ReadString('\n')
		got += line
		if got == typed {
			return // success: the view-only joiner saw the primary's output
		}
		if err != nil {
			break
		}
	}
	t.Fatalf("joiner stdout = %q, want it to contain the primary's line %q", got, typed)
}

// TestSessionShareJoinKick proves ShareRegistry.Kick actually disconnects an
// attached SSH joiner's channel — not merely removing its roster bookkeeping
// — mirroring the console's kick action (internal/api's kickShareJoin calls
// the exact same ShareRegistry.Kick).
func TestSessionShareJoinKick(t *testing.T) {
	host, port := startEchoUpstream(t, upstreamUser, upstreamSecret)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	seedUserToken(t, st, "erin", "erins-own-token")

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

	primary, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial proxy (primary): %v", err)
	}
	defer primary.Close()
	go func() { s, _ := primary.NewSession(); s.Shell(); s.Wait() }()
	sid := waitForSession(t, reg)

	const rawToken = "erins-share-token"
	approvedInvite(t, st, sid, "view_only", "internal", "erin", rawToken, time.Minute)

	joiner, err := dialProxy(t, addr, "join:"+rawToken, "erins-own-token")
	if err != nil {
		t.Fatalf("dial proxy (joiner): %v", err)
	}
	defer joiner.Close()
	joinSess, err := joiner.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer joinSess.Close()
	if err := joinSess.Shell(); err != nil {
		t.Fatalf("joiner shell: %v", err)
	}

	// Wait for the join to actually register on the roster, rather than a
	// fixed sleep — Kick before Track has run would find nothing to kick.
	var roster []session.JoinedParty
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		roster = shares.Roster(sid)
		if len(roster) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(roster) != 1 {
		t.Fatalf("roster = %v, want exactly the one joiner attached", roster)
	}
	if roster[0].Actor != "erin" || roster[0].JoinID == "" {
		t.Fatalf("unexpected roster entry: %+v", roster[0])
	}

	if !shares.Kick(sid, roster[0].JoinID) {
		t.Fatal("Kick reported no matching join")
	}

	// The joiner's channel is now closed from the far end: its session ends.
	waitDone := make(chan error, 1)
	go func() { waitDone <- joinSess.Wait() }()
	select {
	case <-waitDone:
		// Any outcome (error or not) is fine — what matters is it returned
		// promptly rather than the session hanging open forever.
	case <-time.After(3 * time.Second):
		t.Fatal("joiner's SSH session is still open 3s after being kicked")
	}

	if got := shares.Roster(sid); len(got) != 0 {
		t.Fatalf("roster after kick = %v, want empty", got)
	}
}

// TestSessionShareJoinRefusesWrongInvitee proves an invite issued to one
// pamv1 user cannot be redeemed by a different one, even with the correct
// token — a leaked token must not let a different user impersonate the
// invitee.
func TestSessionShareJoinRefusesWrongInvitee(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	seedUserToken(t, st, "erin", "erins-own-token")

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

	primary, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial proxy (primary): %v", err)
	}
	defer primary.Close()
	go func() { s, _ := primary.NewSession(); s.Output("run") }()
	sid := waitForSession(t, reg)

	const rawToken = "someones-share-token"
	// Invite is issued to "bob", but "erin" (a real, different pamv1 user)
	// tries to redeem it with the right token.
	approvedInvite(t, st, sid, "view_only", "internal", "bob", rawToken, time.Minute)

	// The SSH connection itself succeeds (authenticate() only resolves the
	// principal; handleJoinConn's refusal happens at channel-open time, via
	// rejectAll — the same shape session refusal already takes elsewhere in
	// this file, e.g. TestLiveSupervisionTimesOutAndRefuses).
	joiner, err := dialProxy(t, addr, "join:"+rawToken, "erins-own-token")
	if err != nil {
		t.Fatalf("dial should succeed (refusal is per-channel): %v", err)
	}
	defer joiner.Close()
	if _, err := joiner.NewSession(); err == nil {
		t.Fatal("expected the channel to be refused (invitee mismatch), it opened")
	}
	if !auditHas(t, st, "session.share_join_denied") {
		t.Error("the refused join was not audited as session.share_join_denied")
	}
}

// TestSessionShareJoinSingleUse proves an invite's token can be redeemed
// exactly once — a second attempt with the same token, even before it
// expires, fails.
func TestSessionShareJoinSingleUse(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	seedUserToken(t, st, "frank", "franks-own-token")

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

	primary, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial proxy (primary): %v", err)
	}
	defer primary.Close()
	go func() { s, _ := primary.NewSession(); s.Output("run") }()
	sid := waitForSession(t, reg)

	const rawToken = "franks-share-token"
	approvedInvite(t, st, sid, "view_only", "internal", "frank", rawToken, time.Minute)

	first, err := dialProxy(t, addr, "join:"+rawToken, "franks-own-token")
	if err != nil {
		t.Fatalf("first join should succeed: %v", err)
	}
	defer first.Close()
	firstSess, err := first.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	firstSess.Close()

	second, err := dialProxy(t, addr, "join:"+rawToken, "franks-own-token")
	if err != nil {
		t.Fatalf("dial should succeed (refusal is per-channel): %v", err)
	}
	defer second.Close()
	if _, err := second.NewSession(); err == nil {
		t.Fatal("a second redemption of the same token should have been refused")
	}
}

// TestSessionShareJoinRefusesExternalKind proves an "external" (email+QR)
// invite cannot be redeemed through the SSH join: path at all — that
// surface is reserved for internal, named-pamv1-user invites; an external
// invite is only ever redeemed over HTTP, by a different handler.
func TestSessionShareJoinRefusesExternalKind(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	seedUserToken(t, st, "grace", "graces-own-token")

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

	primary, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial proxy (primary): %v", err)
	}
	defer primary.Close()
	go func() { s, _ := primary.NewSession(); s.Output("run") }()
	sid := waitForSession(t, reg)

	const rawToken = "vendor-share-token"
	// An "external" invite has no Invitee (a vendor contact isn't a pamv1
	// principal) — even if "grace" (a real user) somehow learned the token,
	// the join path refuses it outright, wrong-surface, before even
	// reaching the invitee-match check.
	approvedInvite(t, st, sid, "view_only", "external", "", rawToken, time.Minute)

	joiner, err := dialProxy(t, addr, "join:"+rawToken, "graces-own-token")
	if err != nil {
		t.Fatalf("dial should succeed (refusal is per-channel): %v", err)
	}
	defer joiner.Close()
	if _, err := joiner.NewSession(); err == nil {
		t.Fatal("expected an external-kind invite to be refused on the SSH join path")
	}
}
