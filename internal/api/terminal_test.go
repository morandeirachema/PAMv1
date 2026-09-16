package api_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

const (
	termUpstreamUser   = "root"
	termUpstreamSecret = "only-the-vault-knows-this"
	termBanner         = "PAMV1-TERMINAL-BANNER\r\n"
)

// termSigner is a fresh host key.
func termSigner(t *testing.T) ssh.Signer {
	t.Helper()
	pem, err := proxy.GenerateHostKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	s, err := proxy.HostKeyFromPEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// startTermUpstream is the target: an sshd that accepts ONLY the vaulted
// password, and whose shell prints a banner and then echoes every byte back —
// so a banner in the browser proves the proxy injected a secret the browser
// never had, and an echo proves keystrokes travel the other way.
func startTermUpstream(t *testing.T) (host string, port int) {
	t.Helper()
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		if c.User() == termUpstreamUser && string(pass) == termUpstreamSecret {
			return &ssh.Permissions{}, nil
		}
		return nil, fmt.Errorf("upstream: auth denied")
	}}
	cfg.AddHostKey(termSigner(t))
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
					go func() {
						for req := range chReqs {
							switch req.Type {
							case "pty-req", "window-change", "env":
								if req.WantReply {
									req.Reply(true, nil)
								}
							case "shell":
								if req.WantReply {
									req.Reply(true, nil)
								}
								io.WriteString(ch, termBanner)
								go func() { io.Copy(ch, ch); ch.Close() }() // echo
							default:
								if req.WantReply {
									req.Reply(false, nil)
								}
							}
						}
					}()
				}
			}()
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	var pn int
	fmt.Sscanf(p, "%d", &pn)
	return h, pn
}

// termEnv wires the whole path: an upstream sshd, a store with the target and
// its vaulted credential, the session proxy on loopback, and the API server
// told where that proxy is.
type termEnv struct {
	srv   *httptest.Server
	st    store.Store
	reg   *session.Registry
	tgt   *store.Target
	proxy string
}

func newTermEnv(t *testing.T, opts api.Options) *termEnv {
	t.Helper()
	ctx := context.Background()
	st := memstore.New()
	key, err := vault.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(key)
	if err != nil {
		t.Fatal(err)
	}
	host, port := startTermUpstream(t)
	tgt := &store.Target{Name: "web-01", Host: host, Port: port, OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, tgt); err != nil {
		t.Fatal(err)
	}
	cred := &store.Credential{TargetID: tgt.ID, Username: termUpstreamUser, SecretType: "password"}
	if err := st.CreateCredential(ctx, cred); err != nil {
		t.Fatal(err)
	}
	enc, err := v.Encrypt(ctx, termUpstreamSecret, store.CredentialAAD(tgt.ID, cred.ID))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateCredentialSecretEnc(ctx, cred.ID, enc); err != nil {
		t.Fatal(err)
	}
	reg := session.NewRegistry()
	resolver, err := auth.NewResolver(st, testAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	hostKey := termSigner(t)
	// The recording cap is what main always sets from PAM_MAX_RECORDING_MB; a
	// proxy built without one ends an interactive session on its first byte
	// (fail-closed at the cap), which no other test noticed because their
	// upstreams close right after one write.
	px, err := proxy.New(st, v, resolver, proxy.Config{HostKey: hostKey, RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second, Sessions: reg, MaxRecordingBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pctx, cancel := context.WithCancel(ctx)
	go func() { _ = px.Serve(pctx, ln) }()
	t.Cleanup(func() { cancel(); ln.Close() })
	opts.Sessions = reg
	opts.SSHProxyAddr, opts.SSHProxyHostKey = ln.Addr().String(), hostKey.PublicKey()
	srv, _, _ := newTestServerFull(t, nil, st, "", opts)
	return &termEnv{srv: srv, st: st, reg: reg, tgt: tgt, proxy: ln.Addr().String()}
}

// wsURL turns the test server's URL into the terminal's WebSocket URL.
func (e *termEnv) wsURL(targetID int64, query string) string {
	return "ws" + strings.TrimPrefix(e.srv.URL, "http") + fmt.Sprintf("/api/targets/%d/ssh/terminal?%s", targetID, query)
}

// readUntil collects binary frames until want appears or the deadline passes.
func readUntil(t *testing.T, ws *websocket.Conn, want string, d time.Duration) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	var got strings.Builder
	for !strings.Contains(got.String(), want) {
		_, data, err := ws.Read(ctx)
		if err != nil {
			t.Fatalf("waiting for %q, got %q then error: %v", want, got.String(), err)
		}
		got.Write(data)
	}
	return got.String()
}

// TestBrowserTerminalEndToEnd proves the in-portal terminal (Phase 254) is a
// proxy session: a browser-style WebSocket, opened with a terminal token,
// reaches an sshd that accepts ONLY the vaulted password — so the banner the
// browser sees proves the proxy injected a secret the browser never had — and
// keystrokes travel back the other way. It also proves the door's own rules:
// the token is spent by its first session, is refused as an API key, and
// opens no target but the one it was minted for; the session is registered
// under the browser's address, not the loopback dial; and the audit trail
// records the open and the end with that address.
func TestBrowserTerminalEndToEnd(t *testing.T) {
	env := newTermEnv(t, api.Options{})
	aliceTok := seedUser(t, env.srv, "alice", "user")

	// Mint.
	code, d := do(t, env.srv, http.MethodPost, "/api/ssh-token", aliceTok, map[string]any{"target_id": env.tgt.ID})
	if code != http.StatusOK {
		t.Fatalf("mint terminal token: %d %s", code, d)
	}
	m := jsonMap(t, d)
	tok, _ := m["token"].(string)
	if tok == "" || m["cred_user"] != termUpstreamUser || m["session_mfa_required"] != false {
		t.Fatalf("mint response = %s", d)
	}
	auditHas(t, env.st, "ssh.terminal_token", "target:web-01 cred_user:root")

	// A terminal token is not an API key.
	if code, _ := do(t, env.srv, http.MethodGet, "/api/targets", tok, nil); code != http.StatusForbidden {
		t.Errorf("a terminal token on an API route: want 403, got %d", code)
	}

	// Open the terminal.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, env.wsURL(env.tgt.ID, "token="+tok+"&cols=80&rows=24"), &websocket.DialOptions{Subprotocols: []string{"pamv1-terminal"}})
	if err != nil {
		t.Fatalf("open terminal: %v", err)
	}
	defer ws.Close(websocket.StatusNormalClosure, "")
	readUntil(t, ws, strings.TrimSpace(termBanner), 30*time.Second)

	// While it is open: registered by the PROXY as an ssh session, under the
	// browser's address.
	var seen bool
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) && !seen {
		for _, s := range env.reg.List() {
			if s.Protocol == "ssh" && s.Actor == "alice" && s.Target == "web-01" {
				if !strings.HasPrefix(s.Remote, "127.0.0.1") {
					t.Fatalf("session remote = %q, want the browser's address", s.Remote)
				}
				seen = true
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !seen {
		t.Fatal("the terminal session must appear in the live registry as an ssh session")
	}
	auditHas(t, env.st, "terminal.open", "target:web-01 cred_user:root remote:127.0.0.1")

	// Keystrokes go up, the echo comes back.
	if err := ws.Write(ctx, websocket.MessageBinary, []byte("echo pamv1-roundtrip\n")); err != nil {
		t.Fatal(err)
	}
	readUntil(t, ws, "echo pamv1-roundtrip", 30*time.Second)
	// A resize is a text frame and must not be typed into the shell.
	if err := ws.Write(ctx, websocket.MessageText, []byte(`{"resize":{"cols":100,"rows":30}}`)); err != nil {
		t.Fatal(err)
	}

	// The token was spent by this session: a second WebSocket is refused.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel2()
	if ws2, resp, err := websocket.Dial(ctx2, env.wsURL(env.tgt.ID, "token="+tok), nil); err == nil {
		ws2.Close(websocket.StatusNormalClosure, "")
		t.Fatal("a spent terminal token opened a second session")
	} else if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("spent token: want 401 on the handshake, got %v (%v)", resp, err)
	}
	ws.Close(websocket.StatusNormalClosure, "done")
	if !waitAudit(env.st, "terminal.end", "target:web-01 cred_user:root remote:127.0.0.1", 30*time.Second) {
		t.Fatal("terminal.end must be audited when the browser closes")
	}
	// The PROXY's own end, not just the API's: the session goroutine seals its
	// recording into the test's temp dir and the registry entry leaves as the
	// connection unwinds. Returning before that races t.TempDir's cleanup
	// ("directory not empty") — which is exactly what CI saw once.
	if !waitAudit(env.st, "session.end", "target:web-01", 30*time.Second) {
		t.Fatal("the proxy must audit session.end when the terminal closes")
	}
	deadline = time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) && len(env.reg.List()) > 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if n := len(env.reg.List()); n != 0 {
		t.Fatalf("%d session(s) still registered after the terminal closed", n)
	}
}

// TestBrowserTerminalTokenIsBoundToItsTarget proves a token minted for one
// target opens no other, and that minting itself is refused where the proxy
// would refuse: a target the caller may not use (Phase 252's scope included),
// a non-SSH target, and a server with no proxy on loopback.
func TestBrowserTerminalTokenIsBoundToItsTarget(t *testing.T) {
	env := newTermEnv(t, api.Options{})
	aliceTok := seedUser(t, env.srv, "alice", "user")
	other := createTestTarget(t, env.srv, "other-01", "127.0.0.1")
	code, d := do(t, env.srv, http.MethodPost, "/api/ssh-token", aliceTok, map[string]any{"target_id": env.tgt.ID})
	if code != http.StatusOK {
		t.Fatalf("mint: %d %s", code, d)
	}
	tok := jsonMap(t, d)["token"].(string)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if ws, resp, err := websocket.Dial(ctx, env.wsURL(other, "token="+tok), nil); err == nil {
		ws.Close(websocket.StatusNormalClosure, "")
		t.Fatal("a token minted for web-01 opened other-01")
	} else if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("other target: want 403 on the handshake, got %v (%v)", resp, err)
	}
	auditHas(t, env.st, "authz.denied", "reason:terminal-token-target")

	// Minting is refused for a target the caller may not use: gate it with a
	// grant naming somebody else.
	if err := env.st.CreateTargetGrant(context.Background(), &store.TargetGrant{TargetID: env.tgt.ID, SubjectType: "user", Subject: "bob"}); err != nil {
		t.Fatal(err)
	}
	if code, d := do(t, env.srv, http.MethodPost, "/api/ssh-token", aliceTok, map[string]any{"target_id": env.tgt.ID}); code != http.StatusForbidden {
		t.Fatalf("mint for a gated target: want 403, got %d %s", code, d)
	}
	auditHas(t, env.st, "terminal.denied", "target:web-01 cred_user:root reason:target-policy")
	// A non-SSH target has no terminal.
	if code, d := do(t, env.srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{"name": "win-01", "host": "h", "port": 3389, "os_type": "windows", "protocol": "rdp"}); code != http.StatusCreated {
		t.Fatalf("create rdp target: %d %s", code, d)
	} else if code, _ := do(t, env.srv, http.MethodPost, "/api/ssh-token", aliceTok, map[string]any{"target_id": int64(jsonMap(t, d)["id"].(float64))}); code != http.StatusUnprocessableEntity {
		t.Errorf("mint for an rdp target: want 422, got %d", code)
	}
	// With no proxy wired, the terminal says so rather than failing later.
	plain, _ := newTestServerStore(t)
	pt := createTestTarget(t, plain, "t", "h")
	if code, _ := do(t, plain, http.MethodPost, "/api/ssh-token", testAPIKey, map[string]any{"target_id": pt}); code != http.StatusNotFound {
		t.Errorf("no proxy: want 404, got %d", code)
	}
}

// waitAudit polls for an audit row, for events written after a connection
// closes.
func waitAudit(st store.Store, action, detail string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		events, _ := st.ListAudit(context.Background(), 200)
		for _, e := range events {
			if e.Action == action && strings.Contains(e.Detail, detail) {
				return true
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	return false
}
