package proxy_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// alertSink collects alert events.
type alertSink struct {
	mu     sync.Mutex
	events []alert.Event
}

func (a *alertSink) Notify(_ context.Context, e alert.Event) {
	a.mu.Lock()
	a.events = append(a.events, e)
	a.mu.Unlock()
}
func (a *alertSink) has(kind, sub string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.events {
		if e.Type == kind && strings.Contains(e.Detail, sub) {
			return true
		}
	}
	return false
}

func startTOFUProxy(t *testing.T, st store.Store, v *vault.Vault, mode string, sink *alertSink, known ssh.HostKeyCallback) string {
	t.Helper()
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
		HostKeyCheck: mode, Alerter: sink, UpstreamHostKey: known,
	})
	if err != nil {
		t.Fatal(err)
	}
	return serveProxy(t, px)
}

func execThrough(t *testing.T, addr string) error {
	t.Helper()
	c, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		return err
	}
	defer c.Close()
	sess, err := c.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	out, err := sess.Output("whoami")
	if err != nil {
		return err
	}
	if string(out) != targetOutput {
		return errors.New("wrong output")
	}
	return nil
}

// TestHostKeyTOFU proves Phase 272 against two real upstream sshds with
// different host keys: the first contact pins and is audited and alerted;
// the same key is accepted again; a different key on the same target is
// refused, audited and alerted, and stays refused until an administrator
// resets the pin — after which the new key is pinned.
func TestHostKeyTOFU(t *testing.T) {
	keyA, keyB := mustSigner(t), mustSigner(t)
	hostA, portA := startUpstreamKeyed(t, upstreamUser, upstreamSecret, targetOutput, keyA)
	hostB, portB := startUpstreamKeyed(t, upstreamUser, upstreamSecret, targetOutput, keyB)
	st := memstore.New()
	v := mustVault(t)
	target := seedTarget(t, st, v, hostA, portA)
	sink := &alertSink{}
	addr := startTOFUProxy(t, st, v, proxy.HostKeyTOFU, sink, nil)
	ctx := context.Background()
	fpA, fpB := ssh.FingerprintSHA256(keyA.PublicKey()), ssh.FingerprintSHA256(keyB.PublicKey())

	// First contact: pinned.
	if err := execThrough(t, addr); err != nil {
		t.Fatalf("first contact: %v", err)
	}
	waitForAuditDetail(t, st, "target.hostkey_saved", "target:web-01 host:\"127.0.0.1\":"+itoa(int64(portA))+" key_type:"+keyA.PublicKey().Type()+" fingerprint:"+fpA)
	pin, err := st.GetTargetHostKey(ctx, target.ID)
	if err != nil || pin.Fingerprint != fpA {
		t.Fatalf("pin: %+v err %v", pin, err)
	}
	if !sink.has("hostkey.saved", fpA) {
		t.Fatalf("no hostkey.saved alert: %+v", sink.events)
	}
	// Same key: accepted, nothing new audited.
	if err := execThrough(t, addr); err != nil {
		t.Fatalf("second contact: %v", err)
	}

	// The target is "re-keyed": point it at the upstream with key B.
	target.Host, target.Port = hostB, portB
	if err := st.UpdateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	if err := execThrough(t, addr); err == nil {
		t.Fatal("a different host key must be refused")
	}
	waitForAuditDetail(t, st, "target.hostkey_mismatch", "target:web-01 host:\"127.0.0.1\":"+itoa(int64(portB))+" key_type:"+keyB.PublicKey().Type()+" presented:"+fpB+" pinned:"+fpA)
	waitForAuditDetail(t, st, "session.error", "host key mismatch")
	if !sink.has("hostkey.mismatch", fpB) {
		t.Fatalf("no hostkey.mismatch alert: %+v", sink.events)
	}
	if pin, _ := st.GetTargetHostKey(ctx, target.ID); pin.Fingerprint != fpA {
		t.Fatal("a mismatch must not re-learn the key")
	}

	// Reset: the next key is trusted and pinned.
	if err := st.DeleteTargetHostKey(ctx, target.ID); err != nil {
		t.Fatal(err)
	}
	if err := execThrough(t, addr); err != nil {
		t.Fatalf("after reset: %v", err)
	}
	if pin, _ := st.GetTargetHostKey(ctx, target.ID); pin == nil || pin.Fingerprint != fpB {
		t.Fatalf("new key not pinned after reset: %+v", pin)
	}
}

// TestHostKeyStrictAndOff: strict refuses an unpinned target (and admits it
// once pinned); off trusts anything and pins nothing; a known_hosts callback
// leaves the store untouched.
func TestHostKeyStrictAndOff(t *testing.T) {
	key := mustSigner(t)
	host, port := startUpstreamKeyed(t, upstreamUser, upstreamSecret, targetOutput, key)
	v := mustVault(t)
	ctx := context.Background()

	st := memstore.New()
	target := seedTarget(t, st, v, host, port)
	addr := startTOFUProxy(t, st, v, proxy.HostKeyStrict, nil, nil)
	if err := execThrough(t, addr); err == nil {
		t.Fatal("strict mode admitted an unpinned target")
	}
	waitForAuditDetail(t, st, "target.hostkey_unknown", "target:web-01")
	if err := st.PutTargetHostKey(ctx, &store.TargetHostKey{TargetID: target.ID, KeyType: key.PublicKey().Type(),
		Fingerprint: ssh.FingerprintSHA256(key.PublicKey()), PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key.PublicKey())))}); err != nil {
		t.Fatal(err)
	}
	if err := execThrough(t, addr); err != nil {
		t.Fatalf("strict mode with a seeded pin: %v", err)
	}

	st2 := memstore.New()
	t2 := seedTarget(t, st2, v, host, port)
	addr2 := startTOFUProxy(t, st2, v, proxy.HostKeyOff, nil, nil)
	if err := execThrough(t, addr2); err != nil {
		t.Fatalf("off mode: %v", err)
	}
	if _, err := st2.GetTargetHostKey(ctx, t2.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("off mode must pin nothing")
	}

	st3 := memstore.New()
	t3 := seedTarget(t, st3, v, host, port)
	addr3 := startTOFUProxy(t, st3, v, proxy.HostKeyTOFU, nil, ssh.FixedHostKey(key.PublicKey()))
	if err := execThrough(t, addr3); err != nil {
		t.Fatalf("known_hosts callback: %v", err)
	}
	if _, err := st3.GetTargetHostKey(ctx, t3.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a known_hosts callback must leave the pin store untouched")
	}

	if _, err := proxy.New(st, v, mustResolver(t, st), proxy.Config{HostKey: mustSigner(t), HostKeyCheck: "maybe"}); err == nil {
		t.Fatal("unknown mode accepted")
	}
}

func mustResolver(t *testing.T, st store.Store) *auth.Resolver {
	t.Helper()
	r, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	return r
}
