package proxy_test

import (
	"context"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

func startRestrictedProxy(t *testing.T, st store.Store, v *vault.Vault, mode proxy.SFTPMode) string {
	t.Helper()
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
		SFTPMode: mode, Sessions: session.NewRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return serveProxy(t, px)
}

// TestRestrictionRulesExec (Phase 275): a notify rule on the operator's role
// records the match and lets the command run; a kill rule refuses it and
// ends the session — both audited with the rule.
func TestRestrictionRulesExec(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	ctx := context.Background()
	notify := &store.RestrictionRule{SubjectType: "role", Subject: "admin", Subprotocol: "ssh_exec", Pattern: `^whoami$`, Action: "notify"}
	kill := &store.RestrictionRule{SubjectType: "role", Subject: "admin", Subprotocol: "*", Pattern: `rm\s+-rf`, Action: "kill"}
	for _, r := range []*store.RestrictionRule{notify, kill} {
		if err := st.CreateRestrictionRule(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	addr := startRestrictedProxy(t, st, v, proxy.SFTPAllow)

	c, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sess.Output("whoami")
	sess.Close()
	if err != nil || string(out) != targetOutput {
		t.Fatalf("notify rule must let the command run: %q %v", out, err)
	}
	waitForAuditDetail(t, st, "restriction.notified", "target:web-01 via:proxy rule:"+itoa(notify.ID)+` pattern:"^whoami$" cmd:"whoami"`)

	sess2, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sess2.Output("rm -rf /"); err == nil {
		t.Fatal("kill rule must refuse the command")
	}
	sess2.Close()
	waitForAuditDetail(t, st, "restriction.killed", "target:web-01 via:proxy rule:"+itoa(kill.ID)+` pattern:"rm\\s+-rf" cmd:"rm -rf /"`)
	// The session is gone: a new channel on the same connection fails.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := c.NewSession(); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the connection outlived a kill rule")
}

// TestRestrictionSFTPSizeLimit: a $filesize rule refuses an upload once it
// exceeds the limit, audited with the bytes and the rule; with notify the
// bytes pass and the crossing is recorded once.
func TestRestrictionSFTPSizeLimit(t *testing.T) {
	up := startUpstreamSFTP(t)
	ctx := context.Background()
	for _, tc := range []struct {
		action string
		denied bool
	}{{"kill", true}, {"notify", false}} {
		st := memstore.New()
		v := mustVault(t)
		seedTarget(t, st, v, up.host, up.port)
		rule := &store.RestrictionRule{SubjectType: "role", Subject: "admin", Subprotocol: "sftp", Pattern: "$filesize:>10", Action: tc.action}
		if err := st.CreateRestrictionRule(ctx, rule); err != nil {
			t.Fatal(err)
		}
		addr := startRestrictedProxy(t, st, v, proxy.SFTPAllow)
		client, ch, ok := openSFTPChannel(t, addr)
		if !ok {
			t.Fatal("sftp refused")
		}
		initSFTP(t, ch)
		ch.Write(sftpPacket(tOpen, be32(1), sftpStr("/srv/big.bin"), be32(pWrite|pCreat|pTrunc), be32(0)))
		if typ, _, err := readPacket(ch); err != nil || typ == tStatus {
			t.Fatalf("[%s] open: type %d err %v", tc.action, typ, err)
		}
		// 8 bytes: under the 10-byte limit. Then 8 more: over it.
		ch.Write(sftpPacket(tWrite, be32(2), sftpStr("h"), make([]byte, 8), sftpStr("12345678")))
		if typ, _, err := readPacket(ch); err != nil || typ != tStatus {
			t.Fatalf("[%s] first write: type %d err %v", tc.action, typ, err)
		}
		ch.Write(sftpPacket(tWrite, be32(3), sftpStr("h"), append(make([]byte, 7), 8), sftpStr("12345678")))
		typ, body, err := readPacket(ch)
		if err != nil && !tc.denied {
			t.Fatalf("[%s] second write: %v", tc.action, err)
		}
		if err == nil && typ == tStatus && tc.denied {
			// A refusal is a status with a non-OK code (the upstream echoes OK).
			if len(body) >= 8 && be32ToInt(body[4:8]) == 0 {
				t.Fatalf("[%s] second write was not refused", tc.action)
			}
		}
		waitForAuditDetail(t, st, "sftp.size_limit", "direction:up bytes:16 limit:10 rule:"+itoa(rule.ID)+" action:"+tc.action)
		client.Close()
		_ = ssh.ErrNoAuth
	}
}

func be32ToInt(b []byte) int {
	return int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
}
