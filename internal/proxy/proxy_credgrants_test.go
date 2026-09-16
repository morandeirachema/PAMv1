package proxy_test

import (
	"context"
	"testing"

	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// TestCredentialScopedGrantProxy proves object-level access control end to end
// against the in-process sshd (Phase 252). The upstream accepts ONLY the
// vaulted password of the target's `root` credential, so an admitted session
// proves the proxy resolved and injected it, and a refused one proves the
// gate closed before any secret was touched. A second credential, `deploy`,
// exists on the same target so a grant can be scoped to one or the other.
func TestCredentialScopedGrantProxy(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	addr := lifetimeProxy(t, st, 0, 0)
	targets, _ := st.ListTargets(ctx, 0, 0)
	tgt := targets[0]
	deploy := &store.Credential{TargetID: tgt.ID, Username: "deploy", SecretType: "password"}
	if err := st.CreateCredential(ctx, deploy); err != nil {
		t.Fatal(err)
	}
	creds, _ := st.ListCredentials(ctx, tgt.ID, 0, 0)
	var rootID int64
	for _, c := range creds {
		if c.Username == upstreamUser {
			rootID = c.ID
		}
	}
	if rootID == 0 {
		t.Fatal("the seeded root credential is missing")
	}

	aliceTok := seedLabelUser(t, st, "alice", "user")
	bobTok := seedLabelUser(t, st, "bob", "user")
	// alice may use root only; bob may use deploy only.
	if err := st.CreateTargetGrant(ctx, &store.TargetGrant{TargetID: tgt.ID, SubjectType: "user", Subject: "alice", CredentialID: &rootID}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTargetGrant(ctx, &store.TargetGrant{TargetID: tgt.ID, SubjectType: "user", Subject: "bob", CredentialID: &deploy.ID}); err != nil {
		t.Fatal(err)
	}

	// alice on root: a real session, with the injected upstream password.
	client, err := dialProxy(t, addr, upstreamUser+"@web-01", aliceTok)
	if err != nil {
		t.Fatalf("alice on her scoped credential must get a session: %v", err)
	}
	client.Close()

	// alice on deploy: refused — her grant is on root.
	if c, err := dialProxy(t, addr, "deploy@web-01", aliceTok); err == nil {
		if sess, serr := c.NewSession(); serr == nil {
			sess.Close()
			c.Close()
			t.Fatal("alice's grant on root admitted her to deploy")
		}
		c.Close()
	}
	// bob on root: refused — his grant is on deploy. This is the case that
	// matters: root is the credential with a real secret, and bob reaches the
	// same target through another credential, yet root must stay closed to him.
	if c, err := dialProxy(t, addr, upstreamUser+"@web-01", bobTok); err == nil {
		if sess, serr := c.NewSession(); serr == nil {
			sess.Close()
			c.Close()
			t.Fatal("bob's grant on deploy admitted him to root")
		}
		c.Close()
	}
}
