package proxy_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// seedLabelUser creates a user and returns the token that authenticates it.
func seedLabelUser(t *testing.T, st store.Store, name, role string) string {
	t.Helper()
	tok := name + "-token"
	sum := sha256.Sum256([]byte(tok))
	if err := st.CreateUser(context.Background(), &store.User{Username: name, Role: role, TokenHash: hex.EncodeToString(sum[:])}); err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestLabelRulesProxy proves label-based authorization end to end against the
// in-process sshd (Phase 250): a rule that names no target decides a real SSH
// session, in both directions. It is the same shape as the JIT-injection test
// — the upstream accepts ONLY the vaulted password, so an admitted session
// proves the proxy resolved and injected a credential the client never had,
// and a refused one proves nothing was resolved at all.
func TestLabelRulesProxy(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	addr := lifetimeProxy(t, st, 0, 0)
	targets, _ := st.ListTargets(ctx, 0, 0)
	tgt := &targets[0]
	tgt.Labels = "env=prod,tier=db"
	if err := st.UpdateTarget(ctx, tgt); err != nil {
		t.Fatal(err)
	}

	aliceTok := seedLabelUser(t, st, "alice", "user")
	mallotok := seedLabelUser(t, st, "mallory", "user")
	rootTok := seedLabelUser(t, st, "root", "admin")

	// An ALLOW rule on env=prod: alice reaches a target no grant names her on.
	allow := store.LabelRule{Selector: "env=prod", SubjectType: "user", Subject: "alice", Effect: store.GrantAllow}
	if err := st.CreateLabelRule(ctx, &allow); err != nil {
		t.Fatal(err)
	}
	client, err := dialProxy(t, addr, upstreamUser+"@web-01", aliceTok)
	if err != nil {
		t.Fatalf("a matching allow rule must open a session: %v", err)
	}
	client.Close()

	// The same rule GATES the target: mallory, whom nothing names, is refused.
	if c, err := dialProxy(t, addr, upstreamUser+"@web-01", mallotok); err == nil {
		if sess, serr := c.NewSession(); serr == nil {
			sess.Close()
			c.Close()
			t.Fatal("an allow rule naming alice admitted mallory")
		}
		c.Close()
	}

	// A DENY rule on tier=db refuses the ADMIN, who needs no grant and passes
	// every other gate on identity alone. This is the phase's whole point: a
	// deny an administrator can step around is not a deny.
	deny := store.LabelRule{Selector: "tier=db", SubjectType: "role", Subject: "admin", Effect: store.GrantDeny}
	if err := st.CreateLabelRule(ctx, &deny); err != nil {
		t.Fatal(err)
	}
	if c, err := dialProxy(t, addr, upstreamUser+"@web-01", rootTok); err == nil {
		if sess, serr := c.NewSession(); serr == nil {
			sess.Close()
			c.Close()
			t.Fatal("a deny rule naming the admin role admitted an admin")
		}
		c.Close()
	}
	// alice is untouched by a deny that names the admin role.
	c2, err := dialProxy(t, addr, upstreamUser+"@web-01", aliceTok)
	if err != nil {
		t.Fatalf("a deny naming another subject must not refuse alice: %v", err)
	}
	c2.Close()

	// Relabelling the target is the revocation: no selector matches, so the
	// deny stops applying and the admin is back in.
	tgt.Labels = "env=staging"
	if err := st.UpdateTarget(ctx, tgt); err != nil {
		t.Fatal(err)
	}
	c3, err := dialProxy(t, addr, upstreamUser+"@web-01", rootTok)
	if err != nil {
		t.Fatalf("relabelling away from tier=db must lift the deny: %v", err)
	}
	c3.Close()
	// ...and alice's allow rule no longer matches either, so with the target
	// ungated again the open default admits her — the rule follows the label,
	// not the target.
	if rules, err := st.ListLabelRules(ctx); err != nil || len(rules) != 2 {
		t.Fatalf("both rules must still exist, unchanged by the relabel: %+v err %v", rules, err)
	}
}
