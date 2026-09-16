package proxy

import (
	"context"
	"testing"

	"github.com/morandeirachema/pamv1/internal/store"
)

// TestAdmitCredentialScopedGrant proves the session gate decides about the
// credential the operator NAMED (Phase 252): a grant scoped to `deploy`
// admits `deploy@target` and refuses `root@target` at the target-policy gate
// — refuses, not opens, because a scoped grant still gates the target.
func TestAdmitCredentialScopedGrant(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	// env.target already carries gatesTestUser; add a second credential.
	other := &store.Credential{TargetID: env.target.ID, Username: "deploy", SecretType: "password"}
	if err := env.st.CreateCredential(ctx, other); err != nil {
		t.Fatal(err)
	}
	creds, err := env.st.ListCredentials(ctx, env.target.ID, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	var mainID int64
	for _, c := range creds {
		if c.Username == gatesTestUser {
			mainID = c.ID
		}
	}
	if mainID == 0 {
		t.Fatal("the env's own credential is missing")
	}

	// alice may use ONLY the env's main credential.
	if err := env.st.CreateTargetGrant(ctx, &store.TargetGrant{TargetID: env.target.ID, SubjectType: "user", Subject: "alice", CredentialID: &mainID}); err != nil {
		t.Fatal(err)
	}
	if res := env.g.admit(ctx, baseReq(gatesUser("alice"))); res.outcome != admitOK {
		t.Fatalf("alice on her scoped credential: outcome %d gate %d, want admitOK", res.outcome, res.gate)
	}
	req := baseReq(gatesUser("alice"))
	req.credUser = "deploy"
	if res := env.g.admit(ctx, req); res.outcome != admitDenied || res.gate != gateTargetPolicy {
		t.Fatalf("alice on the other credential: outcome %d gate %d, want denied at the target policy", res.outcome, res.gate)
	}
	// bob, named by nothing, is refused both — the scoped grant gates the target.
	for _, cu := range []string{gatesTestUser, "deploy"} {
		req := baseReq(gatesUser("bob"))
		req.credUser = cu
		if res := env.g.admit(ctx, req); res.outcome != admitDenied || res.gate != gateTargetPolicy {
			t.Fatalf("bob on %s: outcome %d gate %d, want denied — a scoped grant must gate the target", cu, res.outcome, res.gate)
		}
	}
	// A whole-target grant for carol covers both credentials: the target
	// policy gate admits her on either. (The `deploy` credential here carries
	// no vaulted secret, so that request fails LATER, at decryption — which is
	// not this gate's decision and not this test's subject.)
	if err := env.st.CreateTargetGrant(ctx, &store.TargetGrant{TargetID: env.target.ID, SubjectType: "user", Subject: "carol"}); err != nil {
		t.Fatal(err)
	}
	if res := env.g.admit(ctx, baseReq(gatesUser("carol"))); res.outcome != admitOK {
		t.Fatalf("carol on %s: outcome %d gate %d, want admitOK", gatesTestUser, res.outcome, res.gate)
	}
	req = baseReq(gatesUser("carol"))
	req.credUser = "deploy"
	if res := env.g.admit(ctx, req); res.gate == gateTargetPolicy {
		t.Fatalf("carol on deploy: refused at the target policy, but a whole-target grant covers every credential")
	}
}
