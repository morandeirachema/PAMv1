package proxy

import (
	"context"
	"testing"

	"github.com/morandeirachema/pamv1/internal/store"
)

// TestAdmitSafePermissions proves the one admission sequence reads a safe
// membership's permissions (Phase 246): only "use" opens a session; a
// retrieve-only or approve-only member is refused at the target-policy gate,
// before anything is decrypted.
func TestAdmitSafePermissions(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		perms []string
		want  admitKind
	}{
		{"use admits a session", []string{"use"}, admitOK},
		{"retrieve alone does not", []string{"retrieve"}, admitDenied},
		{"approve alone does not", []string{"approve"}, admitDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t)
			sf := &store.Safe{Name: "ops"}
			if err := env.st.CreateSafe(ctx, sf); err != nil {
				t.Fatal(err)
			}
			if err := env.st.AssignTargetSafe(ctx, env.target.ID, &sf.ID); err != nil {
				t.Fatal(err)
			}
			if err := env.st.AddSafeMember(ctx, &store.SafeMember{SafeID: sf.ID, SubjectType: "user", Subject: "alice", Permissions: tc.perms}); err != nil {
				t.Fatal(err)
			}
			res := env.g.admit(ctx, baseReq(gatesUser("alice")))
			if res.outcome != tc.want {
				t.Fatalf("outcome %d gate %d, want %d", res.outcome, res.gate, tc.want)
			}
			if tc.want == admitDenied && (res.gate != gateTargetPolicy || res.secret != "") {
				t.Fatalf("gate %d secret %q, want a target-policy refusal with nothing decrypted", res.gate, res.secret)
			}
		})
	}
}
