package api_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/morandeirachema/pamv1/internal/store"
)

// TestDeleteByIDRoutes pins the six plain delete routes — the ones built by
// deleteByID — to their exact contract: 204, one audit row whose action and
// detail are byte-for-byte what each handler wrote when it was hand-typed, and
// 404 (with no second row) for an id that is already gone. Two of the six,
// DELETE /api/profiles/{id} and DELETE /v1/apps/{id}, had no test at all.
func TestDeleteByIDRoutes(t *testing.T) {
	opts := brokerOpts(t, &fakeWinRM{}, approvalRules)
	opts.AppSecretsEnabled = true
	opts.ScimEnabled = true
	srv, st := newTestServerOpts(t, nil, opts)
	ctx := context.Background()

	cases := []struct {
		name   string
		create func() (int64, error)
		path   string
		action string
		field  string
	}{
		{"agent identity", func() (int64, error) {
			a := store.AgentIdentity{SPIFFEID: "spiffe://example.org/agent/del", Owner: "alice"}
			err := st.CreateAgentIdentity(ctx, &a)
			return a.ID, err
		}, "/v1/agents/identities/", "agent.identity_remove", "identity"},
		{"app key", func() (int64, error) {
			k := store.AppKey{Name: "app-del", Owner: "platform", TokenHash: "h-app"}
			err := st.CreateAppKey(ctx, &k)
			return k.ID, err
		}, "/v1/apps/", "app.revoke", "app"},
		{"agent key", func() (int64, error) {
			k := store.AgentKey{Name: "agent-del", Owner: "alice", TokenHash: "h-agent"}
			err := st.CreateAgentKey(ctx, &k)
			return k.ID, err
		}, "/v1/agents/", "agent.revoke", "agent"},
		{"profile", func() (int64, error) {
			p := store.Profile{Name: "profile-del", Capabilities: []string{"read_inventory"}}
			err := st.CreateProfile(ctx, &p)
			return p.ID, err
		}, "/api/profiles/", "profile.delete", "profile"},
		{"restriction rule", func() (int64, error) {
			r := store.RestrictionRule{SubjectType: "role", Subject: "user", Subprotocol: "ssh_exec", Pattern: "^reboot$", Action: "kill"}
			err := st.CreateRestrictionRule(ctx, &r)
			return r.ID, err
		}, "/api/restriction-rules/", "restriction.delete", "rule"},
		{"scim key", func() (int64, error) {
			k := store.ScimKey{Name: "scim-del", Owner: "idp", TokenHash: "h-scim"}
			err := st.CreateScimKey(ctx, &k)
			return k.ID, err
		}, "/v1/scim-keys/", "scim.key_revoke", "scim_key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id, err := c.create()
			if err != nil {
				t.Fatalf("seed: %v", err)
			}
			if status, data := do(t, srv, http.MethodDelete, c.path+itoa(id), testAPIKey, nil); status != http.StatusNoContent {
				t.Fatalf("delete: %d %s, want 204", status, data)
			}
			want := c.field + ":" + itoa(id)
			if n := countAudit(t, st, c.action, want); n != 1 {
				t.Fatalf("%s %q audited %d times, want once", c.action, want, n)
			}
			if status, data := do(t, srv, http.MethodDelete, c.path+itoa(id), testAPIKey, nil); status != http.StatusNotFound {
				t.Fatalf("second delete: %d %s, want 404", status, data)
			}
			if n := countAudit(t, st, c.action, want); n != 1 {
				t.Fatalf("a refused delete audited %s again (%d rows)", c.action, n)
			}
		})
	}
}

// countAudit counts audit rows with exactly this action and detail.
func countAudit(t *testing.T, st store.Store, action, detail string) int {
	t.Helper()
	events, err := st.ListAudit(context.Background(), 500)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range events {
		if e.Action == action && e.Detail == detail {
			n++
		}
	}
	return n
}
