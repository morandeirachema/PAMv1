package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
)

// TestKeyOwnerCannotForgeAuditFields is the regression guard for the app and
// SCIM key owner: both handlers checked the key's name but wrote the owner raw
// into the app.create / scim.key_create audit detail ("<name> owner:<owner>"),
// so a caller could append key:value pairs, or a second line, to the record —
// the forgery validName exists to stop (SECURITY-GAPS finding BD). The agent
// key's owner was always checked. An owner stays optional for these two.
func TestKeyOwnerCannotForgeAuditFields(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{AppSecretsEnabled: true, ScimEnabled: true})
	for _, path := range []string{"/v1/apps", "/v1/scim-keys"} {
		for i, owner := range []string{"platform action:approved", "platform\nscim.key_revoke scim_key:1"} {
			status, data := do(t, srv, http.MethodPost, path, testAPIKey,
				map[string]any{"name": "forged-" + itoa(int64(i)), "owner": owner})
			if status != http.StatusUnprocessableEntity {
				t.Fatalf("%s with owner %q: %d %s, want 422", path, owner, status, data)
			}
		}
		for i, owner := range []string{"", "Platform Team"} {
			status, data := do(t, srv, http.MethodPost, path, testAPIKey,
				map[string]any{"name": "fine-" + itoa(int64(i)), "owner": owner})
			if status != http.StatusCreated {
				t.Fatalf("%s with owner %q: %d %s, want 201", path, owner, status, data)
			}
		}
	}
	events, err := st.ListAudit(context.Background(), 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if strings.Contains(e.Detail, "action:approved") || strings.Contains(e.Detail, "\n") {
			t.Fatalf("a refused owner reached the audit trail: %s %q", e.Action, e.Detail)
		}
	}
}
