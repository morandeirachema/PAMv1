package api_test

// Three authorization gaps from the 2026-07-30 sweep, each a case where one path
// to a credential ran gates that a sibling path skipped.

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
)

// TestRotateAndReconcileObeyApproval proves rotation and remediating reconcile
// honour the same four-eyes gate as reveal, checkout and connect.
//
// Both skipped it, so `manage_credentials` alone changed a production password on
// a target the holder could neither connect to nor reveal, outside any approval
// window. The agent-facing rotate_credential tool was gated for exactly this in
// Phase 52c; the human endpoints were not.
func TestRotateAndReconcileObeyApproval(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{RequireApproval: true})
	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "lnx", "host": "10.0.0.5", "port": 22, "os_type": "linux", "protocol": "ssh"})
	tid := int64(jsonMap(t, td)["id"].(float64))
	_, cd := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": tid, "username": "root", "secret": "pw"})
	cid := int64(jsonMap(t, cd)["id"].(float64))

	if code, body := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/rotate", cid), testAPIKey, nil); code != http.StatusForbidden {
		t.Fatalf("rotate under approval policy: want 403, got %d %s", code, body)
	}
	if code, body := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/reconcile?remediate=true", cid), testAPIKey, nil); code != http.StatusForbidden {
		t.Fatalf("remediating reconcile under approval policy: want 403, got %d %s", code, body)
	}
}

// TestAppSecretGrantObeysCredentialGates proves granting an application a secret
// runs the same gates as revealing it.
//
// The handler's own doc comment says "only a principal who could reveal the secret
// itself may hand it out", but it never loaded the credential — so the grant
// laundered a secret past the approval window, the per-target grants and the
// vendor contract, because GET /v1/app-secrets/{id} then vends the plaintext on
// the app's own grant alone.
func TestAppSecretGrantObeysCredentialGates(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{RequireApproval: true, AppSecretsEnabled: true})
	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "lnx", "host": "10.0.0.5", "port": 22, "os_type": "linux", "protocol": "ssh"})
	tid := int64(jsonMap(t, td)["id"].(float64))
	_, cd := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": tid, "username": "root", "secret": "pw"})
	cid := int64(jsonMap(t, cd)["id"].(float64))
	_, ad := do(t, srv, http.MethodPost, "/v1/apps", testAPIKey, map[string]any{"name": "billing"})
	aid := int64(jsonMap(t, ad)["id"].(float64))

	// Reveal is refused without an approved request; the grant must be too, or it
	// is a way around the gate.
	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/reveal", cid), testAPIKey, nil); code != http.StatusForbidden {
		t.Fatalf("reveal under approval policy: want 403, got %d", code)
	}
	if code, body := do(t, srv, http.MethodPost, fmt.Sprintf("/v1/apps/%d/grants", aid), testAPIKey,
		map[string]any{"credential_id": cid}); code != http.StatusForbidden {
		t.Fatalf("app-secret grant under approval policy: want 403, got %d %s", code, body)
	}
}

// TestAgentRequiresOwner proves an agent cannot be created without an owner.
//
// The broker's four-eyes refusal is keyed on the owner, so an ownerless agent
// silently disabled it: one approver could create an agent, have it request a
// privileged tool call, and approve that call themselves.
func TestAgentRequiresOwner(t *testing.T) {
	// The /v1/agents routes exist only with the broker enabled.
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, &fakeWinRM{}, brokerRules))
	if code, body := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey,
		map[string]any{"name": "ownerless-bot"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("creating an agent with no owner: want 422, got %d %s", code, body)
	}
	if code, body := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey,
		map[string]any{"name": "owned-bot", "owner": "alice"}); code != http.StatusCreated {
		t.Fatalf("creating an agent with an owner: want 201, got %d %s", code, body)
	}
}
