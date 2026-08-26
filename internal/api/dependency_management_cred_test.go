package api_test

// dependency_management_cred_test.go covers Phase 61: a dependent account can
// name the credential PAMv1 connects WITH to update it, instead of logging in
// as the service account whose password is being rotated.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/rotate"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

// seedManagementCred creates a second target + credential to act as the
// management account, returning its id.
func seedManagementCred(t *testing.T, srv *httptest.Server, username, secret string) int64 {
	t.Helper()
	status, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "app-01-admin", "host": "app-01", "port": 5985, "os_type": "windows", "protocol": "winrm",
	})
	if status != http.StatusCreated {
		t.Fatalf("seed management target: %d %s", status, data)
	}
	targetID := int64(jsonMap(t, data)["id"].(float64))
	status, data = do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": targetID, "username": username, "secret": secret,
	})
	if status != http.StatusCreated {
		t.Fatalf("seed management credential: %d %s", status, data)
	}
	return int64(jsonMap(t, data)["id"].(float64))
}

// TestPropagationUsesTheManagementCredential is the phase in one test: with a
// management credential declared, PAMv1 authenticates to the consumer's host as
// THAT account — not as the service account it is rotating, which in a hardened
// environment cannot log on remotely at all and should not hold the rights this
// change needs.
func TestPropagationUsesTheManagementCredential(t *testing.T) {
	fc := &fakeConnector{}
	fake := &fakeWinRM{result: winrm.Result{}}
	srv, st := newTestServerOpts(t, nil, api.Options{
		Rotators:  map[string]rotate.Rotator{"ssh": fc},
		Verifiers: map[string]rotate.Verifier{"ssh": fc},
		WinRM:     fake,
	})
	credID := seedTargetCred(t, srv, "ssh", "", "original-secret")
	mgmtID := seedManagementCred(t, srv, "CONTOSO\\svc-admin", "admin-secret")

	depURL := fmt.Sprintf("/api/credentials/%d/dependencies", credID)
	if code, body := do(t, srv, http.MethodPost, depURL, testAPIKey, map[string]any{
		"kind": "windows_service", "host": "app-01", "name": "MyService",
		"management_credential_id": mgmtID,
	}); code != http.StatusCreated {
		t.Fatalf("declare dependency: %d %s", code, body)
	}

	if code, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/rotate", credID), testAPIKey, nil); code != http.StatusOK {
		t.Fatalf("rotate: %d %s", code, data)
	}
	newSecret := fc.newSecret()
	if newSecret == "" {
		t.Fatal("rotation did not set a new secret")
	}

	// PAMv1 logged in as the management account…
	if fake.gotUser != "CONTOSO\\svc-admin" || fake.gotPass != "admin-secret" {
		t.Fatalf("propagation logged in as %q, want the management credential", fake.gotUser)
	}
	// …and the account being rotated was never used to authenticate.
	if fake.gotPass == newSecret {
		t.Fatal("propagation authenticated with the rotated account's new secret")
	}
	// …while still delivering the new secret INTO the service configuration.
	if !strings.Contains(fake.gotCmd, `sc.exe config "MyService"`) || !strings.Contains(fake.gotCmd, newSecret) {
		t.Fatalf("the service was not reconfigured with the new secret: %q", fake.gotCmd)
	}

	// The audit says which credential was used, and leaks neither secret.
	events, err := st.ListAudit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	var updated bool
	for _, e := range events {
		if e.Action != "credential.dependency_updated" {
			continue
		}
		updated = true
		if !strings.Contains(e.Detail, fmt.Sprintf("managed_via:credential:%d", mgmtID)) {
			t.Fatalf("the audit must name the management credential: %s", e.Detail)
		}
		if strings.Contains(e.Detail, newSecret) || strings.Contains(e.Detail, "admin-secret") {
			t.Fatalf("audit detail leaked a secret: %s", e.Detail)
		}
	}
	if !updated {
		t.Fatal("no credential.dependency_updated audit event")
	}
}

// TestPropagationFallsBackToTheRotatedAccount proves an existing deployment is
// unchanged: a dependency with no management credential still connects as the
// rotated account, exactly as before Phase 61.
func TestPropagationFallsBackToTheRotatedAccount(t *testing.T) {
	fc := &fakeConnector{}
	fake := &fakeWinRM{result: winrm.Result{}}
	srv, st := newTestServerOpts(t, nil, api.Options{
		Rotators:  map[string]rotate.Rotator{"ssh": fc},
		Verifiers: map[string]rotate.Verifier{"ssh": fc},
		WinRM:     fake,
	})
	credID := seedTargetCred(t, srv, "ssh", "", "original-secret")

	depURL := fmt.Sprintf("/api/credentials/%d/dependencies", credID)
	if code, body := do(t, srv, http.MethodPost, depURL, testAPIKey, map[string]any{
		"kind": "windows_service", "host": "app-01", "name": "MyService",
	}); code != http.StatusCreated {
		t.Fatalf("declare dependency: %d %s", code, body)
	}
	if code, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/rotate", credID), testAPIKey, nil); code != http.StatusOK {
		t.Fatalf("rotate: %d %s", code, data)
	}
	newSecret := fc.newSecret()

	if fake.gotUser != "root" || fake.gotPass != newSecret {
		t.Fatalf("without a management credential the rotated account is used: got %q", fake.gotUser)
	}
	auditHas(t, st, "credential.dependency_updated", "managed_via:self")
}

// TestPropagationFailsClosedOnBrokenManagementCredential proves a declared
// management credential that no longer resolves REFUSES the update instead of
// quietly falling back to the rotated account. The operator moved this
// consumer off that account deliberately; resuming it at the least visible
// moment would undo the decision without saying so.
func TestPropagationFailsClosedOnBrokenManagementCredential(t *testing.T) {
	fc := &fakeConnector{}
	fake := &fakeWinRM{result: winrm.Result{}}
	srv, st := newTestServerOpts(t, nil, api.Options{
		Rotators:  map[string]rotate.Rotator{"ssh": fc},
		Verifiers: map[string]rotate.Verifier{"ssh": fc},
		WinRM:     fake,
	})
	credID := seedTargetCred(t, srv, "ssh", "", "original-secret")
	mgmtID := seedManagementCred(t, srv, "CONTOSO\\svc-admin", "admin-secret")

	depURL := fmt.Sprintf("/api/credentials/%d/dependencies", credID)
	if code, body := do(t, srv, http.MethodPost, depURL, testAPIKey, map[string]any{
		"kind": "windows_service", "host": "app-01", "name": "MyService",
		"management_credential_id": mgmtID,
	}); code != http.StatusCreated {
		t.Fatalf("declare dependency: %d %s", code, body)
	}
	// The management credential goes away after the dependency was declared.
	if code, body := do(t, srv, http.MethodDelete, fmt.Sprintf("/api/credentials/%d", mgmtID), testAPIKey, nil); code != http.StatusNoContent {
		t.Fatalf("delete management credential: %d %s", code, body)
	}

	if code, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/rotate", credID), testAPIKey, nil); code != http.StatusOK {
		t.Fatalf("rotate must still succeed — propagation is best-effort: %d %s", code, data)
	}
	if fake.gotUser != "" {
		t.Fatalf("nothing should have been attempted over WinRM, but it logged in as %q", fake.gotUser)
	}
	auditHas(t, st, "credential.dependency_failed", "management-credential-missing")
}

// TestDependencyRejectsUnknownManagementCredential proves the reference is
// checked when the dependency is declared — while a human is present to be
// told — rather than only when an unattended rotation trips over it.
func TestDependencyRejectsUnknownManagementCredential(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{})
	credID := seedTargetCred(t, srv, "ssh", "", "original-secret")
	depURL := fmt.Sprintf("/api/credentials/%d/dependencies", credID)

	if code, _ := do(t, srv, http.MethodPost, depURL, testAPIKey, map[string]any{
		"kind": "windows_service", "host": "app-01", "name": "MyService",
		"management_credential_id": 999999,
	}); code != http.StatusUnprocessableEntity {
		t.Fatalf("unknown management credential: want 422, got %d", code)
	}
	if code, _ := do(t, srv, http.MethodPost, depURL, testAPIKey, map[string]any{
		"kind": "windows_service", "host": "app-01", "name": "MyService",
		"management_credential_id": -1,
	}); code != http.StatusUnprocessableEntity {
		t.Fatalf("negative management credential id: want 422, got %d", code)
	}

	// A valid one round-trips through the listing, so an operator can see which
	// account will be used without reading the audit trail.
	mgmtID := seedManagementCred(t, srv, "CONTOSO\\svc-admin", "admin-secret")
	if code, body := do(t, srv, http.MethodPost, depURL, testAPIKey, map[string]any{
		"kind": "windows_service", "host": "app-01", "name": "MyService",
		"management_credential_id": mgmtID,
	}); code != http.StatusCreated {
		t.Fatalf("declare with a valid management credential: %d %s", code, body)
	}
	code, data := do(t, srv, http.MethodGet, depURL, testAPIKey, nil)
	if code != http.StatusOK || !strings.Contains(string(data), fmt.Sprintf(`"management_credential_id":%d`, mgmtID)) {
		t.Fatalf("listing must show the management credential: %d %s", code, data)
	}
}
