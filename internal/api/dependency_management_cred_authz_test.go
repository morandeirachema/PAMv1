package api_test

// dependency_management_cred_authz_test.go covers Phase 61a: naming a
// credential as a dependency's management credential is a USE of that
// credential, so it is authorized like one.
//
// Phase 61 checked only that the named credential existed. That made the
// reference an exfiltration primitive: a caller holding CapManageCredentials —
// and nothing else — could name a credential they may not reveal, on a target
// they were never granted, and point the dependency's `host` at a machine they
// control. The next rotation of any credential they *could* rotate then made
// PAMv1 decrypt the named secret and present it, in plaintext, to that machine.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/rotate"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

// seedGatedCred creates a target, puts a credential on it and grants that
// target to `grantee` alone — so anyone else is refused by the per-target gate.
// It returns the credential's id.
func seedGatedCred(t *testing.T, srv *httptest.Server, name, username, secret, secretType, grantee string) int64 {
	t.Helper()
	// An SSH key or an ssh_ca (Zero Standing Privilege) credential is only valid
	// on an SSH target, so the target follows the secret it will hold.
	tgt := map[string]any{"name": name, "host": name, "port": 5985, "os_type": "windows", "protocol": "winrm"}
	if strings.HasPrefix(secretType, "ssh_") {
		tgt = map[string]any{"name": name, "host": name, "port": 22, "os_type": "linux", "protocol": "ssh"}
	}
	code, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, tgt)
	if code != http.StatusCreated {
		t.Fatalf("seed target %s: %d %s", name, code, data)
	}
	targetID := int64(jsonMap(t, data)["id"].(float64))
	body := map[string]any{"target_id": targetID, "username": username, "secret": secret}
	if secretType != "" {
		body["secret_type"] = secretType
	}
	code, data = do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, body)
	if code != http.StatusCreated {
		t.Fatalf("seed credential on %s: %d %s", name, code, data)
	}
	credID := int64(jsonMap(t, data)["id"].(float64))
	if grantee != "" {
		if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/targets/%d/grants", targetID), testAPIKey,
			map[string]any{"subject_type": "user", "subject": grantee}); code != http.StatusCreated {
			t.Fatalf("gate target %s: %d %s", name, code, d)
		}
	}
	return credID
}

// seedProfileUser creates a custom permission profile with caps and a user
// carrying it, returning that user's API token.
func seedProfileUser(t *testing.T, srv *httptest.Server, profile, user string, caps ...string) string {
	t.Helper()
	if code, d := do(t, srv, http.MethodPost, "/api/profiles", testAPIKey, map[string]any{
		"name": profile, "capabilities": caps,
	}); code != http.StatusCreated {
		t.Fatalf("create profile %s: %d %s", profile, code, d)
	}
	return seedUser(t, srv, user, profile)
}

// TestManagementCredentialNeedsRevealSecret is the exfiltration attempt itself:
// a credential manager who cannot reveal a secret cannot make PAMv1 present one
// on their behalf. CapManageCredentials buys the right to declare a dependency,
// not the right to spend someone else's crown jewels doing it.
func TestManagementCredentialNeedsRevealSecret(t *testing.T) {
	fc := &fakeConnector{}
	fake := &fakeWinRM{result: winrm.Result{}}
	srv, st := newTestServerOpts(t, nil, api.Options{
		Rotators:  map[string]rotate.Rotator{"ssh": fc},
		Verifiers: map[string]rotate.Verifier{"ssh": fc},
		WinRM:     fake,
	})
	daCredID := seedGatedCred(t, srv, "dc-01", "CONTOSO\\Domain Admin", "SUPER-SECRET-DA", "", "someone-else")
	labCredID := seedTargetCred(t, srv, "ssh", "", "lab-secret")
	tok := seedProfileUser(t, srv, "credmgr", "cm", "manage_credentials", "read_inventory")

	code, body := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/dependencies", labCredID), tok, map[string]any{
		"kind": "windows_service", "host": "attacker.example.com", "port": 443, "name": "MyService",
		"management_credential_id": daCredID,
	})
	if code != http.StatusForbidden {
		t.Fatalf("declaring with an unrevealable management credential: want 403, got %d %s", code, body)
	}
	auditHas(t, st, "dependency.create_denied", "reason:reveal-secret-required")

	// The same refusal for an id that does not exist: the capability is checked
	// before the lookup, so this endpoint is not an oracle over the id space.
	if missing, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/dependencies", labCredID), tok, map[string]any{
		"kind": "windows_service", "host": "attacker.example.com", "name": "OtherService",
		"management_credential_id": daCredID + 9999,
	}); missing != code {
		t.Fatalf("existing id -> %d but missing id -> %d: an existence oracle", code, missing)
	}

	// The refusal held: rotating the lab credential reaches no host at all,
	// because the dependency was never created.
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/rotate", labCredID), tok, nil); code != http.StatusOK {
		t.Fatalf("rotate lab credential: %d %s", code, d)
	}
	if fake.gotHost != "" {
		t.Fatalf("PAMv1 connected to %q presenting %q", fake.gotHost, fake.gotUser)
	}
}

// TestManagementCredentialNeedsTheTargetGrant proves the second half of the
// bar: holding CapRevealSecret is not enough, because reveal itself is bounded
// by the per-target grants. The gate is applied to the MANAGEMENT credential's
// target, which is the one whose secret leaves.
func TestManagementCredentialNeedsTheTargetGrant(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{})
	daCredID := seedGatedCred(t, srv, "dc-01", "CONTOSO\\Domain Admin", "SUPER-SECRET-DA", "", "someone-else")
	labCredID := seedTargetCred(t, srv, "ssh", "", "lab-secret")
	tok := seedProfileUser(t, srv, "revealer", "rv", "manage_credentials", "reveal_secret", "read_inventory")

	depURL := fmt.Sprintf("/api/credentials/%d/dependencies", labCredID)
	code, body := do(t, srv, http.MethodPost, depURL, tok, map[string]any{
		"kind": "windows_service", "host": "attacker.example.com", "name": "MyService",
		"management_credential_id": daCredID,
	})
	if code != http.StatusForbidden {
		t.Fatalf("ungranted management credential's target: want 403, got %d %s", code, body)
	}
	auditHas(t, st, "dependency.create_denied", "reason:target-policy")

	// An ungated management credential is accepted from the same caller, so the
	// refusal above is the grant and not the capability.
	openCredID := seedGatedCred(t, srv, "app-01-admin", "CONTOSO\\svc-admin", "admin-secret", "", "")
	if code, body := do(t, srv, http.MethodPost, depURL, tok, map[string]any{
		"kind": "windows_service", "host": "app-01", "name": "MyService",
		"management_credential_id": openCredID,
	}); code != http.StatusCreated {
		t.Fatalf("granted management credential: want 201, got %d %s", code, body)
	}
}

// TestManagementCredentialMustHoldAPassword refuses the secret types that
// cannot be one. An SSH private key handed to WinRM as a password authenticates
// nothing and discloses the whole key to the consumer's host; a Zero Standing
// Privilege credential holds no secret at all.
func TestManagementCredentialMustHoldAPassword(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{})
	labCredID := seedTargetCred(t, srv, "ssh", "", "lab-secret")
	depURL := fmt.Sprintf("/api/credentials/%d/dependencies", labCredID)

	const pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-real-key\n-----END OPENSSH PRIVATE KEY-----\n"
	for _, tc := range []struct{ name, secret, secretType string }{
		{"jump-01", pem, "ssh_key"},
		{"zsp-01", "", "ssh_ca"},
	} {
		keyCredID := seedGatedCred(t, srv, tc.name, "svc-deploy", tc.secret, tc.secretType, "")
		code, body := do(t, srv, http.MethodPost, depURL, testAPIKey, map[string]any{
			"kind": "windows_service", "host": "app-01", "name": "MyService",
			"management_credential_id": keyCredID,
		})
		if code != http.StatusUnprocessableEntity {
			t.Fatalf("%s management credential: want 422, got %d %s", tc.secretType, code, body)
		}
		if !strings.Contains(string(body), tc.secretType) {
			t.Fatalf("the refusal should say what it holds: %s", body)
		}
	}
}

// TestPropagationRefusesANonPasswordManagementCredential is the use-time half
// of the same rule, proven the only way it can happen once the API refuses it:
// the row is written straight into the store, as one predating the rule would
// be. Nothing reaches WinRM.
func TestPropagationRefusesANonPasswordManagementCredential(t *testing.T) {
	fc := &fakeConnector{}
	fake := &fakeWinRM{result: winrm.Result{}}
	srv, st := newTestServerOpts(t, nil, api.Options{
		Rotators:  map[string]rotate.Rotator{"ssh": fc},
		Verifiers: map[string]rotate.Verifier{"ssh": fc},
		WinRM:     fake,
	})
	labCredID := seedTargetCred(t, srv, "ssh", "", "lab-secret")
	const pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-real-key\n-----END OPENSSH PRIVATE KEY-----\n"
	keyCredID := seedGatedCred(t, srv, "jump-01", "svc-deploy", pem, "ssh_key", "")

	d := store.CredentialDependency{
		CredentialID: labCredID, Kind: "windows_service", Host: "app-01", Name: "MyService",
		ManagementCredentialID: keyCredID,
	}
	if err := st.CreateCredentialDependency(context.Background(), &d); err != nil {
		t.Fatal(err)
	}

	if code, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/rotate", labCredID), testAPIKey, nil); code != http.StatusOK {
		t.Fatalf("rotate must still succeed — propagation is best-effort: %d %s", code, data)
	}
	if fake.gotUser != "" || fake.gotPass != "" {
		t.Fatalf("private key material must not leave: logged in as %q with %q", fake.gotUser, fake.gotPass)
	}
	auditHas(t, st, "credential.dependency_failed", "management-credential-not-a-password")
}
