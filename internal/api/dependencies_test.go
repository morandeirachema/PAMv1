package api_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/rotate"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

// TestRotationPropagatesToDependency proves that rotating a credential updates a
// declared consumer (a Windows Service) over WinRM with the NEW secret, so the
// rotation does not break production.
func TestRotationPropagatesToDependency(t *testing.T) {
	fc := &fakeConnector{}
	fake := &fakeWinRM{result: winrm.Result{}}
	srv, st := newTestServerOpts(t, nil, api.Options{
		Rotators:  map[string]rotate.Rotator{"ssh": fc},
		Verifiers: map[string]rotate.Verifier{"ssh": fc},
		WinRM:     fake,
	})
	credID := seedTargetCred(t, srv, "ssh", "", "original-secret")

	// Declare a Windows Service that logs on with this credential.
	depURL := fmt.Sprintf("/api/credentials/%d/dependencies", credID)
	if code, body := do(t, srv, http.MethodPost, depURL, testAPIKey, map[string]any{
		"kind": "windows_service", "host": "app-01", "name": "MyService",
	}); code != http.StatusCreated {
		t.Fatalf("declare dependency: status %d body %s", code, body)
	}

	// Rotate the credential.
	if code, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/rotate", credID), testAPIKey, nil); code != http.StatusOK {
		t.Fatalf("rotate: status %d body %s", code, data)
	}
	newSecret := fc.newSecret()
	if newSecret == "" {
		t.Fatal("rotation did not set a new secret")
	}

	// The consumer was updated over WinRM on its own host with the new secret.
	if fake.gotHost != "app-01" || fake.gotPort != 5985 {
		t.Fatalf("dependency WinRM target = %s:%d, want app-01:5985", fake.gotHost, fake.gotPort)
	}
	if !strings.Contains(fake.gotCmd, `sc.exe config "MyService"`) {
		t.Fatalf("dependency command = %q, want an sc.exe config for MyService", fake.gotCmd)
	}
	if !strings.Contains(fake.gotCmd, newSecret) {
		t.Fatal("the new secret was not injected into the dependency update")
	}

	// The propagation is audited (without the secret in the detail).
	events, err := st.ListAudit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	var updated bool
	for _, e := range events {
		if e.Action == "credential.dependency_updated" && strings.Contains(e.Detail, "MyService@app-01") {
			updated = true
			if strings.Contains(e.Detail, newSecret) {
				t.Fatal("audit detail leaked the new secret")
			}
		}
	}
	if !updated {
		t.Fatal("no credential.dependency_updated audit event")
	}
}

// TestDependencyNameRejectsCommandInjection proves a dependency name cannot
// smuggle a second command into the WinRM command line that rotation builds.
//
// Why this matters: the name is interpolated into a cmd.exe line such as
//
//	sc.exe config "<name>" password= "<secret>"
//
// so a name containing a double quote closes the quoted argument and anything
// after `&` runs as its own command — on a host of the caller's choosing. The
// fix is an allowlist (letters, digits, spaces and a few separators), checked
// when the dependency is created and again when the command is built.
func TestDependencyNameRejectsCommandInjection(t *testing.T) {
	srv := newTestServer(t)
	targetID := createTestTarget(t, srv, "dep-win", "10.7.0.1")
	code, data := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": targetID, "username": "svc", "secret": secretPassword,
	})
	if code != http.StatusCreated {
		t.Fatalf("create credential: %d %s", code, data)
	}
	credID := int64(jsonMap(t, data)["id"].(float64))
	depURL := fmt.Sprintf("/api/credentials/%d/dependencies", credID)

	for _, bad := range []string{
		`svc" & powershell -enc AAA & rem `, // the canonical break-out
		`svc" | whoami & rem `,
		`svc%USERNAME%`,
		"svc\nnet user pwn",
		`svc;calc`,
		`svc<in`,
		`svc>out`,
		`svc^&calc`,
	} {
		if code, _ := do(t, srv, http.MethodPost, depURL, testAPIKey, map[string]any{
			"kind": "windows_service", "host": "win01", "name": bad,
		}); code != http.StatusUnprocessableEntity {
			t.Fatalf("dependency name %q accepted with status %d; want 422", bad, code)
		}
	}

	// A hostile host is refused for the same reason (it selects where the
	// command runs, and must not carry shell syntax either).
	for _, badHost := range []string{"win01 & calc", "win01;calc", "win01\nx", `win01"`} {
		if code, _ := do(t, srv, http.MethodPost, depURL, testAPIKey, map[string]any{
			"kind": "windows_service", "host": badHost, "name": "svc",
		}); code != http.StatusUnprocessableEntity {
			t.Fatalf("dependency host %q accepted with status %d; want 422", badHost, code)
		}
	}

	// Names real deployments actually use must still be accepted, and this list is
	// the reason the allowlist is checked rather than assumed. `MSSQL$SQLEXPRESS`
	// in particular: a named SQL Server instance registers its services with a
	// `$`, and rejecting it did not merely refuse new dependencies — the same
	// check runs again when the command is built, so an existing row would have
	// been skipped at rotation time, leaving SQL Server holding a stale password
	// until its next restart failed. `$` is inert in cmd.exe, so admitting it
	// costs nothing.
	for _, good := range []string{
		"MSSQLSERVER", "My App Pool", "Contoso.Web", `Corp\Nightly Backup`, "svc-01_x",
		"MSSQL$SQLEXPRESS", "SQLAgent$PROD", "ReportServer$TEST",
	} {
		if code, body := do(t, srv, http.MethodPost, depURL, testAPIKey, map[string]any{
			"kind": "windows_service", "host": "win01", "name": good,
		}); code != http.StatusCreated {
			t.Fatalf("legitimate dependency name %q refused: %d %s", good, code, body)
		}
	}
}
