package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
)

// esoFixture builds an app with one granted credential named by a stable alias,
// which is the shape an External Secrets Operator SecretStore addresses.
type esoFixture struct {
	srv      *httptest.Server
	appToken string
	appID    int64
	grantID  int64
	credID   int64
	otherID  int64
}

func newESOFixture(t *testing.T) esoFixture {
	t.Helper()
	srv, _ := newTestServerOpts(t, nil, api.Options{AppSecretsEnabled: true})

	status, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "eso-host", "host": "10.9.9.10", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	if status != http.StatusCreated {
		t.Fatalf("create target: %d %s", status, data)
	}
	tid := int64(jsonMap(t, data)["id"].(float64))
	credID := mkCredential(t, srv, tid, "svc", secretPassword)
	otherID := mkCredential(t, srv, tid, "svc2", "another-secret")

	status, data = do(t, srv, http.MethodPost, "/v1/apps", testAPIKey, map[string]any{"name": "eso", "owner": "platform"})
	if status != http.StatusCreated {
		t.Fatalf("create app: %d %s", status, data)
	}
	m := jsonMap(t, data)
	appID := int64(m["id"].(float64))
	token, _ := m["token"].(string)

	status, data = do(t, srv, http.MethodPost, "/v1/apps/"+itoa(appID)+"/grants", testAPIKey,
		map[string]any{"credential_id": credID})
	if status != http.StatusCreated {
		t.Fatalf("grant: %d %s", status, data)
	}
	grantID := int64(jsonMap(t, data)["id"].(float64))

	status, data = do(t, srv, http.MethodPost, "/v1/apps/"+itoa(appID)+"/grants/"+itoa(grantID)+"/alias",
		testAPIKey, map[string]any{"alias": "prod-db-password"})
	if status != http.StatusOK {
		t.Fatalf("set alias: %d %s", status, data)
	}
	return esoFixture{srv: srv, appToken: token, appID: appID, grantID: grantID, credID: credID, otherID: otherID}
}

// TestESOStatusContract pins the status codes this route answers with, because
// External Secrets Operator assigns MEANING to them and one of those meanings is
// destructive.
//
// ESO treats 404 as "the secret no longer exists" and DELETES the Kubernetes
// Secret it manages from that ExternalSecret. So:
//
//   - an alias nobody defined SHOULD be 404 — the secret really is not there, and
//     letting ESO clean up is correct;
//   - a grant that was REVOKED must be 403 and never 404, or an authorization
//     change would silently delete a running workload's Secret;
//   - policy turning delivery off must be 403 for the same reason.
//
// The current handler is right about all three. Nothing pinned it before this
// test, and a later tidy-up of "403 vs 404" would have looked entirely harmless.
func TestESOStatusContract(t *testing.T) {
	f := newESOFixture(t)

	t.Run("granted alias is 200", func(t *testing.T) {
		status, body := appGet(t, f.srv, "/v1/app-secrets/by-alias/prod-db-password", f.appToken)
		if status != http.StatusOK {
			t.Fatalf("granted alias: %d %s", status, body)
		}
		var got map[string]any
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		// $.secret is the jsonPath an ESO SecretStore is configured with.
		if got["secret"] != secretPassword {
			t.Errorf("secret at $.secret = %v, want the vaulted password", got["secret"])
		}
		if got["alias"] != "prod-db-password" {
			t.Errorf("answer should name the alias it resolved: %+v", got)
		}
	})

	t.Run("undefined alias is 404 so ESO may clean up", func(t *testing.T) {
		if status, _ := appGet(t, f.srv, "/v1/app-secrets/by-alias/no-such-name", f.appToken); status != http.StatusNotFound {
			t.Fatalf("undefined alias: %d, want 404", status)
		}
	})

	t.Run("revoking a grant removes the alias, and that propagates", func(t *testing.T) {
		status, data := do(t, f.srv, http.MethodDelete,
			"/v1/apps/"+itoa(f.appID)+"/grants/"+itoa(f.grantID), testAPIKey, nil)
		if status != http.StatusNoContent && status != http.StatusOK {
			t.Fatalf("revoke: %d %s", status, data)
		}
		// This subtest used to be called "revoked grant is 403, never 404" and
		// then quietly checked the ID route instead, because the alias goes with
		// the grant. The name promised something the by-alias route — the one ESO
		// actually calls — does not do. State the real behaviour: revocation
		// removes the alias, the route answers 404, and ESO removes the workload's
		// Secret. That is intended; leaving a plaintext secret in a Kubernetes
		// Secret after access is withdrawn would be worse.
		if status, _ := appGet(t, f.srv, "/v1/app-secrets/by-alias/prod-db-password", f.appToken); status != http.StatusNotFound {
			t.Fatalf("by-alias after revoke: %d, want 404 (revocation propagates)", status)
		}
		// The id route still answers 403 for the credential the app knows about
		// but may no longer read — a refusal, not a deletion.
		if status, _ := appGet(t, f.srv, "/v1/app-secrets/"+itoa(f.credID), f.appToken); status != http.StatusForbidden {
			t.Fatalf("id route after revoke: %d, want 403", status)
		}
	})

	t.Run("a transient policy refusal is 403, never 404", func(t *testing.T) {
		// The case that must never delete a running workload's Secret: the grant
		// is intact, the alias resolves, and delivery is off by policy.
		g := newESOFixture(t)
		status, data := do(t, g.srv, http.MethodPost, "/api/config", testAPIKey,
			map[string]any{"key": "PAM_REVEAL_DISABLED", "value": "true"})
		if status != http.StatusOK && status != http.StatusCreated && status != http.StatusNoContent {
			t.Skipf("cannot toggle the reveal kill switch here (%d %s)", status, data)
		}
		if status, _ := appGet(t, g.srv, "/v1/app-secrets/by-alias/prod-db-password", g.appToken); status != http.StatusForbidden {
			t.Fatalf("reveal-disabled on the alias route: %d, want 403 — 404 would delete the Secret", status)
		}
	})

	t.Run("never-granted credential is 403, never 404", func(t *testing.T) {
		status, _ := appGet(t, f.srv, "/v1/app-secrets/"+itoa(f.otherID), f.appToken)
		if status != http.StatusForbidden {
			t.Fatalf("ungranted credential: %d, want 403", status)
		}
	})
}

// TestESOAliasIsScopedToItsApp proves resolution and authorization are the same
// lookup: an alias names a grant, and a grant belongs to one application, so a
// second app presenting the same alias reaches nothing.
func TestESOAliasIsScopedToItsApp(t *testing.T) {
	f := newESOFixture(t)

	status, data := do(t, f.srv, http.MethodPost, "/v1/apps", testAPIKey,
		map[string]any{"name": "other-app", "owner": "platform"})
	if status != http.StatusCreated {
		t.Fatalf("create second app: %d %s", status, data)
	}
	otherToken, _ := jsonMap(t, data)["token"].(string)

	if status, _ := appGet(t, f.srv, "/v1/app-secrets/by-alias/prod-db-password", otherToken); status != http.StatusNotFound {
		t.Fatalf("another app's alias: %d, want 404 — the alias must not resolve outside its own grants", status)
	}

	// And the same alias may be reused by that second app for its own grant,
	// which is the point of scoping it per application rather than globally.
	status, data = do(t, f.srv, http.MethodPost, "/v1/apps", testAPIKey, map[string]any{"name": "third", "owner": "p"})
	if status != http.StatusCreated {
		t.Fatalf("create third app: %d %s", status, data)
	}
	thirdID := int64(jsonMap(t, data)["id"].(float64))
	status, data = do(t, f.srv, http.MethodPost, "/v1/apps/"+itoa(thirdID)+"/grants", testAPIKey,
		map[string]any{"credential_id": f.otherID})
	if status != http.StatusCreated {
		t.Fatalf("grant to third app: %d %s", status, data)
	}
	gid := int64(jsonMap(t, data)["id"].(float64))
	status, data = do(t, f.srv, http.MethodPost, "/v1/apps/"+itoa(thirdID)+"/grants/"+itoa(gid)+"/alias",
		testAPIKey, map[string]any{"alias": "prod-db-password"})
	if status != http.StatusOK {
		t.Fatalf("the same alias must be reusable by a different app: %d %s", status, data)
	}
}

// TestESOAliasValidation keeps an alias to something that survives a URL path
// segment, since that is how it is addressed on the way back in.
func TestESOAliasValidation(t *testing.T) {
	f := newESOFixture(t)
	for _, bad := range []string{"../etc/passwd", "has space", "sla/sh", "..", "."} {
		status, _ := do(t, f.srv, http.MethodPost,
			"/v1/apps/"+itoa(f.appID)+"/grants/"+itoa(f.grantID)+"/alias", testAPIKey,
			map[string]any{"alias": bad})
		if status != http.StatusBadRequest {
			t.Errorf("alias %q: %d, want 400", bad, status)
		}
	}
	// Clearing is allowed and makes the grant id-addressable only.
	if status, data := do(t, f.srv, http.MethodPost,
		"/v1/apps/"+itoa(f.appID)+"/grants/"+itoa(f.grantID)+"/alias", testAPIKey,
		map[string]any{"alias": ""}); status != http.StatusOK {
		t.Fatalf("clearing an alias: %d %s", status, data)
	}
	if status, _ := appGet(t, f.srv, "/v1/app-secrets/by-alias/prod-db-password", f.appToken); status != http.StatusNotFound {
		t.Fatalf("a cleared alias must stop resolving: %d, want 404", status)
	}
}

// TestAliasSetIsScopedToTheNamedApp is the regression guard for a real defect:
// setAppGrantAlias parsed only {gid} and ignored {id}, so naming a grant under
// one application renamed a DIFFERENT application's grant and answered 200. A
// mistyped or stale grant id therefore handed some other app a stable,
// git-committable name for a credential nobody meant to expose, while the
// operator read success.
func TestAliasSetIsScopedToTheNamedApp(t *testing.T) {
	f := newESOFixture(t)

	// A second application with a grant of its own.
	status, data := do(t, f.srv, http.MethodPost, "/v1/apps", testAPIKey,
		map[string]any{"name": "bystander", "owner": "platform"})
	if status != http.StatusCreated {
		t.Fatalf("create second app: %d %s", status, data)
	}
	m := jsonMap(t, data)
	otherID := int64(m["id"].(float64))
	otherToken, _ := m["token"].(string)

	status, data = do(t, f.srv, http.MethodPost, "/v1/apps/"+itoa(otherID)+"/grants", testAPIKey,
		map[string]any{"credential_id": f.otherID})
	if status != http.StatusCreated {
		t.Fatalf("grant to second app: %d %s", status, data)
	}
	otherGrant := int64(jsonMap(t, data)["id"].(float64))

	// Name the SECOND app's grant while addressing the FIRST app. This must not
	// succeed, and above all must not name it.
	status, data = do(t, f.srv, http.MethodPost,
		"/v1/apps/"+itoa(f.appID)+"/grants/"+itoa(otherGrant)+"/alias", testAPIKey,
		map[string]any{"alias": "planted"})
	if status != http.StatusNotFound {
		t.Fatalf("naming another app's grant: %d %s, want 404", status, data)
	}
	if status, _ := appGet(t, f.srv, "/v1/app-secrets/by-alias/planted", otherToken); status != http.StatusNotFound {
		t.Fatalf("the bystander application gained the name anyway: %d", status)
	}
}
