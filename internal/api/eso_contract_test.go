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

	t.Run("revoked grant is 403, never 404", func(t *testing.T) {
		status, data := do(t, f.srv, http.MethodDelete,
			"/v1/apps/"+itoa(f.appID)+"/grants/"+itoa(f.grantID), testAPIKey, nil)
		if status != http.StatusNoContent && status != http.StatusOK {
			t.Fatalf("revoke: %d %s", status, data)
		}
		// The alias went with the grant, so by-alias is now genuinely absent (404
		// is right); what must NOT be 404 is the credential the app still knows
		// the id of but may no longer read.
		status, _ = appGet(t, f.srv, "/v1/app-secrets/"+itoa(f.credID), f.appToken)
		if status == http.StatusNotFound {
			t.Fatal("a revoked grant answered 404 — an ESO would read that as 'deleted' and remove the workload's Secret")
		}
		if status != http.StatusForbidden {
			t.Fatalf("revoked grant: %d, want 403", status)
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
