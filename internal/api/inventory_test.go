package api_test

import (
	"encoding/csv"
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/store"
)

// mustDo fails the test unless the call answers want.
func mustDo(t *testing.T, code, want int, data []byte, what string) {
	t.Helper()
	if code != want {
		t.Fatalf("%s: %d %s", what, code, data)
	}
}

// csvRows parses a CSV response into its rows, header first.
func csvRows(t *testing.T, data []byte) [][]string {
	t.Helper()
	rows, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
	if err != nil {
		t.Fatalf("not CSV: %v\n%s", err, data)
	}
	return rows
}

const inventorySecret = "Sup3r-S3cret-vaulted"

// seedInventory builds a small inventory through the API: a shared and a
// personal safe, a target in each, a credential, a user and a grant.
func seedInventory(t *testing.T) (store.Store, func(method, path, key string, body any) (int, []byte)) {
	t.Helper()
	s, st := newTestServerOpts(t, nil, api.Options{})
	call := func(method, path, key string, body any) (int, []byte) { return do(t, s, method, path, key, body) }
	code, d := call(http.MethodPost, "/api/safes", testAPIKey, map[string]any{"name": "prod", "description": "production", "require_approval": true})
	mustDo(t, code, http.StatusCreated, d, "shared safe")
	prodID := jsonMap(t, d)["id"]
	code, d = call(http.MethodPost, "/api/users", testAPIKey, map[string]any{"username": "alice", "role": "user", "manager": ""})
	mustDo(t, code, http.StatusCreated, d, "user")
	code, d = call(http.MethodPost, "/api/safes", testAPIKey, map[string]any{"name": "alice-vault", "personal": true, "owner": "alice"})
	mustDo(t, code, http.StatusCreated, d, "personal safe")
	vaultID := jsonMap(t, d)["id"]

	tid := smfaTarget(t, s, "web-01", "ssh", map[string]any{"critical": true, "labels": map[string]string{"env": "prod"}})
	code, d = call(http.MethodPut, "/api/targets/"+itoa(tid)+"/safe", testAPIKey, map[string]any{"safe_id": prodID})
	mustDo(t, code, http.StatusNoContent, d, "assign shared safe")
	pid := smfaTarget(t, s, "alice-box", "ssh", nil)
	code, d = call(http.MethodPut, "/api/targets/"+itoa(pid)+"/safe", testAPIKey, map[string]any{"safe_id": vaultID})
	mustDo(t, code, http.StatusNoContent, d, "assign personal safe")
	cid := smfaCred(t, s, tid, "root", inventorySecret)
	code, d = call(http.MethodPost, "/api/targets/"+itoa(tid)+"/grants", testAPIKey,
		map[string]any{"subject_type": "user", "subject": "alice", "credential_id": cid, "time_frame": "Mon-Fri 08:00-18:00"})
	mustDo(t, code, http.StatusCreated, d, "grant")
	return st, call
}

// TestInventoryExport proves Phase 278's export: every class names its
// references, no secret material leaves, a personal safe is not exported
// (nor named on its target), each export is audited, and each class keeps
// the capability of its own list route.
func TestInventoryExport(t *testing.T) {
	st, call := seedInventory(t)

	code, d := call(http.MethodGet, "/api/inventory/safes.csv", testAPIKey, nil)
	rows := csvRows(t, d)
	if code != http.StatusOK || len(rows) != 2 || rows[1][0] != "prod" || rows[1][2] != "true" {
		t.Fatalf("safes: %d %q", code, rows)
	}

	code, d = call(http.MethodGet, "/api/inventory/targets.csv", testAPIKey, nil)
	rows = csvRows(t, d)
	if code != http.StatusOK || len(rows) != 3 {
		t.Fatalf("targets: %d %q", code, rows)
	}
	// Sorted by name: alice-box, then web-01.
	if rows[1][0] != "alice-box" || rows[1][5] != "" || rows[2][0] != "web-01" || rows[2][5] != "prod" || rows[2][8] != "true" || rows[2][9] != "env=prod" {
		t.Fatalf("targets rows = %q", rows)
	}

	code, d = call(http.MethodGet, "/api/inventory/credentials.csv", testAPIKey, nil)
	rows = csvRows(t, d)
	if code != http.StatusOK || len(rows) != 2 || rows[1][0] != "web-01" || rows[1][1] != "root" || rows[1][4] != "" {
		t.Fatalf("credentials: %d %q", code, rows)
	}
	if strings.Contains(string(d), inventorySecret) || strings.Contains(string(d), "v2:") {
		t.Fatalf("a secret or its ciphertext left in the export:\n%s", d)
	}

	code, d = call(http.MethodGet, "/api/inventory/grants.csv", testAPIKey, nil)
	rows = csvRows(t, d)
	if code != http.StatusOK || len(rows) != 2 || rows[1][0] != "web-01" || rows[1][2] != "alice" || rows[1][3] != "root" || rows[1][5] != "Mon-Fri 08:00-18:00" {
		t.Fatalf("grants: %d %q", code, rows)
	}

	code, d = call(http.MethodGet, "/api/inventory/users.csv", testAPIKey, nil)
	rows = csvRows(t, d)
	if code != http.StatusOK || len(rows) != 2 || rows[1][0] != "alice" || rows[1][1] != "user" {
		t.Fatalf("users: %d %q", code, rows)
	}
	auditHas(t, st, "inventory.export", "class:credentials rows:1")

	// An auditor reads inventory but manages neither users nor grants.
	code, d = call(http.MethodPost, "/api/users", testAPIKey, map[string]any{"username": "aud", "role": "auditor"})
	mustDo(t, code, http.StatusCreated, d, "auditor")
	tok := jsonMap(t, d)["token"].(string)
	for path, want := range map[string]int{
		"/api/inventory/targets.csv":     http.StatusOK,
		"/api/inventory/credentials.csv": http.StatusOK,
		"/api/inventory/users.csv":       http.StatusForbidden,
		"/api/inventory/grants.csv":      http.StatusForbidden,
	} {
		if code, _ := call(http.MethodGet, path, tok, nil); code != want {
			t.Errorf("auditor %s = %d, want %d", path, code, want)
		}
	}
}
