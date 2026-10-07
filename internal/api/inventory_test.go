package api_test

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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
func seedInventory(t *testing.T) (*httptest.Server, store.Store, func(method, path, key string, body any) (int, []byte)) {
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
	return s, st, call
}

// TestInventoryExport proves Phase 278's export: every class names its
// references, no secret material leaves, a personal safe is not exported
// (nor named on its target), each export is audited, and each class keeps
// the capability of its own list route.
func TestInventoryExport(t *testing.T) {
	_, st, call := seedInventory(t)

	code, d := call(http.MethodGet, "/api/inventory/safes.csv", testAPIKey, nil)
	rows := csvRows(t, d)
	if code != http.StatusOK || len(rows) != 2 || rows[1][0] != "prod" || rows[1][2] != "true" {
		t.Fatalf("safes: %d %q", code, rows)
	}

	code, d = call(http.MethodGet, "/api/inventory/targets.csv", testAPIKey, nil)
	rows = csvRows(t, d)
	// alice-box sits in alice's personal safe: it is not exported at all
	// (review of 274-280), or it would import as a target in no safe.
	if code != http.StatusOK || len(rows) != 2 {
		t.Fatalf("targets: %d %q", code, rows)
	}
	if rows[1][0] != "web-01" || rows[1][5] != "prod" || rows[1][8] != "true" || rows[1][9] != "env=prod" {
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

// postCSV uploads a CSV file to an import route.
func postCSV(t *testing.T, srv *httptest.Server, path, key, body string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-API-Key", key)
	req.Header.Set("Content-Type", "text/csv")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// importCounts reads created/exists/failed from an import result.
func importCounts(m map[string]any) [3]int {
	return [3]int{int(m["created"].(float64)), int(m["exists"].(float64)), int(m["failed"].(float64))}
}

// TestInventoryRoundTrip proves Phase 278's import end to end: a whole
// inventory exported from one server imports into an empty one, class by
// class, and comes out the same — the safe assignment, the critical flag,
// the labels, the credential-scoped grant — with the personal safe left
// behind. The credential imports with its secret filled into the exported
// template, and REVEAL returns it: the row went through createCredential,
// so it was encrypted under the AAD the decrypt side expects. Re-importing
// changes nothing; every row is "exists".
func TestInventoryRoundTrip(t *testing.T) {
	_, _, from := seedInventory(t)
	export := map[string]string{}
	for _, c := range []string{"safes", "targets", "credentials", "users", "grants"} {
		code, d := from(http.MethodGet, "/api/inventory/"+c+".csv", testAPIKey, nil)
		mustDo(t, code, http.StatusOK, d, "export "+c)
		export[c] = string(d)
	}
	// The operator fills the secret into the template the export produced.
	export["credentials"] = strings.Replace(export["credentials"], "web-01,root,password,false,", "web-01,root,password,false,"+inventorySecret, 1)

	to, st := newTestServerOpts(t, nil, api.Options{})
	want := map[string][3]int{"safes": {1, 0, 0}, "targets": {1, 0, 0}, "credentials": {1, 0, 0}, "users": {1, 0, 0}, "grants": {1, 0, 0}}
	var token string
	for _, c := range []string{"safes", "targets", "credentials", "users", "grants"} {
		code, res := postCSV(t, to, "/api/inventory/"+c+".csv", testAPIKey, export[c])
		if code != http.StatusOK || importCounts(res) != want[c] {
			t.Fatalf("import %s: %d %v", c, code, res)
		}
		if c == "users" {
			token, _ = res["rows"].([]any)[0].(map[string]any)["token"].(string)
		}
		if strings.Contains(fmt.Sprint(res), inventorySecret) {
			t.Fatalf("the import result echoed a secret: %v", res)
		}
	}
	if token == "" {
		t.Fatal("an imported user must get its token, once, in the result")
	}
	auditHas(t, st, "inventory.import", "class:targets rows:1 created:1 exists:0 failed:0")
	auditHas(t, st, "target.create", "web-01")
	auditHas(t, st, "credential.create", "")

	// The second server exports what the first did (the user's token aside).
	for _, c := range []string{"safes", "targets", "credentials", "grants", "users"} {
		code, d := do(t, to, http.MethodGet, "/api/inventory/"+c+".csv", testAPIKey, nil)
		got := string(d)
		if c == "credentials" {
			got = strings.Replace(got, "web-01,root,password,false,", "web-01,root,password,false,"+inventorySecret, 1)
		}
		if code != http.StatusOK || got != export[c] {
			t.Errorf("%s differs after the round trip:\n--- exported\n%s--- re-exported\n%s", c, export[c], got)
		}
	}

	creds, err := st.ListCredentialsMeta(context.Background(), 0, 0, 0)
	if err != nil || len(creds) != 1 {
		t.Fatalf("credentials: %v %v", creds, err)
	}
	// The imported safe requires approval, as the original did; take the
	// target out of it so an admin may reveal without a request.
	code, d := do(t, to, http.MethodPut, "/api/targets/"+itoa(creds[0].TargetID)+"/safe", testAPIKey, map[string]any{"safe_id": nil})
	mustDo(t, code, http.StatusNoContent, d, "unassign safe")
	code, d = do(t, to, http.MethodPost, "/api/credentials/"+itoa(creds[0].ID)+"/reveal", testAPIKey, nil)
	if code != http.StatusOK || jsonMap(t, d)["secret"] != inventorySecret {
		t.Fatalf("the imported secret does not decrypt: %d %s", code, d)
	}

	for _, c := range []string{"safes", "targets", "credentials", "users", "grants"} {
		n := strings.Count(strings.TrimSpace(export[c]), "\n")
		if code, res := postCSV(t, to, "/api/inventory/"+c+".csv", testAPIKey, export[c]); code != http.StatusOK || importCounts(res) != [3]int{0, n, 0} {
			t.Errorf("re-import %s must change nothing: %d %v", c, code, res)
		}
	}
}

// TestInventoryImportErrors proves a file that does not parse imports
// nothing (422), a bad row fails alone with its line and reason while the
// rest import, and the import routes keep their create routes' capability.
func TestInventoryImportErrors(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{})
	if code, res := postCSV(t, srv, "/api/inventory/targets.csv", testAPIKey, "name,host,os_type,protocol,password\n"); code != http.StatusUnprocessableEntity {
		t.Fatalf("unknown column: %d %v", code, res)
	}

	file := "name,host,os_type,protocol,safe,critical,labels\n" +
		"ok-01,10.0.0.1,linux,ssh,,true,env=prod\n" +
		"nosafe,10.0.0.2,linux,ssh,missing,,\n" +
		"badbool,10.0.0.3,linux,ssh,,maybe,\n" +
		"badlabel,10.0.0.4,linux,ssh,,,envprod\n" +
		"badproto,10.0.0.5,linux,gopher,,,\n"
	code, res := postCSV(t, srv, "/api/inventory/targets.csv", testAPIKey, file)
	if code != http.StatusOK || importCounts(res) != [3]int{1, 0, 4} {
		t.Fatalf("mixed file: %d %v", code, res)
	}
	rows := res["rows"].([]any)
	for i, want := range []string{"", "safe \"missing\" does not exist", "critical:", "label \"envprod\"", "protocol must be"} {
		r := rows[i].(map[string]any)
		if r["line"].(float64) != float64(i+2) || !strings.Contains(fmt.Sprint(r["error"]), want) {
			t.Errorf("row %d = %v, want line %d and %q", i, r, i+2, want)
		}
	}
	if ts, _ := st.ListTargets(context.Background(), 0, 0); len(ts) != 1 {
		t.Fatalf("only the good row may create a target: %d", len(ts))
	}

	code, res = postCSV(t, srv, "/api/inventory/credentials.csv", testAPIKey,
		"target,username,secret\nok-01,root,\nnowhere,root,x\n")
	if code != http.StatusOK || importCounts(res) != [3]int{0, 0, 2} {
		t.Fatalf("credentials without a secret or a target: %d %v", code, res)
	}

	code, d := do(t, srv, http.MethodPost, "/api/users", testAPIKey, map[string]any{"username": "aud", "role": "auditor"})
	mustDo(t, code, http.StatusCreated, d, "auditor")
	tok := jsonMap(t, d)["token"].(string)
	for _, c := range []string{"safes", "targets", "credentials", "users", "grants"} {
		if code, _ := postCSV(t, srv, "/api/inventory/"+c+".csv", tok, "x\n"); code != http.StatusForbidden {
			t.Errorf("an auditor importing %s = %d, want 403", c, code)
		}
	}
}

// TestInventoryImportReviewFixes (review of 274-280): a secret reaches the
// vault byte-exact — a leading quote or space is not "restored" or trimmed
// away — and a repeated label key fails the row instead of keeping one value.
func TestInventoryImportReviewFixes(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{})
	code, res := postCSV(t, srv, "/api/inventory/targets.csv", testAPIKey,
		"name,host,os_type,protocol,labels\nweb-01,10.0.0.5,linux,ssh,env=prod\ndup-01,10.0.0.6,linux,ssh,\"env=prod,env=dev\"\n")
	if code != http.StatusOK || importCounts(res) != [3]int{1, 0, 1} {
		t.Fatalf("targets: %d %v", code, res)
	}
	if e := fmt.Sprint(res["rows"].([]any)[1].(map[string]any)["error"]); !strings.Contains(e, "appears twice") {
		t.Fatalf("duplicate label key: %q", e)
	}
	const secret = "'-Odd pw "
	code, res = postCSV(t, srv, "/api/inventory/credentials.csv", testAPIKey, "target,username,secret\nweb-01,root,\""+secret+"\"\n")
	if code != http.StatusOK || importCounts(res) != [3]int{1, 0, 0} {
		t.Fatalf("credentials: %d %v", code, res)
	}
	creds, err := st.ListCredentialsMeta(context.Background(), 0, 0, 0)
	if err != nil || len(creds) != 1 {
		t.Fatal(creds, err)
	}
	code, d := do(t, srv, http.MethodPost, "/api/credentials/"+itoa(creds[0].ID)+"/reveal", testAPIKey, nil)
	if code != http.StatusOK || jsonMap(t, d)["secret"] != secret {
		t.Fatalf("the secret changed on import: %d %s", code, d)
	}
}
