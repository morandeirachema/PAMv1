package api_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// getWithKey performs a GET and returns the full response for header inspection.
func getWithKey(t *testing.T, srv *httptest.Server, path, apiKey string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-API-Key", apiKey)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

// TestAuditExportJSON verifies the JSON export carries a matching SHA-256 in both
// body and header and is deterministic over a fixed time window.
func TestAuditExportJSON(t *testing.T) {
	srv := newTestServer(t)
	// Generate a couple of audit events.
	do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "web-01", "host": "10.0.0.5", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	seedUser(t, srv, "alice", "auditor")

	resp, body := getWithKey(t, srv, "/api/audit/export", testAPIKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(resp.Header.Get("Content-Disposition"), "attachment") {
		t.Fatalf("missing attachment disposition: %q", resp.Header.Get("Content-Disposition"))
	}
	hdrDigest := resp.Header.Get("X-PAM-Export-SHA256")
	if hdrDigest == "" {
		t.Fatal("missing X-PAM-Export-SHA256 header")
	}
	var out struct {
		Count  int `json:"count"`
		Events []struct {
			Action string `json:"action"`
		} `json:"events"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.Count < 2 || len(out.Events) != out.Count {
		t.Fatalf("count mismatch: count=%d events=%d", out.Count, len(out.Events))
	}
	// The header digest must be the SHA-256 of the exact delivered bytes, so a
	// regulator can sha256sum the downloaded file and match it.
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != hdrDigest {
		t.Fatalf("header digest %q != sha256(body)", hdrDigest)
	}

	// Deterministic over a fixed range: two exports of the same closed window
	// (here an empty historical window) produce the same digest, so a regulator
	// re-running the export can confirm nothing changed.
	const window = "/api/audit/export?since=2000-01-01T00:00:00Z&until=2000-01-02T00:00:00Z"
	r1, _ := getWithKey(t, srv, window, testAPIKey)
	r2, _ := getWithKey(t, srv, window, testAPIKey)
	if r1.Header.Get("X-PAM-Export-SHA256") != r2.Header.Get("X-PAM-Export-SHA256") {
		t.Fatal("export digest is not deterministic over a fixed range")
	}
}

// TestAuditExportCSVAndFilter verifies CSV output and the ?action= filter scoping.
func TestAuditExportCSVAndFilter(t *testing.T) {
	srv := newTestServer(t)
	do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "web-01", "host": "10.0.0.5", "port": 22, "os_type": "linux", "protocol": "ssh",
	})

	resp, body := getWithKey(t, srv, "/api/audit/export?format=csv", testAPIKey)
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/csv") {
		t.Fatalf("csv export: %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if !strings.HasPrefix(string(body), "id,ts,actor,action,detail") {
		t.Fatalf("csv header missing: %q", string(body)[:min(40, len(body))])
	}

	// Filter by action: only target.create rows come back.
	status, fbody := do(t, srv, http.MethodGet, "/api/audit/export?action=target.create", testAPIKey, nil)
	if status != http.StatusOK {
		t.Fatalf("filtered export: %d", status)
	}
	var out struct {
		Events []struct {
			Action string `json:"action"`
		} `json:"events"`
	}
	json.Unmarshal(fbody, &out)
	if len(out.Events) == 0 {
		t.Fatal("expected at least one target.create event")
	}
	for _, e := range out.Events {
		if e.Action != "target.create" {
			t.Fatalf("filter leaked action %q", e.Action)
		}
	}
}

// TestAuditExportRequiresReadAudit verifies the export requires CapReadAudit
// (auditor allowed, plain user forbidden).
func TestAuditExportRequiresReadAudit(t *testing.T) {
	srv := newTestServer(t)
	auditor := seedUser(t, srv, "bob", "auditor")
	user := seedUser(t, srv, "carol", "user")

	if status, _ := do(t, srv, http.MethodGet, "/api/audit/export", auditor, nil); status != http.StatusOK {
		t.Fatalf("auditor export: want 200, got %d", status)
	}
	if status, _ := do(t, srv, http.MethodGet, "/api/audit/export", user, nil); status != http.StatusForbidden {
		t.Fatalf("user export: want 403, got %d", status)
	}
}

// nis2ReportBody is the shape TestNIS2Report* unmarshals into.
type nis2ReportBody struct {
	Framework   string `json:"framework"`
	TotalEvents int    `json:"total_events"`
	Controls    []struct {
		Letter   string         `json:"letter"`
		Status   string         `json:"status"`
		Evidence map[string]any `json:"evidence"`
	} `json:"controls"`
}

// TestNIS2ReportShape verifies the report carries all ten Art. 21(2) letters,
// a matching digest header, and is deterministic over a fixed window — the
// same three guarantees TestAuditExportJSON checks for the raw export.
func TestNIS2ReportShape(t *testing.T) {
	srv := newTestServer(t)
	do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "web-01", "host": "10.0.0.5", "port": 22, "os_type": "linux", "protocol": "ssh",
	})

	resp, body := getWithKey(t, srv, "/api/compliance/nis2", testAPIKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("nis2 report: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(resp.Header.Get("Content-Disposition"), "attachment") {
		t.Fatalf("missing attachment disposition: %q", resp.Header.Get("Content-Disposition"))
	}
	hdrDigest := resp.Header.Get("X-PAM-Export-SHA256")
	if hdrDigest == "" {
		t.Fatal("missing X-PAM-Export-SHA256 header")
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != hdrDigest {
		t.Fatalf("header digest %q != sha256(body)", hdrDigest)
	}

	var out nis2ReportBody
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.Framework != "NIS2 Art. 21(2)" {
		t.Fatalf("framework = %q", out.Framework)
	}
	wantLetters := "abcdefghij"
	if len(out.Controls) != len(wantLetters) {
		t.Fatalf("controls = %d, want %d", len(out.Controls), len(wantLetters))
	}
	for i, c := range out.Controls {
		if want := string(wantLetters[i]); c.Letter != want {
			t.Fatalf("control[%d].letter = %q, want %q", i, c.Letter, want)
		}
		if c.Status != "implemented" && c.Status != "partial" {
			t.Fatalf("control %s: unexpected status %q", c.Letter, c.Status)
		}
	}

	// Deterministic over a fixed historical range, like the raw export.
	const window = "/api/compliance/nis2?since=2000-01-01T00:00:00Z&until=2000-01-02T00:00:00Z"
	r1, _ := getWithKey(t, srv, window, testAPIKey)
	r2, _ := getWithKey(t, srv, window, testAPIKey)
	if r1.Header.Get("X-PAM-Export-SHA256") != r2.Header.Get("X-PAM-Export-SHA256") {
		t.Fatal("nis2 report digest is not deterministic over a fixed range")
	}
}

// TestNIS2ReportEvidenceCounts verifies a real event lands under the right
// control's window evidence, bucketed by its action's family prefix.
func TestNIS2ReportEvidenceCounts(t *testing.T) {
	srv := newTestServer(t)
	if status, body := do(t, srv, http.MethodPost, "/api/safes", testAPIKey,
		map[string]any{"name": "nis2-test-safe"}); status != http.StatusCreated {
		t.Fatalf("create safe: %d %s", status, body)
	}

	_, body := getWithKey(t, srv, "/api/compliance/nis2", testAPIKey)
	var out nis2ReportBody
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	// Control (i) tracks the "safe" family.
	var found bool
	for _, c := range out.Controls {
		if c.Letter != "i" {
			continue
		}
		found = true
		families, _ := c.Evidence["families"].(map[string]any)
		count, _ := families["safe"].(float64)
		if count < 1 {
			t.Fatalf("control i evidence.families.safe = %v, want >= 1 (evidence: %+v)", families["safe"], c.Evidence)
		}
	}
	if !found {
		t.Fatal("control i missing from report")
	}
}

// TestNIS2ReportRequiresReadAudit verifies the report requires CapReadAudit
// (auditor allowed, plain user forbidden) — the same gate as every other
// audit-derived export.
func TestNIS2ReportRequiresReadAudit(t *testing.T) {
	srv := newTestServer(t)
	auditor := seedUser(t, srv, "dave", "auditor")
	user := seedUser(t, srv, "erin", "user")

	if status, _ := do(t, srv, http.MethodGet, "/api/compliance/nis2", auditor, nil); status != http.StatusOK {
		t.Fatalf("auditor report: want 200, got %d", status)
	}
	if status, _ := do(t, srv, http.MethodGet, "/api/compliance/nis2", user, nil); status != http.StatusForbidden {
		t.Fatalf("user report: want 403, got %d", status)
	}
}
