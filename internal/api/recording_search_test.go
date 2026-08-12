package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// TestSearchRecordings proves content search over stored SSH recordings end
// to end: a query whose text was echoed to the terminal in separate writes
// (so it never appears intact in any single asciicast event) is still found
// once the output is reconstructed, a recording that does not contain it is
// excluded, the owning target/actor are resolved from the audit trail the
// same way the listing does, the search itself is audited, and only
// read_audit roles may search.
func TestSearchRecordings(t *testing.T) {
	dir := t.TempDir()
	srv, st := newTestServerOpts(t, nil, api.Options{RecordingDir: dir})
	ctx := context.Background()

	// "topsecret" split across two writes, exactly as a slow terminal echo
	// would produce it — the shape this feature exists to find.
	hit := "{\"version\":2,\"width\":80,\"height\":24}\n" +
		"[0.1,\"o\",\"$ export TOKEN=top\"]\n" +
		"[0.2,\"o\",\"secret123\\r\\n\"]\n"
	if err := os.WriteFile(filepath.Join(dir, "100_web-01_alice.cast"), []byte(hit), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendAudit(ctx, &store.AuditEvent{
		Actor: "alice", Action: "session.record",
		Detail: "target:web-01 cred_user:root file:100_web-01_alice.cast bytes:34 sha256:x chain:ab",
	}); err != nil {
		t.Fatal(err)
	}

	miss := "{\"version\":2,\"width\":80,\"height\":24}\n[0.1,\"o\",\"$ ls\\r\\n\"]\n[0.2,\"o\",\"README.md\\r\\n\"]\n"
	if err := os.WriteFile(filepath.Join(dir, "200_web-02_bob.cast"), []byte(miss), 0o600); err != nil {
		t.Fatal(err)
	}

	auditor := seedUser(t, srv, "search-auditor", "auditor")

	code, data := do(t, srv, http.MethodGet, "/api/recordings/search?q=topsecret123", auditor, nil)
	if code != http.StatusOK {
		t.Fatalf("search: %d %s", code, data)
	}
	var hits []map[string]any
	if err := json.Unmarshal(data, &hits); err != nil {
		t.Fatalf("unmarshal: %v (%s)", err, data)
	}
	if len(hits) != 1 {
		t.Fatalf("hits = %d, want 1 (the non-matching recording must be excluded): %s", len(hits), data)
	}
	h := hits[0]
	if h["name"] != "100_web-01_alice.cast" {
		t.Fatalf("hit name = %v, want the matching file", h["name"])
	}
	if h["matches"].(float64) != 1 {
		t.Fatalf("matches = %v, want 1", h["matches"])
	}
	if h["target"] != "web-01" || h["actor"] != "alice" {
		t.Fatalf("owner not resolved from the audit trail: target=%v actor=%v", h["target"], h["actor"])
	}
	if h["truncated"] != false {
		t.Fatalf("truncated = %v, want false", h["truncated"])
	}
	// The match starts inside the FIRST event ("...TOKEN=top", at t=0.1),
	// even though "topsecret123" only completes once the second event's
	// "secret123" is concatenated on — proving the console gets a seek time
	// for where the match begins, not merely that a match occurred somewhere.
	if h["match_seconds"] != 0.1 {
		t.Fatalf("match_seconds = %v, want 0.1", h["match_seconds"])
	}

	// The search itself left a durable record of the query — the sensitive
	// fact, independent of whether it hit anything.
	if ok, err := st.FindAuditDetail(ctx, "session.search", `query:"topsecret123"`); err != nil || !ok {
		t.Fatalf("search must be audited session.search with the query: ok=%v err=%v", ok, err)
	}

	// Case-insensitive.
	if code, data := do(t, srv, http.MethodGet, "/api/recordings/search?q=TOPSECRET123", auditor, nil); code != http.StatusOK {
		t.Fatalf("case-insensitive search: %d %s", code, data)
	} else {
		var h2 []map[string]any
		_ = json.Unmarshal(data, &h2)
		if len(h2) != 1 {
			t.Fatalf("case-insensitive search hits = %d, want 1", len(h2))
		}
	}

	// Query bounds.
	if code, _ := do(t, srv, http.MethodGet, "/api/recordings/search?q=ab", auditor, nil); code != http.StatusUnprocessableEntity {
		t.Fatalf("2-char query: want 422, got %d", code)
	}
	if code, _ := do(t, srv, http.MethodGet, "/api/recordings/search", auditor, nil); code != http.StatusUnprocessableEntity {
		t.Fatalf("empty query: want 422, got %d", code)
	}

	// RBAC: search needs read_audit, same as list/playback.
	user := seedUser(t, srv, "search-user", "user")
	if code, _ := do(t, srv, http.MethodGet, "/api/recordings/search?q=topsecret123", user, nil); code != http.StatusForbidden {
		t.Fatalf("plain user searching: want 403, got %d", code)
	}
}

// TestSearchRecordingsFailsClosedWithoutAudit proves a search is refused
// (503), not silently served without a trace, when the durable audit write
// fails — the query is the sensitive fact this endpoint discloses about
// itself, so it holds the same invariant §6.4 as every other read of
// protected material.
func TestSearchRecordingsFailsClosedWithoutAudit(t *testing.T) {
	dir := t.TempDir()
	fs := &failAuditStore{Store: memstore.New()}
	masterKey, err := vault.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := auth.NewResolver(fs, testAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	resolver.WithProfiles(fs)
	handler, err := api.New(fs, v, resolver, nil, api.Options{RecordingDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	const marker = "S3CRET-FINDME-MARKER"
	cast := "{\"version\":2}\n[0.1,\"o\",\"" + marker + "\"]\n"
	if err := os.WriteFile(filepath.Join(dir, "100_web-01_alice.cast"), []byte(cast), 0o600); err != nil {
		t.Fatal(err)
	}

	fs.fail = true
	status, body := do(t, srv, http.MethodGet, "/api/recordings/search?q="+marker, testAPIKey, nil)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("search with a failing audit store: want 503, got %d (%s)", status, body)
	}
	if strings.Contains(strings.ToUpper(string(body)), marker) {
		t.Fatalf("search leaked a snippet despite a failed audit: %s", body)
	}
}
