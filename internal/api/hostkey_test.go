package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/store"
)

// TestTargetHostKeyRoutes (Phase 272): the pin is readable once the proxy has
// stored one, resetting it is audited with the dropped fingerprint, an
// auditor may read but not reset, and an unknown target is 404.
func TestTargetHostKeyRoutes(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{})
	status, body := do(t, srv, http.MethodPost, "/api/targets", testAPIKey,
		map[string]any{"name": "box", "host": "10.0.0.5", "port": 22, "os_type": "linux", "protocol": "ssh"})
	if status != http.StatusCreated {
		t.Fatalf("create target: %d %s", status, body)
	}
	var tgt store.Target
	_ = json.Unmarshal(body, &tgt)
	path := "/api/targets/" + itoa64(tgt.ID) + "/host-key"

	if s, _ := do(t, srv, http.MethodGet, path, testAPIKey, nil); s != http.StatusNotFound {
		t.Fatalf("no pin yet: %d", s)
	}
	if s, _ := do(t, srv, http.MethodDelete, path, testAPIKey, nil); s != http.StatusNotFound {
		t.Fatalf("reset with no pin: %d", s)
	}
	if err := st.PutTargetHostKey(t.Context(), &store.TargetHostKey{TargetID: tgt.ID, KeyType: "ssh-ed25519", Fingerprint: "SHA256:abc", PublicKey: "ssh-ed25519 AAAA"}); err != nil {
		t.Fatal(err)
	}
	status, body = do(t, srv, http.MethodGet, path, testAPIKey, nil)
	var k store.TargetHostKey
	_ = json.Unmarshal(body, &k)
	if status != http.StatusOK || k.Fingerprint != "SHA256:abc" || k.PublicKey != "ssh-ed25519 AAAA" || k.FirstSeen.IsZero() {
		t.Fatalf("get pin: %d %s", status, body)
	}
	auditor := seedUser(t, srv, "aud", "auditor")
	if s, _ := do(t, srv, http.MethodGet, path, auditor, nil); s != http.StatusOK {
		t.Fatalf("auditor read: %d", s)
	}
	if s, _ := do(t, srv, http.MethodDelete, path, auditor, nil); s != http.StatusForbidden {
		t.Fatalf("auditor reset: %d", s)
	}
	if s, _ := do(t, srv, http.MethodDelete, path, testAPIKey, nil); s != http.StatusNoContent {
		t.Fatalf("reset: %d", s)
	}
	if s, _ := do(t, srv, http.MethodGet, path, testAPIKey, nil); s != http.StatusNotFound {
		t.Fatalf("after reset: %d", s)
	}
	if s, _ := do(t, srv, http.MethodGet, "/api/targets/999999/host-key", testAPIKey, nil); s != http.StatusNotFound {
		t.Fatalf("unknown target: %d", s)
	}
	events, _ := st.ListAudit(t.Context(), 20)
	var seen bool
	for _, e := range events {
		if e.Action == "target.hostkey_reset" && strings.Contains(e.Detail, "target:box key_type:ssh-ed25519 fingerprint:SHA256:abc") {
			seen = true
		}
	}
	if !seen {
		t.Fatal("reset not audited with the dropped fingerprint")
	}
}
