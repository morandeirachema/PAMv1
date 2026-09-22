package api_test

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/probe"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
)

// TestProbeRuleActionAndArtifactSearch (Phase 271): a rule takes an action
// (kill by default, notify allowed, anything else refused) and a probe
// metadata artifact in the recording directory lists as kind "probe", plays
// back, and is found by the content search.
func TestProbeRuleActionAndArtifactSearch(t *testing.T) {
	recDir := t.TempDir()
	srv, st := newTestServerOpts(t, nil, api.Options{EndpointAgents: session.NewEndpointAgents(), ProbeHub: probe.NewHub(nil, nil), RecordingDir: recDir})

	status, body := do(t, srv, http.MethodPost, "/api/probe-rules", testAPIKey, map[string]any{"kind": "process", "match": "cmd.exe"})
	if status != http.StatusCreated {
		t.Fatalf("default action: %d %s", status, body)
	}
	var r store.ProbeRule
	_ = json.Unmarshal(body, &r)
	if r.Action != store.ProbeActionKill {
		t.Fatalf("default action: %+v", r)
	}
	status, body = do(t, srv, http.MethodPost, "/api/probe-rules", testAPIKey, map[string]any{"kind": "process", "match": "powershell*", "action": "Notify"})
	_ = json.Unmarshal(body, &r)
	if status != http.StatusCreated || r.Action != store.ProbeActionNotify {
		t.Fatalf("notify action: %d %s", status, body)
	}
	if status, _ = do(t, srv, http.MethodPost, "/api/probe-rules", testAPIKey, map[string]any{"kind": "process", "match": "x", "action": "block"}); status != http.StatusUnprocessableEntity {
		t.Fatalf("unknown action: %d", status)
	}
	events, _ := st.ListAudit(t.Context(), 20)
	var sawNotify bool
	for _, e := range events {
		if e.Action == "probe.rule_create" && strings.Contains(e.Detail, "action:notify") {
			sawNotify = true
		}
	}
	if !sawNotify {
		t.Fatal("rule_create audit row lacks action:notify")
	}

	// A probe artifact, as the proxy would write it (plaintext here).
	name := "1700000000000000000_win-01_alice.probe.log"
	content := `{"probe":{"agent_id":9,"target_name":"win-01"}}` + "\n" +
		`{"kind":"process_started","pid":300,"name":"PsExec.exe","command_line":"psexec \\\\dc01 cmd"}` + "\n" +
		`{"kind":"foreground_window","pid":300,"title":"secret.txt - Notepad"}` + "\n"
	if err := os.WriteFile(filepath.Join(recDir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	status, body = do(t, srv, http.MethodGet, "/api/recordings", testAPIKey, nil)
	var list []struct {
		Name string `json:"name"`
		Kind string `json:"kind"`
	}
	_ = json.Unmarshal(body, &list)
	var found bool
	for _, x := range list {
		if x.Name == name && x.Kind == "probe" {
			found = true
		}
	}
	if status != http.StatusOK || !found {
		t.Fatalf("probe artifact not listed as kind probe: %d %s", status, body)
	}
	status, body = do(t, srv, http.MethodGet, "/api/recordings/"+name, testAPIKey, nil)
	if status != http.StatusOK || !strings.Contains(string(body), "process_started") {
		t.Fatalf("play probe artifact: %d %s", status, body)
	}
	status, body = do(t, srv, http.MethodGet, "/api/recordings/search?q=psexec", testAPIKey, nil)
	var hits []struct {
		Name    string `json:"name"`
		Matches int    `json:"matches"`
		Snippet string `json:"snippet"`
	}
	_ = json.Unmarshal(body, &hits)
	if status != http.StatusOK || len(hits) != 1 || hits[0].Name != name || hits[0].Matches != 1 || !strings.Contains(hits[0].Snippet, "PsExec") {
		t.Fatalf("search probe artifact: %d %s", status, body)
	}
}
