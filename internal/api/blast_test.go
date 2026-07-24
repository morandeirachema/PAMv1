package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestBlastAnalyze proves the CIEM engine over the API (Phase 31): a submitted
// cross-provider escalation graph yields a critical finding, a blast-radius
// query, and a who-can-reach query — and is audited. read_audit is required.
func TestBlastAnalyze(t *testing.T) {
	srv, _ := newTestServerStore(t)

	graph := map[string]any{
		"principals": []map[string]any{
			{"id": "gh:app/drift", "provider": "github", "labels": map[string]string{"priv": "low"}},
			{"id": "aws:role/admin", "provider": "aws",
				"identity": []map[string]any{{"statements": []map[string]any{{"effect": "Allow", "actions": []string{"*"}, "resources": []string{"*"}}}}}},
		},
		"edges": []map[string]any{
			{"from": "gh:app/drift", "to": "aws:role/admin", "kind": "can_assume", "via": "oauth-federation"},
		},
	}
	body := map[string]any{"graph": graph, "source": "gh:app/drift", "target": "aws:role/admin"}

	code, data := do(t, srv, http.MethodPost, "/api/blast/analyze", testAPIKey, body)
	if code != http.StatusOK {
		t.Fatalf("analyze: %d %s", code, data)
	}
	var resp struct {
		Summary struct {
			Admins     int `json:"admins"`
			PivotEdges int `json:"pivot_edges"`
		} `json:"summary"`
		Findings []struct {
			Source, Target, Severity string
		} `json:"findings"`
		BlastRadius []struct{ Principal string } `json:"blast_radius"`
		WhoCanReach []string                     `json:"who_can_reach"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Summary.Admins != 1 || resp.Summary.PivotEdges != 1 {
		t.Fatalf("summary: %+v", resp.Summary)
	}
	if len(resp.Findings) == 0 || resp.Findings[0].Severity != "critical" {
		t.Fatalf("expected a critical finding: %s", data)
	}
	if len(resp.BlastRadius) == 0 || resp.BlastRadius[0].Principal != "aws:role/admin" {
		t.Fatalf("blast_radius: %s", data)
	}
	if len(resp.WhoCanReach) == 0 || resp.WhoCanReach[0] != "gh:app/drift" {
		t.Fatalf("who_can_reach: %s", data)
	}

	// An empty graph is rejected; a plain user (no read_audit) is refused.
	if c, _ := do(t, srv, http.MethodPost, "/api/blast/analyze", testAPIKey, map[string]any{"graph": map[string]any{}}); c != http.StatusUnprocessableEntity {
		t.Fatalf("empty graph: want 422, got %d", c)
	}
	user := seedUser(t, srv, "blast-user", "user")
	if c, _ := do(t, srv, http.MethodPost, "/api/blast/analyze", user, body); c != http.StatusForbidden {
		t.Fatalf("non-auditor: want 403, got %d", c)
	}
}
