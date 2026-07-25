package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/morandeirachema/pamv1/internal/blast"
)

// Bounds on a submitted identity graph: a byte cap so an oversized payload can't
// exhaust memory, and node/edge caps so the ~O(V²) full scan (per-source
// reachability) stays bounded even within the byte budget.
const (
	maxBlastGraphBytes = 4 << 20 // 4 MiB request body
	maxBlastPrincipals = 20000
	maxBlastEdges      = 100000
)

type blastAnalyzeIn struct {
	Graph blast.Graph `json:"graph"`
	// Optional focused queries. Source computes that principal's blast radius;
	// Target asks who can reach it. Both empty → the full toxic-combination scan.
	Source string `json:"source,omitempty"`
	Target string `json:"target,omitempty"`
}

// analyzeBlast runs the identity blast-radius / CIEM engine (Phase 31) over a
// submitted normalized graph and returns toxic-combination findings, a summary,
// and (optionally) a focused reachability query. It is pure read-only analysis —
// the graph is supplied by an external ingester — so no cloud credentials or
// state are involved. Requires CapReadAudit (a security reviewer's capability).
func (s *Server) analyzeBlast(w http.ResponseWriter, r *http.Request) {
	// Read with the graph byte cap directly — not readJSON, whose smaller inner cap
	// would reject a legitimately large graph before this one applies.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBlastGraphBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "graph exceeds the size limit or is unreadable")
		return
	}
	var in blastAnalyzeIn
	if err := json.Unmarshal(body, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(in.Graph.Principals) == 0 {
		writeError(w, http.StatusUnprocessableEntity, "graph.principals is required")
		return
	}
	if len(in.Graph.Principals) > maxBlastPrincipals || len(in.Graph.Edges) > maxBlastEdges {
		writeError(w, http.StatusUnprocessableEntity, fmt.Sprintf("graph too large (max %d principals, %d edges)", maxBlastPrincipals, maxBlastEdges))
		return
	}
	// A focused query for a principal not in the graph is a client error, not a
	// silent empty result the caller can't distinguish from "reaches nothing".
	if in.Source != "" && in.Graph.Principal(in.Source) == nil {
		writeError(w, http.StatusUnprocessableEntity, "source is not a principal in the graph")
		return
	}
	if in.Target != "" && in.Graph.Principal(in.Target) == nil {
		writeError(w, http.StatusUnprocessableEntity, "target is not a principal in the graph")
		return
	}
	findings, err := in.Graph.Findings()
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if findings == nil {
		findings = []blast.Finding{} // a clean graph returns [], not JSON null
	}
	resp := map[string]any{
		"summary":  in.Graph.Summary(),
		"findings": findings,
	}
	if in.Source != "" {
		reach, err := in.Graph.BlastRadius(in.Source)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		if reach == nil {
			reach = []blast.Reach{}
		}
		resp["blast_radius"] = reach
	}
	if in.Target != "" {
		who, err := in.Graph.WhoCanReach(in.Target)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		if who == nil {
			who = []string{}
		}
		resp["who_can_reach"] = who
	}
	s.audit(r.Context(), "blast.analyze", fmt.Sprintf("principals:%d edges:%d findings:%d", len(in.Graph.Principals), len(in.Graph.Edges), len(findings)))
	writeJSON(w, http.StatusOK, resp)
}
