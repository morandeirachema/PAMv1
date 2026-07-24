package api

import (
	"fmt"
	"net/http"

	"github.com/morandeirachema/pamv1/internal/blast"
)

// maxBlastGraphBytes bounds a submitted identity graph so an oversized payload
// can't exhaust memory during analysis.
const maxBlastGraphBytes = 4 << 20 // 4 MiB

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
	r.Body = http.MaxBytesReader(w, r.Body, maxBlastGraphBytes)
	var in blastAnalyzeIn
	if !readJSON(w, r, &in) {
		return
	}
	if len(in.Graph.Principals) == 0 {
		writeError(w, http.StatusUnprocessableEntity, "graph.principals is required")
		return
	}
	findings, err := in.Graph.Findings()
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
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
		resp["blast_radius"] = reach
	}
	if in.Target != "" {
		who, err := in.Graph.WhoCanReach(in.Target)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		resp["who_can_reach"] = who
	}
	s.audit(r.Context(), "blast.analyze", fmt.Sprintf("principals:%d edges:%d findings:%d", len(in.Graph.Principals), len(in.Graph.Edges), len(findings)))
	writeJSON(w, http.StatusOK, resp)
}
