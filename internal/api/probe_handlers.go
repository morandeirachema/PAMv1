package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/morandeirachema/pamv1/internal/auditfmt"
	"github.com/morandeirachema/pamv1/internal/probe"
	"github.com/morandeirachema/pamv1/internal/store"
)

// probeOut is one connected probe as the API reports it: the hub's status
// plus, on the detail routes, its latest snapshot.
type probeOut struct {
	probe.Status
	Snapshot *probe.Snapshot `json:"snapshot,omitempty"`
}

// listProbes returns every session probe connected to THIS replica (a probe's
// connection terminates on one process, like a tunnel's), newest first, with
// what its latest snapshot amounted to — not the snapshot itself.
func (s *Server) listProbes(w http.ResponseWriter, r *http.Request) {
	out := make([]probeOut, 0)
	for _, st := range s.probeHub.List() {
		out = append(out, probeOut{Status: st})
	}
	writeJSON(w, http.StatusOK, out)
}

// getProbe returns one probe's status and latest snapshot: the processes and
// network connections of the operator's logon session as of the last scan.
func (s *Server) getProbe(w http.ResponseWriter, r *http.Request) {
	key, ok := idParam(w, r)
	if !ok {
		return
	}
	st, snap, found := s.probeHub.Get(key)
	if !found {
		writeError(w, http.StatusNotFound, "no such probe is connected to this replica")
		return
	}
	writeJSON(w, http.StatusOK, probeOut{Status: st, Snapshot: snap})
}

// probeKillIn is the body of POST /api/probes/{id}/kill.
type probeKillIn struct {
	PID uint32 `json:"pid"`
}

// killProbeProcess asks a probe to end one process of its session, with the
// session user's own permissions — a process that user does not own is
// refused by Windows and the refusal is the answer here. Audited before the
// command is sent (so a hung probe still leaves the intent on the trail) and
// again with the outcome.
func (s *Server) killProbeProcess(w http.ResponseWriter, r *http.Request) {
	key, ok := idParam(w, r)
	if !ok {
		return
	}
	var in probeKillIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.PID == 0 {
		writeError(w, http.StatusUnprocessableEntity, "pid is required")
		return
	}
	st, _, found := s.probeHub.Get(key)
	if !found {
		writeError(w, http.StatusNotFound, "no such probe is connected to this replica")
		return
	}
	detail := fmt.Sprintf("probe:%d agent:%d target:%s user:%s session:%d pid:%d", key, st.AgentID, st.TargetName, auditfmt.Value(st.Hello.User, 128), st.Hello.SessionID, in.PID)
	s.audit(r.Context(), "probe.kill", detail)
	if err := s.probeHub.Kill(r.Context(), key, in.PID); err != nil {
		s.audit(r.Context(), "probe.kill_refused", detail+" error:"+auditfmt.Value(err.Error(), 128))
		status := http.StatusBadGateway
		if errors.Is(err, probe.ErrProbeGone) {
			status = http.StatusNotFound
		}
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pid": in.PID})
}

// sessionProbes returns the probes that belong to a live brokered session:
// those on the session's target running as the account the session was
// opened as (a desktop knows only the account, so two sessions of one
// account on one server share the answer). Empty when the target carries no
// probe, the operator's session has not launched it, or the session was
// opened as an account with no logon session (a database role).
func (s *Server) sessionProbes(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	info, ok := s.sessions.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "no such live session")
		return
	}
	out := make([]probeOut, 0)
	if info.CredUser != "" {
		for _, st := range s.probeHub.ForSession(info.Target, info.CredUser) {
			_, snap, _ := s.probeHub.Get(st.Key)
			out = append(out, probeOut{Status: st, Snapshot: snap})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// probeRuleIn is the body of POST /api/probe-rules.
type probeRuleIn struct {
	TargetID int64  `json:"target_id"`
	Kind     string `json:"kind"`
	Match    string `json:"match"`
	Port     int    `json:"port"`
	Proto    string `json:"proto"`
	Note     string `json:"note"`
}

// listProbeRules returns every block rule, with target names resolved.
func (s *Server) listProbeRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListProbeRules(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	names := map[int64]string{}
	if targets, err := s.store.ListTargets(r.Context(), 0, 0); err == nil {
		for _, t := range targets {
			names[t.ID] = t.Name
		}
	}
	type row struct {
		store.ProbeRule
		TargetName string `json:"target_name,omitempty"`
	}
	out := make([]row, 0, len(rules))
	for _, pr := range rules {
		out = append(out, row{ProbeRule: pr, TargetName: names[pr.TargetID]})
	}
	writeJSON(w, http.StatusOK, out)
}

// createProbeRule adds a block rule and pushes the new rule set to every
// connected probe at once — a rule takes effect on the next scan, not the
// next logon.
func (s *Server) createProbeRule(w http.ResponseWriter, r *http.Request) {
	var in probeRuleIn
	if !readJSON(w, r, &in) {
		return
	}
	in.Kind = strings.ToLower(strings.TrimSpace(in.Kind))
	in.Proto = strings.ToLower(strings.TrimSpace(in.Proto))
	in.Match = strings.TrimSpace(in.Match)
	if err := (probe.Rule{Kind: in.Kind, Match: in.Match, Port: in.Port, Proto: in.Proto}).Validate(); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if len(in.Match) > 255 || len(in.Note) > 255 {
		writeError(w, http.StatusUnprocessableEntity, "match and note are limited to 255 characters")
		return
	}
	targetName := "*"
	if in.TargetID != 0 {
		t, err := s.store.GetTarget(r.Context(), in.TargetID)
		if err != nil {
			storeError(w, err)
			return
		}
		targetName = t.Name
	}
	pr := store.ProbeRule{TargetID: in.TargetID, Kind: in.Kind, Match: in.Match, Port: in.Port, Proto: in.Proto, Note: in.Note, CreatedBy: actorFrom(r.Context())}
	if err := s.store.CreateProbeRule(r.Context(), &pr); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "probe.rule_create", fmt.Sprintf("rule:%d target:%s kind:%s match:%s port:%d proto:%s", pr.ID, targetName, pr.Kind, auditfmt.Value(pr.Match, 128), pr.Port, pr.Proto))
	s.probeHub.RefreshPolicy(r.Context())
	writeJSON(w, http.StatusCreated, pr)
}

// deleteProbeRule removes a rule and pushes the reduced set to every probe.
func (s *Server) deleteProbeRule(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteProbeRule(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "probe.rule_delete", fmt.Sprintf("rule:%d", id))
	s.probeHub.RefreshPolicy(r.Context())
	w.WriteHeader(http.StatusNoContent)
}
