package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/morandeirachema/pamv1/internal/auditfmt"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/restrict"
	"github.com/morandeirachema/pamv1/internal/store"
)

// restrictionIn is the body of POST /api/restriction-rules.
type restrictionIn struct {
	SubjectType string `json:"subject_type"`
	Subject     string `json:"subject"`
	Subprotocol string `json:"subprotocol"`
	Pattern     string `json:"pattern"`
	Action      string `json:"action"`
	Note        string `json:"note"`
}

// listRestrictionRules returns every per-subject restriction rule.
func (s *Server) listRestrictionRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListRestrictionRules(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	if rules == nil {
		rules = []store.RestrictionRule{}
	}
	writeJSON(w, http.StatusOK, rules)
}

// createRestrictionRule adds a rule (Phase 275). It takes effect on the next
// session admitted for the subject — a set is loaded at admission, so a
// running session keeps the rules it was admitted under.
func (s *Server) createRestrictionRule(w http.ResponseWriter, r *http.Request) {
	var in restrictionIn
	if !readJSON(w, r, &in) {
		return
	}
	in.SubjectType = strings.ToLower(strings.TrimSpace(in.SubjectType))
	in.Subject = strings.TrimSpace(in.Subject)
	in.Subprotocol = strings.ToLower(strings.TrimSpace(in.Subprotocol))
	in.Action = strings.ToLower(strings.TrimSpace(in.Action))
	if in.Subprotocol == "" {
		in.Subprotocol = "*"
	}
	if in.Action == "" {
		in.Action = restrict.ActionKill
	}
	switch in.SubjectType {
	case "user":
		if !checkName(w, "subject", in.Subject) {
			return
		}
	case "role":
		if _, err := auth.ParseGrantRole(in.Subject); err != nil {
			writeError(w, http.StatusUnprocessableEntity, "subject must be a valid role (admin|user|auditor|approver|agent)")
			return
		}
	default:
		writeError(w, http.StatusUnprocessableEntity, `subject_type must be "user" or "role"`)
		return
	}
	if len(in.Pattern) > 500 || len(in.Note) > 255 {
		writeError(w, http.StatusUnprocessableEntity, "pattern is limited to 500 characters and note to 255")
		return
	}
	rule := store.RestrictionRule{SubjectType: in.SubjectType, Subject: in.Subject, Subprotocol: in.Subprotocol, Pattern: in.Pattern, Action: in.Action, Note: in.Note, CreatedBy: actorFrom(r.Context())}
	if err := restrict.Validate(rule); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := s.store.CreateRestrictionRule(r.Context(), &rule); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "restriction.create", fmt.Sprintf("rule:%d %s:%s subprotocol:%s action:%s pattern:%s", rule.ID, rule.SubjectType, rule.Subject, rule.Subprotocol, rule.Action, auditfmt.Value(rule.Pattern, 200)))
	writeJSON(w, http.StatusCreated, rule)
}

// deleteRestrictionRule removes a rule; sessions already admitted keep it.
func (s *Server) deleteRestrictionRule(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteRestrictionRule(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "restriction.delete", fmt.Sprintf("rule:%d", id))
	w.WriteHeader(http.StatusNoContent)
}

// checkRestriction evaluates the caller's restriction set against a command
// on a REST-brokered path (Phase 275): a notify match is audited and let
// through; a kill match refuses the call (there is no session to end on this
// path) with the same error command control uses. A store failure refuses
// too — a set that cannot be read must not read as empty.
func (s *Server) checkRestriction(ctx context.Context, actor, targetName, path, command string) error {
	p := principalFrom(ctx)
	if p == nil {
		return nil
	}
	set, err := restrict.Load(ctx, s.store, restrict.Subject{Name: p.Name, Roles: p.RoleNames()})
	if err != nil {
		s.log.Error("restriction set load failed", "actor", actor, "err", err)
		return errCommandBlocked
	}
	m, ok := set.Check(path, command)
	if !ok {
		return nil
	}
	detail := fmt.Sprintf("target:%s path:%s rule:%d pattern:%s", targetName, path, m.RuleID, auditfmt.Value(m.Pattern, 128))
	if m.Action == restrict.ActionNotify {
		s.auditAs(ctx, actor, "restriction.notified", detail)
		return nil
	}
	s.auditAs(ctx, actor, "restriction.killed", detail)
	return errCommandBlocked
}
