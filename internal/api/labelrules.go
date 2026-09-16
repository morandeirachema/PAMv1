package api

// labelrules.go is the REST side of label-based authorization (Phase 250): the
// three routes that manage the rules, and the validation that keeps a rule
// meaning what its author typed. The decision itself lives in
// auth.CanAccessTargetAt beside every other one — a rule is folded into a
// target's effective grants by the store, so every door that already reads
// grants reads label rules too without a line of its own.
//
// These routes are CapManageTargets, not CapManageUsers: a label rule is a
// statement about the ESTATE ("nothing labelled tier=db is reachable by
// contractors"), and the person who labels the targets is the person who
// should be able to say what a label means.

import (
	"fmt"
	"net/http"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
)

type labelRuleIn struct {
	Selector    string     `json:"selector"`
	SubjectType string     `json:"subject_type"`
	Subject     string     `json:"subject"`
	Effect      string     `json:"effect"`
	Permissions []string   `json:"permissions"`
	ExpiresAt   *time.Time `json:"expires_at"`
	TimeFrame   string     `json:"time_frame"`
}

// createLabelRule adds a label rule. The selector is PARSED here, not merely
// stored: an unparsable selector matches nothing, which would leave an
// operator looking at a deny rule in the list that denies nobody — the one
// failure mode where silence is indistinguishable from enforcement.
func (s *Server) createLabelRule(w http.ResponseWriter, r *http.Request) {
	var in labelRuleIn
	if !readJSON(w, r, &in) {
		return
	}
	switch {
	case in.SubjectType != "user" && in.SubjectType != "role":
		writeError(w, http.StatusUnprocessableEntity, `subject_type must be "user" or "role"`)
		return
	case validName(in.Subject) != nil:
		writeError(w, http.StatusUnprocessableEntity, "subject "+validName(in.Subject).Error())
		return
	}
	if in.SubjectType == "role" {
		if _, err := auth.ParseGrantRole(in.Subject); err != nil {
			writeError(w, http.StatusUnprocessableEntity, `subject must be a valid role (admin|user|auditor|approver|agent)`)
			return
		}
	}
	sel, err := store.ParseLabelSelector(in.Selector)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	effect := in.Effect
	if effect == "" {
		effect = store.GrantAllow
	}
	if effect != store.GrantAllow && effect != store.GrantDeny {
		writeError(w, http.StatusUnprocessableEntity, `effect must be "allow" or "deny"`)
		return
	}
	frame, ok := validGrantLifetime(w, in.ExpiresAt, in.TimeFrame)
	if !ok {
		return
	}
	perms := store.DefaultSafePermissions()
	if in.Permissions != nil {
		var perr error
		if perms, perr = store.NormalizeSafePermissions(in.Permissions); perr != nil {
			writeError(w, http.StatusUnprocessableEntity, perr.Error())
			return
		}
	}
	if effect == store.GrantDeny {
		// A deny rule refuses every action; a permission set on one would read
		// like a partial denial it does not implement.
		if in.Permissions != nil {
			writeError(w, http.StatusUnprocessableEntity, "a deny rule refuses every action; it takes no permissions")
			return
		}
		perms = nil
	} else if len(perms) == 0 {
		writeError(w, http.StatusUnprocessableEntity, "an allow rule with no permissions would grant nothing")
		return
	}
	rule := store.LabelRule{Selector: sel.String(), SubjectType: in.SubjectType, Subject: in.Subject,
		Effect: effect, Permissions: perms, ExpiresAt: in.ExpiresAt, TimeFrame: frame,
		CreatedBy: actorFrom(r.Context())}
	if err := s.store.CreateLabelRule(r.Context(), &rule); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "labelrule.create",
		fmt.Sprintf("rule:%d selector:%s %s:%s effect:%s", rule.ID, auditField(sel.String(), 128), in.SubjectType, in.Subject, effect)+
			lifetimeDetail(in.ExpiresAt, frame))
	writeJSON(w, http.StatusCreated, rule)
}

// listLabelRules returns every label rule. It is read-inventory rather than
// manage-targets: a rule decides who reaches what, so an auditor has to be
// able to read the policy without being able to write it.
func (s *Server) listLabelRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListLabelRules(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rules)
}

// deleteLabelRule removes a label rule. Deleting a DENY rule widens access
// across every target its selector matched, which is why the audit detail
// carries the selector and the effect rather than just the id.
func (s *Server) deleteLabelRule(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	rules, err := s.store.ListLabelRules(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	var found *store.LabelRule
	for i := range rules {
		if rules[i].ID == id {
			found = &rules[i]
			break
		}
	}
	if found == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err := s.store.DeleteLabelRule(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "labelrule.delete",
		fmt.Sprintf("rule:%d selector:%s %s:%s effect:%s", id, auditField(found.Selector, 128), found.SubjectType, found.Subject, found.Effect))
	w.WriteHeader(http.StatusNoContent)
}
