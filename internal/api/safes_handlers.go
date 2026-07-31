package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
)

// --- safes (Phase 17): named containers that group targets and delegate who may
// access them. A safe member may connect to every target in the safe (an
// authorization path alongside per-target grants); a can_manage member is a
// delegated safe administrator. ---

type safeIn struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Safe-scoped access policy (Phase 58). Both are strictest-wins with the
	// global and per-target settings: a safe can tighten them, never loosen them.
	RequireApproval bool `json:"require_approval,omitempty"`
	MinApprovers    int  `json:"min_approvers,omitempty"`
}

// maxSafeApprovers bounds the dual-control floor. A floor larger than any
// plausible approver pool is not stricter policy, it is a target nobody can
// ever reach — a denial of service written as a setting.
const maxSafeApprovers = 10

// validSafePolicy checks the policy fields, writing the error response itself.
func validSafePolicy(w http.ResponseWriter, in safeIn) bool {
	if in.MinApprovers < 0 || in.MinApprovers > maxSafeApprovers {
		writeError(w, http.StatusUnprocessableEntity,
			fmt.Sprintf("min_approvers must be between 0 and %d", maxSafeApprovers))
		return false
	}
	return true
}

// createSafe creates a safe (CapManageTargets) and audits it.
func (s *Server) createSafe(w http.ResponseWriter, r *http.Request) {
	var in safeIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.Name == "" {
		writeError(w, http.StatusUnprocessableEntity, "name is required")
		return
	}
	if !validSafePolicy(w, in) {
		return
	}
	sf := store.Safe{Name: in.Name, Description: in.Description,
		RequireApproval: in.RequireApproval, MinApprovers: in.MinApprovers}
	if err := s.store.CreateSafe(r.Context(), &sf); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "safe.create", fmt.Sprintf("safe:%s require_approval:%t min_approvers:%d",
		in.Name, sf.RequireApproval, sf.MinApprovers))
	writeJSON(w, http.StatusCreated, sf)
}

// listSafes returns a page of the safes (CapReadInventory; ?limit=&after=).
func (s *Server) listSafes(w http.ResponseWriter, r *http.Request) {
	limit, after := listWindow(r)
	safes, err := s.store.ListSafes(r.Context(), limit, after)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, safes)
}

// updateSafe renames a safe / edits its description in place (CapManageTargets,
// like create). Membership and target assignment are untouched.
func (s *Server) updateSafe(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in safeIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.Name == "" {
		writeError(w, http.StatusUnprocessableEntity, "name is required")
		return
	}
	if !validSafePolicy(w, in) {
		return
	}
	sf := store.Safe{ID: id, Name: in.Name, Description: in.Description,
		RequireApproval: in.RequireApproval, MinApprovers: in.MinApprovers}
	if err := s.store.UpdateSafe(r.Context(), &sf); err != nil {
		storeError(w, err)
		return
	}
	// The policy is in the audit detail because raising or LOWERING it changes
	// who may reach every target in the safe — a change a reviewer must be able
	// to see without diffing two API reads.
	s.audit(r.Context(), "safe.update", fmt.Sprintf("safe:%d name:%s require_approval:%t min_approvers:%d",
		sf.ID, sf.Name, sf.RequireApproval, sf.MinApprovers))
	writeJSON(w, http.StatusOK, sf)
}

// deleteSafe removes a safe (CapManageTargets); its members cascade and its
// targets are unassigned.
func (s *Server) deleteSafe(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteSafe(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "safe.delete", fmt.Sprintf("safe:%d", id))
	w.WriteHeader(http.StatusNoContent)
}

type safeMemberIn struct {
	SubjectType string `json:"subject_type"`
	Subject     string `json:"subject"`
	CanManage   bool   `json:"can_manage"`
}

// addSafeMember adds a member to a safe. The route is open to inventory readers
// so a delegated can_manage member (not only a global target manager) can grant
// access to their own safe; canManageSafe enforces the finer check.
func (s *Server) addSafeMember(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if !s.canManageSafe(r.Context(), id) {
		writeError(w, http.StatusForbidden, "not authorized to manage this safe")
		return
	}
	var in safeMemberIn
	if !readJSON(w, r, &in) {
		return
	}
	switch {
	case in.SubjectType != "user" && in.SubjectType != "role":
		writeError(w, http.StatusUnprocessableEntity, `subject_type must be "user" or "role"`)
		return
	case in.Subject == "":
		writeError(w, http.StatusUnprocessableEntity, "subject is required")
		return
	}
	if in.SubjectType == "role" {
		if _, err := auth.ParseGrantRole(in.Subject); err != nil {
			writeError(w, http.StatusUnprocessableEntity, `subject must be a valid role (admin|user|auditor|approver|agent)`)
			return
		}
	}
	// The creator is recorded for the certification four-eyes check (Phase 46).
	m := store.SafeMember{SafeID: id, SubjectType: in.SubjectType, Subject: in.Subject, CanManage: in.CanManage, CreatedBy: actorFrom(r.Context())}
	if err := s.store.AddSafeMember(r.Context(), &m); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "safe.member.add", fmt.Sprintf("safe:%d %s:%s manage:%t", id, in.SubjectType, in.Subject, in.CanManage))
	writeJSON(w, http.StatusCreated, m)
}

// listSafeMembers returns a safe's members (CapReadInventory).
func (s *Server) listSafeMembers(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	members, err := s.store.ListSafeMembers(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, members)
}

// deleteSafeMember removes a member from a safe (target manager or a can_manage
// member of that safe).
func (s *Server) deleteSafeMember(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if !s.canManageSafe(r.Context(), id) {
		writeError(w, http.StatusForbidden, "not authorized to manage this safe")
		return
	}
	mid, err := strconv.ParseInt(r.PathValue("mid"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid member id")
		return
	}
	// canManageSafe authorized THIS safe, so the member must belong to it: a
	// delegated manager of one safe must not be able to remove a member of any
	// other safe by guessing its id (member ids are global).
	members, err := s.store.ListSafeMembers(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	found := false
	for _, m := range members {
		if m.ID == mid {
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "member not found in this safe")
		return
	}
	if err := s.store.DeleteSafeMember(r.Context(), mid); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "safe.member.remove", fmt.Sprintf("safe:%d member:%d", id, mid))
	w.WriteHeader(http.StatusNoContent)
}

// canManageSafe reports whether the caller may manage a safe's membership: a
// global target manager (CapManageTargets) or a can_manage member of that safe.
func (s *Server) canManageSafe(ctx context.Context, safeID int64) bool {
	p := principalFrom(ctx)
	if p.Can(auth.CapManageTargets) {
		return true
	}
	members, err := s.store.ListSafeMembers(ctx, safeID)
	if err != nil {
		return false
	}
	for _, m := range members {
		if m.CanManage && auth.SubjectMatches(p, m.SubjectType, m.Subject) {
			return true
		}
	}
	return false
}

type targetSafeIn struct {
	SafeID *int64 `json:"safe_id"`
}

// setTargetSafe places a target in a safe (or clears it when safe_id is null);
// CapManageTargets. Putting a target in a safe restricts it to the safe's
// members (plus any direct target grants).
func (s *Server) setTargetSafe(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in targetSafeIn
	if !readJSON(w, r, &in) {
		return
	}
	if err := s.store.AssignTargetSafe(r.Context(), id, in.SafeID); err != nil {
		storeError(w, err)
		return
	}
	detail := fmt.Sprintf("target:%d safe:none", id)
	if in.SafeID != nil {
		detail = fmt.Sprintf("target:%d safe:%d", id, *in.SafeID)
	}
	s.audit(r.Context(), "target.safe_set", detail)
	w.WriteHeader(http.StatusNoContent)
}
