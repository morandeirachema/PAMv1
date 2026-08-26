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
	// Personal (Phase 139) marks the safe private — see store.Safe.Personal.
	// Read only by createSafe; updateSafe never reads it, so it cannot be
	// changed after creation through this struct even by accident (the store
	// layer enforces the same immutability independently).
	Personal bool `json:"personal,omitempty"`
	// Owner is required when Personal is true: the username createSafe adds
	// as the safe's first can_manage member in the same call, so a personal
	// safe is never created ownerless and unmanageable (canManageSafe no
	// longer treats CapManageTargets alone as enough once a safe is
	// personal). Must be empty when Personal is false.
	Owner string `json:"owner,omitempty"`
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

// createSafe creates a safe (CapManageTargets) and audits it. A Personal
// safe (Phase 139) additionally requires Owner and seeds them as its first
// can_manage member in the same call — see safeIn.Owner — so it is never
// left in an unmanageable, memberless state.
func (s *Server) createSafe(w http.ResponseWriter, r *http.Request) {
	var in safeIn
	if !readJSON(w, r, &in) {
		return
	}
	if !checkName(w, "name", in.Name) {
		return
	}
	if !validSafePolicy(w, in) {
		return
	}
	switch {
	case in.Personal && in.Owner == "":
		writeError(w, http.StatusUnprocessableEntity, "owner is required for a personal safe")
		return
	case in.Personal && validName(in.Owner) != nil:
		writeError(w, http.StatusUnprocessableEntity, "owner "+validName(in.Owner).Error())
		return
	case !in.Personal && in.Owner != "":
		writeError(w, http.StatusUnprocessableEntity, "owner is only meaningful for a personal safe")
		return
	}
	sf := store.Safe{Name: in.Name, Description: in.Description,
		RequireApproval: in.RequireApproval, MinApprovers: in.MinApprovers, Personal: in.Personal}
	if err := s.store.CreateSafe(r.Context(), &sf); err != nil {
		storeError(w, err)
		return
	}
	if in.Personal {
		owner := store.SafeMember{SafeID: sf.ID, SubjectType: "user", Subject: in.Owner,
			CanManage: true, CreatedBy: actorFrom(r.Context())}
		if err := s.store.AddSafeMember(r.Context(), &owner); err != nil {
			// A personal safe nobody can manage is dead weight, not a smaller
			// version of the feature — roll it back rather than leave it stuck.
			_ = s.store.DeleteSafe(context.WithoutCancel(r.Context()), sf.ID)
			storeError(w, err)
			return
		}
	}
	s.audit(r.Context(), "safe.create", fmt.Sprintf("safe:%s require_approval:%t min_approvers:%d personal:%t owner:%s",
		in.Name, sf.RequireApproval, sf.MinApprovers, sf.Personal, in.Owner))
	writeJSON(w, http.StatusCreated, sf)
}

// listSafes returns a page of the safes (CapReadInventory; ?limit=&after=).

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
	if !checkName(w, "name", in.Name) {
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
	if !s.guardPersonalSafe(w, r, id) {
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
// global target manager (CapManageTargets) or a can_manage member of that
// safe. For a Personal safe (Phase 139), CapManageTargets alone is
// deliberately NOT enough — it would be a side door around
// auth.CanConnectTarget's own personal-safe protection, letting any target
// manager add themselves as a member and connect normally. A personal
// safe's roster is managed only by its own can_manage member(s) (seeded at
// creation — see createSafe) or a principal holding CapUnlimitedVaultAccess,
// the same override CanConnectTarget itself honors.
// guardPersonalTarget refuses an operation on a target that currently sits in a
// Personal safe unless the caller holds CapUnlimitedVaultAccess. It returns true
// when the caller may proceed and, when it does not, has already written the 403
// and an audit row.
//
// This exists because of the 2026-08-26 audit (M-5). Personal-safe privacy was
// enforced at CONNECT time (auth.CanConnectTarget) and inside canManageSafe, but
// three management routes that a plain CapManageTargets holder can reach —
// reassigning a target's safe, deleting the safe, and granting the target
// directly — went straight to the store with no personal check, so any such
// admin could unwrap a CISO's private target and reach it. The override
// capability is the one deliberate exception, matching canManageSafe.
func (s *Server) guardPersonalTarget(w http.ResponseWriter, r *http.Request, targetID int64) bool {
	p := principalFrom(r.Context())
	if p.Can(auth.CapUnlimitedVaultAccess) {
		return true
	}
	t, err := s.store.GetTarget(r.Context(), targetID)
	if err != nil {
		storeError(w, err)
		return false
	}
	personal, err := store.EffectiveSafePersonal(r.Context(), s.store, t)
	if err != nil {
		// Fail closed: an unreadable safe must not read as "not personal".
		s.audit(r.Context(), "authz.denied", fmt.Sprintf("target:%d reason:personal-safe-check-failed", targetID))
		writeError(w, http.StatusForbidden, "not authorized for this target")
		return false
	}
	if personal {
		s.audit(r.Context(), "authz.denied", fmt.Sprintf("target:%d reason:personal-safe", targetID))
		writeError(w, http.StatusForbidden, "this target is in a personal safe")
		return false
	}
	return true
}

// guardPersonalSafe is guardPersonalTarget's sibling for an operation named by
// SAFE id rather than target id (deleteSafe). Same rule, same override.
func (s *Server) guardPersonalSafe(w http.ResponseWriter, r *http.Request, safeID int64) bool {
	p := principalFrom(r.Context())
	if p.Can(auth.CapUnlimitedVaultAccess) {
		return true
	}
	sf, err := s.store.GetSafe(r.Context(), safeID)
	if err != nil {
		storeError(w, err)
		return false
	}
	if sf.Personal {
		s.audit(r.Context(), "authz.denied", fmt.Sprintf("safe:%d reason:personal-safe", safeID))
		writeError(w, http.StatusForbidden, "this is a personal safe")
		return false
	}
	return true
}

// guardPersonalTargetWrite refuses a WRITE to a target that sits in a personal
// safe — adding or deleting one of its credentials, deleting the target —
// unless the caller may manage that safe (canManageSafe: its owner or a
// can_manage member, or CapUnlimitedVaultAccess). Phase 212's M-5 guarded
// the three ways a plain target manager could bypass a personal safe's
// PRIVACY; the 2026-08-27 audit found its INTEGRITY still open — a plain
// manage_targets / manage_credentials principal could delete the owner's
// target or plant a credential on it. Unlike guardPersonalTarget (grants,
// which nobody but the override may add), the owner is admitted here: a
// personal safe's owner must be able to keep their own target. A built-in
// admin is admitted too: a write reveals nothing, and provisioning a personal
// safe (create it for the owner, add the target, vault its credential) is an
// admin's job — the bound this closes is the DELEGATED manager's, whose
// custom profile was never meant to reach into someone's personal folder. A
// target in no safe, or in an ordinary safe, passes untouched.
func (s *Server) guardPersonalTargetWrite(w http.ResponseWriter, r *http.Request, t *store.Target) bool {
	if t.SafeID == nil || principalFrom(r.Context()).IsAdmin() {
		return true
	}
	personal, err := store.EffectiveSafePersonal(r.Context(), s.store, t)
	if err != nil {
		s.audit(r.Context(), "authz.denied", fmt.Sprintf("target:%d reason:personal-safe-check-failed", t.ID))
		writeError(w, http.StatusForbidden, "not authorized for this target")
		return false
	}
	if !personal || s.canManageSafe(r.Context(), *t.SafeID) {
		return true
	}
	s.audit(r.Context(), "authz.denied", fmt.Sprintf("target:%d reason:personal-safe", t.ID))
	writeError(w, http.StatusForbidden, "this target is in a personal safe")
	return false
}

func (s *Server) canManageSafe(ctx context.Context, safeID int64) bool {
	p := principalFrom(ctx)
	sf, err := s.store.GetSafe(ctx, safeID)
	if err != nil {
		return false
	}
	switch {
	case !sf.Personal && p.Can(auth.CapManageTargets):
		return true
	case sf.Personal && p.Can(auth.CapUnlimitedVaultAccess):
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
	if !s.guardPersonalTarget(w, r, id) {
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
