package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

// --- third-party vendor access gate (Phase 29) ---

type vendorIn struct {
	Username string `json:"username"`
	Org      string `json:"org"`
}

// createVendor registers a third-party vendor: it mints a `user`-role login
// (token shown once) and a linked vendor record. The vendor can then reach a
// target only while a customer-approved, in-window contract grant is active.
// Requires CapManageUsers.
func (s *Server) createVendor(w http.ResponseWriter, r *http.Request) {
	var in vendorIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.Username == "" {
		writeError(w, http.StatusUnprocessableEntity, "username is required")
		return
	}
	// Same privilege-escalation guard as createUser: you cannot mint an identity
	// more capable than yourself. The role here is fixed at "user" rather than
	// caller-chosen, which is why the check was missed — but a delegated
	// user-admin whose own profile lacks the `user` role's capabilities could
	// still create a vendor login that HAS them, and the token comes back in the
	// response. A fixed role is not the same as a safe one.
	grantCaps, err := s.capsForGrant(r.Context(), "user")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "role lookup failed")
		return
	}
	if !principalFrom(r.Context()).Covers(grantCaps) {
		writeError(w, http.StatusForbidden, "cannot create a vendor login with capabilities you do not hold")
		return
	}
	token, err := generateToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	u := store.User{Username: in.Username, Role: "user", TokenHash: hashHex(token)}
	if err := s.store.CreateUser(r.Context(), &u); err != nil {
		storeError(w, err)
		return
	}
	v := store.Vendor{Username: in.Username, Org: in.Org}
	if err := s.store.CreateVendor(r.Context(), &v); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "vendor.create", fmt.Sprintf("vendor:%s org:%q", v.Username, v.Org))
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": v.ID, "username": v.Username, "org": v.Org, "token": token,
		"note": "Give this token to the vendor; only its hash is stored. Access needs an approved contract grant.",
	})
}

// listVendors returns a page of the registered vendors (?limit=&after=).
// Requires CapReadInventory.
func (s *Server) listVendors(w http.ResponseWriter, r *http.Request) {
	limit, after := listWindow(r)
	vendors, err := s.store.ListVendors(r.Context(), limit, after)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, vendors)
}

// updateVendor edits a vendor's organization label in place. The username is
// immutable (it links the vendor to its login identity); disabling is the
// offboard cascade, never an edit. Requires CapManageUsers, like create.
func (s *Server) updateVendor(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in struct {
		Org string `json:"org"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	v, err := s.vendorByID(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	if err := s.store.UpdateVendorOrg(r.Context(), id, in.Org); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "vendor.update", fmt.Sprintf("vendor:%s org:%q", v.Username, in.Org))
	v.Org = in.Org
	writeJSON(w, http.StatusOK, v)
}

// offboardVendor disables the vendor, revokes every contract grant, and cuts all
// their live sessions — the instant-offboard cascade. Persisted, so a revoked
// technician can't return after a restart. Requires CapManageUsers.
func (s *Server) offboardVendor(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	v, err := s.vendorByID(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	if err := s.store.OffboardVendor(r.Context(), id, time.Now()); err != nil {
		storeError(w, err)
		return
	}
	killed := 0
	if s.sessions != nil {
		killed = s.sessions.KillByActor(v.Username)
	}
	s.audit(r.Context(), "vendor.offboard", fmt.Sprintf("vendor:%s sessions_killed:%d", v.Username, killed))
	writeJSON(w, http.StatusOK, map[string]any{"vendor": v.Username, "offboarded": true, "sessions_killed": killed})
}

type vendorGrantIn struct {
	Target    string     `json:"target"`
	Principal string     `json:"principal"`
	NotBefore *time.Time `json:"not_before,omitempty"`
	NotAfter  *time.Time `json:"not_after"`
}

// createVendorGrant records a pending contract grant for a vendor: which target
// they may reach, as which account, and the time window. It must still be
// approved by a customer (a different principal) before it grants access.
// Requires CapManageTargets.
func (s *Server) createVendorGrant(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if _, err := s.vendorByID(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	var in vendorGrantIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.Target == "" || in.Principal == "" || in.NotAfter == nil {
		writeError(w, http.StatusUnprocessableEntity, "target, principal and not_after are required")
		return
	}
	target, err := s.targetByName(r.Context(), in.Target)
	if err != nil {
		writeError(w, http.StatusNotFound, "unknown target")
		return
	}
	g := store.VendorGrant{VendorID: id, TargetID: target.ID, Principal: in.Principal, Status: "pending", NotBefore: in.NotBefore, NotAfter: in.NotAfter.UTC()}
	if err := s.store.CreateVendorGrant(r.Context(), &g); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "vendor.grant_created", fmt.Sprintf("grant:%d vendor:%d target:%s principal:%s not_after:%s", g.ID, id, target.Name, in.Principal, g.NotAfter.Format(time.RFC3339)))
	writeJSON(w, http.StatusCreated, g)
}

// listVendorGrants lists a vendor's contract grants. Requires CapReadInventory.
func (s *Server) listVendorGrants(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	grants, err := s.store.ListVendorGrants(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, grants)
}

// approveVendorGrant is the customer's approval of a contract grant: the approver
// must be a different principal than the vendor (four eyes) and the vendor's live
// employment attestation must pass. On success the grant becomes active for its
// window. Requires CapApprove.
func (s *Server) approveVendorGrant(w http.ResponseWriter, r *http.Request) {
	gid, ok := idParamNamed(w, r, "gid")
	if !ok {
		return
	}
	g, v, err := s.vendorGrant(r.Context(), gid)
	if err != nil {
		storeError(w, err)
		return
	}
	approver := actorFrom(r.Context())
	if strings.EqualFold(approver, v.Username) {
		s.audit(r.Context(), "vendor.grant_decision_denied", fmt.Sprintf("grant:%d reason:self-approval", gid))
		writeError(w, http.StatusForbidden, "four-eyes: a vendor cannot approve their own contract grant")
		return
	}
	// Live employment attestation: refuse if the vendor is no longer attested.
	if s.vendorAttestor.Enabled() {
		if err := s.vendorAttestor.Attest(r.Context(), v.Username, v.Org); err != nil {
			s.audit(r.Context(), "vendor.attestation_failed", fmt.Sprintf("vendor:%s grant:%d reason:%v", v.Username, gid, err))
			writeError(w, http.StatusUnprocessableEntity, "vendor attestation failed: "+err.Error())
			return
		}
	}
	err = s.store.ApproveVendorGrant(r.Context(), gid, approver, time.Now())
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "grant is not pending")
		return
	}
	if err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "vendor.grant_approved", fmt.Sprintf("grant:%d vendor:%s approver:%s", gid, v.Username, approver))
	g.Status = "approved"
	writeJSON(w, http.StatusOK, g)
}

// revokeVendorGrant revokes one contract grant and cuts the vendor's live
// sessions to that target. Requires CapManageTargets.
func (s *Server) revokeVendorGrant(w http.ResponseWriter, r *http.Request) {
	gid, ok := idParamNamed(w, r, "gid")
	if !ok {
		return
	}
	g, v, err := s.vendorGrant(r.Context(), gid)
	if err != nil {
		storeError(w, err)
		return
	}
	if err := s.store.RevokeVendorGrant(r.Context(), gid, time.Now()); err != nil {
		storeError(w, err)
		return
	}
	killed := 0
	if s.sessions != nil {
		if target, terr := s.store.GetTarget(r.Context(), g.TargetID); terr == nil {
			killed = s.sessions.KillByActorTarget(v.Username, target.Name)
		}
	}
	s.audit(r.Context(), "vendor.grant_revoked", fmt.Sprintf("grant:%d vendor:%s sessions_killed:%d", gid, v.Username, killed))
	writeJSON(w, http.StatusOK, map[string]any{"grant": gid, "revoked": true, "sessions_killed": killed})
}

// vendorEvidence produces a per-vendor evidence bundle for SOC 2 / DORA review:
// the vendor's contract grants plus the audit slice attributable to them, with a
// SHA-256 digest over the delivered bytes. Requires CapReadAudit.
func (s *Server) vendorEvidence(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	v, err := s.vendorByID(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	grants, err := s.store.ListVendorGrants(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	events, err := s.store.ExportAudit(r.Context(), time.Time{}, time.Now())
	if err != nil {
		storeError(w, err)
		return
	}
	events = filterAudit(events, v.Username, "")
	body, _ := json.MarshalIndent(map[string]any{
		"vendor": v, "grants": grants, "audit": events, "audit_events": len(events),
	}, "", "  ")
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	s.audit(r.Context(), "vendor.evidence_export", fmt.Sprintf("vendor:%s events:%d sha256:%s", v.Username, len(events), digest))
	w.Header().Set("X-PAM-Export-SHA256", digest)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=pamv1-vendor-evidence.json")
	_, _ = w.Write(body)
}

// RunVendorSweeper periodically cuts a vendor's live sessions once their contract
// window closes or they are offboarded (Phase 29), so a session that was valid at
// connect time is terminated when its grant expires — the "time-boxed access,
// session ends mid-stream" guarantee. It runs until ctx is cancelled.
func (s *Server) RunVendorSweeper(ctx context.Context, interval time.Duration) {
	if s.sessions == nil {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sweepVendorSessions(ctx, time.Now())
		}
	}
}

// sweepVendorSessions kills every live session held by a vendor who no longer has
// an active contract grant to that session's target.
func (s *Server) sweepVendorSessions(ctx context.Context, now time.Time) {
	for _, sess := range s.sessions.List() {
		// account "" = any: kill only when the vendor has NO active grant to this
		// target for any account (a live session doesn't record which account it uses).
		isVendor, allowed, err := s.store.VendorSessionAllowed(ctx, sess.Actor, sess.Target, "", now)
		if err != nil || !isVendor || allowed {
			continue
		}
		if n := s.sessions.KillByActorTarget(sess.Actor, sess.Target); n > 0 {
			s.auditAs(ctx, sess.Actor, "vendor.session_expired", fmt.Sprintf("target:%s sessions_killed:%d", sess.Target, n))
		}
	}
}

// vendorGate enforces the vendor contract gate on an API connect / credential
// path: a vendor may reach the target only while an approved, in-window contract
// grant authorizing `account` (the login account being used) is active.
// Non-vendors pass through. It writes a 403 and returns false when a vendor is
// blocked. action names the audited denial.
func (s *Server) vendorGate(w http.ResponseWriter, r *http.Request, target *store.Target, account, action string) bool {
	isVendor, allowed, err := s.store.VendorSessionAllowed(r.Context(), actorFrom(r.Context()), target.Name, account, time.Now())
	if err != nil {
		storeError(w, err)
		return false
	}
	if isVendor && !allowed {
		s.audit(r.Context(), action, "target:"+target.Name+" reason:vendor-contract")
		writeError(w, http.StatusForbidden, "vendor access requires an approved, in-window contract grant for this account")
		return false
	}
	return true
}

// vendorByID resolves a vendor by row id (via the list, since lookups are by
// username in the store).
func (s *Server) vendorByID(ctx context.Context, id int64) (*store.Vendor, error) {
	vendors, err := s.store.ListVendors(ctx, 0, 0)
	if err != nil {
		return nil, err
	}
	for i := range vendors {
		if vendors[i].ID == id {
			return &vendors[i], nil
		}
	}
	return nil, store.ErrNotFound
}

// vendorGrant resolves a grant by id and its owning vendor.
func (s *Server) vendorGrant(ctx context.Context, gid int64) (*store.VendorGrant, *store.Vendor, error) {
	vendors, err := s.store.ListVendors(ctx, 0, 0)
	if err != nil {
		return nil, nil, err
	}
	for i := range vendors {
		grants, gerr := s.store.ListVendorGrants(ctx, vendors[i].ID)
		if gerr != nil {
			return nil, nil, gerr
		}
		for j := range grants {
			if grants[j].ID == gid {
				return &grants[j], &vendors[i], nil
			}
		}
	}
	return nil, nil, store.ErrNotFound
}
