package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

// --- access certification / attestation campaigns (Phase 19): a point-in-time
// review of who has access to what. A campaign snapshots the current access
// grants (target grants + safe members); a reviewer certifies or revokes each,
// and a "revoke" actually removes the underlying grant. ---

type campaignIn struct {
	Name  string     `json:"name"`
	DueAt *time.Time `json:"due_at,omitempty"`
	// Scope (Phase 68). Absent means the whole estate, as before.
	ScopeKind    store.CampaignScope `json:"scope_kind,omitempty"`
	ScopeSafeID  *int64              `json:"scope_safe_id,omitempty"`
	ScopeSubject string              `json:"scope_subject,omitempty"`
	// RecurDays > 0 makes this campaign the anchor of a recurring series.
	RecurDays int `json:"recur_days,omitempty"`
}

// maxRecurDays bounds a recurrence at roughly a year. A campaign that repeats
// less often than annually is not a schedule anybody is relying on, and the
// bound keeps a fat-fingered value from parking a series past any horizon an
// operator would think to look at.
const maxRecurDays = 366

// createCampaign snapshots the current access grants into a new campaign
// (CapManageUsers) and audits it.
func (s *Server) createCampaign(w http.ResponseWriter, r *http.Request) {
	var in campaignIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.Name == "" {
		writeError(w, http.StatusUnprocessableEntity, "name is required")
		return
	}
	ctx := r.Context()
	c := store.Campaign{
		Name: in.Name, CreatedBy: actorFrom(ctx), DueAt: in.DueAt, Status: "open",
		ScopeKind: in.ScopeKind, ScopeSafeID: in.ScopeSafeID, ScopeSubject: in.ScopeSubject,
		RecurDays: in.RecurDays,
	}
	if !s.validateCampaignScope(w, ctx, &c) {
		return
	}
	if c.RecurDays > 0 {
		next := time.Now().UTC().AddDate(0, 0, c.RecurDays)
		c.NextRunAt = &next
	}
	if err := s.store.CreateCampaign(ctx, &c); err != nil {
		storeError(w, err)
		return
	}
	items, err := s.snapshotAccess(ctx, &c)
	if err != nil {
		storeError(w, err)
		return
	}
	s.audit(ctx, "certification.campaign_created",
		fmt.Sprintf("campaign:%d name:%q items:%d %s", c.ID, c.Name, items, campaignScopeDetail(&c)))
	writeJSON(w, http.StatusCreated, map[string]any{"campaign": c, "items": items})
}

// validateCampaignScope checks a campaign's scope and recurrence, writing the
// refusal and reporting false when it does not hold.
//
// An unknown scope is refused rather than ignored: falling back to "review
// everything" would turn a typo into the unreviewable campaign the scope exists
// to avoid, and the caller would never know their filter was dropped.
func (s *Server) validateCampaignScope(w http.ResponseWriter, ctx context.Context, c *store.Campaign) bool {
	if !store.ValidCampaignScope(c.ScopeKind) {
		writeError(w, http.StatusUnprocessableEntity, "scope_kind must be omitted, \"safe\" or \"subject\"")
		return false
	}
	switch c.ScopeKind {
	case store.CampaignScopeSafe:
		if c.ScopeSafeID == nil {
			writeError(w, http.StatusUnprocessableEntity, "scope_safe_id is required for a safe-scoped campaign")
			return false
		}
		// Resolved now, while a human is present to be told: a campaign scoped to
		// a safe that does not exist snapshots nothing and looks complete.
		if _, err := s.store.GetSafe(ctx, *c.ScopeSafeID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusUnprocessableEntity, "scope_safe_id does not name an existing safe")
			} else {
				storeError(w, err)
			}
			return false
		}
		c.ScopeSubject = ""
	case store.CampaignScopeSubject:
		if strings.TrimSpace(c.ScopeSubject) == "" {
			writeError(w, http.StatusUnprocessableEntity, "scope_subject is required for a subject-scoped campaign")
			return false
		}
		c.ScopeSafeID = nil
	default:
		c.ScopeSafeID, c.ScopeSubject = nil, ""
	}
	if c.RecurDays < 0 || c.RecurDays > maxRecurDays {
		writeError(w, http.StatusUnprocessableEntity,
			fmt.Sprintf("recur_days must be between 0 (one-off) and %d", maxRecurDays))
		return false
	}
	return true
}

// campaignScopeDetail renders a campaign's scope and recurrence for an audit
// detail, so the trail records what a campaign actually covered rather than
// leaving a reader to infer it from the item count.
func campaignScopeDetail(c *store.Campaign) string {
	scope := "scope:all"
	switch c.ScopeKind {
	case store.CampaignScopeSafe:
		if c.ScopeSafeID != nil {
			scope = fmt.Sprintf("scope:safe safe:%d", *c.ScopeSafeID)
		}
	case store.CampaignScopeSubject:
		scope = "scope:subject subject:" + auditField(c.ScopeSubject, 128)
	}
	if c.RecurDays > 0 {
		scope += fmt.Sprintf(" recur_days:%d", c.RecurDays)
	}
	return scope
}

// snapshotAccess records the access under review as items of campaign c,
// returning how many were captured.
//
// The scope is applied HERE rather than by filtering afterwards, because an item
// that is not in scope should never be written: a campaign's items are its
// evidence, and a reviewer certifying a list they were not asked to review is
// worse than a list that is too long.
//
// A safe-scoped campaign covers both halves of what "access to that safe" means:
// its members, and the grants on every target assigned to it. Covering only the
// members would leave a target in the safe reachable by a direct grant that the
// review never showed.
func (s *Server) snapshotAccess(ctx context.Context, c *store.Campaign) (int, error) {
	n := 0
	targets, err := s.store.ListTargets(ctx, 0, 0)
	if err != nil {
		return 0, err
	}
	for _, t := range targets {
		if c.ScopeKind == store.CampaignScopeSafe {
			if t.SafeID == nil || c.ScopeSafeID == nil || *t.SafeID != *c.ScopeSafeID {
				continue
			}
		}
		grants, err := s.store.ListTargetGrants(ctx, t.ID)
		if err != nil {
			return 0, err
		}
		for _, g := range grants {
			if !campaignCovers(c, g.Subject) {
				continue
			}
			if err := s.store.AddCampaignItem(ctx, &store.CampaignItem{
				CampaignID: c.ID, Kind: "target_grant", RefID: g.ID,
				SubjectType: g.SubjectType, Subject: g.Subject,
				Detail:    itemDetail(fmt.Sprintf("grant on target %q", t.Name), g.CreatedBy),
				GrantedBy: g.CreatedBy,
			}); err != nil {
				return 0, err
			}
			n++
		}
	}
	safes, err := s.store.ListSafes(ctx, 0, 0)
	if err != nil {
		return 0, err
	}
	for _, sf := range safes {
		if c.ScopeKind == store.CampaignScopeSafe && (c.ScopeSafeID == nil || sf.ID != *c.ScopeSafeID) {
			continue
		}
		members, err := s.store.ListSafeMembers(ctx, sf.ID)
		if err != nil {
			return 0, err
		}
		for _, mem := range members {
			if !campaignCovers(c, mem.Subject) {
				continue
			}
			if err := s.store.AddCampaignItem(ctx, &store.CampaignItem{
				CampaignID: c.ID, Kind: "safe_member", RefID: mem.ID,
				SubjectType: mem.SubjectType, Subject: mem.Subject,
				Detail:    itemDetail(fmt.Sprintf("member of safe %q", sf.Name), mem.CreatedBy),
				GrantedBy: mem.CreatedBy,
			}); err != nil {
				return 0, err
			}
			n++
		}
	}
	return n, nil
}

// campaignCovers reports whether a grant held by subject belongs in c. Only the
// subject scope filters on the holder; the others are decided by the loops above.
func campaignCovers(c *store.Campaign, subject string) bool {
	if c.ScopeKind != store.CampaignScopeSubject {
		return true
	}
	return subject == c.ScopeSubject
}

// itemDetail appends the grant's creator to an item's human-readable detail
// when it was recorded, so the reviewer sees who they are attesting for.
func itemDetail(base, grantedBy string) string {
	if grantedBy == "" {
		return base
	}
	return fmt.Sprintf("%s, granted by %s", base, grantedBy)
}

// listCampaigns returns all campaigns (CapReadAudit).
func (s *Server) listCampaigns(w http.ResponseWriter, r *http.Request) {
	cs, err := s.store.ListCampaigns(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cs)
}

// getCampaign returns a campaign with its items (CapReadAudit).
func (s *Server) getCampaign(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	c, err := s.store.GetCampaign(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	items, err := s.store.ListCampaignItems(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"campaign": c, "items": items})
}

type certDecisionIn struct {
	Decision string `json:"decision"` // certify | revoke
}

// decideCampaignItem records a certify/revoke decision (CapManageUsers). A
// "revoke" deletes the underlying access grant/member.
func (s *Server) decideCampaignItem(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	iid, err := strconv.ParseInt(r.PathValue("iid"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid item id")
		return
	}
	var in certDecisionIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.Decision != "certify" && in.Decision != "revoke" {
		writeError(w, http.StatusUnprocessableEntity, `decision must be "certify" or "revoke"`)
		return
	}
	ctx := r.Context()
	c, err := s.store.GetCampaign(ctx, id)
	if err != nil {
		storeError(w, err)
		return
	}
	if c.Status != "open" {
		writeError(w, http.StatusConflict, "campaign is closed")
		return
	}
	item, err := s.store.GetCampaignItem(ctx, iid)
	if err != nil {
		storeError(w, err)
		return
	}
	if item.CampaignID != id {
		writeError(w, http.StatusNotFound, "item not in this campaign")
		return
	}
	// Per-item four-eyes (Phase 46): the principal who granted the access may
	// not CERTIFY it — attesting to your own grant is what an access review
	// exists to prevent. Revoking your own grant is allowed (it reduces
	// access), and an item whose creator was never recorded (pre-migration)
	// cannot be enforced retroactively.
	if in.Decision == "certify" && item.GrantedBy != "" && strings.EqualFold(item.GrantedBy, actorFrom(ctx)) {
		s.audit(ctx, "certification.decision_denied", fmt.Sprintf("campaign:%d item:%d reason:four-eyes granted_by:%s", id, iid, item.GrantedBy))
		writeError(w, http.StatusForbidden, "four-eyes: you cannot certify access you granted yourself")
		return
	}

	if in.Decision == "revoke" {
		if err := s.revokeAccess(ctx, item); err != nil {
			storeError(w, err)
			return
		}
		if err := s.store.DecideCampaignItem(ctx, iid, "revoked", actorFrom(ctx), time.Now()); err != nil {
			storeError(w, err)
			return
		}
		s.audit(ctx, "certification.item_revoked", fmt.Sprintf("campaign:%d item:%d %s:%s %s", id, iid, item.SubjectType, item.Subject, item.Detail))
	} else {
		if err := s.store.DecideCampaignItem(ctx, iid, "certified", actorFrom(ctx), time.Now()); err != nil {
			storeError(w, err)
			return
		}
		s.audit(ctx, "certification.item_certified", fmt.Sprintf("campaign:%d item:%d %s:%s %s", id, iid, item.SubjectType, item.Subject, item.Detail))
	}
	w.WriteHeader(http.StatusNoContent)
}

// revokeAccess deletes the underlying grant an item points at. A grant already
// gone (e.g. deleted since the snapshot) is not an error — the goal state is
// "no access", which already holds.
func (s *Server) revokeAccess(ctx context.Context, item *store.CampaignItem) error {
	// Resolve which targets this item granted access to BEFORE deleting it —
	// afterwards the link is gone and there is nothing left to match sessions
	// against.
	affected := s.targetsGrantedBy(ctx, item)

	var err error
	switch item.Kind {
	case "target_grant":
		err = s.store.DeleteTargetGrant(ctx, item.RefID)
	case "safe_member":
		err = s.store.DeleteSafeMember(ctx, item.RefID)
	default:
		return fmt.Errorf("unknown campaign item kind %q", item.Kind)
	}
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}

	// Cut the revoked user's live sessions to those targets, exactly as
	// DELETE /api/targets/{id}/grants/{gid} does for the same state change.
	//
	// Without this a certification campaign — whose entire purpose is a reviewer
	// deciding someone should no longer have access — removed the grant while
	// leaving the operator connected to the machine, for as long as they cared to
	// stay. The reviewer sees "revoked" and the session continues.
	//
	// Role grants are not matched: the session registry does not carry each
	// session actor's role set, so a role revocation still affects only new
	// connections. That limit is shared with the grant-delete route.
	if item.SubjectType != "user" || s.sessions == nil {
		return nil
	}
	for _, name := range affected {
		killed := s.sessions.KillByActorTarget(item.Subject, name)
		// Unconditional: killed == 0 in HA usually means "hosted elsewhere".
		s.audit(ctx, "session.killed",
			fmt.Sprintf("user:%s target:%s killed_here:%d reason:certification-revoked", item.Subject, name, killed))
	}
	return nil
}

// targetsGrantedBy returns the names of the targets a campaign item's grant
// authorizes, so live sessions can be cut when it is revoked. Best-effort: a
// lookup failure yields no names, which loses the session kill rather than
// blocking the revocation — the grant removal is the part that must not fail.
func (s *Server) targetsGrantedBy(ctx context.Context, item *store.CampaignItem) []string {
	targets, err := s.store.ListTargets(ctx, 0, 0)
	if err != nil {
		return nil
	}
	switch item.Kind {
	case "target_grant":
		for _, t := range targets {
			grants, gerr := s.store.ListTargetGrants(ctx, t.ID)
			if gerr != nil {
				continue
			}
			for _, g := range grants {
				if g.ID == item.RefID {
					return []string{t.Name}
				}
			}
		}
	case "safe_member":
		// A safe membership grants every target scoped to that safe, so all of
		// them lose access at once.
		safes, serr := s.store.ListSafes(ctx, 0, 0)
		if serr != nil {
			return nil
		}
		for _, sf := range safes {
			members, merr := s.store.ListSafeMembers(ctx, sf.ID)
			if merr != nil {
				continue
			}
			for _, mem := range members {
				if mem.ID != item.RefID {
					continue
				}
				var names []string
				for _, t := range targets {
					if t.SafeID != nil && *t.SafeID == sf.ID {
						names = append(names, t.Name)
					}
				}
				return names
			}
		}
	}
	return nil
}

// closeCampaign marks a campaign closed (CapManageUsers).
func (s *Server) closeCampaign(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.store.CloseCampaign(r.Context(), id, time.Now()); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "certification.campaign_closed", fmt.Sprintf("campaign:%d", id))
	w.WriteHeader(http.StatusNoContent)
}
