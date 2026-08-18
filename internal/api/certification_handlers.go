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
	// Reviewer is stamped onto every item this campaign snapshots (Phase 69).
	Reviewer string `json:"reviewer,omitempty"`
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
	if !checkName(w, "name", in.Name) {
		return
	}
	ctx := r.Context()
	if !checkOptionalName(w, "reviewer", strings.TrimSpace(in.Reviewer)) {
		return
	}
	c := store.Campaign{
		Name: in.Name, CreatedBy: actorFrom(ctx), DueAt: in.DueAt, Status: "open",
		ScopeKind: in.ScopeKind, ScopeSafeID: in.ScopeSafeID, ScopeSubject: in.ScopeSubject,
		RecurDays: in.RecurDays, Reviewer: strings.TrimSpace(in.Reviewer),
	}
	if !s.validateCampaignScope(w, ctx, &c) {
		return
	}
	if c.RecurDays > 0 {
		next := time.Now().UTC().AddDate(0, 0, c.RecurDays)
		c.NextRunAt = &next
	}
	c.RemindAt = s.firstReminder(c.DueAt, time.Now())
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
		fmt.Sprintf("campaign:%d name:%s items:%d %s", c.ID, auditField(c.Name, 128), items, campaignScopeDetail(&c)))
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
	if c.Reviewer != "" {
		scope += " reviewer:" + auditField(c.Reviewer, 128)
	}
	return scope
}

// firstReminder is when a campaign should first nudge its reviewers: remindDays
// before it is due. Nil — no reminder — when reminders are switched off, or when
// the campaign has no due date, since there is nothing to be early for.
//
// A campaign created with a due date already inside the window (or past it)
// reminds on the NEXT tick rather than being skipped: "you gave me two days" is
// exactly when a nudge is worth most, and silently declining to remind because
// the ideal moment had passed would be the failure this exists to prevent.
func (s *Server) firstReminder(due *time.Time, now time.Time) *time.Time {
	if s.certRemindDays <= 0 || due == nil {
		return nil
	}
	at := due.AddDate(0, 0, -s.certRemindDays)
	if at.Before(now) {
		at = now
	}
	return &at
}

type reviewerIn struct {
	Reviewer string `json:"reviewer"`
}

// assignCampaignItem reassigns one item's reviewer (CapManageUsers), or
// unassigns it with an empty value.
//
// Assignment is ADVISORY — it routes work and makes a queue visible; it is not
// an authorization gate, and anyone holding `approve` can still decide any item.
// Making it binding would add a deadlock (the assigned reviewer leaves and the
// campaign cannot be closed) without adding evidence, because the trail already
// records who actually decided. Say it plainly here so nobody reads the field as
// a control it is not.
func (s *Server) assignCampaignItem(w http.ResponseWriter, r *http.Request) {
	cid, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "campaign id must be numeric")
		return
	}
	itemID, err := strconv.ParseInt(r.PathValue("itemID"), 10, 64)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "item id must be numeric")
		return
	}
	var in reviewerIn
	if !readJSON(w, r, &in) {
		return
	}
	ctx := r.Context()
	// Scoped to the campaign in the path, like every other child-resource route:
	// an item id alone must never let one campaign's route touch another's item.
	item, err := s.store.GetCampaignItem(ctx, itemID)
	if err != nil || item.CampaignID != cid {
		writeError(w, http.StatusNotFound, "no such item in this campaign")
		return
	}
	// Empty is meaningful here — it unassigns — so the optional form.
	reviewer := strings.TrimSpace(in.Reviewer)
	if !checkOptionalName(w, "reviewer", reviewer) {
		return
	}
	if err := s.store.SetCampaignItemReviewer(ctx, itemID, reviewer); err != nil {
		storeError(w, err)
		return
	}
	who := reviewer
	if who == "" {
		who = "(unassigned)"
	}
	s.audit(ctx, "certification.item_assigned",
		fmt.Sprintf("campaign:%d item:%d reviewer:%s", cid, itemID, auditField(who, 128)))
	writeJSON(w, http.StatusOK, map[string]any{"item": itemID, "reviewer": reviewer})
}

// myReviewQueue returns the caller's pending items across every open campaign —
// "what is waiting on me". Gated on CapApprove, the capability that can act on
// the answer; an auditor reads campaigns through the campaign endpoints.
func (s *Server) myReviewQueue(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListItemsForReviewer(r.Context(), actorFrom(r.Context()))
	if err != nil {
		storeError(w, err)
		return
	}
	if items == nil {
		items = []store.CampaignItem{}
	}
	writeJSON(w, http.StatusOK, items)
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
				GrantedBy: g.CreatedBy, Reviewer: c.Reviewer,
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
				GrantedBy: mem.CreatedBy, Reviewer: c.Reviewer,
			}); err != nil {
				return 0, err
			}
			n++
		}
	}
	// Non-human identities are reviewed too (Phase 175). A campaign snapshotted
	// only target grants and safe membership, so the AI-agent identities — which
	// hold brokered access to the same estate — were never certified by anyone,
	// and the one place they did surface (a grant naming an agent) was filed
	// under subject type "user", reviewed as though it were a person.
	//
	// Safe-scoped campaigns skip them: an agent identity is not a member of a
	// safe, and padding a safe review with unrelated rows is the "list you were
	// not asked to review" failure this function's own header warns about.
	if c.ScopeKind == store.CampaignScopeSafe {
		return n, nil
	}
	agents, err := s.snapshotAgents(ctx, c)
	if err != nil {
		return 0, err
	}
	return n + agents, nil
}

// snapshotAgents adds one campaign item per AI-agent identity, of both kinds:
// the static keys pamv1 issued and the SPIFFE identities it has seen or
// enrolled. The reviewer's question is the one nobody was being asked — "should
// this non-human identity still exist, and is the human named beside it really
// the one accountable for it?" — so the detail carries the owner, the state and
// the dormancy signal that make it answerable.
func (s *Server) snapshotAgents(ctx context.Context, c *store.Campaign) (int, error) {
	known := s.knownUsernames(ctx)
	n := 0
	keys, err := s.store.ListAgentKeys(ctx)
	if err != nil {
		return 0, err
	}
	for _, k := range keys {
		if !campaignCovers(c, k.Name) {
			continue
		}
		detail := fmt.Sprintf("AI-agent key, %s, last used %s", agentKeyState(k), stampOrNever(k.LastUsedAt))
		if !ownerIsKnown(known, k.Owner) {
			detail += ownerUnknownNote
		}
		if err := s.store.AddCampaignItem(ctx, &store.CampaignItem{
			CampaignID: c.ID, Kind: "agent_key", RefID: k.ID,
			SubjectType: "agent", Subject: k.Name,
			Detail: itemDetail(detail, k.Owner), GrantedBy: k.Owner, Reviewer: c.Reviewer,
		}); err != nil {
			return 0, err
		}
		n++
	}
	ids, err := s.store.ListAgentIdentities(ctx)
	if err != nil {
		return 0, err
	}
	for _, a := range ids {
		if !campaignCovers(c, a.SPIFFEID) {
			continue
		}
		state := "enrolled"
		if !a.Enrolled {
			state = "SEEN, never claimed"
		}
		detail := fmt.Sprintf("SPIFFE agent identity, %s, last seen %s", state, stampOrNever(a.LastSeen))
		if a.Attributed() && !ownerIsKnown(known, a.Owner) {
			detail += ownerUnknownNote
		}
		if err := s.store.AddCampaignItem(ctx, &store.CampaignItem{
			CampaignID: c.ID, Kind: "agent_identity", RefID: a.ID,
			SubjectType: "agent", Subject: a.SPIFFEID,
			Detail: itemDetail(detail, a.Owner), GrantedBy: a.Owner, Reviewer: c.Reviewer,
		}); err != nil {
			return 0, err
		}
		n++
	}
	return n, nil
}

// ownerUnknownNote is appended to an item whose owner matches no pamv1 user —
// the state in which offboarding can never reach this agent.
const ownerUnknownNote = " — WARNING: owner is not a pamv1 user, so offboarding cannot reach this agent"

// agentKeyState renders a key's lifecycle for a reviewer in three words.
func agentKeyState(k store.AgentKey) string {
	switch {
	case k.Disabled:
		return "suspended"
	case !k.Active(time.Now()):
		return "expired"
	default:
		return "active"
	}
}

// stampOrNever renders an optional timestamp for a reviewer.
func stampOrNever(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
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
	case "agent_key", "agent_identity":
		// Revoking a non-human identity STOPS it; it never deletes it (Phase
		// 175, following 159's stance). A reviewer's "this should not exist" is
		// a containment decision, and the row is the evidence an investigation
		// needs afterwards — so a static key is suspended and an attested
		// identity is quarantined, both reversible, both loudly audited, and
		// both using the control that already exists for that identity kind.
		return s.revokeAgentIdentity(ctx, item)
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

// revokeAgentIdentity applies a reviewer's revocation to an AI-agent identity:
// suspend the static key, quarantine the attested subject. Neither deletes.
//
// An identity already stopped is success, not an error: the goal state is "this
// cannot act", which already holds — the same reasoning the grant path uses for
// a grant that is already gone. For quarantine that means ErrConflict (the
// subject is already on the list) is swallowed deliberately, and the existing
// entry, with whoever imposed it and why, is left untouched rather than
// overwritten by this one.
func (s *Server) revokeAgentIdentity(ctx context.Context, item *store.CampaignItem) error {
	if item.Kind == "agent_key" {
		if err := s.store.SetAgentKeyDisabled(ctx, item.RefID, true); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil
			}
			return err
		}
		s.audit(ctx, "agent.disable",
			fmt.Sprintf("agent:%d subject:%s reason:certification-revoked", item.RefID, auditField(item.Subject, 200)))
		return nil
	}
	q := store.AgentQuarantine{
		Subject:   item.Subject,
		Reason:    "certification revoked",
		CreatedBy: actorFrom(ctx),
	}
	switch err := s.store.QuarantineAgent(ctx, &q); {
	case err == nil:
		s.audit(ctx, "agent.quarantine",
			fmt.Sprintf("subject:%s reason:certification-revoked", auditField(item.Subject, maxSPIFFEIDLen)))
		return nil
	case errors.Is(err, store.ErrConflict):
		return nil // already stopped
	default:
		return err
	}
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
