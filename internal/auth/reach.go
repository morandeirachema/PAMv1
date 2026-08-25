package auth

import (
	"context"
	"errors"
	"sort"

	"github.com/morandeirachema/pamv1/internal/store"
)

// Why a principal reaches a target. The first two are principal-level bypasses
// (nothing about the target grants them), the third is a property of the target
// alone, and the last two are actual grants — the store's own vocabulary
// (store.GrantViaGrant / store.GrantViaSafe), kept identical so a reason read
// out of a Reach means the same thing as one read out of a SubjectGrant.
const (
	// ReachViaAdmin is the built-in admin bypass: an admin reaches every target
	// that is not in a personal safe, grants or no grants.
	ReachViaAdmin = "admin"
	// ReachViaUnlimited is CapUnlimitedVaultAccess, the named override for a
	// target in a personal safe (Phase 139).
	ReachViaUnlimited = "unlimited_vault_access"
	// ReachViaOpen is a target nothing gates: no direct grants, no safe
	// membership, so any connect-capable principal reaches it. This is an
	// estate-wide default, not a decision anyone made about this subject.
	ReachViaOpen = "open"
	// ReachViaGrant is a direct target grant naming the subject or a role it holds.
	ReachViaGrant = store.GrantViaGrant
	// ReachViaSafe is membership of the safe the target sits in.
	ReachViaSafe = store.GrantViaSafe
)

// ReachStore is the slice of the store ReachableTargets needs: the inventory,
// the safes (for the personal flag), the subject-indexed grant query and the
// set of targets anything gates at all.
type ReachStore interface {
	ListTargets(ctx context.Context, limit int, afterID int64) ([]store.Target, error)
	ListSafes(ctx context.Context, limit int, afterID int64) ([]store.Safe, error)
	GrantsForSubjects(ctx context.Context, subjects []store.GrantSubject) ([]store.SubjectGrant, error)
	GatedTargetIDs(ctx context.Context) ([]int64, error)
}

// Reach is one target a principal may reach and the reason it may. Subject and
// SubjectType are the grant that admitted it (empty on the three non-grant
// reasons); SafeID names the safe a ReachViaSafe row came through.
type Reach struct {
	Target      store.Target `json:"target"`
	Via         string       `json:"via"`
	SubjectType string       `json:"subject_type,omitempty"` // user | role
	Subject     string       `json:"subject,omitempty"`
	SafeID      *int64       `json:"safe_id,omitempty"`
	// SafeName is the name of the SafeID safe, filled in from the same read
	// that resolves the personal flags. An id is not an answer to a person, and
	// the safes are already in hand — a caller that had to map ids to names
	// itself would read the whole safes table a second time, which is what the
	// API did before this field existed.
	SafeName string `json:"safe_name,omitempty"`
}

// GrantSubjects lists every identifier a grant may name this principal by: its
// own name as a "user" subject, and each role it holds as a "role" subject.
// It is the exact set SubjectMatches compares against, expressed as data so it
// can be handed to a store query — if the two ever disagree, the subject-indexed
// answer stops matching the connect-time decision, which is the one drift this
// whole path has to avoid.
func GrantSubjects(p *Principal) []store.GrantSubject {
	if p == nil {
		return nil
	}
	roles := p.effectiveRoles()
	out := make([]store.GrantSubject, 0, len(roles)+1)
	out = append(out, store.GrantSubject{Type: "user", Name: p.Name})
	for _, r := range roles {
		out = append(out, store.GrantSubject{Type: "role", Name: string(r)})
	}
	return out
}

// ReachableTargets answers "what can this subject reach?" for the whole estate
// in four reads, regardless of how many targets there are.
//
// It is the subject-indexed twin of the connect-time decision, and it is
// deliberately built out of the same pieces rather than re-deciding anything:
// for every target it reproduces CanConnectTarget's answer exactly — admin
// bypass (or CapUnlimitedVaultAccess on a personal safe) first, then an ungated
// target outside a safe as open, then the grants that name the subject — and
// additionally reports WHICH of those reasons applied, which is what turns a
// yes/no gate into something a person can review. TestReachMatchesCanConnect
// pins the equivalence against the naive per-target loop.
//
// The naive loop is what the broker did before (two store reads per target, in
// a listing an agent makes on every run) because no subject-indexed query
// existed; store.GrantsForSubjects is that query, and this is its one consumer
// of record. Results keep the store's target order (id-ascending).
//
// A target in a safe that has been deleted underneath it is treated as
// personal — i.e. closed to a plain admin — matching store.EffectiveSafePersonal,
// which fails closed the same way when it cannot read the safe.
func ReachableTargets(ctx context.Context, st ReachStore, p *Principal) ([]Reach, error) {
	if st == nil || p == nil {
		return nil, errors.New("auth: reach needs a store and a principal")
	}
	targets, err := st.ListTargets(ctx, 0, 0)
	if err != nil {
		return nil, err
	}
	safes, err := st.ListSafes(ctx, 0, 0)
	if err != nil {
		return nil, err
	}
	personal := make(map[int64]bool, len(safes))
	safeName := make(map[int64]string, len(safes))
	for _, sf := range safes {
		personal[sf.ID] = sf.Personal
		safeName[sf.ID] = sf.Name
	}
	// ORDER MATTERS between these two reads, and it is the fail-closed direction
	// that decides it. They are not one transaction, so a grant written between
	// them is seen by one and not the other. Reading the subject's grants FIRST
	// means a grant created in the window makes the target appear gated with no
	// matching row — the target drops out, which under-reports for one query.
	// Reading the gated set first would mean the opposite: the target is still
	// "ungated" from the older snapshot and gets reported as OPEN, i.e. reachable
	// by anyone, at the exact moment somebody restricted it. Since this same path
	// decides which targets the broker names to an agent, the direction that
	// briefly hides a target beats the one that briefly advertises it.
	//
	// The deletion window resolves correctly either way in this order: grants
	// read first still holds the row, the gated set no longer does, and an
	// ungated target IS open — which is exactly what gets reported.
	grants, err := st.GrantsForSubjects(ctx, GrantSubjects(p))
	if err != nil {
		return nil, err
	}
	gatedIDs, err := st.GatedTargetIDs(ctx)
	if err != nil {
		return nil, err
	}
	gated := make(map[int64]struct{}, len(gatedIDs))
	for _, id := range gatedIDs {
		gated[id] = struct{}{}
	}
	byTarget := make(map[int64][]store.SubjectGrant, len(grants))
	for _, g := range grants {
		byTarget[g.TargetID] = append(byTarget[g.TargetID], g)
	}
	isAdmin := false
	for _, r := range p.effectiveRoles() {
		if r == RoleAdmin {
			isAdmin = true
			break
		}
	}
	out := make([]Reach, 0, len(targets))
	for i := range targets {
		t := targets[i]
		inPersonalSafe := false
		if t.SafeID != nil {
			sfPersonal, known := personal[*t.SafeID]
			inPersonalSafe = sfPersonal || !known
		}
		switch {
		case !inPersonalSafe && isAdmin:
			out = append(out, Reach{Target: t, Via: ReachViaAdmin})
			continue
		case inPersonalSafe && p.Can(CapUnlimitedVaultAccess):
			out = append(out, Reach{Target: t, Via: ReachViaUnlimited})
			continue
		}
		if _, ok := gated[t.ID]; !ok {
			// Ungated ⇒ open; safe-scoped-but-no-members ⇒ closed (containment),
			// exactly as CanConnectTarget reads it.
			if t.SafeID == nil {
				out = append(out, Reach{Target: t, Via: ReachViaOpen})
			}
			continue
		}
		if match, ok := bestGrant(byTarget[t.ID]); ok {
			rc := Reach{
				Target: t, Via: match.Via, SubjectType: match.SubjectType,
				Subject: match.Subject, SafeID: match.SafeID,
			}
			if match.SafeID != nil {
				rc.SafeName = safeName[*match.SafeID]
			}
			out = append(out, rc)
		}
	}
	return out, nil
}

// bestGrant picks the one grant to report when several admit the same target.
// A direct grant beats safe membership, and within a path a grant naming the
// subject by name beats one naming a role it happens to hold: the more specific
// the row, the more it says about a decision someone actually made about this
// subject. All of them admit; the review shows the sharpest reason.
func bestGrant(gs []store.SubjectGrant) (store.SubjectGrant, bool) {
	if len(gs) == 0 {
		return store.SubjectGrant{}, false
	}
	rank := func(g store.SubjectGrant) int {
		n := 0
		if g.Via != store.GrantViaGrant {
			n += 2
		}
		if g.SubjectType != "user" {
			n++
		}
		return n
	}
	best := 0
	for i := 1; i < len(gs); i++ {
		if rank(gs[i]) < rank(gs[best]) {
			best = i
		}
	}
	return gs[best], true
}

// CanUseAnyTarget reports whether p holds any capability that can actually DO
// something with a target: open a session, reveal its credential, or call a
// brokered tool against it.
//
// It exists because ReachableTargets deliberately reproduces CanConnectTarget,
// and CanConnectTarget does not consider capabilities at all — every call site
// checks CapConnect separately, at the door (the API's authz middleware, the
// proxy's admit sequence). Read on its own, then, the reach answer says an
// auditor "reaches" every ungated target, and the console prints those rows in
// red as a finding. They are not a finding: an auditor holds read_inventory and
// read_audit and can never open a session, reveal a secret or call a tool. The
// grant model really does admit those targets, so the rows are not wrong — what
// is missing is that nothing downstream of the grant model would let this
// subject use them. A reviewer needs both halves.
func CanUseAnyTarget(p *Principal) bool {
	if p == nil {
		return false
	}
	return p.Can(CapConnect) || p.Can(CapRevealSecret) || p.Can(CapCallTool)
}

// ReachSubjectCounts summarises a reach listing by reason, for a console or an
// API caller that wants the shape of an answer before its detail ("reaches 40
// targets: 3 granted, 37 because nothing gates them" is a different finding
// from 40 deliberate grants). Keys are the ReachVia* constants.
func ReachSubjectCounts(rs []Reach) map[string]int {
	out := make(map[string]int, 5)
	for _, r := range rs {
		out[r.Via]++
	}
	return out
}

// SortReachByName orders a reach listing by target name, the order a person
// reads. The store's own order is by id (creation order), which is what
// ReachableTargets returns.
func SortReachByName(rs []Reach) {
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].Target.Name < rs[j].Target.Name })
}
