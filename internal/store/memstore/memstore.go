// Package memstore is an in-memory store.Store used by tests and the
// "memory" demo mode. Data is lost on restart; production runs on pgstore.
package memstore

import (
	"bytes"
	"context"
	"crypto/hmac"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
)

type Memstore struct {
	mu              sync.Mutex
	nextID          int64
	targets         map[int64]store.Target
	creds           map[int64]store.Credential
	users           map[int64]store.User
	sessions        map[int64]store.Session
	mfa             map[string]store.MFAEnrollment
	recovery        map[string]map[string]bool // username -> set of code hashes
	grants          map[int64]store.TargetGrant
	accessReq       map[int64]store.AccessRequest
	checkouts       map[int64]store.Checkout
	oidcStates      map[string]oidcState
	audit           []store.AuditEvent
	auditKey        []byte // set ⇒ chain the primary audit trail
	agentKeys       map[int64]store.AgentKey
	agentQuarantine map[int64]store.AgentQuarantine
	agentIdentities map[int64]store.AgentIdentity
	// callReservations is the compare-and-spend ledger behind the agent budget
	// and the per-token ceiling (Phase 219), keyed by reservation id.
	callReservations map[int64]store.AgentCallReservation
	sshCerts         map[int64]store.SSHCert
	vendors          map[int64]store.Vendor
	vendorGrants     map[int64]store.VendorGrant
	appKeys          map[int64]store.AppKey
	appGrants        map[int64]store.AppSecretGrant
	scimKeys         map[int64]store.ScimKey
	endpointAgents   map[int64]store.EndpointAgent
	brokerLog        []store.BrokerAuditEvent
	brokerTok        map[string]store.BrokerToken
	settings         map[string]store.Setting
	keyMaterial      map[string]string
	profiles         map[int64]store.Profile
	safes            map[int64]store.Safe
	safeMembers      map[int64]store.SafeMember
	credDeps         map[int64]store.CredentialDependency
	campaigns        map[int64]store.Campaign
	campaignItems    map[int64]store.CampaignItem
	shareInvites     map[int64]store.SessionShareInvite
	approvalInvites  map[int64]store.ApprovalInvite
	pwHistory        map[int64][]pwHistoryEntry // credentialID -> hashes, oldest first
	webauthnCreds    map[int64]store.WebAuthnCredential
	webauthnChal     map[webauthnChalKey]webauthnChallenge

	killMu   sync.Mutex
	killSubs map[chan session.KillSelector]struct{} // cross-replica kill fan-out

	liveMu       sync.Mutex
	liveSessions map[string]liveRow                  // shared live-session inventory
	frameSubs    map[chan session.LiveFrame]struct{} // live-output fan-out
	interestSubs map[chan string]struct{}            // watch-interest fan-out

	stepupMu   sync.Mutex
	stepups    map[string]stepUpRow                     // shared pending step-up inventory
	stepupSubs map[chan session.StepUpDecision]struct{} // decision fan-out
}

// New returns an empty in-memory store ready for use.
func New() *Memstore {
	return &Memstore{
		targets:          make(map[int64]store.Target),
		creds:            make(map[int64]store.Credential),
		users:            make(map[int64]store.User),
		sessions:         make(map[int64]store.Session),
		mfa:              make(map[string]store.MFAEnrollment),
		recovery:         make(map[string]map[string]bool),
		webauthnCreds:    make(map[int64]store.WebAuthnCredential),
		webauthnChal:     make(map[webauthnChalKey]webauthnChallenge),
		grants:           make(map[int64]store.TargetGrant),
		accessReq:        make(map[int64]store.AccessRequest),
		checkouts:        make(map[int64]store.Checkout),
		agentKeys:        make(map[int64]store.AgentKey),
		agentQuarantine:  make(map[int64]store.AgentQuarantine),
		agentIdentities:  make(map[int64]store.AgentIdentity),
		callReservations: make(map[int64]store.AgentCallReservation),
		sshCerts:         make(map[int64]store.SSHCert),
		vendors:          make(map[int64]store.Vendor),
		vendorGrants:     make(map[int64]store.VendorGrant),
		appKeys:          make(map[int64]store.AppKey),
		appGrants:        make(map[int64]store.AppSecretGrant),
		scimKeys:         make(map[int64]store.ScimKey),
		endpointAgents:   make(map[int64]store.EndpointAgent),
		brokerTok:        make(map[string]store.BrokerToken),
		settings:         make(map[string]store.Setting),
		keyMaterial:      make(map[string]string),
		profiles:         make(map[int64]store.Profile),
		safes:            make(map[int64]store.Safe),
		safeMembers:      make(map[int64]store.SafeMember),
		credDeps:         make(map[int64]store.CredentialDependency),
		campaigns:        make(map[int64]store.Campaign),
		campaignItems:    make(map[int64]store.CampaignItem),
		shareInvites:     make(map[int64]store.SessionShareInvite),
		approvalInvites:  make(map[int64]store.ApprovalInvite),
		pwHistory:        make(map[int64][]pwHistoryEntry),
		killSubs:         make(map[chan session.KillSelector]struct{}),
		liveSessions:     make(map[string]liveRow),
		frameSubs:        make(map[chan session.LiveFrame]struct{}),
		interestSubs:     make(map[chan string]struct{}),
		stepups:          make(map[string]stepUpRow),
		stepupSubs:       make(map[chan session.StepUpDecision]struct{}),
	}
}

// cloneProfile deep-copies a profile so callers can't mutate the stored slice.
func cloneProfile(p store.Profile) store.Profile {
	p.Capabilities = append([]string(nil), p.Capabilities...)
	return p
}

// id returns the next monotonically increasing identity; the caller holds the lock.
func (m *Memstore) id() int64 {
	m.nextID++
	return m.nextID
}

// window applies the shared list-cursor semantics to an id-ascending slice:
// rows with id > afterID, capped at limit rows when limit > 0 (Phase 44).
// getRow is the shared body of every by-id lookup that returns a copy of the
// stored value or ErrNotFound. It takes the receiver so it can hold the one
// mutex (Go does not allow type parameters on methods). Returning &v yields a
// pointer to a fresh copy, never into the map, so a caller cannot mutate stored
// state — the same guarantee each hand-written Get gave.
func getRow[K comparable, V any](m *Memstore, rows map[K]V, k K) (*V, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := rows[k]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &v, nil
}

// deleteRow is the shared body of every non-cascading delete: ErrNotFound if the
// key is absent, otherwise remove it. Cascading deletes keep their own bodies —
// this covers only the leaf rows.
func deleteRow[K comparable, V any](m *Memstore, rows map[K]V, k K) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := rows[k]; !ok {
		return store.ErrNotFound
	}
	delete(rows, k)
	return nil
}

func window[T any](rows []T, id func(T) int64, limit int, afterID int64) []T {
	if afterID > 0 {
		i := sort.Search(len(rows), func(i int) bool { return id(rows[i]) > afterID })
		rows = rows[i:]
	}
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

// CreateTarget inserts a target, assigning its ID and CreatedAt; ErrConflict if the name is taken.
func (m *Memstore) CreateTarget(_ context.Context, t *store.Target) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.targets {
		if existing.Name == t.Name {
			return store.ErrConflict
		}
	}
	t.ID = m.id()
	t.CreatedAt = time.Now().UTC()
	m.targets[t.ID] = *t
	return nil
}

// ListTargets returns targets in the (limit, afterID) window, ordered by ID.
func (m *Memstore) ListTargets(_ context.Context, limit int, afterID int64) ([]store.Target, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.Target, 0, len(m.targets))
	for _, t := range m.targets {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return window(out, func(t store.Target) int64 { return t.ID }, limit, afterID), nil
}

// GetTarget returns the target with the given ID, or ErrNotFound.
func (m *Memstore) GetTarget(_ context.Context, id int64) (*store.Target, error) {
	return getRow(m, m.targets, id)
}

// UpdateTarget replaces a target's editable fields, preserving its safe
// assignment and creation time; ErrNotFound if absent, ErrConflict if the new
// name belongs to another target.
func (m *Memstore) UpdateTarget(_ context.Context, t *store.Target) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.targets[t.ID]
	if !ok {
		return store.ErrNotFound
	}
	for id, ex := range m.targets {
		if id != t.ID && ex.Name == t.Name {
			return store.ErrConflict
		}
	}
	t.SafeID = cur.SafeID
	t.CreatedAt = cur.CreatedAt
	m.targets[t.ID] = *t
	return nil
}

// DeleteTarget removes a target and cascades to its credentials, grants, and
// access requests; ErrNotFound if the target is absent.
func (m *Memstore) DeleteTarget(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.targets[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.targets, id)
	for cid, c := range m.creds {
		if c.TargetID == id {
			delete(m.creds, cid)
		}
	}
	for gid, g := range m.grants {
		if g.TargetID == id {
			delete(m.grants, gid)
		}
	}
	for aid, ar := range m.accessReq {
		if ar.TargetID == id {
			delete(m.accessReq, aid)
			// approval_invites.access_request_id cascades in pgstore (Phase 137) — match it.
			for iid, inv := range m.approvalInvites {
				if inv.AccessRequestID == aid {
					delete(m.approvalInvites, iid)
				}
			}
		}
	}
	// endpoint_agents.target_id cascades in pgstore (Phase 153) — match it.
	for eid, ea := range m.endpointAgents {
		if ea.TargetID == id {
			delete(m.endpointAgents, eid)
		}
	}
	// pgstore FKs cascade checkouts on target delete — match it so an orphaned
	// active lease can't survive only in the demo store.
	for coid, co := range m.checkouts {
		if co.TargetID == id {
			delete(m.checkouts, coid)
		}
	}
	return nil
}

// CreateTargetGrant adds a grant for an existing target; ErrNotFound if the
// target is missing, ErrConflict if an identical grant already exists.
func (m *Memstore) CreateTargetGrant(_ context.Context, g *store.TargetGrant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.targets[g.TargetID]; !ok {
		return store.ErrNotFound
	}
	for _, ex := range m.grants {
		if ex.TargetID == g.TargetID && ex.SubjectType == g.SubjectType && ex.Subject == g.Subject {
			return store.ErrConflict
		}
	}
	g.ID = m.id()
	m.grants[g.ID] = *g
	return nil
}

// ListTargetGrants returns the grants for a target, ordered by ID.
func (m *Memstore) ListTargetGrants(_ context.Context, targetID int64) ([]store.TargetGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.TargetGrant, 0)
	for _, g := range m.grants {
		if g.TargetID == targetID {
			out = append(out, g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// DeleteTargetGrant removes a grant by ID; ErrNotFound if absent.
func (m *Memstore) DeleteTargetGrant(_ context.Context, id int64) error {
	return deleteRow(m, m.grants, id)
}

// EffectiveTargetGrants unions a target's direct grants with grants derived from
// its safe's membership (Phase 17).
func (m *Memstore) EffectiveTargetGrants(_ context.Context, targetID int64) ([]store.TargetGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.TargetGrant, 0)
	for _, g := range m.grants {
		if g.TargetID == targetID {
			out = append(out, g)
		}
	}
	if t, ok := m.targets[targetID]; ok && t.SafeID != nil {
		for _, sm := range m.safeMembers {
			if sm.SafeID == *t.SafeID {
				out = append(out, store.TargetGrant{ID: sm.ID, TargetID: targetID, SubjectType: sm.SubjectType, Subject: sm.Subject})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// GrantsForSubjects returns every grant naming any of the given subjects, from
// both paths (direct grants and safe membership), ordered by target id, then by
// path (grant before safe), then by subject — a SubjectGrant carries no grant id
// to order by. See store.GrantStore for why the question is asked this way round.
func (m *Memstore) GrantsForSubjects(_ context.Context, subjects []store.GrantSubject) ([]store.SubjectGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.grantsForSubjectsLocked(subjects), nil
}

// grantsForSubjectsLocked is GrantsForSubjects' body. The caller holds m.mu, so
// ReachGrantSnapshot can take both answers without releasing it in between.
func (m *Memstore) grantsForSubjectsLocked(subjects []store.GrantSubject) []store.SubjectGrant {
	want := make(map[store.GrantSubject]struct{}, len(subjects))
	for _, sub := range subjects {
		want[sub] = struct{}{}
	}
	out := make([]store.SubjectGrant, 0)
	if len(want) == 0 {
		return out
	}
	named := func(subjectType, subject string) bool {
		_, ok := want[store.GrantSubject{Type: subjectType, Name: subject}]
		return ok
	}
	for _, g := range m.grants {
		if !named(g.SubjectType, g.Subject) {
			continue
		}
		t, ok := m.targets[g.TargetID]
		if !ok {
			continue // a grant whose target is gone reaches nothing
		}
		out = append(out, store.SubjectGrant{
			TargetID: g.TargetID, TargetName: t.Name, SubjectType: g.SubjectType,
			Subject: g.Subject, Via: store.GrantViaGrant,
		})
	}
	for _, sm := range m.safeMembers {
		if !named(sm.SubjectType, sm.Subject) {
			continue
		}
		for _, t := range m.targets {
			if t.SafeID == nil || *t.SafeID != sm.SafeID {
				continue
			}
			safeID := sm.SafeID
			out = append(out, store.SubjectGrant{
				TargetID: t.ID, TargetName: t.Name, SubjectType: sm.SubjectType,
				Subject: sm.Subject, Via: store.GrantViaSafe, SafeID: &safeID,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TargetID != out[j].TargetID {
			return out[i].TargetID < out[j].TargetID
		}
		if out[i].Via != out[j].Via {
			return out[i].Via < out[j].Via
		}
		return out[i].Subject < out[j].Subject
	})
	return out
}

// GatedTargetIDs returns the ids of targets holding at least one effective
// grant, ascending — the targets that are NOT open to every connect-capable
// principal.
func (m *Memstore) GatedTargetIDs(_ context.Context) ([]int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.gatedTargetIDsLocked(), nil
}

// gatedTargetIDsLocked is GatedTargetIDs' body, for the same reason.
func (m *Memstore) gatedTargetIDsLocked() []int64 {
	gated := make(map[int64]struct{})
	for _, g := range m.grants {
		if _, ok := m.targets[g.TargetID]; ok {
			gated[g.TargetID] = struct{}{}
		}
	}
	withMembers := make(map[int64]struct{}, len(m.safeMembers))
	for _, sm := range m.safeMembers {
		withMembers[sm.SafeID] = struct{}{}
	}
	for _, t := range m.targets {
		if t.SafeID == nil {
			continue
		}
		if _, ok := withMembers[*t.SafeID]; ok {
			gated[t.ID] = struct{}{}
		}
	}
	out := make([]int64, 0, len(gated))
	for id := range gated {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ReachGrantSnapshot takes both grant answers under ONE hold of m.mu, so no
// writer can land between them. It is the in-memory twin of pgstore's read-only
// REPEATABLE READ transaction — see store.GrantStore for why the pair has to be
// consistent with each other rather than merely correct one at a time.
func (m *Memstore) ReachGrantSnapshot(_ context.Context, subjects []store.GrantSubject) ([]store.SubjectGrant, []int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.grantsForSubjectsLocked(subjects), m.gatedTargetIDsLocked(), nil
}

// CreateSafe inserts a safe, assigning ID and CreatedAt.
func (m *Memstore) CreateSafe(_ context.Context, sf *store.Safe) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ex := range m.safes {
		if ex.Name == sf.Name {
			return store.ErrConflict
		}
	}
	sf.ID = m.id()
	sf.CreatedAt = time.Now().UTC()
	m.safes[sf.ID] = *sf
	return nil
}

// ListSafes returns safes in the (limit, afterID) window, ordered by ID
// (creation order — the stable order a cursor needs).
func (m *Memstore) ListSafes(_ context.Context, limit int, afterID int64) ([]store.Safe, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.Safe, 0, len(m.safes))
	for _, sf := range m.safes {
		out = append(out, sf)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return window(out, func(sf store.Safe) int64 { return sf.ID }, limit, afterID), nil
}

// UpdateSafe replaces a safe's name, description and approval policy;
// ErrNotFound if absent, ErrConflict if the new name belongs to another
// safe. Personal is carried forward from the existing row, never from the
// caller's struct — see store.Safe.Personal and PGStore.UpdateSafe's
// matching comment.
func (m *Memstore) UpdateSafe(_ context.Context, sf *store.Safe) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.safes[sf.ID]
	if !ok {
		return store.ErrNotFound
	}
	for id, ex := range m.safes {
		if id != sf.ID && ex.Name == sf.Name {
			return store.ErrConflict
		}
	}
	sf.CreatedAt = cur.CreatedAt
	sf.Personal = cur.Personal
	m.safes[sf.ID] = *sf
	return nil
}

// GetSafe returns a safe by ID, or ErrNotFound.
func (m *Memstore) GetSafe(_ context.Context, id int64) (*store.Safe, error) {
	return getRow(m, m.safes, id)
}

// DeleteSafe removes a safe, cascading its members and unassigning its targets.
func (m *Memstore) DeleteSafe(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.safes[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.safes, id)
	for mid, sm := range m.safeMembers {
		if sm.SafeID == id {
			delete(m.safeMembers, mid)
		}
	}
	for tid, t := range m.targets {
		if t.SafeID != nil && *t.SafeID == id {
			t.SafeID = nil
			m.targets[tid] = t
		}
	}
	return nil
}

// AddSafeMember adds a member to a safe.
func (m *Memstore) AddSafeMember(_ context.Context, mem *store.SafeMember) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.safes[mem.SafeID]; !ok {
		return store.ErrNotFound
	}
	for _, ex := range m.safeMembers {
		if ex.SafeID == mem.SafeID && ex.SubjectType == mem.SubjectType && ex.Subject == mem.Subject {
			return store.ErrConflict
		}
	}
	mem.ID = m.id()
	m.safeMembers[mem.ID] = *mem
	return nil
}

// ListSafeMembers returns a safe's members ordered by id.
func (m *Memstore) ListSafeMembers(_ context.Context, safeID int64) ([]store.SafeMember, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.SafeMember, 0)
	for _, sm := range m.safeMembers {
		if sm.SafeID == safeID {
			out = append(out, sm)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// DeleteSafeMember removes a safe member by ID, or ErrNotFound.
func (m *Memstore) DeleteSafeMember(_ context.Context, id int64) error {
	return deleteRow(m, m.safeMembers, id)
}

// AssignTargetSafe sets (or clears, when safeID is nil) a target's safe.
func (m *Memstore) AssignTargetSafe(_ context.Context, targetID int64, safeID *int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.targets[targetID]
	if !ok {
		return store.ErrNotFound
	}
	if safeID != nil {
		if _, ok := m.safes[*safeID]; !ok {
			return store.ErrNotFound
		}
	}
	t.SafeID = safeID
	m.targets[targetID] = t
	return nil
}

// CreateCredentialDependency declares a consumer of a credential.
func (m *Memstore) CreateCredentialDependency(_ context.Context, d *store.CredentialDependency) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.creds[d.CredentialID]; !ok {
		return store.ErrNotFound
	}
	if d.Port == 0 {
		d.Port = 5985
	}
	d.ID = m.id()
	m.credDeps[d.ID] = *d
	return nil
}

// ListCredentialDependencies returns a credential's declared consumers.
func (m *Memstore) ListCredentialDependencies(_ context.Context, credentialID int64) ([]store.CredentialDependency, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.CredentialDependency, 0)
	for _, d := range m.credDeps {
		if d.CredentialID == credentialID {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// DeleteCredentialDependency removes a dependency by ID, or ErrNotFound.
func (m *Memstore) DeleteCredentialDependency(_ context.Context, id int64) error {
	return deleteRow(m, m.credDeps, id)
}

// CreateCampaign inserts a certification campaign, assigning ID and CreatedAt.
func (m *Memstore) CreateCampaign(_ context.Context, c *store.Campaign) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c.Status == "" {
		c.Status = "open"
	}
	c.ID = m.id()
	c.CreatedAt = time.Now().UTC()
	m.campaigns[c.ID] = *c
	return nil
}

// ListCampaigns returns all campaigns, newest first.
func (m *Memstore) ListCampaigns(_ context.Context) ([]store.Campaign, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.Campaign, 0, len(m.campaigns))
	for _, c := range m.campaigns {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

// GetCampaign returns a campaign by ID, or ErrNotFound.
func (m *Memstore) GetCampaign(_ context.Context, id int64) (*store.Campaign, error) {
	return getRow(m, m.campaigns, id)
}

// CloseCampaign marks a campaign closed at the given time.
func (m *Memstore) CloseCampaign(_ context.Context, id int64, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.campaigns[id]
	if !ok {
		return store.ErrNotFound
	}
	c.Status = "closed"
	t := at.UTC()
	c.ClosedAt = &t
	m.campaigns[id] = c
	return nil
}

// SetCampaignItemReviewer reassigns one item.
func (m *Memstore) SetCampaignItemReviewer(_ context.Context, itemID int64, reviewer string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	it, ok := m.campaignItems[itemID]
	if !ok {
		return store.ErrNotFound
	}
	it.Reviewer = reviewer
	m.campaignItems[itemID] = it
	return nil
}

// ListItemsForReviewer returns the pending items assigned to reviewer across
// every open campaign, oldest first — the same predicate pgstore applies in SQL.
func (m *Memstore) ListItemsForReviewer(_ context.Context, reviewer string) ([]store.CampaignItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.CampaignItem
	for _, it := range m.campaignItems {
		if it.Reviewer != reviewer || it.Decision != "pending" {
			continue
		}
		if c, ok := m.campaigns[it.CampaignID]; !ok || c.Status != "open" {
			continue
		}
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ListCampaignsToRemind returns the open campaigns whose reminder has come due,
// oldest first — the same predicate pgstore applies in SQL.
func (m *Memstore) ListCampaignsToRemind(_ context.Context, now time.Time) ([]store.Campaign, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Campaign
	for _, c := range m.campaigns {
		if c.Status != "open" || c.RemindAt == nil || c.RemindAt.After(now) {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].RemindAt.Equal(*out[j].RemindAt) {
			return out[i].RemindAt.Before(*out[j].RemindAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// SetCampaignRemindAt schedules or cancels a campaign's next reminder.
func (m *Memstore) SetCampaignRemindAt(_ context.Context, id int64, at *time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.campaigns[id]
	if !ok {
		return store.ErrNotFound
	}
	if at == nil {
		c.RemindAt = nil
	} else {
		t := at.UTC()
		c.RemindAt = &t
	}
	m.campaigns[id] = c
	return nil
}

// ListDueCampaigns returns the open recurring anchors whose next run has
// arrived, oldest first — the same predicate pgstore applies in SQL.
func (m *Memstore) ListDueCampaigns(_ context.Context, now time.Time) ([]store.Campaign, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Campaign
	for _, c := range m.campaigns {
		if c.Status != "open" || c.RecurDays <= 0 || c.NextRunAt == nil || c.NextRunAt.After(now) {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].NextRunAt.Equal(*out[j].NextRunAt) {
			return out[i].NextRunAt.Before(*out[j].NextRunAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// SetCampaignNextRun moves an anchor's next occurrence.
func (m *Memstore) SetCampaignNextRun(_ context.Context, id int64, next time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.campaigns[id]
	if !ok {
		return store.ErrNotFound
	}
	t := next.UTC()
	c.NextRunAt = &t
	m.campaigns[id] = c
	return nil
}

// AddCampaignItem adds one access item to a campaign.
func (m *Memstore) AddCampaignItem(_ context.Context, item *store.CampaignItem) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.campaigns[item.CampaignID]; !ok {
		return store.ErrNotFound
	}
	if item.Decision == "" {
		item.Decision = "pending"
	}
	item.ID = m.id()
	m.campaignItems[item.ID] = *item
	return nil
}

// ListCampaignItems returns a campaign's items ordered by id.
func (m *Memstore) ListCampaignItems(_ context.Context, campaignID int64) ([]store.CampaignItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.CampaignItem, 0)
	for _, it := range m.campaignItems {
		if it.CampaignID == campaignID {
			out = append(out, it)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// GetCampaignItem returns one item by ID, or ErrNotFound.
func (m *Memstore) GetCampaignItem(_ context.Context, id int64) (*store.CampaignItem, error) {
	return getRow(m, m.campaignItems, id)
}

// DecideCampaignItem records a certify/revoke decision on an item.
func (m *Memstore) DecideCampaignItem(_ context.Context, id int64, decision, decidedBy string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	it, ok := m.campaignItems[id]
	if !ok {
		return store.ErrNotFound
	}
	it.Decision = decision
	it.DecidedBy = decidedBy
	t := at.UTC()
	it.DecidedAt = &t
	m.campaignItems[id] = it
	return nil
}

// CreateAccessRequest records a new request (defaulting status to pending) for
// an existing target; ErrNotFound if the target is missing.
func (m *Memstore) CreateAccessRequest(_ context.Context, ar *store.AccessRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.targets[ar.TargetID]; !ok {
		return store.ErrNotFound
	}
	ar.ID = m.id()
	ar.CreatedAt = time.Now().UTC()
	if ar.Status == "" {
		ar.Status = "pending"
	}
	if ar.RequiredApprovals < 1 {
		ar.RequiredApprovals = 1
	}
	m.accessReq[ar.ID] = *ar
	return nil
}

// SetApprovalState records a multi-approver decision (Phase 21).
func (m *Memstore) SetApprovalState(_ context.Context, id int64, approvedBy, status, approver string, decidedAt *time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ar, ok := m.accessReq[id]
	if !ok {
		return store.ErrNotFound
	}
	// CAS on pending, matching pgstore (2026-08-26 audit, M-4).
	if ar.Status != "pending" {
		return store.ErrConflict
	}
	ar.ApprovedBy = approvedBy
	ar.Status = status
	ar.Approver = approver
	if decidedAt != nil {
		t := decidedAt.UTC()
		ar.DecidedAt = &t
	}
	m.accessReq[id] = ar
	return nil
}

// GetAccessRequest returns the access request with the given ID, or ErrNotFound.
func (m *Memstore) GetAccessRequest(_ context.Context, id int64) (*store.AccessRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ar, ok := m.accessReq[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	ar.DecidedAt = cloneTimePtr(ar.DecidedAt)
	ar.ConsumedAt = cloneTimePtr(ar.ConsumedAt)
	ar.NextRunAt = cloneTimePtr(ar.NextRunAt)
	return &ar, nil
}

// ListAccessRequests returns requests with the given status (all when status is
// "") in the (limit, afterID) window, ordered by ID.
func (m *Memstore) ListAccessRequests(_ context.Context, status string, limit int, afterID int64) ([]store.AccessRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.AccessRequest, 0, len(m.accessReq))
	for _, ar := range m.accessReq {
		if status == "" || ar.Status == status {
			ar.DecidedAt = cloneTimePtr(ar.DecidedAt)
			ar.ConsumedAt = cloneTimePtr(ar.ConsumedAt)
			ar.NextRunAt = cloneTimePtr(ar.NextRunAt)
			out = append(out, ar)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return window(out, func(ar store.AccessRequest) int64 { return ar.ID }, limit, afterID), nil
}

// DecideAccessRequest records an approve/deny decision, approver, and decision
// time; ErrNotFound if the request is missing.
func (m *Memstore) DecideAccessRequest(_ context.Context, id int64, status, approver string, decidedAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ar, ok := m.accessReq[id]
	if !ok {
		return store.ErrNotFound
	}
	// Compare-and-set on pending, matching pgstore (2026-08-26 audit, M-4): a
	// request already decided cannot be re-decided, so a racing approve can no
	// longer overwrite a deny.
	if ar.Status != "pending" {
		return store.ErrConflict
	}
	ar.Status = status
	ar.Approver = approver
	at := decidedAt.UTC()
	ar.DecidedAt = &at
	m.accessReq[id] = ar
	return nil
}

// ListDueAccessRequests returns the approved recurring anchors whose next run
// has arrived, oldest first (Phase 120).
func (m *Memstore) ListDueAccessRequests(_ context.Context, now time.Time) ([]store.AccessRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.AccessRequest
	for _, ar := range m.accessReq {
		if ar.Status != "approved" || ar.RecurDays <= 0 || ar.NextRunAt == nil || ar.NextRunAt.After(now) {
			continue
		}
		out = append(out, ar)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].NextRunAt.Equal(*out[j].NextRunAt) {
			return out[i].NextRunAt.Before(*out[j].NextRunAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// SetAccessRequestNextRun moves an anchor's next occurrence.
func (m *Memstore) SetAccessRequestNextRun(_ context.Context, id int64, next time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ar, ok := m.accessReq[id]
	if !ok {
		return store.ErrNotFound
	}
	t := next.UTC()
	ar.NextRunAt = &t
	m.accessReq[id] = ar
	return nil
}

// StopAccessRequestRecurrence ends a recurring anchor's series.
func (m *Memstore) StopAccessRequestRecurrence(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ar, ok := m.accessReq[id]
	if !ok {
		return store.ErrNotFound
	}
	ar.RecurDays = 0
	ar.NextRunAt = nil
	m.accessReq[id] = ar
	return nil
}

// HasActiveApproval reports whether requester has an approved, unexpired request
// for targetID as of now. A consumed single-use approval is not active.
func (m *Memstore) HasActiveApproval(_ context.Context, requester string, targetID int64, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ar := range m.accessReq {
		if approvalActiveAt(ar, requester, targetID, now) {
			return true, nil
		}
	}
	return false, nil
}

// approvalActiveAt reports whether one access request is an active approval for
// (requester, targetID) as of now: approved, unexpired, inside its scheduled
// window, and not a consumed single-use approval.
func approvalActiveAt(ar store.AccessRequest, requester string, targetID int64, now time.Time) bool {
	return ar.Requester == requester && ar.TargetID == targetID &&
		ar.Status == "approved" && now.Before(ar.ExpiresAt) &&
		(ar.NotBefore == nil || !now.Before(*ar.NotBefore)) &&
		(!ar.OneTime || ar.ConsumedAt == nil)
}

// ActiveApprovals returns every approval that could admit requester to targetID
// as of now, without consuming any of them, most-preferred first: standing
// approvals before single-use ones and oldest id first, which is the order
// ConsumeApproval would have picked them in. The map this iterates has no
// order of its own, so the result is sorted explicitly — a caller re-reading
// the list must see the same answer twice.
func (m *Memstore) ActiveApprovals(_ context.Context, requester string, targetID int64, now time.Time, limit int) ([]store.AccessRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.AccessRequest
	for _, ar := range m.accessReq {
		if approvalActiveAt(ar, requester, targetID, now) {
			out = append(out, ar)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OneTime != out[j].OneTime {
			return !out[i].OneTime // standing first
		}
		return out[i].ID < out[j].ID
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// ConsumeApproval reports whether requester holds an active approval for
// targetID and, when the only active approval is single-use, burns it by
// stamping ConsumedAt (under the store lock, so of two racing consumers exactly
// one wins). A standing approval, when present, is preferred and left
// untouched.
func (m *Memstore) ConsumeApproval(_ context.Context, requester string, targetID int64, now time.Time) (bool, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var oneTimeID int64
	for _, ar := range m.accessReq {
		if !approvalActiveAt(ar, requester, targetID, now) {
			continue
		}
		if !ar.OneTime {
			return true, 0, nil // a standing approval wins; nothing is burned
		}
		if oneTimeID == 0 || ar.ID < oneTimeID {
			oneTimeID = ar.ID // burn deterministically: the oldest single-use approval
		}
	}
	if oneTimeID == 0 {
		return false, 0, nil
	}
	ar := m.accessReq[oneTimeID]
	at := now.UTC()
	ar.ConsumedAt = &at
	m.accessReq[oneTimeID] = ar
	return true, oneTimeID, nil
}

// ConsumeApprovalByID claims the one approval the caller named, under the same
// lock, so of two racing consumers of the SAME single-use approval exactly one
// wins and the loser is told to look elsewhere rather than handed an error.
func (m *Memstore) ConsumeApprovalByID(_ context.Context, id int64, requester string, targetID int64, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ar, ok := m.accessReq[id]
	if !ok || !approvalActiveAt(ar, requester, targetID, now) {
		return false, nil
	}
	if !ar.OneTime {
		return true, nil // a standing approval is never burned
	}
	at := now.UTC()
	ar.ConsumedAt = &at
	m.accessReq[id] = ar
	return true, nil
}

// activeCheckoutLocked returns the credential's active (unreturned, unexpired)
// checkout, if any; the caller holds the lock.
func (m *Memstore) activeCheckoutLocked(credentialID int64, now time.Time) (store.Checkout, bool) {
	for _, co := range m.checkouts {
		if co.CredentialID == credentialID && co.ReturnedAt == nil && now.Before(co.ExpiresAt) {
			return co, true
		}
	}
	return store.Checkout{}, false
}

// CreateCheckout leases a credential; ErrNotFound if the credential is missing,
// ErrConflict if it already has an active (unexpired, unreturned) checkout as of
// now. An expired-but-unreturned lease is auto-closed rather than blocking the new
// checkout, mirroring pgstore's expire-then-insert so at most one unreturned lease
// per credential exists in either store.
func (m *Memstore) CreateCheckout(_ context.Context, co *store.Checkout, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.creds[co.CredentialID]; !ok {
		return store.ErrNotFound
	}
	for id, existing := range m.checkouts {
		if existing.CredentialID != co.CredentialID || existing.ReturnedAt != nil {
			continue
		}
		if now.Before(existing.ExpiresAt) {
			return store.ErrConflict // an active lease still holds the credential
		}
		t := now.UTC() // expired: close it so it neither blocks nor lingers unreturned
		existing.ReturnedAt = &t
		m.checkouts[id] = existing
	}
	co.ID = m.id()
	co.CheckedOutAt = now.UTC()
	m.checkouts[co.ID] = *co
	return nil
}

// GetActiveCheckout returns the credential's active checkout as of now, or ErrNotFound.
func (m *Memstore) GetActiveCheckout(_ context.Context, credentialID int64, now time.Time) (*store.Checkout, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if co, active := m.activeCheckoutLocked(credentialID, now); active {
		co.ReturnedAt = cloneTimePtr(co.ReturnedAt)
		return &co, nil
	}
	return nil, store.ErrNotFound
}

// CheckinCheckout marks a checkout returned; ErrNotFound if missing or already returned.
func (m *Memstore) CheckinCheckout(_ context.Context, id int64, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	co, ok := m.checkouts[id]
	if !ok || co.ReturnedAt != nil {
		return store.ErrNotFound
	}
	t := at.UTC()
	co.ReturnedAt = &t
	m.checkouts[id] = co
	return nil
}

// ListCheckouts returns checkouts in the (limit, afterID) window, ordered by
// ID; activeOnly limits to unreturned, unexpired ones as of now.
func (m *Memstore) ListCheckouts(_ context.Context, activeOnly bool, now time.Time, limit int, afterID int64) ([]store.Checkout, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.Checkout, 0, len(m.checkouts))
	for _, co := range m.checkouts {
		if activeOnly && (co.ReturnedAt != nil || !now.Before(co.ExpiresAt)) {
			continue
		}
		co.ReturnedAt = cloneTimePtr(co.ReturnedAt)
		out = append(out, co)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return window(out, func(co store.Checkout) int64 { return co.ID }, limit, afterID), nil
}

// GetCheckout returns one checkout by ID, or ErrNotFound.
func (m *Memstore) GetCheckout(_ context.Context, id int64) (*store.Checkout, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	co, ok := m.checkouts[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	co.ReturnedAt = cloneTimePtr(co.ReturnedAt)
	return &co, nil
}

// ExtendCheckout pushes an active (unreturned, unexpired) checkout's expiry to
// newExpiresAt; ErrNotFound if missing, already returned, or already expired.
func (m *Memstore) ExtendCheckout(_ context.Context, id int64, newExpiresAt, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	co, ok := m.checkouts[id]
	if !ok || co.ReturnedAt != nil || !now.Before(co.ExpiresAt) {
		return store.ErrNotFound
	}
	co.ExpiresAt = newExpiresAt.UTC()
	m.checkouts[id] = co
	return nil
}

// pwHistoryEntry is one rotation's secret hash, in the order it was recorded.
type pwHistoryEntry struct {
	Hash string
	At   time.Time
}

// RecordPasswordHistory appends secretHash to credentialID's history and
// prunes anything beyond the most recent keep entries.
func (m *Memstore) RecordPasswordHistory(_ context.Context, credentialID int64, secretHash string, at time.Time, keep int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := append(m.pwHistory[credentialID], pwHistoryEntry{Hash: secretHash, At: at.UTC()})
	if keep < 0 {
		keep = 0
	}
	if len(h) > keep {
		h = h[len(h)-keep:]
	}
	m.pwHistory[credentialID] = h
	return nil
}

// RecentPasswordHashes returns up to limit of a credential's most recent
// rotation hashes, newest first.
func (m *Memstore) RecentPasswordHashes(_ context.Context, credentialID int64, limit int) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := m.pwHistory[credentialID]
	out := make([]string, 0, len(h))
	for i := len(h) - 1; i >= 0 && (limit <= 0 || len(out) < limit); i-- {
		out = append(out, h[i].Hash)
	}
	return out, nil
}

// CreateCredential inserts a credential for an existing target, assigning its ID
// and CreatedAt; ErrNotFound if the target is missing.
func (m *Memstore) CreateCredential(_ context.Context, c *store.Credential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.targets[c.TargetID]; !ok {
		return store.ErrNotFound
	}
	c.ID = m.id()
	c.CreatedAt = time.Now().UTC()
	m.creds[c.ID] = *c
	return nil
}

// ListCredentials returns credentials for one target (or all when targetID is
// 0) in the (limit, afterID) window, ordered by ID, WITH SecretEnc — see the
// interface doc comment (store.Store) for why this must stay full-fidelity.
func (m *Memstore) ListCredentials(_ context.Context, targetID int64, limit int, afterID int64) ([]store.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.Credential, 0, len(m.creds))
	for _, c := range m.creds {
		if targetID == 0 || c.TargetID == targetID {
			c.RotatedAt = cloneTimePtr(c.RotatedAt)
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return window(out, func(c store.Credential) int64 { return c.ID }, limit, afterID), nil
}

// ListCredentialsMeta is ListCredentials without SecretEnc, DoubleLockVerifier
// or DoubleLockEnc (Phase 145), matching pgstore's narrower query so a
// contract test run against both backends catches a caller wired to the
// wrong one instead of passing here and failing only in production.
func (m *Memstore) ListCredentialsMeta(ctx context.Context, targetID int64, limit int, afterID int64) ([]store.Credential, error) {
	out, err := m.ListCredentials(ctx, targetID, limit, afterID)
	for i := range out {
		out[i].SecretEnc, out[i].DoubleLockVerifier, out[i].DoubleLockEnc = "", "", ""
	}
	return out, err
}

// GetCredential returns the credential with the given ID, or ErrNotFound.
func (m *Memstore) GetCredential(_ context.Context, id int64) (*store.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.creds[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	c.RotatedAt = cloneTimePtr(c.RotatedAt)
	return &c, nil
}

// cloneTimePtr returns a fresh copy of a *time.Time so a caller can't mutate the
// value the store still holds in its map (pgstore hands back independent values).
func cloneTimePtr(p *time.Time) *time.Time {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// UpdateCredentialSecretEnc replaces a credential's encrypted secret without
// touching rotated_at or DoubleLock; ErrNotFound if absent. Used only by the
// KEK re-wrap path (-rotate-kek): the plaintext is unchanged, only which KEK
// wraps it, so any DoubleLock (independent of the KEK entirely) stays valid.
func (m *Memstore) UpdateCredentialSecretEnc(_ context.Context, id int64, secretEnc string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.creds[id]
	if !ok {
		return store.ErrNotFound
	}
	c.SecretEnc = secretEnc
	m.creds[id] = c
	return nil
}

// RotateCredentialSecret replaces the encrypted secret, stamps rotated_at, and
// clears any DoubleLock — the password-derived DoubleLockEnc now seals a
// stale secret and the password to reseal a new one isn't available here;
// ErrNotFound if absent.
func (m *Memstore) RotateCredentialSecret(_ context.Context, id int64, secretEnc string, rotatedAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.creds[id]
	if !ok {
		return store.ErrNotFound
	}
	c.SecretEnc = secretEnc
	at := rotatedAt.UTC()
	c.RotatedAt = &at
	c.DoubleLockHolder = ""
	c.DoubleLockVerifier = ""
	c.DoubleLockEnc = ""
	m.creds[id] = c
	return nil
}

// SetCredentialDoubleLock enables DoubleLock on a credential; ErrNotFound if absent.
func (m *Memstore) SetCredentialDoubleLock(_ context.Context, id int64, holder, verifier, enc string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.creds[id]
	if !ok {
		return store.ErrNotFound
	}
	c.DoubleLockHolder = holder
	c.DoubleLockVerifier = verifier
	c.DoubleLockEnc = enc
	m.creds[id] = c
	return nil
}

// ClearCredentialDoubleLock disables DoubleLock on a credential; ErrNotFound if absent.
func (m *Memstore) ClearCredentialDoubleLock(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.creds[id]
	if !ok {
		return store.ErrNotFound
	}
	c.DoubleLockHolder = ""
	c.DoubleLockVerifier = ""
	c.DoubleLockEnc = ""
	m.creds[id] = c
	return nil
}

// DeleteCredential removes a credential by ID; ErrNotFound if absent.
func (m *Memstore) DeleteCredential(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.creds[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.creds, id)
	// pgstore FKs cascade checkouts and dependencies on credential delete — match it.
	for coid, co := range m.checkouts {
		if co.CredentialID == id {
			delete(m.checkouts, coid)
		}
	}
	for did, d := range m.credDeps {
		if d.CredentialID == id {
			delete(m.credDeps, did)
		}
	}
	// pgstore FK cascades app_secret_grants on credential delete — match it.
	for gid, g := range m.appGrants {
		if g.CredentialID == id {
			delete(m.appGrants, gid)
		}
	}
	return nil
}

// AppendAudit appends an audit event, assigning its ID and timestamp.
func (m *Memstore) AppendAudit(_ context.Context, e *store.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e.ID = m.id()
	e.TS = time.Now().UTC()
	if len(m.auditKey) > 0 {
		var prev []byte
		for i := len(m.audit) - 1; i >= 0; i-- {
			if m.audit[i].HMAC != nil {
				prev = m.audit[i].HMAC
				break
			}
		}
		e.PrevHash = prev
		e.HMAC = store.AuditMAC(m.auditKey, prev, e)
	}
	m.audit = append(m.audit, *e)
	return nil
}

// EnableAuditChain turns on tamper-evident chaining of the primary audit trail.
func (m *Memstore) EnableAuditChain(key []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.auditKey = key
}

// GetAuditHead returns the most recent chained audit event, or (nil, nil) if none.
func (m *Memstore) GetAuditHead(_ context.Context) (*store.AuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.audit) - 1; i >= 0; i-- {
		if m.audit[i].HMAC != nil {
			e := m.audit[i]
			return &e, nil
		}
	}
	return nil, nil
}

// VerifyAuditChain recomputes the chain over every chained audit event in order.
func (m *Memstore) VerifyAuditChain(_ context.Context) (bool, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.auditKey) == 0 {
		return false, 0, errors.New("memstore: audit chain not enabled")
	}
	var prev []byte
	for i := range m.audit {
		e := m.audit[i]
		if e.HMAC == nil {
			continue
		}
		want := store.AuditMAC(m.auditKey, prev, &e)
		if !hmac.Equal(want, e.HMAC) || !bytes.Equal(prev, e.PrevHash) {
			return false, e.ID, nil
		}
		prev = e.HMAC
	}
	return true, 0, nil
}

// ListAudit returns the most recent audit events, newest first, applying the
// limit semantics defined on store.Store. It used to return EVERYTHING for a
// non-positive or oversized limit, which made tests pass against behaviour
// pgstore did not share.
func (m *Memstore) ListAudit(_ context.Context, limit int) ([]store.AuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := len(m.audit)
	limit = store.ClampAuditLimit(limit)
	if limit > n {
		limit = n // fewer events exist than were asked for
	}
	out := make([]store.AuditEvent, 0, limit)
	for i := n - 1; i >= n-limit; i-- {
		out = append(out, m.audit[i])
	}
	return out, nil
}

// ExportAudit returns audit events with since <= ts < until, oldest-first; a
// zero since means from the beginning and a zero until means up to now.
func (m *Memstore) ExportAudit(_ context.Context, since, until time.Time) ([]store.AuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if until.IsZero() {
		until = time.Now()
	}
	out := make([]store.AuditEvent, 0, len(m.audit))
	for _, e := range m.audit {
		if (since.IsZero() || !e.TS.Before(since)) && e.TS.Before(until) {
			out = append(out, e)
		}
	}
	return out, nil
}

// LatestAuditByAction returns the most recent event with the given action, or
// (nil, nil) if there is none.
func (m *Memstore) LatestAuditByAction(_ context.Context, action string) (*store.AuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.audit) - 1; i >= 0; i-- {
		if m.audit[i].Action == action {
			e := m.audit[i]
			return &e, nil
		}
	}
	return nil, nil
}

// AuditSince returns up to limit audit events with id > afterID, oldest-first.
// The in-memory slice is append-ordered with ascending ids, so a forward scan
// with a cap satisfies the contract.
func (m *Memstore) AuditSince(_ context.Context, afterID int64, limit int) ([]store.AuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.AuditEvent, 0, limit)
	for _, e := range m.audit {
		if e.ID > afterID {
			out = append(out, e)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

// PruneAuditBefore deletes audit events with ts < cutoff, returning the count.
func (m *Memstore) PruneAuditBefore(_ context.Context, cutoff time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.audit[:0:0]
	removed := 0
	for _, e := range m.audit {
		if e.TS.Before(cutoff) {
			removed++
			continue
		}
		kept = append(kept, e)
	}
	m.audit = kept
	return removed, nil
}

// FindAuditDetail reports whether any audit event with the given action has a
// detail containing substr, matched literally.
func (m *Memstore) FindAuditDetail(_ context.Context, action, substr string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.audit {
		if e.Action == action && strings.Contains(e.Detail, substr) {
			return true, nil
		}
	}
	return false, nil
}

// CreateUser inserts a user, assigning its ID and CreatedAt; ErrConflict if the username is taken.
// CreateUser always creates an active user — Active on the input struct is
// ignored, matching pgstore: a bare Go bool cannot tell "wants an inactive
// user" apart from "never heard of this field," and the second case must
// never silently create a deactivated account. A caller that genuinely needs
// a freshly-created user to start deactivated makes a separate
// UpdateUserActive call right after.
func (m *Memstore) CreateUser(_ context.Context, u *store.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.users {
		// pgstore has UNIQUE constraints on both columns; match it so identity
		// resolution (GetUserByTokenHash) can't become ambiguous in the demo store.
		if existing.Username == u.Username || existing.TokenHash == u.TokenHash {
			return store.ErrConflict
		}
	}
	u.ID = m.id()
	u.CreatedAt = time.Now().UTC()
	u.Active = true
	m.users[u.ID] = *u
	return nil
}

// ListUsers returns users in the (limit, afterID) window, ordered by ID.
func (m *Memstore) ListUsers(_ context.Context, limit int, afterID int64) ([]store.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.User, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return window(out, func(u store.User) int64 { return u.ID }, limit, afterID), nil
}

// GetUser returns the user with the given ID, or ErrNotFound.
func (m *Memstore) GetUser(_ context.Context, id int64) (*store.User, error) {
	return getRow(m, m.users, id)
}

// UpdateUserRole changes a user's role, leaving username and token untouched;
// ErrNotFound if absent.
func (m *Memstore) UpdateUserRole(_ context.Context, id int64, role string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return store.ErrNotFound
	}
	u.Role = role
	m.users[id] = u
	return nil
}

// UpdateUserIPAllowlist sets a user's source-address restriction (Phase 118).
func (m *Memstore) UpdateUserIPAllowlist(_ context.Context, id int64, allowlist string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return store.ErrNotFound
	}
	u.IPAllowlist = allowlist
	m.users[id] = u
	return nil
}

// UpdateUserDeviceFingerprint sets a user's enrolled device-certificate
// fingerprint (Phase 133).
func (m *Memstore) UpdateUserDeviceFingerprint(_ context.Context, id int64, fingerprint string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return store.ErrNotFound
	}
	u.DeviceFingerprint = fingerprint
	m.users[id] = u
	return nil
}

// GetUserByTokenHash returns the user whose token hash matches, or ErrNotFound.
func (m *Memstore) GetUserByTokenHash(_ context.Context, tokenHashHex string) (*store.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.TokenHash == tokenHashHex {
			return &u, nil
		}
	}
	return nil, store.ErrNotFound
}

// GetUserByUsername returns the user with the given username, or ErrNotFound.
func (m *Memstore) GetUserByUsername(_ context.Context, username string) (*store.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.Username == username {
			return &u, nil
		}
	}
	return nil, store.ErrNotFound
}

// GetUserByExternalID returns the user with the given SCIM externalId, or
// ErrNotFound. An empty externalID always misses, matching pgstore.
func (m *Memstore) GetUserByExternalID(_ context.Context, externalID string) (*store.User, error) {
	if externalID == "" {
		return nil, store.ErrNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.ExternalID == externalID {
			return &u, nil
		}
	}
	return nil, store.ErrNotFound
}

// UpdateUserActive sets a user's SCIM active flag (Phase 149); ErrNotFound if absent.
func (m *Memstore) UpdateUserActive(_ context.Context, id int64, active bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return store.ErrNotFound
	}
	u.Active = active
	m.users[id] = u
	return nil
}

// UpdateUserExternalID sets a user's SCIM externalId (Phase 149); ErrNotFound
// if absent, ErrConflict if another user already claims the same non-empty value.
func (m *Memstore) UpdateUserExternalID(_ context.Context, id int64, externalID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[id]; !ok {
		return store.ErrNotFound
	}
	if externalID != "" {
		for otherID, other := range m.users {
			if otherID != id && other.ExternalID == externalID {
				return store.ErrConflict
			}
		}
	}
	u := m.users[id]
	u.ExternalID = externalID
	m.users[id] = u
	return nil
}

// DeleteUser removes a user by ID; ErrNotFound if absent.
func (m *Memstore) DeleteUser(_ context.Context, id int64) error {
	return deleteRow(m, m.users, id)
}

// CreateAgentKey inserts an agent key, assigning its ID and CreatedAt; ErrConflict
// if the token hash is taken.
func (m *Memstore) CreateAgentKey(_ context.Context, k *store.AgentKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.agentKeys {
		if existing.TokenHash == k.TokenHash {
			return store.ErrConflict
		}
		// At most one ACTIVE key per name (2026-08-26 audit, M-3), matching the
		// pgstore partial unique index in migration 0049. A revoked (disabled)
		// key with the same name is fine — that is rotation.
		if !existing.Disabled && existing.Name == k.Name && !k.Disabled {
			return store.ErrConflict
		}
	}
	k.ID = m.id()
	k.CreatedAt = time.Now().UTC()
	m.agentKeys[k.ID] = *k
	return nil
}

// GetAgentKeyByTokenHash returns the enabled agent key whose token hash matches,
// or ErrNotFound (a disabled key is treated as not found).
func (m *Memstore) GetAgentKeyByTokenHash(_ context.Context, tokenHashHex string) (*store.AgentKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range m.agentKeys {
		if k.TokenHash == tokenHashHex && !k.Disabled {
			out := k
			return &out, nil
		}
	}
	return nil, store.ErrNotFound
}

// ListAgentKeys returns all agent keys ordered by ID.
func (m *Memstore) ListAgentKeys(_ context.Context) ([]store.AgentKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.AgentKey, 0, len(m.agentKeys))
	for _, k := range m.agentKeys {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ListAgentKeysByOwner returns one owner's agent keys ordered by ID (empty, not
// nil, when the owner has none).
func (m *Memstore) ListAgentKeysByOwner(_ context.Context, owner string) ([]store.AgentKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.AgentKey, 0, len(m.agentKeys))
	for _, k := range m.agentKeys {
		if k.Owner == owner {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// DeleteAgentKey removes an agent key by ID; ErrNotFound if absent.
func (m *Memstore) DeleteAgentKey(_ context.Context, id int64) error {
	return deleteRow(m, m.agentKeys, id)
}

// SetAgentKeyDisabled suspends or restores an agent key (idempotent);
// ErrNotFound if absent.
func (m *Memstore) SetAgentKeyDisabled(_ context.Context, id int64, disabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.agentKeys[id]
	if !ok {
		return store.ErrNotFound
	}
	k.Disabled = disabled
	m.agentKeys[id] = k
	return nil
}

// TouchAgentKey records when the agent key last authenticated; ErrNotFound if absent.
func (m *Memstore) TouchAgentKey(_ context.Context, id int64, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.agentKeys[id]
	if !ok {
		return store.ErrNotFound
	}
	t := at.UTC()
	k.LastUsedAt = &t
	m.agentKeys[id] = k
	return nil
}

// SetAgentKeyBudget sets an agent key's daily brokered-call budget, or clears
// it with nil so the server-wide default applies again; ErrNotFound if absent.
//
// The pointer is copied, not dereferenced, so all three states survive: nil
// stays nil ("no per-agent setting"), a pointer to 0 stays a pointer to 0
// ("this agent may make no calls at all"), and a positive value is kept as is.
// A copy of the pointed-to value is stored rather than the caller's pointer:
// in Go the caller still holds a reference to that int and could otherwise
// change a stored budget after the fact just by assigning through it, which
// pgstore (where the value is written to a column) would never do.
func (m *Memstore) SetAgentKeyBudget(_ context.Context, id int64, budgetPerDay *int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.agentKeys[id]
	if !ok {
		return store.ErrNotFound
	}
	if budgetPerDay == nil {
		k.BudgetPerDay = nil
	} else {
		v := *budgetPerDay
		k.BudgetPerDay = &v
	}
	m.agentKeys[id] = k
	return nil
}

// CountAgentToolCallsSince counts the brokered tool calls one agent has spent
// since `since` (inclusive), scanning the primary audit trail.
//
// Only `broker.tool_call.executed` (work done immediately) and
// `broker.tool_call.resumed` (the agent collecting the result of a call a
// human approved) count -- denied and failed calls do not, because a budget
// measures what the agent was allowed to DO, and refusals must not eat it. The
// action names are compared for exact equality, never by prefix, so a future
// broker.tool_call.* outcome cannot start charging the budget by accident.
// See BrokerStore's interface doc for the full reasoning; the constants live
// in internal/broker, which this package cannot import without an import
// cycle, so the strings are repeated here and must be kept in step.
//
// The actor comparison is ==, i.e. exact and case-sensitive, matching pgstore.
func (m *Memstore) CountAgentToolCallsSince(_ context.Context, agent string, since time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, e := range m.audit {
		if e.Actor != agent {
			continue
		}
		if e.Action != store.AuditActionToolCallExecuted && e.Action != store.AuditActionToolCallResumed {
			continue
		}
		// !Before rather than After: `since` is inclusive, so an event
		// stamped at exactly that instant counts.
		if !e.TS.Before(since) {
			n++
		}
	}
	return n, nil
}

// CountAgentCallsForTokenSince counts the brokered tool calls made while
// presenting one token, identified by its `jti`.
//
// The needle is built through store.AgentTokenAuditField, the same function the
// API writes the field with, so this backend and pgstore and the writer all
// agree on the exact bytes. Matching a quoted field rather than a bare id is
// what stops one jti matching as a prefix of another.
//
// Actor is matched too, so quoting another agent's jti cannot spend its ceiling.
func (m *Memstore) CountAgentCallsForTokenSince(_ context.Context, agent, jti string, since time.Time) (int, error) {
	if jti == "" {
		return 0, nil // a static agent key has no token id; see the interface doc
	}
	needle := store.AgentTokenAuditField(jti)
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, e := range m.audit {
		if e.Actor != agent {
			continue
		}
		if e.Action != store.AuditActionToolCallExecuted && e.Action != store.AuditActionToolCallResumed {
			continue
		}
		// !Before rather than After: `since` is inclusive, matching its sibling.
		if !e.TS.Before(since) && strings.Contains(e.Detail, needle) {
			n++
		}
	}
	return n, nil
}

// ReserveAgentCall is the compare-and-spend under the store's one lock: the
// purge, both counts and the insert happen while no other reservation can, so
// two calls arriving together cannot both read the count the other is about to
// change. See the interface doc for the limit semantics.
func (m *Memstore) ReserveAgentCall(_ context.Context, agent, jti string, at, since time.Time, agentLimit, tokenLimit int) (store.AgentCallReservation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := store.AgentCallReservation{Agent: agent, TokenID: jti, At: at.UTC()}
	for id, r := range m.callReservations {
		if r.Agent != agent {
			continue
		}
		if r.At.Before(since) {
			delete(m.callReservations, id) // aged out of every window: self-GC on write
			continue
		}
		res.AgentUsed++
		if jti != "" && r.TokenID == jti {
			res.TokenUsed++
		}
	}
	if agentLimit >= 0 && res.AgentUsed >= agentLimit {
		res.Refused = store.ReservationRefusedBudget
		return res, nil
	}
	if jti != "" && tokenLimit > 0 && res.TokenUsed >= tokenLimit {
		res.Refused = store.ReservationRefusedToken
		return res, nil
	}
	res.ID = m.id()
	m.callReservations[res.ID] = res
	return res, nil
}

// ReleaseAgentCallReservation deletes a reservation whose call did no work, or
// ErrNotFound.
func (m *Memstore) ReleaseAgentCallReservation(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.callReservations[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.callReservations, id)
	return nil
}

// QuarantineAgent stops one agent by subject, assigning ID and CreatedAt;
// ErrConflict if that subject is already quarantined.
func (m *Memstore) QuarantineAgent(_ context.Context, q *store.AgentQuarantine) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.agentQuarantine {
		if existing.Subject == q.Subject {
			return store.ErrConflict
		}
	}
	q.ID = m.id()
	q.CreatedAt = time.Now().UTC()
	m.agentQuarantine[q.ID] = *q
	return nil
}

// IsAgentQuarantined reports whether the subject is currently quarantined.
func (m *Memstore) IsAgentQuarantined(_ context.Context, subject string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, q := range m.agentQuarantine {
		if q.Subject == subject {
			return true, nil
		}
	}
	return false, nil
}

// ListAgentQuarantine returns every quarantine entry ordered by ID.
func (m *Memstore) ListAgentQuarantine(_ context.Context) ([]store.AgentQuarantine, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.AgentQuarantine, 0, len(m.agentQuarantine))
	for _, q := range m.agentQuarantine {
		out = append(out, q)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ReleaseAgentQuarantine lifts one quarantine by ID; ErrNotFound if absent.
func (m *Memstore) ReleaseAgentQuarantine(_ context.Context, id int64) error {
	return deleteRow(m, m.agentQuarantine, id)
}

// CreateAgentIdentity records the owner of a SPIFFE-attested agent, assigning ID
// and CreatedAt; ErrConflict if that SPIFFE ID is already registered.
func (m *Memstore) CreateAgentIdentity(_ context.Context, a *store.AgentIdentity) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.agentIdentities {
		if existing.SPIFFEID == a.SPIFFEID {
			return store.ErrConflict
		}
	}
	a.ID = m.id()
	a.CreatedAt = time.Now().UTC()
	a.Enrolled = true // an operator recorded it deliberately
	m.agentIdentities[a.ID] = *a
	return nil
}

// SeeAgentIdentity records that a SPIFFE identity authenticated, creating an
// unenrolled row on the first sighting and stamping last-seen after that.
func (m *Memstore) SeeAgentIdentity(_ context.Context, spiffeID string, seen time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	at := seen.UTC()
	for id, a := range m.agentIdentities {
		if a.SPIFFEID != spiffeID {
			continue
		}
		if a.FirstSeen == nil {
			first := at
			a.FirstSeen = &first
		}
		last := at
		a.LastSeen = &last
		m.agentIdentities[id] = a
		return false, nil
	}
	first, last := at, at
	a := store.AgentIdentity{
		ID: m.id(), SPIFFEID: spiffeID, CreatedBy: "first-seen",
		Enrolled: false, FirstSeen: &first, LastSeen: &last, CreatedAt: time.Now().UTC(),
	}
	m.agentIdentities[a.ID] = a
	return true, nil
}

// GetAgentIdentity returns one SPIFFE ID's registration, or ErrNotFound.
func (m *Memstore) GetAgentIdentity(_ context.Context, spiffeID string) (*store.AgentIdentity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.agentIdentities {
		if a.SPIFFEID == spiffeID {
			out := a
			return &out, nil
		}
	}
	return nil, store.ErrNotFound
}

// ListAgentIdentities returns every registration ordered by ID.
func (m *Memstore) ListAgentIdentities(_ context.Context) ([]store.AgentIdentity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.AgentIdentity, 0, len(m.agentIdentities))
	for _, a := range m.agentIdentities {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ListAgentIdentitiesByOwner returns one owner's registrations ordered by ID
// (empty, not nil, when they own none).
func (m *Memstore) ListAgentIdentitiesByOwner(_ context.Context, owner string) ([]store.AgentIdentity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.AgentIdentity, 0, len(m.agentIdentities))
	for _, a := range m.agentIdentities {
		if a.Owner == owner {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// EnrollAgentIdentity claims a discovered identity: owner, note, enrolled.
func (m *Memstore) EnrollAgentIdentity(_ context.Context, id int64, owner, note string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.agentIdentities[id]
	if !ok {
		return store.ErrNotFound
	}
	a.Owner, a.Note, a.Enrolled = owner, note, true
	m.agentIdentities[id] = a
	return nil
}

// SetAgentIdentityOwner reassigns one registration's owner; ErrNotFound if absent.
func (m *Memstore) SetAgentIdentityOwner(_ context.Context, id int64, owner string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.agentIdentities[id]
	if !ok {
		return store.ErrNotFound
	}
	// Naming an owner IS enrolling — see the pgstore twin.
	a.Owner = owner
	a.Enrolled = true
	m.agentIdentities[id] = a
	return nil
}

// DeleteAgentIdentity removes one registration by ID; ErrNotFound if absent.
func (m *Memstore) DeleteAgentIdentity(_ context.Context, id int64) error {
	return deleteRow(m, m.agentIdentities, id)
}

// RecordSSHCert stores an issued operator SSH certificate (Phase 28); ErrConflict
// if the serial is already recorded.
func (m *Memstore) RecordSSHCert(_ context.Context, c *store.SSHCert) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.sshCerts {
		if existing.Serial == c.Serial {
			return store.ErrConflict
		}
	}
	c.ID = m.id()
	c.IssuedAt = time.Now().UTC()
	m.sshCerts[c.ID] = *c
	return nil
}

// RevokeSSHCert stamps a certificate serial revoked; ErrNotFound if unknown,
// ErrConflict if already revoked.
func (m *Memstore) RevokeSSHCert(_ context.Context, serial int64, by string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, c := range m.sshCerts {
		if c.Serial != serial {
			continue
		}
		if c.RevokedAt != nil {
			return store.ErrConflict
		}
		t := at.UTC()
		c.RevokedAt = &t
		c.RevokedBy = by
		m.sshCerts[id] = c
		return nil
	}
	return store.ErrNotFound
}

// ListRevokedSSHCertSerials returns the serials of every revoked certificate.
func (m *Memstore) ListRevokedSSHCertSerials(_ context.Context) ([]int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []int64
	for _, c := range m.sshCerts {
		if c.RevokedAt != nil {
			out = append(out, c.Serial)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// ListSSHCerts returns recent issued certificates, newest first (capped).
func (m *Memstore) ListSSHCerts(_ context.Context, limit int) ([]store.SSHCert, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.SSHCert, 0, len(m.sshCerts))
	for _, c := range m.sshCerts {
		c.RevokedAt = cloneTimePtr(c.RevokedAt)
		c.ValidBefore = cloneTimePtr(c.ValidBefore)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// CreateVendor registers a vendor (Phase 29); ErrConflict on a duplicate username.
func (m *Memstore) CreateVendor(_ context.Context, v *store.Vendor) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.vendors {
		if existing.Username == v.Username {
			return store.ErrConflict
		}
	}
	v.ID = m.id()
	v.CreatedAt = time.Now().UTC()
	m.vendors[v.ID] = *v
	return nil
}

// GetVendorByUsername returns the vendor for a login, or ErrNotFound.
func (m *Memstore) GetVendorByUsername(_ context.Context, username string) (*store.Vendor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, v := range m.vendors {
		if v.Username == username {
			out := v
			return &out, nil
		}
	}
	return nil, store.ErrNotFound
}

// ListVendors returns vendors in the (limit, afterID) window, ordered by ID.
func (m *Memstore) ListVendors(_ context.Context, limit int, afterID int64) ([]store.Vendor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.Vendor, 0, len(m.vendors))
	for _, v := range m.vendors {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return window(out, func(v store.Vendor) int64 { return v.ID }, limit, afterID), nil
}

// UpdateVendorOrg changes a vendor's organization label; ErrNotFound if absent.
func (m *Memstore) UpdateVendorOrg(_ context.Context, id int64, org string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.vendors[id]
	if !ok {
		return store.ErrNotFound
	}
	v.Org = org
	m.vendors[id] = v
	return nil
}

// UpdateVendorEmail sets the vendor's on-file contact address, or ErrNotFound.
func (m *Memstore) UpdateVendorEmail(_ context.Context, id int64, email string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.vendors[id]
	if !ok {
		return store.ErrNotFound
	}
	v.Email = email
	m.vendors[id] = v
	return nil
}

// CreateVendorGrant records a pending contract grant; ErrNotFound if the vendor
// or target is missing.
func (m *Memstore) CreateVendorGrant(_ context.Context, g *store.VendorGrant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.vendors[g.VendorID]; !ok {
		return store.ErrNotFound
	}
	if _, ok := m.targets[g.TargetID]; !ok {
		return store.ErrNotFound
	}
	if g.Status == "" {
		g.Status = "pending"
	}
	g.ID = m.id()
	g.CreatedAt = time.Now().UTC()
	m.vendorGrants[g.ID] = *g
	return nil
}

// ApproveVendorGrant flips a pending grant to approved; ErrNotFound if unknown,
// ErrConflict if not pending.
func (m *Memstore) ApproveVendorGrant(_ context.Context, id int64, approver string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.vendorGrants[id]
	if !ok {
		return store.ErrNotFound
	}
	if g.Status != "pending" {
		return store.ErrConflict
	}
	g.Status = "approved"
	g.Approver = approver
	t := at.UTC()
	g.ApprovedAt = &t
	m.vendorGrants[id] = g
	return nil
}

// RevokeVendorGrant marks a grant revoked; ErrNotFound if unknown.
func (m *Memstore) RevokeVendorGrant(_ context.Context, id int64, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.vendorGrants[id]
	if !ok {
		return store.ErrNotFound
	}
	g.Status = "revoked"
	t := at.UTC()
	g.RevokedAt = &t
	m.vendorGrants[id] = g
	return nil
}

// ListVendorGrants lists a vendor's grants, newest first.
func (m *Memstore) ListVendorGrants(_ context.Context, vendorID int64) ([]store.VendorGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.VendorGrant
	for _, g := range m.vendorGrants {
		if g.VendorID != vendorID {
			continue
		}
		g.NotBefore = cloneTimePtr(g.NotBefore)
		g.ApprovedAt = cloneTimePtr(g.ApprovedAt)
		g.RevokedAt = cloneTimePtr(g.RevokedAt)
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

// OffboardVendor disables the vendor and revokes all its grants.
func (m *Memstore) OffboardVendor(_ context.Context, id int64, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.vendors[id]
	if !ok {
		return store.ErrNotFound
	}
	v.Disabled = true
	m.vendors[id] = v
	t := at.UTC()
	for gid, g := range m.vendorGrants {
		if g.VendorID == id && g.Status != "revoked" {
			g.Status = "revoked"
			rt := t
			g.RevokedAt = &rt
			m.vendorGrants[gid] = g
		}
	}
	return nil
}

// VendorSessionAllowed reports whether username is a vendor and, if so, whether an
// active contract grant to targetName exists as of now.
func (m *Memstore) VendorSessionAllowed(_ context.Context, username, targetName, account string, now time.Time) (bool, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var vendor *store.Vendor
	for _, v := range m.vendors {
		if v.Username == username {
			vv := v
			vendor = &vv
			break
		}
	}
	if vendor == nil {
		return false, true, nil // not a vendor — unaffected
	}
	if vendor.Disabled {
		return true, false, nil
	}
	var targetID int64
	for _, t := range m.targets {
		if t.Name == targetName {
			targetID = t.ID
			break
		}
	}
	if targetID == 0 {
		return true, false, nil
	}
	for _, g := range m.vendorGrants {
		if g.VendorID == vendor.ID && g.TargetID == targetID && vendorGrantActive(g, now) &&
			(account == "" || g.Principal == "" || g.Principal == account) {
			return true, true, nil
		}
	}
	return true, false, nil
}

// vendorGrantActive reports whether a grant is approved, unrevoked, and now within
// its window.
func vendorGrantActive(g store.VendorGrant, now time.Time) bool {
	return g.Status == "approved" && g.RevokedAt == nil &&
		now.Before(g.NotAfter) &&
		(g.NotBefore == nil || !now.Before(*g.NotBefore))
}

// CreateSessionShareInvite records a pending session-share request.
func (m *Memstore) CreateSessionShareInvite(_ context.Context, inv *store.SessionShareInvite) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv.ID = m.id()
	inv.CreatedAt = time.Now().UTC()
	m.shareInvites[inv.ID] = *inv
	return nil
}

// GetSessionShareInvite returns one invite by id, or ErrNotFound.
func (m *Memstore) GetSessionShareInvite(_ context.Context, id int64) (*store.SessionShareInvite, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.shareInvites[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	out := inv
	return &out, nil
}

// ListSessionShareInvites lists a session's invites, newest first.
func (m *Memstore) ListSessionShareInvites(_ context.Context, sessionID string) ([]store.SessionShareInvite, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.SessionShareInvite, 0)
	for _, inv := range m.shareInvites {
		if inv.SessionID == sessionID {
			out = append(out, inv)
		}
	}
	// Newest first with an id tie-break, matching pgstore's ORDER BY, so two
	// rows created in one instant order the same way in both stores.
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

// DecideSessionShareInvite records an approve/deny decision; ErrNotFound if
// unknown. The caller (matching DecideAccessRequest's own convention) is
// responsible for checking the invite is still pending before calling this.
func (m *Memstore) DecideSessionShareInvite(_ context.Context, id int64, status, approver string, at time.Time, tokenHash string, expiresAt *time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.shareInvites[id]
	if !ok {
		return store.ErrNotFound
	}
	inv.Status = status
	inv.Approver = approver
	decided := at.UTC()
	inv.DecidedAt = &decided
	if status == "approved" {
		inv.TokenHash = tokenHash
		if expiresAt != nil {
			exp := expiresAt.UTC()
			inv.ExpiresAt = &exp
		}
	}
	m.shareInvites[id] = inv
	return nil
}

// RevokeSessionShareInvite marks an invite revoked, or ErrNotFound.
func (m *Memstore) RevokeSessionShareInvite(_ context.Context, id int64, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.shareInvites[id]
	if !ok {
		return store.ErrNotFound
	}
	revoked := at.UTC()
	inv.RevokedAt = &revoked
	m.shareInvites[id] = inv
	return nil
}

// ConsumeSessionShareInviteByTokenHash atomically redeems an approved,
// unexpired, unrevoked, not-yet-consumed invite matching tokenHash.
func (m *Memstore) ConsumeSessionShareInviteByTokenHash(_ context.Context, tokenHash string, now time.Time) (*store.SessionShareInvite, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, inv := range m.shareInvites {
		if inv.TokenHash == "" || inv.TokenHash != tokenHash {
			continue
		}
		if inv.Status != "approved" || inv.RevokedAt != nil || inv.ConsumedAt != nil {
			return nil, store.ErrNotFound
		}
		if inv.ExpiresAt == nil || !now.Before(*inv.ExpiresAt) {
			return nil, store.ErrNotFound
		}
		consumed := now.UTC()
		inv.ConsumedAt = &consumed
		m.shareInvites[id] = inv
		out := inv
		return &out, nil
	}
	return nil, store.ErrNotFound
}

// CreateApprovalInvite records a new magic-link invite; the caller has
// already generated and hashed the token and computed ExpiresAt.
func (m *Memstore) CreateApprovalInvite(_ context.Context, inv *store.ApprovalInvite) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// The two constraints approval_invites carries in pgstore (a foreign key to
	// the request, a unique token hash) — matched here so the contract suite
	// holds both stores to them (Phase 217).
	if _, ok := m.accessReq[inv.AccessRequestID]; !ok {
		return store.ErrNotFound
	}
	for _, existing := range m.approvalInvites {
		if existing.TokenHash == inv.TokenHash {
			return store.ErrConflict
		}
	}
	inv.ID = m.id()
	inv.CreatedAt = time.Now().UTC()
	m.approvalInvites[inv.ID] = *inv
	return nil
}

// GetApprovalInvite returns one invite by id, or ErrNotFound.
func (m *Memstore) GetApprovalInvite(_ context.Context, id int64) (*store.ApprovalInvite, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.approvalInvites[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	out := inv
	return &out, nil
}

// ListApprovalInvitesForRequest lists an access request's invites, newest first.
func (m *Memstore) ListApprovalInvitesForRequest(_ context.Context, accessRequestID int64) ([]store.ApprovalInvite, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.ApprovalInvite, 0)
	for _, inv := range m.approvalInvites {
		if inv.AccessRequestID == accessRequestID {
			out = append(out, inv)
		}
	}
	// Newest first with an id tie-break, matching pgstore's ORDER BY, so two
	// rows created in one instant order the same way in both stores.
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

// RevokeApprovalInvite marks an invite revoked, or ErrNotFound.
func (m *Memstore) RevokeApprovalInvite(_ context.Context, id int64, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.approvalInvites[id]
	if !ok {
		return store.ErrNotFound
	}
	revoked := at.UTC()
	inv.RevokedAt = &revoked
	m.approvalInvites[id] = inv
	return nil
}

// GetApprovalInviteByTokenHash is the non-consuming preview lookup: it
// refuses (ErrNotFound) an unknown, expired, revoked or already-consumed
// invite, but does not itself write anything.
func (m *Memstore) GetApprovalInviteByTokenHash(_ context.Context, tokenHash string) (*store.ApprovalInvite, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, inv := range m.approvalInvites {
		if inv.TokenHash != tokenHash {
			continue
		}
		if inv.RevokedAt != nil || inv.ConsumedAt != nil || !time.Now().Before(inv.ExpiresAt) {
			return nil, store.ErrNotFound
		}
		out := inv
		return &out, nil
	}
	return nil, store.ErrNotFound
}

// ConsumeApprovalInviteByTokenHash atomically redeems an unexpired,
// unrevoked, not-yet-consumed invite matching tokenHash.
func (m *Memstore) ConsumeApprovalInviteByTokenHash(_ context.Context, tokenHash string, now time.Time) (*store.ApprovalInvite, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, inv := range m.approvalInvites {
		if inv.TokenHash != tokenHash {
			continue
		}
		if inv.RevokedAt != nil || inv.ConsumedAt != nil || !now.Before(inv.ExpiresAt) {
			return nil, store.ErrNotFound
		}
		consumed := now.UTC()
		inv.ConsumedAt = &consumed
		m.approvalInvites[id] = inv
		out := inv
		return &out, nil
	}
	return nil, store.ErrNotFound
}

// RecordApprovalInviteDecision stamps the outcome on an already-consumed
// invite, or ErrNotFound.
func (m *Memstore) RecordApprovalInviteDecision(_ context.Context, id int64, decision string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.approvalInvites[id]
	if !ok {
		return store.ErrNotFound
	}
	inv.Decision = decision
	m.approvalInvites[id] = inv
	return nil
}

// GetAgentKey returns an agent key by ID (regardless of disabled), or ErrNotFound.
func (m *Memstore) GetAgentKey(_ context.Context, id int64) (*store.AgentKey, error) {
	return getRow(m, m.agentKeys, id)
}

// CreateAppKey inserts an application key; ErrConflict if the token hash is taken.
func (m *Memstore) CreateAppKey(_ context.Context, k *store.AppKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.appKeys {
		if existing.TokenHash == k.TokenHash {
			return store.ErrConflict
		}
	}
	k.ID = m.id()
	k.CreatedAt = time.Now().UTC()
	m.appKeys[k.ID] = *k
	return nil
}

// GetAppKeyByTokenHash returns the enabled app key whose token hash matches, or
// ErrNotFound (a disabled key is treated as not found).
func (m *Memstore) GetAppKeyByTokenHash(_ context.Context, tokenHashHex string) (*store.AppKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range m.appKeys {
		if k.TokenHash == tokenHashHex && !k.Disabled {
			out := k
			return &out, nil
		}
	}
	return nil, store.ErrNotFound
}

// ListAppKeys returns all application keys ordered by ID.
func (m *Memstore) ListAppKeys(_ context.Context) ([]store.AppKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.AppKey, 0, len(m.appKeys))
	for _, k := range m.appKeys {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// DeleteAppKey removes an app key by ID (cascading its secret grants), or ErrNotFound.
func (m *Memstore) DeleteAppKey(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.appKeys[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.appKeys, id)
	// pgstore FK cascades the app's grants on delete — match it.
	for gid, g := range m.appGrants {
		if g.AppID == id {
			delete(m.appGrants, gid)
		}
	}
	return nil
}

// CreateScimKey inserts a SCIM client identity key, assigning its ID and
// CreatedAt; ErrConflict if the token hash is taken.
func (m *Memstore) CreateScimKey(_ context.Context, k *store.ScimKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.scimKeys {
		if existing.TokenHash == k.TokenHash {
			return store.ErrConflict
		}
	}
	k.ID = m.id()
	k.CreatedAt = time.Now().UTC()
	m.scimKeys[k.ID] = *k
	return nil
}

// GetScimKeyByTokenHash returns the enabled SCIM key whose token hash
// matches, or ErrNotFound (a disabled key is treated as not found).
func (m *Memstore) GetScimKeyByTokenHash(_ context.Context, tokenHashHex string) (*store.ScimKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range m.scimKeys {
		if k.TokenHash == tokenHashHex && !k.Disabled {
			out := k
			return &out, nil
		}
	}
	return nil, store.ErrNotFound
}

// ListScimKeys returns all SCIM client keys ordered by ID.
func (m *Memstore) ListScimKeys(_ context.Context) ([]store.ScimKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.ScimKey, 0, len(m.scimKeys))
	for _, k := range m.scimKeys {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// DeleteScimKey removes a SCIM key by ID, or ErrNotFound.
func (m *Memstore) DeleteScimKey(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.scimKeys[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.scimKeys, id)
	return nil
}

// CreateEndpointAgent inserts an endpoint agent, assigning ID and CreatedAt;
// ErrConflict on a duplicate key hash or a second live agent for the target,
// ErrNotFound if the target does not exist.
func (m *Memstore) CreateEndpointAgent(_ context.Context, a *store.EndpointAgent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.targets[a.TargetID]; !ok {
		return store.ErrNotFound
	}
	for _, existing := range m.endpointAgents {
		if existing.KeyHash == a.KeyHash || (existing.TargetID == a.TargetID && existing.RevokedAt == nil) {
			return store.ErrConflict
		}
	}
	a.ID = m.id()
	a.CreatedAt = time.Now().UTC()
	m.endpointAgents[a.ID] = *a
	return nil
}

// GetEndpointAgentByKeyHash returns the agent (revoked or not) whose key hash
// matches, or ErrNotFound.
func (m *Memstore) GetEndpointAgentByKeyHash(_ context.Context, keyHashHex string) (*store.EndpointAgent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.endpointAgents {
		if a.KeyHash == keyHashHex {
			out := a
			return &out, nil
		}
	}
	return nil, store.ErrNotFound
}

// GetEndpointAgentForTarget returns the target's unrevoked agent, or ErrNotFound.
func (m *Memstore) GetEndpointAgentForTarget(_ context.Context, targetID int64) (*store.EndpointAgent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.endpointAgents {
		if a.TargetID == targetID && a.RevokedAt == nil {
			out := a
			return &out, nil
		}
	}
	return nil, store.ErrNotFound
}

// ListEndpointAgents returns every endpoint agent ordered by ID.
func (m *Memstore) ListEndpointAgents(_ context.Context) ([]store.EndpointAgent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.EndpointAgent, 0, len(m.endpointAgents))
	for _, a := range m.endpointAgents {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// RevokeEndpointAgent stamps RevokedAt (left alone if already set); ErrNotFound if absent.
func (m *Memstore) RevokeEndpointAgent(_ context.Context, id int64, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.endpointAgents[id]
	if !ok {
		return store.ErrNotFound
	}
	if a.RevokedAt == nil {
		t := at.UTC()
		a.RevokedAt = &t
		m.endpointAgents[id] = a
	}
	return nil
}

// TouchEndpointAgent records the agent's last connection time; ErrNotFound if absent.
func (m *Memstore) TouchEndpointAgent(_ context.Context, id int64, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.endpointAgents[id]
	if !ok {
		return store.ErrNotFound
	}
	t := at.UTC()
	a.LastSeen = &t
	m.endpointAgents[id] = a
	return nil
}

// GrantAppSecret authorizes an app to retrieve a credential's secret (ErrConflict
// on a duplicate grant, ErrNotFound if the app or credential is missing).
func (m *Memstore) GrantAppSecret(_ context.Context, g *store.AppSecretGrant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.appKeys[g.AppID]; !ok {
		return store.ErrNotFound
	}
	if _, ok := m.creds[g.CredentialID]; !ok {
		return store.ErrNotFound
	}
	for _, existing := range m.appGrants {
		if existing.AppID == g.AppID && existing.CredentialID == g.CredentialID {
			return store.ErrConflict
		}
	}
	g.ID = m.id()
	g.CreatedAt = time.Now().UTC()
	m.appGrants[g.ID] = *g
	return nil
}

// ListAppSecretGrants returns an app's secret grants ordered by id.
func (m *Memstore) ListAppSecretGrants(_ context.Context, appID int64) ([]store.AppSecretGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.AppSecretGrant, 0)
	for _, g := range m.appGrants {
		if g.AppID == appID {
			out = append(out, g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// DeleteAppSecretGrant removes a grant by ID, or ErrNotFound.
func (m *Memstore) DeleteAppSecretGrant(_ context.Context, id int64) error {
	return deleteRow(m, m.appGrants, id)
}

// SetAppGrantAlias sets or clears a grant's stable name, refusing a collision
// within the same app the way the partial unique index does in Postgres.
func (m *Memstore) SetAppGrantAlias(_ context.Context, grantID int64, alias string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.appGrants[grantID]
	if !ok {
		return store.ErrNotFound
	}
	if alias != "" {
		for id, other := range m.appGrants {
			if id != grantID && other.AppID == g.AppID && other.Alias == alias {
				return store.ErrConflict
			}
		}
	}
	g.Alias = alias
	m.appGrants[grantID] = g
	return nil
}

// AppCredentialByAlias resolves an alias within one app's own grants.
func (m *Memstore) AppCredentialByAlias(_ context.Context, appID int64, alias string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if alias == "" {
		return 0, store.ErrNotFound
	}
	for _, g := range m.appGrants {
		if g.AppID == appID && g.Alias == alias {
			return g.CredentialID, nil
		}
	}
	return 0, store.ErrNotFound
}

// AppMayAccessCredential reports whether app appID has a grant for credentialID.
func (m *Memstore) AppMayAccessCredential(_ context.Context, appID, credentialID int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, g := range m.appGrants {
		if g.AppID == appID && g.CredentialID == credentialID {
			return true, nil
		}
	}
	return false, nil
}

// CreateBrokerToken stores a single-use resume token for a parked tool call.
func (m *Memstore) CreateBrokerToken(_ context.Context, t *store.BrokerToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.brokerTok[t.JTI]; exists {
		return store.ErrConflict // match pgstore's PK-violation semantics
	}
	m.brokerTok[t.JTI] = *t
	return nil
}

// ConsumeBrokerToken spends a token under the lock, so only the first caller
// wins; a used, expired, or unknown jti returns ErrNotFound.
func (m *Memstore) ConsumeBrokerToken(_ context.Context, jti string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.brokerTok[jti]
	if !ok || t.UsedAt != nil || time.Now().After(t.ExpiresAt) {
		return "", store.ErrNotFound
	}
	now := time.Now().UTC()
	t.UsedAt = &now
	m.brokerTok[jti] = t
	return t.CallID, nil
}

// PeekBrokerToken returns a token's bound call id without spending it.
func (m *Memstore) PeekBrokerToken(_ context.Context, jti string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.brokerTok[jti]
	if !ok || t.UsedAt != nil || time.Now().After(t.ExpiresAt) {
		return "", store.ErrNotFound
	}
	return t.CallID, nil
}

// DeleteExpiredBrokerTokens removes spent or expired tokens (periodic GC).
func (m *Memstore) DeleteExpiredBrokerTokens(_ context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	now := time.Now()
	for jti, t := range m.brokerTok {
		if t.UsedAt != nil || now.After(t.ExpiresAt) {
			delete(m.brokerTok, jti)
			n++
		}
	}
	return n, nil
}

// EnsureKeyMaterial claims custody of a named key under the store lock, so even
// in-process racers converge on one value — the same guarantee pgstore gets from
// the primary key.
func (m *Memstore) EnsureKeyMaterial(_ context.Context, name, value string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.keyMaterial[name]; ok {
		return existing, nil
	}
	m.keyMaterial[name] = value
	return value, nil
}

// ListKeyMaterial returns every named key envelope, ordered by name.
func (m *Memstore) ListKeyMaterial(_ context.Context) ([]store.KeyMaterial, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.KeyMaterial, 0, len(m.keyMaterial))
	for name, value := range m.keyMaterial {
		out = append(out, store.KeyMaterial{Name: name, Value: value})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// UpdateKeyMaterial replaces a named key's envelope; ErrNotFound if absent.
func (m *Memstore) UpdateKeyMaterial(_ context.Context, name, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.keyMaterial[name]; !ok {
		return store.ErrNotFound
	}
	m.keyMaterial[name] = value
	return nil
}

// PutSetting upserts a configuration override, stamping UpdatedAt.
func (m *Memstore) PutSetting(_ context.Context, s *store.Setting) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s.UpdatedAt = time.Now().UTC()
	m.settings[s.Key] = *s
	return nil
}

// GetSetting returns the override for key, or ErrNotFound.
func (m *Memstore) GetSetting(_ context.Context, key string) (*store.Setting, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.settings[key]; ok {
		out := s
		return &out, nil
	}
	return nil, store.ErrNotFound
}

// ListSettings returns all configuration overrides ordered by key.
func (m *Memstore) ListSettings(_ context.Context) ([]store.Setting, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.Setting, 0, len(m.settings))
	for _, s := range m.settings {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// DeleteSetting removes the override for key; ErrNotFound if absent.
func (m *Memstore) DeleteSetting(_ context.Context, key string) error {
	return deleteRow(m, m.settings, key)
}

// CreateProfile inserts a custom permission profile; ErrConflict on a duplicate name.
func (m *Memstore) CreateProfile(_ context.Context, p *store.Profile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.profiles {
		if e.Name == p.Name {
			return store.ErrConflict
		}
	}
	p.ID = m.id()
	p.CreatedAt = time.Now().UTC()
	m.profiles[p.ID] = cloneProfile(*p)
	return nil
}

// GetProfile returns the profile with the given name, or ErrNotFound.
func (m *Memstore) GetProfile(_ context.Context, name string) (*store.Profile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.profiles {
		if p.Name == name {
			out := cloneProfile(p)
			return &out, nil
		}
	}
	return nil, store.ErrNotFound
}

// ListProfiles returns all custom profiles ordered by name.
func (m *Memstore) ListProfiles(_ context.Context) ([]store.Profile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.Profile, 0, len(m.profiles))
	for _, p := range m.profiles {
		out = append(out, cloneProfile(p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// DeleteProfile removes a profile by ID; ErrNotFound if absent.
func (m *Memstore) DeleteProfile(_ context.Context, id int64) error {
	return deleteRow(m, m.profiles, id)
}

// AppendBrokerAuditLinked links the event to the current head and appends it
// under the store mutex — the single-process analogue of pgstore's advisory
// lock — assigning ID and TS. Reading the head and appending are one atomic
// step, so an appender's cached head is only advisory.
func (m *Memstore) AppendBrokerAuditLinked(_ context.Context, link func(head *store.BrokerAuditEvent) store.BrokerAuditEvent) (store.BrokerAuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var head *store.BrokerAuditEvent
	if n := len(m.brokerLog); n > 0 {
		h := cloneBrokerEvent(m.brokerLog[n-1])
		head = &h
	}
	ev := link(head)
	ev.ID = m.id()
	ev.TS = time.Now().UTC()
	// Deep-copy the hash-chain byte slices so the stored row can't alias (and be
	// mutated through) the returned event — parity with pgstore's fresh scans.
	m.brokerLog = append(m.brokerLog, cloneBrokerEvent(ev))
	return ev, nil
}

// cloneBrokerEvent returns a copy whose PrevHash/HMAC byte slices are independent
// of the argument, so stored and returned rows never alias.
func cloneBrokerEvent(e store.BrokerAuditEvent) store.BrokerAuditEvent {
	e.PrevHash = append([]byte(nil), e.PrevHash...)
	e.HMAC = append([]byte(nil), e.HMAC...)
	return e
}

// ListBrokerAudit returns broker audit events oldest-first; limit <= 0 returns
// the whole chain, limit > 0 the most recent limit events (still in chain order).
func (m *Memstore) ListBrokerAudit(_ context.Context, limit int) ([]store.BrokerAuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := len(m.brokerLog)
	start := 0
	if limit > 0 && limit < n {
		start = n - limit
	}
	out := make([]store.BrokerAuditEvent, 0, n-start)
	for _, e := range m.brokerLog[start:] {
		out = append(out, cloneBrokerEvent(e))
	}
	return out, nil
}

// GetBrokerAuditHead returns the most recent broker audit event, or (nil, nil)
// when the log is empty.
func (m *Memstore) GetBrokerAuditHead(_ context.Context) (*store.BrokerAuditEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.brokerLog) == 0 {
		return nil, nil
	}
	out := cloneBrokerEvent(m.brokerLog[len(m.brokerLog)-1])
	return &out, nil
}

// CreateSession inserts a session, assigning its ID and CreatedAt.
func (m *Memstore) CreateSession(_ context.Context, s *store.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s.ID = m.id()
	s.CreatedAt = time.Now().UTC()
	m.sessions[s.ID] = *s
	return nil
}

// GetSessionByTokenHash returns a non-expired session matching the token hash,
// or ErrNotFound.
func (m *Memstore) GetSessionByTokenHash(_ context.Context, tokenHashHex string) (*store.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for _, s := range m.sessions {
		if s.TokenHash == tokenHashHex {
			if now.After(s.ExpiresAt) {
				return nil, store.ErrNotFound
			}
			return &s, nil
		}
	}
	return nil, store.ErrNotFound
}

// DeleteSession removes the session with the given token hash; ErrNotFound if absent.
func (m *Memstore) DeleteSession(_ context.Context, tokenHashHex string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.sessions {
		if s.TokenHash == tokenHashHex {
			delete(m.sessions, id)
			return nil
		}
	}
	return store.ErrNotFound
}

// ListSessions returns all non-expired login sessions, newest first.
func (m *Memstore) ListSessions(_ context.Context) ([]store.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	out := make([]store.Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		if now.After(s.ExpiresAt) {
			continue
		}
		out = append(out, s)
	}
	// Newest first, with a stable id tiebreak so two sessions created in the same
	// instant order deterministically — matching pgstore's ORDER BY, so the two
	// implementations cannot disagree on an ordering the contract test can compare.
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

// DeleteSessionsByUsername revokes every session for a username, returning the count.
func (m *Memstore) DeleteSessionsByUsername(_ context.Context, username string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, s := range m.sessions {
		if s.Username == username {
			delete(m.sessions, id)
			n++
		}
	}
	return n, nil
}

// DeleteExpiredSessions removes login sessions past their expiry. In memstore
// this is the difference between a bounded map and one that grows by an entry
// per RDP viewer token for the life of the process.
func (m *Memstore) DeleteExpiredSessions(_ context.Context, now time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for id, s := range m.sessions {
		if !s.ExpiresAt.After(now) {
			delete(m.sessions, id)
			n++
		}
	}
	return n, nil
}

// UpsertMFAEnrollment creates or replaces a user's TOTP enrollment.
func (m *Memstore) UpsertMFAEnrollment(_ context.Context, e *store.MFAEnrollment) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	m.mfa[e.Username] = *e
	return nil
}

// GetMFAEnrollment returns a user's TOTP enrollment, or ErrNotFound.
func (m *Memstore) GetMFAEnrollment(_ context.Context, username string) (*store.MFAEnrollment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.mfa[username]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &e, nil
}

// ConsumeTOTPStep records step as the user's last-used TOTP step, returning true
// only if it is newer than the stored one (else it is a replay).
func (m *Memstore) ConsumeTOTPStep(_ context.Context, username string, step int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.mfa[username]
	if !ok {
		return false, nil
	}
	if step > e.LastTOTPStep {
		e.LastTOTPStep = step
		m.mfa[username] = e
		return true, nil
	}
	return false, nil
}

// ListMFAEnrollments returns all enrollments ordered by username.
func (m *Memstore) ListMFAEnrollments(_ context.Context) ([]store.MFAEnrollment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]store.MFAEnrollment, 0, len(m.mfa))
	for _, e := range m.mfa {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}

// DeleteMFAEnrollment removes a user's enrollment and any recovery codes;
// ErrNotFound if the enrollment is absent.
func (m *Memstore) DeleteMFAEnrollment(_ context.Context, username string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.mfa[username]; !ok {
		return store.ErrNotFound
	}
	delete(m.mfa, username)
	delete(m.recovery, username)
	return nil
}

// ReplaceMFARecoveryCodes stores a fresh set of recovery-code hashes for a user,
// discarding any previous set.
func (m *Memstore) ReplaceMFARecoveryCodes(_ context.Context, username string, codeHashes []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	set := make(map[string]bool, len(codeHashes))
	for _, h := range codeHashes {
		set[h] = true
	}
	m.recovery[username] = set
	return nil
}

// ConsumeMFARecoveryCode removes a matching unused recovery code and reports
// whether one was consumed.
func (m *Memstore) ConsumeMFARecoveryCode(_ context.Context, username, codeHash string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	set := m.recovery[username]
	if set == nil || !set[codeHash] {
		return false, nil
	}
	delete(set, codeHash)
	return true, nil
}

// CountMFARecoveryCodes returns how many recovery codes remain for a user.
func (m *Memstore) CountMFARecoveryCodes(_ context.Context, username string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.recovery[username]), nil
}

type oidcState struct {
	verifier, nonce string
	expiresAt       time.Time
}

// PutOIDCState stores PKCE verifier/nonce state for an OIDC login, sweeping
// expired entries first.
func (m *Memstore) PutOIDCState(_ context.Context, state, verifier, nonce string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.oidcStates == nil {
		m.oidcStates = make(map[string]oidcState)
	}
	now := time.Now()
	for k, v := range m.oidcStates { // opportunistic expiry sweep
		if now.After(v.expiresAt) {
			delete(m.oidcStates, k)
		}
	}
	m.oidcStates[state] = oidcState{verifier: verifier, nonce: nonce, expiresAt: expiresAt.UTC()}
	return nil
}

// TakeOIDCState atomically fetches and deletes an unexpired state; ok is false
// if it is missing or expired.
func (m *Memstore) TakeOIDCState(_ context.Context, state string, now time.Time) (string, string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.oidcStates[state]
	if ok {
		delete(m.oidcStates, state)
	}
	if !ok || now.After(s.expiresAt) {
		return "", "", false, nil
	}
	return s.verifier, s.nonce, true, nil
}

// CreateWebAuthnCredential registers a new authenticator, populating ID and CreatedAt.
func (m *Memstore) CreateWebAuthnCredential(_ context.Context, c *store.WebAuthnCredential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c.ID = m.id()
	c.CreatedAt = time.Now().UTC()
	m.webauthnCreds[c.ID] = *c
	return nil
}

// ListWebAuthnCredentials returns every authenticator a user has registered, oldest first.
func (m *Memstore) ListWebAuthnCredentials(_ context.Context, username string) ([]store.WebAuthnCredential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.WebAuthnCredential
	for _, c := range m.webauthnCreds {
		if c.Username == username {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// GetWebAuthnCredentialByCredentialID looks up an authenticator by the credential ID an assertion presents, or ErrNotFound.
func (m *Memstore) GetWebAuthnCredentialByCredentialID(_ context.Context, credentialID []byte) (*store.WebAuthnCredential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.webauthnCreds {
		if bytes.Equal(c.CredentialID, credentialID) {
			cc := c
			return &cc, nil
		}
	}
	return nil, store.ErrNotFound
}

// UpdateWebAuthnSignCount writes back the sign counter, clone-warning flag and last-used time after a successful login.
func (m *Memstore) UpdateWebAuthnSignCount(_ context.Context, id int64, signCount uint32, cloneWarning bool, usedAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.webauthnCreds[id]
	if !ok {
		return store.ErrNotFound
	}
	c.SignCount = signCount
	c.CloneWarning = cloneWarning
	t := usedAt.UTC()
	c.LastUsedAt = &t
	m.webauthnCreds[id] = c
	return nil
}

// DeleteWebAuthnCredential removes one authenticator by ID, scoped to username, or ErrNotFound.
func (m *Memstore) DeleteWebAuthnCredential(_ context.Context, id int64, username string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.webauthnCreds[id]
	if !ok || c.Username != username {
		return store.ErrNotFound
	}
	delete(m.webauthnCreds, id)
	return nil
}

// webauthnChalKey is the composite (username, purpose) key mfa_webauthn_challenges uses.
type webauthnChalKey struct{ username, purpose string }

type webauthnChallenge struct {
	sessionData []byte
	expiresAt   time.Time
}

// PutWebAuthnChallenge stores (or replaces) the in-flight ceremony state for a
// (username, purpose) pair, sweeping expired entries first.
func (m *Memstore) PutWebAuthnChallenge(_ context.Context, username, purpose string, sessionData []byte, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for k, v := range m.webauthnChal { // opportunistic expiry sweep
		if now.After(v.expiresAt) {
			delete(m.webauthnChal, k)
		}
	}
	m.webauthnChal[webauthnChalKey{username, purpose}] = webauthnChallenge{sessionData: sessionData, expiresAt: expiresAt.UTC()}
	return nil
}

// TakeWebAuthnChallenge atomically fetches and deletes an unexpired challenge; ok is false if it is missing or expired.
func (m *Memstore) TakeWebAuthnChallenge(_ context.Context, username, purpose string, now time.Time) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := webauthnChalKey{username, purpose}
	c, ok := m.webauthnChal[key]
	if ok {
		delete(m.webauthnChal, key)
	}
	if !ok || now.After(c.expiresAt) {
		return nil, false, nil
	}
	return c.sessionData, true, nil
}

// Ping always succeeds for the in-memory store.
func (m *Memstore) Ping(_ context.Context) error { return nil }

// WithLeaderLock always runs fn: the in-memory store is single-process, so there
// is no other replica to coordinate with.
func (m *Memstore) WithLeaderLock(ctx context.Context, _ int64, fn func(context.Context) error) (bool, error) {
	return true, fn(ctx)
}

// Close is a no-op for the in-memory store.
func (m *Memstore) Close() {}
