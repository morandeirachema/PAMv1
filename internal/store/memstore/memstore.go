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
	mu            sync.Mutex
	nextID        int64
	targets       map[int64]store.Target
	creds         map[int64]store.Credential
	users         map[int64]store.User
	sessions      map[int64]store.Session
	mfa           map[string]store.MFAEnrollment
	recovery      map[string]map[string]bool // username -> set of code hashes
	grants        map[int64]store.TargetGrant
	accessReq     map[int64]store.AccessRequest
	checkouts     map[int64]store.Checkout
	oidcStates    map[string]oidcState
	audit         []store.AuditEvent
	auditKey      []byte // set ⇒ chain the primary audit trail
	agentKeys     map[int64]store.AgentKey
	sshCerts      map[int64]store.SSHCert
	vendors       map[int64]store.Vendor
	vendorGrants  map[int64]store.VendorGrant
	appKeys       map[int64]store.AppKey
	appGrants     map[int64]store.AppSecretGrant
	brokerLog     []store.BrokerAuditEvent
	brokerTok     map[string]store.BrokerToken
	settings      map[string]store.Setting
	keyMaterial   map[string]string
	profiles      map[int64]store.Profile
	safes         map[int64]store.Safe
	safeMembers   map[int64]store.SafeMember
	credDeps      map[int64]store.CredentialDependency
	campaigns     map[int64]store.Campaign
	campaignItems map[int64]store.CampaignItem

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
		targets:       make(map[int64]store.Target),
		creds:         make(map[int64]store.Credential),
		users:         make(map[int64]store.User),
		sessions:      make(map[int64]store.Session),
		mfa:           make(map[string]store.MFAEnrollment),
		recovery:      make(map[string]map[string]bool),
		grants:        make(map[int64]store.TargetGrant),
		accessReq:     make(map[int64]store.AccessRequest),
		checkouts:     make(map[int64]store.Checkout),
		agentKeys:     make(map[int64]store.AgentKey),
		sshCerts:      make(map[int64]store.SSHCert),
		vendors:       make(map[int64]store.Vendor),
		vendorGrants:  make(map[int64]store.VendorGrant),
		appKeys:       make(map[int64]store.AppKey),
		appGrants:     make(map[int64]store.AppSecretGrant),
		brokerTok:     make(map[string]store.BrokerToken),
		settings:      make(map[string]store.Setting),
		keyMaterial:   make(map[string]string),
		profiles:      make(map[int64]store.Profile),
		safes:         make(map[int64]store.Safe),
		safeMembers:   make(map[int64]store.SafeMember),
		credDeps:      make(map[int64]store.CredentialDependency),
		campaigns:     make(map[int64]store.Campaign),
		campaignItems: make(map[int64]store.CampaignItem),
		killSubs:      make(map[chan session.KillSelector]struct{}),
		liveSessions:  make(map[string]liveRow),
		frameSubs:     make(map[chan session.LiveFrame]struct{}),
		interestSubs:  make(map[chan string]struct{}),
		stepups:       make(map[string]stepUpRow),
		stepupSubs:    make(map[chan session.StepUpDecision]struct{}),
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
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.targets[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &t, nil
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
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.grants[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.grants, id)
	return nil
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

// UpdateSafe replaces a safe's name and description; ErrNotFound if absent,
// ErrConflict if the new name belongs to another safe.
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
	m.safes[sf.ID] = *sf
	return nil
}

// GetSafe returns a safe by ID, or ErrNotFound.
func (m *Memstore) GetSafe(_ context.Context, id int64) (*store.Safe, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sf, ok := m.safes[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &sf, nil
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
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.safeMembers[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.safeMembers, id)
	return nil
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
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.credDeps[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.credDeps, id)
	return nil
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
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.campaigns[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &c, nil
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
	m.mu.Lock()
	defer m.mu.Unlock()
	it, ok := m.campaignItems[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &it, nil
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
	ar.Status = status
	ar.Approver = approver
	at := decidedAt.UTC()
	ar.DecidedAt = &at
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
// 0) in the (limit, afterID) window, ordered by ID.
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
// touching rotated_at; ErrNotFound if absent.
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

// RotateCredentialSecret replaces the encrypted secret and stamps rotated_at;
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
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &u, nil
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

// DeleteUser removes a user by ID; ErrNotFound if absent.
func (m *Memstore) DeleteUser(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.users, id)
	return nil
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

// DeleteAgentKey removes an agent key by ID; ErrNotFound if absent.
func (m *Memstore) DeleteAgentKey(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.agentKeys[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.agentKeys, id)
	return nil
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

// SetVendorDisabled enables/disables a vendor by id, or ErrNotFound.
func (m *Memstore) SetVendorDisabled(_ context.Context, id int64, disabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.vendors[id]
	if !ok {
		return store.ErrNotFound
	}
	v.Disabled = disabled
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

// GetAgentKey returns an agent key by ID (regardless of disabled), or ErrNotFound.
func (m *Memstore) GetAgentKey(_ context.Context, id int64) (*store.AgentKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.agentKeys[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &k, nil
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
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.appGrants[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.appGrants, id)
	return nil
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
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.settings[key]; !ok {
		return store.ErrNotFound
	}
	delete(m.settings, key)
	return nil
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
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.profiles[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.profiles, id)
	return nil
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
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
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

// Ping always succeeds for the in-memory store.
func (m *Memstore) Ping(_ context.Context) error { return nil }

// WithLeaderLock always runs fn: the in-memory store is single-process, so there
// is no other replica to coordinate with.
func (m *Memstore) WithLeaderLock(ctx context.Context, _ int64, fn func(context.Context) error) (bool, error) {
	return true, fn(ctx)
}

// Close is a no-op for the in-memory store.
func (m *Memstore) Close() {}
