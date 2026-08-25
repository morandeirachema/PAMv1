package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
)

// maxReachSubjectLen bounds the subject a caller may ask about. A SPIFFE ID is
// the longest legitimate value (an agent's canonical name IS its SVID subject),
// so this matches the cap the agent paths already use.
const maxReachSubjectLen = maxSPIFFEIDLen

// reachTarget is one reachable target as the API reports it: the target's
// identity, why the subject reaches it, and — for a grant that came through a
// safe — which safe, resolved to its name because an id is not an answer.
type reachTarget struct {
	TargetID    int64  `json:"target_id"`
	Target      string `json:"target"`
	Host        string `json:"host"`
	Protocol    string `json:"protocol"`
	Via         string `json:"via"`
	SubjectType string `json:"subject_type,omitempty"`
	Subject     string `json:"subject,omitempty"`
	Safe        string `json:"safe,omitempty"`
}

// reachResponse is the answer to "what can this subject reach?".
//
// Counts are by reason, because the shape of an answer is itself a finding:
// "reaches 40 targets, 37 of them because nothing gates them" is a very
// different posture from 40 deliberate grants, and a flat total hides it.
type reachResponse struct {
	Subject string `json:"subject"`
	Kind    string `json:"kind"`  // user | agent
	Known   bool   `json:"known"` // the subject exists in the registry for its kind
	// AgentKind names which registry an agent was found in: "key" (a pamv1-issued
	// static key), "identity" (a SPIFFE-attested workload) or "" when unknown.
	AgentKind string `json:"agent_kind,omitempty"`
	// Owner is the accountable human recorded for an agent identity or key.
	Owner string `json:"owner,omitempty"`
	// Roles are the roles the subject's access was evaluated with — the union a
	// grant may name it by, alongside its own name.
	Roles []string `json:"roles"`
	// Blocked lists every reason this subject cannot exercise the reach below
	// RIGHT NOW, drawn from its own state rather than from any target's: no
	// capability that can use a target at all, a deactivated account, a disabled
	// or expired agent key, a quarantined identity. Empty means nothing in the
	// subject's own state stands in the way.
	//
	// The targets are reported either way, and the total does not change. That
	// is the whole point of a standing-entitlement view: a suspended account's
	// grants are still grants, and they come back the moment somebody flips it
	// on. But "reaches 40 targets" and "would reach 40 targets if it could log
	// in" are different findings, and before this the answer could not tell them
	// apart — which is the failure mode that matters here, because every one of
	// these states makes the bare number an OVERSTATEMENT.
	Blocked []string       `json:"blocked"`
	Total   int            `json:"total"`
	Counts  map[string]int `json:"counts"`
	Targets []reachTarget  `json:"targets"`
}

// Why a subject cannot exercise its standing reach right now. Each is a fact
// about the SUBJECT — never about a target — so any of them applies to the
// whole answer at once.
const (
	// blockedNoCapability: the subject holds none of connect / reveal_secret /
	// call_tool, so no grant it holds can be acted on. An auditor is the
	// ordinary case, and its "open" rows are not the finding they look like.
	blockedNoCapability = "no_usable_capability"
	// blockedDeactivated: a local user with active=false (SCIM deprovisioning),
	// whose token auth.Resolver.Resolve refuses outright.
	blockedDeactivated = "deactivated"
	// blockedKeyDisabled: a static agent key revoked or suspended — which is
	// what a certification campaign's revoke does to one (Phase 175).
	blockedKeyDisabled = "key_disabled"
	// blockedKeyExpired: a static agent key past its expires_at (Phase 159).
	blockedKeyExpired = "key_expired"
	// blockedQuarantined: the identity is under the agent stop-switch (Phase
	// 159) — the one containment control that covers every agent kind.
	blockedQuarantined = "quarantined"
	// blockedNotEnrolled: an attested identity recorded on sight but claimed by
	// nobody (Phase 174), refused at the door wherever
	// PAM_BROKER_REQUIRE_ENROLLED_SVID is on.
	blockedNotEnrolled = "not_enrolled"
)

// subjectReach answers GET /api/access/reach?subject=<name>&kind=user|agent —
// the subject-indexed view of the grant model (Phase 189).
//
// Every other grant query in pamv1 is target-indexed ("who may reach this
// target?"), which is the question the connect gate asks. The question an
// investigator asks is the reverse one, and until now it could only be answered
// by walking every target and re-deriving the answer by hand. This route asks it
// directly, in four store reads regardless of estate size, through
// auth.ReachableTargets — the same CanConnectTarget decision, reproduced target
// for target and pinned by auth.TestReachMatchesCanConnect.
//
// What it reports is STANDING reachability: what the grant model admits. The
// other gates a connect attempt still passes — an access request's approval and
// its window, a vendor contract, a checkout, step-up, posture, maintenance
// windows, quarantine — can only ever narrow this list, never widen it, so the
// answer is an upper bound on what the subject can reach right now and a
// complete list of what it stands to reach at all. That is the right shape for a
// review: an entitlement nobody uses is still an entitlement.
//
// Read-only, guarded by CapReadAudit (admins, auditors and approvers), and
// audited — asking who can reach what across the whole estate is exactly the
// kind of question a reviewer should be able to see was asked.
func (s *Server) subjectReach(w http.ResponseWriter, r *http.Request) {
	subject := strings.TrimSpace(r.URL.Query().Get("subject"))
	if subject == "" {
		writeError(w, http.StatusBadRequest, "subject is required")
		return
	}
	if len(subject) > maxReachSubjectLen {
		writeError(w, http.StatusBadRequest, "subject is too long")
		return
	}
	kind := strings.TrimSpace(r.URL.Query().Get("kind"))
	if kind == "" {
		kind = "user"
	}
	if kind != "user" && kind != "agent" {
		writeError(w, http.StatusBadRequest, `kind must be "user" or "agent"`)
		return
	}

	ctx := r.Context()
	resp := reachResponse{Subject: subject, Kind: kind}
	var principal *auth.Principal

	if kind == "agent" {
		// An agent identity is one of two kinds, and BOTH are worth answering
		// for. A name in neither registry is not an error: "an unenrolled
		// workload that authenticates reaches these targets" is precisely the
		// question Phase 174's inventory left open, and refusing to answer it
		// would hide the ungated targets any agent in the trust domain reaches.
		// Known:false is how the caller tells the two apart.
		var blocked []string
		resp.AgentKind, resp.Owner, resp.Known, blocked = s.lookupAgentSubject(ctx, subject)
		resp.Blocked = append(resp.Blocked, blocked...)
		principal = &auth.Principal{Name: subject, Role: auth.RoleAgent}
	} else {
		u, err := s.store.GetUserByUsername(ctx, subject)
		if errors.Is(err, store.ErrNotFound) {
			// A directory-authenticated identity (AD/LDAP/Entra/OIDC/SAML) has no
			// local row and carries roles decided by group mapping at login, which
			// nothing here can know. Answering with the built-in defaults would be
			// inventing an identity, so the route says so instead.
			writeError(w, http.StatusNotFound,
				"no local user with that name; a directory-authenticated identity carries roles resolved at login and cannot be reviewed this way")
			return
		}
		if err != nil {
			storeError(w, err)
			return
		}
		p, err := s.resolver.PrincipalForRole(ctx, u.Username, u.Role)
		if err != nil {
			// An unresolvable role (a deleted custom profile) is fail-closed at
			// login, and must read the same way here rather than as "reaches
			// nothing because it has no roles".
			writeError(w, http.StatusUnprocessableEntity,
				fmt.Sprintf("user %q carries role/profile %q, which no longer resolves", u.Username, u.Role))
			return
		}
		principal, resp.Known = p, true
		if !u.Active {
			// SCIM deprovisioning (Phase 149). The row survives so that
			// re-activating restores access without minting a new token — which
			// is exactly why the entitlement is still worth listing, and exactly
			// why it must not read as live.
			resp.Blocked = append(resp.Blocked, blockedDeactivated)
		}
	}
	if !auth.CanUseAnyTarget(principal) {
		resp.Blocked = append(resp.Blocked, blockedNoCapability)
	}

	for _, sub := range auth.GrantSubjects(principal) {
		if sub.Type == "role" {
			resp.Roles = append(resp.Roles, sub.Name)
		}
	}
	reaches, err := auth.ReachableTargets(ctx, s.store, principal)
	if err != nil {
		storeError(w, err)
		return
	}
	auth.SortReachByName(reaches)

	resp.Targets = make([]reachTarget, 0, len(reaches))
	for _, rc := range reaches {
		resp.Targets = append(resp.Targets, reachTarget{
			TargetID: rc.Target.ID, Target: rc.Target.Name, Host: rc.Target.Host,
			Protocol: rc.Target.Protocol, Via: rc.Via,
			SubjectType: rc.SubjectType, Subject: rc.Subject, Safe: rc.SafeName,
		})
	}
	resp.Total = len(resp.Targets)
	resp.Counts = auth.ReachSubjectCounts(reaches)
	if resp.Roles == nil {
		resp.Roles = []string{}
	}
	if resp.Blocked == nil {
		resp.Blocked = []string{}
	}

	s.audit(ctx, "access.reach_query", fmt.Sprintf("subject:%s kind:%s targets:%d blocked:%s",
		auditField(subject, maxReachSubjectLen), kind, resp.Total,
		auditField(strings.Join(resp.Blocked, ","), maxReachSubjectLen)))
	writeJSON(w, http.StatusOK, resp)
}

// lookupAgentSubject reports which agent registry names this subject, the
// accountable owner recorded there, whether it was found at all, and every
// reason its own state stops it using what it may reach. A static key is looked
// up by name and a SPIFFE-attested identity by its SVID subject, which for that
// kind IS the agent's canonical name (see agentid.Identity).
//
// Registry read failures are treated as "not found": this is descriptive detail
// on a read-only review, never an authorization decision, so degrading to an
// unattributed answer is safe where failing the whole query would not be useful.
// The quarantine check is deliberately made for EVERY subject, known or not —
// quarantine is keyed by subject name and is the one containment control that
// covers an agent no registry lists, which is exactly the case where a reviewer
// most needs to be told.
func (s *Server) lookupAgentSubject(ctx context.Context, subject string) (agentKind, owner string, known bool, blocked []string) {
	if q, err := s.store.IsAgentQuarantined(ctx, subject); err == nil && q {
		blocked = append(blocked, blockedQuarantined)
	}
	if id, err := s.store.GetAgentIdentity(ctx, subject); err == nil && id != nil {
		if !id.Enrolled {
			blocked = append(blocked, blockedNotEnrolled)
		}
		return "identity", id.Owner, true, blocked
	}
	keys, err := s.store.ListAgentKeys(ctx)
	if err != nil {
		return "", "", false, blocked
	}
	for i := range keys {
		if keys[i].Name != subject {
			continue
		}
		if keys[i].Disabled {
			blocked = append(blocked, blockedKeyDisabled)
		}
		if keys[i].ExpiresAt != nil && keys[i].ExpiresAt.Before(time.Now()) {
			blocked = append(blocked, blockedKeyExpired)
		}
		return "key", keys[i].Owner, true, blocked
	}
	return "", "", false, blocked
}
