package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

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
	Roles   []string       `json:"roles"`
	Total   int            `json:"total"`
	Counts  map[string]int `json:"counts"`
	Targets []reachTarget  `json:"targets"`
}

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
		resp.AgentKind, resp.Owner, resp.Known = s.lookupAgentSubject(ctx, subject)
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

	safeNames, err := s.safeNames(ctx)
	if err != nil {
		storeError(w, err)
		return
	}
	resp.Targets = make([]reachTarget, 0, len(reaches))
	for _, rc := range reaches {
		row := reachTarget{
			TargetID: rc.Target.ID, Target: rc.Target.Name, Host: rc.Target.Host,
			Protocol: rc.Target.Protocol, Via: rc.Via,
			SubjectType: rc.SubjectType, Subject: rc.Subject,
		}
		if rc.SafeID != nil {
			row.Safe = safeNames[*rc.SafeID]
		}
		resp.Targets = append(resp.Targets, row)
	}
	resp.Total = len(resp.Targets)
	resp.Counts = auth.ReachSubjectCounts(reaches)
	if resp.Roles == nil {
		resp.Roles = []string{}
	}

	s.audit(ctx, "access.reach_query", fmt.Sprintf("subject:%s kind:%s targets:%d",
		auditField(subject, maxReachSubjectLen), kind, resp.Total))
	writeJSON(w, http.StatusOK, resp)
}

// lookupAgentSubject reports which agent registry names this subject, the
// accountable owner recorded there, and whether it was found at all. A static
// key is looked up by name and a SPIFFE-attested identity by its SVID subject,
// which for that kind IS the agent's canonical name (see agentid.Identity).
// Registry read failures are treated as "not found": this is descriptive detail
// on a read-only review, never an authorization decision, so degrading to an
// unattributed answer is safe where failing the whole query would not be useful.
func (s *Server) lookupAgentSubject(ctx context.Context, subject string) (agentKind, owner string, known bool) {
	if id, err := s.store.GetAgentIdentity(ctx, subject); err == nil && id != nil {
		return "identity", id.Owner, true
	}
	keys, err := s.store.ListAgentKeys(ctx)
	if err != nil {
		return "", "", false
	}
	for i := range keys {
		if keys[i].Name == subject {
			return "key", keys[i].Owner, true
		}
	}
	return "", "", false
}

// safeNames maps every safe id to its name, so a safe-derived grant can be
// reported by the name an operator knows it by.
func (s *Server) safeNames(ctx context.Context) (map[int64]string, error) {
	safes, err := s.store.ListSafes(ctx, 0, 0)
	if err != nil {
		return nil, err
	}
	out := make(map[int64]string, len(safes))
	for _, sf := range safes {
		out[sf.ID] = sf.Name
	}
	return out, nil
}
