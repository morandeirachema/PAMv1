package api

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/morandeirachema/pamv1/internal/agentid"
	"github.com/morandeirachema/pamv1/internal/auditchain"
	"github.com/morandeirachema/pamv1/internal/broker"
	"github.com/morandeirachema/pamv1/internal/store"
)

// maxToolCallBytes bounds a tool-call request body.
const maxToolCallBytes = 64 << 10

// agentHandler is an HTTP handler that has already resolved the agent identity.
type agentHandler func(w http.ResponseWriter, r *http.Request, id *agentid.Identity)

// agentAuth authenticates an agent bearer credential (static key or, later, an
// SVID) and invokes next with the verified identity, or returns 401.
func (s *Server) agentAuth(next agentHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := s.agentVerifier.Verify(r.Context(), bearerToken(r))
		if err != nil {
			s.authFailed(w, r, "agent", "invalid or missing agent credential")
			return
		}
		// Quarantine is the incident responder's stop button, and it is keyed on
		// the agent's canonical NAME rather than on an agent_keys row id on
		// purpose: an SVID-authenticated agent has no row to disable (its
		// identity is attested by SPIFFE, pamv1 never issued it a key), and for
		// that identity kind AgentName IS the full SPIFFE ID — see svid.go, where
		// the JWT subject is assigned to both AgentName and SPIFFEID. Keying on
		// the name is therefore the one containment control that covers BOTH
		// authentication paths. It follows the presented token's whole delegation
		// chain (quarantineSubjects), not just its presenter. A store failure
		// refuses the call: an unverifiable quarantine must never read as "not
		// quarantined".
		hit, qerr := s.quarantinedSubject(r.Context(), id)
		if qerr != nil {
			s.log.Error("agent quarantine check failed; refusing the call (fail closed)",
				"agent", id.AgentName, "err", qerr)
			_ = s.auditAs(r.Context(), id.AgentName, "agent.quarantine_refused",
				"agent:"+auditField(id.AgentName, 200)+" reason:quarantine-check-failed")
			s.authFailed(w, r, "agent", "invalid or missing agent credential")
			return
		}
		if hit != "" {
			// Refused through authFailed, the same path a bad bearer takes: the
			// response, the throttling and the api.auth_failed record are
			// identical, so a quarantined agent learns nothing from the reply
			// about why it stopped working. The reason is in the audit trail,
			// where the responder looks, not in the 401 body.
			_ = s.auditAs(r.Context(), id.AgentName, "agent.quarantine_refused",
				"agent:"+auditField(id.AgentName, 200)+" path:"+auditField(r.URL.Path, 200)+
					quarantineHitField(id, hit))
			s.authFailed(w, r, "agent", "invalid or missing agent credential")
			return
		}
		// Inventory the attested identity (Phase 174), and — when the deployment
		// asks for it — require that somebody has claimed it. See noteSVID.
		if id.SPIFFEID != "" && !s.noteSVID(w, r, id) {
			return
		}
		// Per-agent rate limit (keyed by agent name) bounds tool-call volume.
		if s.brokerLimiter != nil && !s.brokerLimiter.Allow(id.AgentName) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "agent rate limit exceeded; try again shortly")
			return
		}
		// Put the agent principal in the request context so reused helpers (e.g.
		// execWinRM's s.audit) attribute the sensitive action to the agent, not the
		// "unknown" fallback, and the access log records the agent.
		r = r.WithContext(withPrincipal(r.Context(), id.Principal()))
		setActor(r.Context(), id.AgentName)
		// Stamp last use on a static key so a dormant agent identity is visible
		// (the "this key has not been used in 90 days" report an owner needs
		// before deciding to retire it). Best-effort by design: this is
		// bookkeeping, not authorization, so a write failure must never turn an
		// authenticated call into a refused one. SVIDs have no row (KeyID 0).
		if id.KeyID > 0 {
			if err := s.store.TouchAgentKey(r.Context(), id.KeyID, time.Now()); err != nil {
				s.log.Debug("agent key last-use stamp failed", "key_id", id.KeyID, "err", err)
			}
		}
		next(w, r, id)
	}
}

// quarantineSubjects lists every identity one presented agent credential must
// be checked against before it is honoured: the presenter's own subject first,
// then every actor in its RFC 8693 delegation chain (innermost..outermost, as
// agentid.Identity records it).
//
// Checking only the presenter — what shipped in Phase 159 — left delegation
// uncontained. A root agent that has already exchanged its token for sub-agent
// tokens keeps acting through them after it is quarantined, because each
// sub-agent presents its OWN subject and the compromised root appears only in
// the token's `act` chain; the only thing that would eventually stop it is the
// delegated token's TTL. A stop button a compromised agent can route around by
// delegating one hop is not a stop button, so the whole chain is consulted and
// any quarantined link refuses the call.
//
// A static key's OnBehalfOf is deliberately NOT included: for that identity kind
// it holds the accountable HUMAN's username (see agentid.StaticVerifier), and
// quarantine is an inventory of agent identities, not of people. Blocking every
// agent one human owns is offboarding, a different action with a different
// audit vocabulary. An SVID's accountable party is the outermost chain element,
// so it is already covered above. Duplicates are dropped, which keeps the
// ordinary undelegated case a single store lookup.
func quarantineSubjects(id *agentid.Identity) []string {
	out := make([]string, 0, len(id.ActorChain)+1)
	seen := make(map[string]struct{}, len(id.ActorChain)+1)
	for _, subject := range append([]string{id.AgentName}, id.ActorChain...) {
		if subject == "" {
			continue
		}
		if _, dup := seen[subject]; dup {
			continue
		}
		seen[subject] = struct{}{}
		out = append(out, subject)
	}
	return out
}

// quarantinedSubject returns the first quarantined identity in id's chain, or ""
// when none is. An error is the caller's signal to fail closed — every caller
// refuses the call rather than treating an unreadable quarantine as an absent
// one.
func (s *Server) quarantinedSubject(ctx context.Context, id *agentid.Identity) (string, error) {
	for _, subject := range quarantineSubjects(id) {
		quarantined, err := s.store.IsAgentQuarantined(ctx, subject)
		if err != nil {
			return "", err
		}
		if quarantined {
			return subject, nil
		}
	}
	return "", nil
}

// quarantineHitField renders the audit suffix naming WHICH identity in the chain
// is quarantined, and only when that is not the presenter itself. Without it a
// delegated refusal would record the sub-agent that happened to make the call
// and leave the responder to guess why an agent they never quarantined stopped
// working; with it the trail names the entry that did the stopping.
func quarantineHitField(id *agentid.Identity, hit string) string {
	if hit == "" || hit == id.AgentName {
		return ""
	}
	return " subject:" + auditField(hit, 200)
}

// noteSVID records that an attested identity authenticated and, when
// PAM_BROKER_REQUIRE_ENROLLED_SVID is set, refuses one nobody has enrolled. It
// reports whether the call may proceed, writing the refusal itself when not.
//
// **Why an inventory at all.** A static agent key exists because pamv1 minted
// it, so the set of static agents is knowable by definition. An SVID is the
// opposite: any workload the trust domain vouches for can authenticate, and
// until Phase 174 pamv1 knew only about the ones an admin had happened to type
// into the owner registry. There was no list to review, no first-seen, no
// last-seen — and the containment built in 159/169/170 all keys on a SUBJECT a
// responder has to be able to name. Recording every identity that calls is what
// makes those controls usable on the identity kind they were built for.
//
// **Recording is best-effort; refusing is fail-closed.** The sighting is
// bookkeeping, so a store failure must not turn an authenticated call into a
// refused one (the same stance TouchAgentKey takes for static keys). The
// enrollment CHECK is the opposite: if the deployment has said only enrolled
// identities may call, an unreadable registry cannot be read as "enrolled".
//
// A first sighting is audited once, not per call: a workload nobody enrolled
// calling for the first time is worth telling an operator about, and the same
// workload's thousandth call is not.
func (s *Server) noteSVID(w http.ResponseWriter, r *http.Request, id *agentid.Identity) bool {
	if s.brokerRequireEnrolledSVID {
		reg, err := s.store.GetAgentIdentity(r.Context(), id.SPIFFEID)
		switch {
		case err != nil && !errors.Is(err, store.ErrNotFound):
			s.log.Error("agent enrollment check failed; refusing the call (fail closed)",
				"spiffe_id", id.SPIFFEID, "err", err)
			_ = s.auditAs(r.Context(), id.AgentName, "agent.not_enrolled",
				"agent:"+auditField(id.AgentName, maxSPIFFEIDLen)+" reason:enrollment-check-failed")
			s.authFailed(w, r, "agent", "invalid or missing agent credential")
			return false
		case err != nil || !reg.Enrolled:
			// Record the sighting anyway, so the identity that knocked appears in
			// the inventory an operator enrolls FROM. Refused first, listed
			// second: the refusal is the control, the row is the evidence.
			s.seeSVID(r, id)
			_ = s.auditAs(r.Context(), id.AgentName, "agent.not_enrolled",
				"agent:"+auditField(id.AgentName, maxSPIFFEIDLen)+" path:"+auditField(r.URL.Path, 200))
			s.authFailed(w, r, "agent", "invalid or missing agent credential")
			return false
		}
	}
	s.seeSVID(r, id)
	return true
}

// seeSVID stamps the inventory row for the presented identity AND for every
// actor in its delegation chain, creating rows on a first sighting and auditing
// each once. Best-effort by design — see noteSVID.
//
// The chain is included (Phase 176) because those identities are verified facts
// inside a signed token, and the controls that read the inventory read the whole
// chain: quarantine walks it (169) and four-eyes resolves an owner for every
// link (170). Without this, a delegating root that never calls pamv1 directly
// has no row, so an operator cannot enrol it from the list — they have to know
// the SPIFFE ID and type it — and every approval of a call it delegated is
// refused as unattributed until they do.
func (s *Server) seeSVID(r *http.Request, id *agentid.Identity) {
	for _, subject := range quarantineSubjects(id) {
		if !isSPIFFEID(subject) || !s.sightingDue(subject) {
			continue
		}
		created, err := s.store.SeeAgentIdentity(r.Context(), subject, time.Now())
		if err != nil {
			s.log.Debug("agent identity sighting not recorded", "spiffe_id", subject, "err", err)
			s.forgetSighting(subject)
			continue
		}
		if created {
			_ = s.auditAs(r.Context(), id.AgentName, "agent.identity_first_seen",
				"spiffe_id:"+auditField(subject, maxSPIFFEIDLen)+" enrolled:false"+
					viaField(id, subject))
		}
	}
}

// viaField names the presenting agent when the identity being recorded is one it
// merely acts for, so the trail says how pamv1 came to know about it.
func viaField(id *agentid.Identity, subject string) string {
	if subject == id.AgentName {
		return ""
	}
	return " via:" + auditField(id.AgentName, maxSPIFFEIDLen)
}

// sightingInterval is how often one identity's last-seen stamp is rewritten.
//
// The stamp answers "is this workload still active?", which nobody asks to the
// second — but the write happens on the authentication path, so an agent at the
// default rate limit would rewrite its row sixty times a minute, every minute,
// forever. A minute of granularity keeps the answer useful and the writes rare;
// a FIRST sighting is never throttled, because that one is the signal.
const sightingInterval = time.Minute

// sightingDue reports whether subject's stamp is due to be written, recording
// the attempt. In-process and per-replica by design: it is a write-rate damper,
// not a distributed lock, and a second replica stamping the same identity a few
// seconds later costs one row write and loses nothing.
func (s *Server) sightingDue(subject string) bool {
	now := time.Now()
	if last, ok := s.svidSeen.Load(subject); ok {
		if t, _ := last.(time.Time); now.Sub(t) < sightingInterval {
			return false
		}
	}
	s.svidSeen.Store(subject, now)
	return true
}

// forgetSighting drops a damper entry after a failed write, so the next call
// retries instead of waiting out an interval it never actually recorded.
func (s *Server) forgetSighting(subject string) { s.svidSeen.Delete(subject) }

// bearerToken extracts a Bearer token from the Authorization header.
func bearerToken(r *http.Request) string {
	const p = "Bearer "
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, p) {
		return strings.TrimSpace(h[len(p):])
	}
	return ""
}

type toolCallIn struct {
	// SessionID and Client are the agent's own run identifier and its
	// self-declared software/model. Both are unverified provenance, recorded so a
	// run can be reconstructed, never consulted for a decision — see broker.Call.
	SessionID string         `json:"session_id"`
	Client    string         `json:"client"`
	Tool      string         `json:"tool"`
	Args      map[string]any `json:"args"`
}

// brokerCallDetail renders the primary-trail audit detail for a brokered tool
// call: what was asked for, what happened, and the fields that let an
// investigator stitch this one event back into a whole agent run.
//
// `target:` is included when the arguments name one, because the risk engine's
// baseline reads exactly that key to notice an actor touching a host it never
// touched before — without it, an agent's first-ever reach into a new system
// looks identical to its thousandth routine call. Every caller-supplied value is
// quoted and bounded (auditField): these come straight off the wire, and an
// unquoted value in a `key:value` detail lets whoever controls it forge fields.
func brokerCallDetail(in toolCallIn, out broker.Outcome) string {
	detail := fmt.Sprintf("tool:%s status:%s call:%s", auditField(in.Tool, 64), out.Status, out.CallID)
	if t := targetArg(in.Args); t != "" {
		detail += " target:" + auditField(t, 128)
	}
	if in.SessionID != "" {
		detail += " session:" + auditField(in.SessionID, 128)
	}
	if in.Client != "" {
		detail += " client:" + auditField(in.Client, 128)
	}
	return detail
}

// runField renders one optional correlation field for an audit detail, or ""
// when the value is absent — so an event about a call that declared no run id is
// not padded with an empty `session:""` key. The value is quoted and bounded
// because it is caller-declared text.
func runField(key, value string) string {
	if value == "" {
		return ""
	}
	return " " + key + ":" + auditField(value, 128)
}

// targetArg returns the tool call's `target` argument when it is a string.
//
// Go's map[string]any holds values of unknown type, so the comma-ok type
// assertion below is the equivalent of asking "is this actually a str?" before
// using it — a non-string target (a number, an object) simply yields "" rather
// than a panic or a mangled record.
func targetArg(args map[string]any) string {
	t, _ := args["target"].(string)
	return t
}

// processToolCall runs an agent tool call through the broker's policy loop. It
// always returns HTTP 200: the decision is in the body's status field (per the
// broker contract, transport failures are the only non-200 responses).
func (s *Server) processToolCall(w http.ResponseWriter, r *http.Request, id *agentid.Identity) {
	r.Body = http.MaxBytesReader(w, r.Body, maxToolCallBytes)
	var in toolCallIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.Tool == "" {
		writeError(w, http.StatusUnprocessableEntity, "tool is required")
		return
	}
	// Cumulative budget (Phase 167). Checked here rather than in agentAuth so it
	// bounds NEW work only: collecting the result of a call a human already
	// approved must not be refused for budget, because the work is done and
	// withholding the result would hide it while keeping the side effect.
	if s.refuseOverBudget(w, r, id, in.Tool) {
		return
	}
	out := s.broker.ProcessCall(r.Context(), id, broker.Call{SessionID: in.SessionID, Client: in.Client, Tool: in.Tool, Args: in.Args})
	// Surface broker activity in the unified audit trail too; the hash chain
	// remains the authoritative, verifiable record.
	//
	// The action carries the OUTCOME (`broker.tool_call.denied`, not a flat
	// `broker.tool_call` with the outcome buried in the detail text), because both
	// consumers of this trail key on the action name: the OCSF export classifies a
	// denial as a Detection Finding, and the risk engine counts a denial and an
	// execution as different signals. Phase 161 — before it, an agent could be
	// refused a privileged tool call every minute for a week and neither surface
	// would show anything but routine activity.
	s.auditAs(r.Context(), id.AgentName, broker.ActionFor(out.Status), brokerCallDetail(in, out))
	writeJSON(w, http.StatusOK, out)
}

// getToolCall returns the status of a call id. It is a poll for the outcome's
// state (pending → executed/denied/failed) and deliberately never returns the
// result body: a result is delivered exactly once — in the original call
// response, or via the single-use resume token — so a secret-bearing
// reveal_credential result can't be re-read by polling this endpoint.
func (s *Server) getToolCall(w http.ResponseWriter, r *http.Request, _ *agentid.Identity) {
	out, ok := s.broker.Lookup(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "unknown call id")
		return
	}
	out.Result = nil
	out.ResumeToken = "" // never re-serve the single-use token on the status poll
	writeJSON(w, http.StatusOK, out)
}

type resumeIn struct {
	Token string `json:"token"`
}

// resumeToolCall spends the single-use resume token and returns the parked call's
// post-approval outcome exactly once. The token is the ticket; the path id must
// match the call it unlocks.
func (s *Server) resumeToolCall(w http.ResponseWriter, r *http.Request, id *agentid.Identity) {
	var in resumeIn
	if !readJSON(w, r, &in) {
		return
	}
	// Pass the path id so the token is checked against the call it unlocks BEFORE it
	// is spent — a wrong/stale id no longer burns the single-use token (leaving the
	// post-approval result, possibly a secret, permanently uncollectable).
	out, ok := s.broker.Resume(r.Context(), id, in.Token, r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "invalid, expired, or already-used resume token")
		return
	}
	s.auditAs(r.Context(), id.AgentName, broker.ActionToolCallResumed,
		fmt.Sprintf("tool:%s call:%s status:%s%s", auditField(out.Tool, 64), out.CallID, out.Status, runField("session", out.SessionID)))
	writeJSON(w, http.StatusOK, out)
}

// listBrokerApprovals returns the tool calls parked awaiting a human decision.
func (s *Server) listBrokerApprovals(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.broker.PendingApprovals())
}

type decisionIn struct {
	Approve bool `json:"approve"`
}

// decideBrokerApproval records an approver's decision on a parked tool call. On
// approve the broker executes the call server-side (JIT) and returns the result;
// on reject it becomes denied. Separation of duties (Phase 27): the decider must
// belong to one of the rule's approver groups (or be an admin), else 403.
func (s *Server) decideBrokerApproval(w http.ResponseWriter, r *http.Request) {
	var in decisionIn
	if !readJSON(w, r, &in) {
		return
	}
	p := principalFrom(r.Context())
	approver := actorFrom(r.Context())
	// Four-eyes: a human who owns any agent in the chain that made this call may
	// not approve it (mirrors the human access-request self-approval refusal).
	//
	// Resolving the owner is not a field read, because the two agent identity
	// kinds keep it in different places — an agent key on its row, a SPIFFE
	// identity in the Phase 170 registry. Before that registry existed this gate
	// compared a SPIFFE ID against a username, which can never match, so on the
	// attested path (the intended production posture) four-eyes was INERT: the
	// human operating an agent could approve their own agent's privileged call.
	if ident, ok := s.broker.ApprovalIdentity(r.PathValue("id")); ok {
		owners, unattributed, err := s.accountableOwners(r.Context(), ident)
		switch {
		case err != nil:
			// Fail closed: an owner registry that cannot be read is not evidence
			// that nobody owns this agent.
			s.log.Error("could not resolve a parked call's accountable owner; refusing the decision (fail closed)",
				"call", r.PathValue("id"), "err", err)
			s.audit(r.Context(), "broker.approval.refused",
				fmt.Sprintf("call:%s reason:owner-lookup-failed", auditField(r.PathValue("id"), 64)))
			writeError(w, http.StatusServiceUnavailable,
				"the agent owner registry is unavailable, so four-eyes cannot be established; the call stays parked")
			return
		case unattributed != "":
			// Fail closed on an UNKNOWN owner as well as a matching one. Agent
			// creation requires an owner, but a SPIFFE identity is admitted by the
			// trust domain rather than created here, so it has one only if somebody
			// recorded it. An unattributed agent is exactly the case where a second
			// pair of eyes cannot be proven, so the decision is refused rather than
			// waved through — the call stays parked and decidable once an owner
			// exists.
			s.audit(r.Context(), "broker.approval.refused",
				fmt.Sprintf("call:%s reason:agent-has-no-owner subject:%s",
					auditField(r.PathValue("id"), 64), auditField(unattributed, maxSPIFFEIDLen)))
			writeError(w, http.StatusForbidden,
				"this call's agent identity "+unattributed+" has no recorded owner, so four-eyes cannot be established; "+
					"register one with POST /v1/agents/identities (or set an owner on the agent key)")
			return
		}
		for _, owner := range owners {
			if strings.EqualFold(owner, approver) {
				writeError(w, http.StatusForbidden, "cannot approve a call for an agent you own (four-eyes)")
				return
			}
		}
		// An owner nobody holds cannot be compared to anybody (Phase 176). The
		// gate refuses when owner == approver, so an owner of "caro1" — a typo,
		// or a team address that is not a pamv1 account — can never match, and
		// carol may approve her own agent's call while the row still reads as
		// though somebody were accountable. That is four-eyes silently not
		// applying, which is worse than four-eyes visibly absent.
		//
		// pamv1 records it rather than guessing: the decision is audited as
		// unverified, naming the owner, so the trail says the second pair of eyes
		// could not be established. A deployment that wants the stricter reading
		// sets PAM_BROKER_REQUIRE_KNOWN_OWNER and the decision is refused instead
		// — off by default, because a team-owned agent is a legitimate
		// arrangement and turning this on without warning would block approvals
		// that have been working.
		if unknown := s.unknownOwners(r.Context(), owners); len(unknown) > 0 {
			detail := fmt.Sprintf("call:%s owner:%s reason:owner-not-a-pamv1-user",
				auditField(r.PathValue("id"), 64), auditField(strings.Join(unknown, ","), 200))
			if s.brokerRequireKnownOwner {
				s.audit(r.Context(), "broker.approval.refused", detail)
				writeError(w, http.StatusForbidden,
					"this call's agent is owned by "+strings.Join(unknown, ", ")+
						", which is not a pamv1 user, so four-eyes cannot be established")
				return
			}
			s.audit(r.Context(), "broker.approval.four_eyes_unverified", detail)
		}
	}
	out, ok, err := s.broker.Decide(r.Context(), r.PathValue("id"),
		broker.Approver{Name: approver, Groups: p.ApproverGroups(), IsAdmin: p.IsAdmin()}, in.Approve)
	if errors.Is(err, broker.ErrNotApprover) {
		s.audit(r.Context(), "broker.approval.refused", fmt.Sprintf("call:%s reason:not-in-approver-group", r.PathValue("id")))
		writeError(w, http.StatusForbidden, "you are not a member of this call's approver group (separation of duties)")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "unknown or already-decided approval")
		return
	}
	s.audit(r.Context(), "broker.approval."+map[bool]string{true: "granted", false: "denied"}[in.Approve],
		fmt.Sprintf("call:%s status:%s", out.CallID, out.Status))
	writeJSON(w, http.StatusOK, out)
}

type agentKeyIn struct {
	Name  string `json:"name"`
	Owner string `json:"owner"`
	// ExpiresInDays optionally retires the key automatically. Absent or 0 keeps
	// the historical behaviour (never expires) so existing callers are
	// unaffected; a positive value is bounded by maxAgentKeyDays.
	ExpiresInDays int `json:"expires_in_days,omitempty"`
}

// maxAgentKeyDays bounds an agent key's requested lifetime (~10 years). An
// unbounded value would let a caller push the expiry far enough out to be
// indistinguishable from "never" while looking like it had one.
const maxAgentKeyDays = 3650

// createAgentKey mints a new agent identity key for an admin; the token is shown
// once and only its SHA-256 hash is stored.
func (s *Server) createAgentKey(w http.ResponseWriter, r *http.Request) {
	var in agentKeyIn
	if !readJSON(w, r, &in) {
		return
	}
	if !checkName(w, "name", in.Name) {
		return
	}
	// An owner is REQUIRED, because the broker's four-eyes refusal is
	// `owner != "" && EqualFold(owner, approver)`: an ownerless agent silently
	// disabled it, so one approver could create an agent, have it request a
	// privileged tool call, and then approve that call themselves — satisfying
	// both sides of the gate alone. The owner is the human the agent acts for, so
	// there is always one to name.
	if strings.TrimSpace(in.Owner) == "" {
		writeError(w, http.StatusUnprocessableEntity,
			"owner is required: it is the human this agent acts for, and the four-eyes approval refusal is keyed on it")
		return
	}
	if !checkName(w, "owner", strings.TrimSpace(in.Owner)) {
		return
	}
	if in.ExpiresInDays < 0 || in.ExpiresInDays > maxAgentKeyDays {
		writeError(w, http.StatusUnprocessableEntity,
			fmt.Sprintf("expires_in_days must be between 1 and %d (omit it, or 0, for a key that never expires)", maxAgentKeyDays))
		return
	}
	token, err := generateToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	k := store.AgentKey{Name: in.Name, Owner: in.Owner, TokenHash: hashHex(token)}
	expiryDetail := "never"
	if in.ExpiresInDays > 0 {
		exp := time.Now().Add(time.Duration(in.ExpiresInDays) * 24 * time.Hour)
		k.ExpiresAt = &exp
		expiryDetail = exp.UTC().Format(time.RFC3339)
	}
	if err := s.store.CreateAgentKey(r.Context(), &k); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "agent.create", fmt.Sprintf("%s owner:%s expires:%s", k.Name, k.Owner, expiryDetail))
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": k.ID, "name": k.Name, "owner": k.Owner, "token": token,
		"expires_at": k.ExpiresAt,
		"note":       "Give this token to the agent; only its hash is stored.",
	})
}

// listAgentKeys returns the registered agent identities (never their token hash),
// each with its live budget usage.
//
// Usage is counted per agent, so this is one query per row. That is acceptable
// here and nowhere near a hot path — this is an administrative screen listing
// the handful of agent identities an installation has, not something an agent
// itself calls. A counting failure degrades to zero used rather than failing the
// whole listing: an operator looking at the agent screen during a database
// hiccup should still see who exists.
func (s *Server) listAgentKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.store.ListAgentKeys(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	since := time.Now().Add(-budgetWindow)
	known := s.knownUsernames(r.Context())
	out := make([]agentWithBudget, 0, len(keys))
	for _, k := range keys {
		row := agentWithBudget{
			AgentKey: k, BudgetLimitEffective: s.brokerBudgetPerDay,
			// Phase 175: an owner the offboarding cascade could never match is
			// worth seeing on the screen where owners are read.
			OwnerKnown: ownerIsKnown(known, k.Owner),
		}
		if k.BudgetPerDay != nil {
			row.BudgetLimitEffective = *k.BudgetPerDay
		}
		if used, cerr := s.store.CountAgentToolCallsSince(r.Context(), k.Name, since); cerr == nil {
			row.BudgetUsedToday = used
		} else {
			s.log.Debug("agent budget usage count failed", "agent", k.Name, "err", cerr)
		}
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, out)
}

// deleteAgentKey revokes an agent identity so its bearer token stops resolving.
func (s *Server) deleteAgentKey(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteAgentKey(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "agent.revoke", fmt.Sprintf("agent:%d", id))
	w.WriteHeader(http.StatusNoContent)
}

// disableAgentKey suspends an agent identity: its bearer token stops
// authenticating immediately, but the row — and therefore the agent's name, its
// owner and every audit event that resolves through it — survives.
//
// This is the control that was missing: until now the only answer to "this agent
// is behaving strangely, stop it while we look" was DELETE, which destroys the
// very row an incident responder wants to keep. Suspension is reversible;
// revocation is not.
func (s *Server) disableAgentKey(w http.ResponseWriter, r *http.Request) {
	s.setAgentKeyDisabled(w, r, true)
}

// enableAgentKey restores a suspended agent identity so its existing token
// authenticates again. The token itself never changed — only the row's flag —
// so resuming an agent does not mean re-issuing its credential.
func (s *Server) enableAgentKey(w http.ResponseWriter, r *http.Request) {
	s.setAgentKeyDisabled(w, r, false)
}

// setAgentKeyDisabled is the shared body of disable/enable: parse the id, flip
// the flag, audit under the matching action name, 204.
func (s *Server) setAgentKeyDisabled(w http.ResponseWriter, r *http.Request, disabled bool) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.store.SetAgentKeyDisabled(r.Context(), id, disabled); err != nil {
		storeError(w, err)
		return
	}
	action := "agent.enable"
	if disabled {
		action = "agent.disable"
	}
	s.audit(r.Context(), action, fmt.Sprintf("agent:%d", id))
	w.WriteHeader(http.StatusNoContent)
}

// maxQuarantineSubjectLen bounds a quarantine subject. It is larger than
// nameMaxLen because a subject may be a full SPIFFE ID
// ("spiffe://trust.domain/agent/name"), and checkName cannot be used on it at
// all: a SPIFFE ID contains colons, which checkName refuses precisely because
// they separate fields in an audit detail. The subject is quoted with
// auditField at every audit sink instead.
const maxQuarantineSubjectLen = 256

// maxQuarantineReasonLen bounds the free-text reason an operator types.
const maxQuarantineReasonLen = 512

type quarantineIn struct {
	Subject string `json:"subject"`
	Reason  string `json:"reason"`
}

// quarantineAgent stops one agent identity dead, by canonical name: the
// agent-key name for a static key, the full SPIFFE ID for an attested one. It is
// checked both at ingress (agentAuth) and when a parked call is approved
// (revalidateAgent), so it covers an agent that is mid-workflow as well as one
// making fresh calls — and, unlike disable, it works for an SVID agent that has
// no key row to suspend.
func (s *Server) quarantineAgent(w http.ResponseWriter, r *http.Request) {
	var in quarantineIn
	if !readJSON(w, r, &in) {
		return
	}
	in.Subject = strings.TrimSpace(in.Subject)
	if !checkBoundedText(w, "subject", in.Subject, maxQuarantineSubjectLen, true) {
		return
	}
	if !checkBoundedText(w, "reason", in.Reason, maxQuarantineReasonLen, false) {
		return
	}
	q := store.AgentQuarantine{Subject: in.Subject, Reason: in.Reason, CreatedBy: actorFrom(r.Context())}
	if err := s.store.QuarantineAgent(r.Context(), &q); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "agent.quarantine",
		fmt.Sprintf("subject:%s reason:%s", auditField(q.Subject, maxQuarantineSubjectLen), auditField(q.Reason, 200)))
	writeJSON(w, http.StatusCreated, q)
}

// listAgentQuarantine returns every agent identity currently quarantined.
func (s *Server) listAgentQuarantine(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListAgentQuarantine(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// releaseAgentQuarantine lifts one quarantine so the agent can act again. It is
// audited as loudly as imposing it: releasing a stop button is the more
// dangerous of the two decisions.
func (s *Server) releaseAgentQuarantine(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.store.ReleaseAgentQuarantine(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "agent.quarantine_release", fmt.Sprintf("quarantine:%d", id))
	w.WriteHeader(http.StatusNoContent)
}

// checkBoundedText validates a free-text field that checkName cannot police
// because it may legitimately contain a colon (a SPIFFE ID, an operator's
// sentence). It enforces only what the audit trail actually needs — a length
// bound and no control characters, since a newline would split one audit record
// into what reads as two — and writes the 422 itself. required says whether an
// empty value is acceptable.
func checkBoundedText(w http.ResponseWriter, field, value string, max int, required bool) bool {
	if value == "" {
		if required {
			writeError(w, http.StatusUnprocessableEntity, field+" is required")
			return false
		}
		return true
	}
	if len(value) > max {
		writeError(w, http.StatusUnprocessableEntity,
			fmt.Sprintf("%s must be at most %d bytes (got %d)", field, max, len(value)))
		return false
	}
	for _, c := range value {
		if unicode.IsControl(c) {
			writeError(w, http.StatusUnprocessableEntity, field+" must not contain control characters")
			return false
		}
	}
	return true
}

// listBrokerAudit returns recent broker audit events (oldest-first, chain order).
func (s *Server) listBrokerAudit(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil {
			limit = n
		}
	}
	// Clamp so the HTTP listing can't request the entire chain in one response
	// (limit<=0 makes the store return everything); chain verification has its own
	// endpoints (/v1/audit/verify, /v1/audit/head).
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	events, err := s.store.ListBrokerAudit(r.Context(), limit)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

// verifyBrokerAudit walks the broker audit chain and reports whether it is intact:
// the HMAC chain reproduces, every in-chain signed checkpoint verifies against a
// trusted key, and — when ?min_entries=N is supplied (from a previously archived
// checkpoint count) — the chain has not been tail-truncated below that floor.
func (s *Server) verifyBrokerAudit(w http.ResponseWriter, r *http.Request) {
	var minEntries int64
	if q := r.URL.Query().Get("min_entries"); q != "" {
		n, err := strconv.ParseInt(q, 10, 64)
		if err != nil || n < 0 {
			writeError(w, http.StatusUnprocessableEntity, "min_entries must be a non-negative integer")
			return
		}
		minEntries = n
	}
	res, err := s.auditChain.VerifyFloor(r.Context(), minEntries)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// brokerAuditJWKS publishes the ed25519 public keys trusted to sign audit
// checkpoints (current + rotated-out predecessors) as a JWKS, so an external
// auditor can verify an archived checkpoint's signature across a signing-key
// rotation. Requires CapReadAudit.
func (s *Server) brokerAuditJWKS(w http.ResponseWriter, r *http.Request) {
	keys := s.auditChain.TrustedKeys()
	jwks := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		jwks = append(jwks, map[string]any{
			"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA",
			"kid": auditchain.KeyID(k),
			"x":   base64.RawURLEncoding.EncodeToString(k),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": jwks})
}

// brokerAuditHead returns a signed checkpoint anchoring the chain, for offline
// truncation detection.
func (s *Server) brokerAuditHead(w http.ResponseWriter, r *http.Request) {
	cp, err := s.auditChain.Head(r.Context(), time.Now())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cp)
}
