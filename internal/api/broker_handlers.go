package api

import (
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
		// authentication paths. A store failure refuses the call: an unverifiable
		// quarantine must never read as "not quarantined".
		quarantined, qerr := s.store.IsAgentQuarantined(r.Context(), id.AgentName)
		if qerr != nil {
			s.log.Error("agent quarantine check failed; refusing the call (fail closed)",
				"agent", id.AgentName, "err", qerr)
			_ = s.auditAs(r.Context(), id.AgentName, "agent.quarantine_refused",
				"agent:"+auditField(id.AgentName, 200)+" reason:quarantine-check-failed")
			s.authFailed(w, r, "agent", "invalid or missing agent credential")
			return
		}
		if quarantined {
			// Refused through authFailed, the same path a bad bearer takes: the
			// response, the throttling and the api.auth_failed record are
			// identical, so a quarantined agent learns nothing from the reply
			// about why it stopped working. The reason is in the audit trail,
			// where the responder looks, not in the 401 body.
			_ = s.auditAs(r.Context(), id.AgentName, "agent.quarantine_refused",
				"agent:"+auditField(id.AgentName, 200)+" path:"+auditField(r.URL.Path, 200))
			s.authFailed(w, r, "agent", "invalid or missing agent credential")
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
	// Four-eyes: the human who owns the agent may not approve their own agent's
	// call (mirrors the human access-request self-approval refusal).
	if owner, ok := s.broker.ApprovalOwner(r.PathValue("id")); ok {
		// Fail closed on an UNKNOWN owner as well as a matching one. Agent creation
		// now requires an owner, but rows created before that could have none — and
		// for those the old `owner != ""` guard silently disabled four-eyes
		// entirely, letting one principal both request and approve. An unattributed
		// agent is exactly the case where a second pair of eyes cannot be proven,
		// so the decision is refused rather than waved through.
		if owner == "" {
			s.audit(r.Context(), "broker.approval.refused",
				fmt.Sprintf("call:%s reason:agent-has-no-owner", auditField(r.PathValue("id"), 64)))
			writeError(w, http.StatusForbidden,
				"this call's agent has no recorded owner, so four-eyes cannot be established; set an owner on the agent")
			return
		}
		if strings.EqualFold(owner, approver) {
			writeError(w, http.StatusForbidden, "cannot approve a call for an agent you own (four-eyes)")
			return
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

// listAgentKeys returns the registered agent identities (never their token hash).
func (s *Server) listAgentKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.store.ListAgentKeys(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, keys)
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
