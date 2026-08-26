package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/broker"
	"github.com/morandeirachema/pamv1/internal/store"
)

// Bounds on the registry's free-text fields. A SPIFFE ID is a URI and can
// legitimately contain colons and slashes, so it is length-bounded and
// control-character-checked (checkBoundedText) rather than run through
// checkName, exactly as a quarantine subject is.
const (
	maxSPIFFEIDLen     = 512
	maxIdentityNoteLen = 200
)

// spiffePrefix is the scheme every SPIFFE ID starts with. The registry stores
// only SPIFFE IDs, because the identity kind it exists for is the one PAMv1
// never issued a key to; a static key already carries its owner in its own row.
const spiffePrefix = "spiffe://"

// isSPIFFEID reports whether a subject is a SPIFFE ID rather than a static
// agent-key name. It is how the four-eyes gate decides which side of the split
// an identity's owner lives on: an agent key's owner is a column on its row, a
// SPIFFE identity's owner is a row in agent_identities.
func isSPIFFEID(subject string) bool { return strings.HasPrefix(subject, spiffePrefix) }

type agentIdentityIn struct {
	SPIFFEID string `json:"spiffe_id"`
	Owner    string `json:"owner"`
	Note     string `json:"note,omitempty"`
}

// createAgentIdentity records the human accountable for a SPIFFE-attested agent.
//
// This is deliberately NOT enrollment: registering an identity admits nothing
// (the trust domain already decided who may authenticate) and attests nothing.
// It records one fact — who PAMv1 holds responsible — which the broker's
// four-eyes refusal and the offboarding cascade both need and neither could
// read for an identity with no agent_keys row.
func (s *Server) createAgentIdentity(w http.ResponseWriter, r *http.Request) {
	var in agentIdentityIn
	if !readJSON(w, r, &in) {
		return
	}
	in.SPIFFEID = strings.TrimSpace(in.SPIFFEID)
	in.Owner = strings.TrimSpace(in.Owner)
	if !checkBoundedText(w, "spiffe_id", in.SPIFFEID, maxSPIFFEIDLen, true) {
		return
	}
	if !isSPIFFEID(in.SPIFFEID) {
		writeError(w, http.StatusUnprocessableEntity,
			`spiffe_id must be a SPIFFE ID (spiffe://<trust-domain>/<path>); a static agent key carries its owner on its own row`)
		return
	}
	// The owner is a person (or a team account) this deployment can name, so it
	// is held to the same name rules every other actor field is — an owner that
	// cannot be compared to an approver's username is not an owner.
	if !checkName(w, "owner", in.Owner) {
		return
	}
	if !checkBoundedText(w, "note", in.Note, maxIdentityNoteLen, false) {
		return
	}
	a := store.AgentIdentity{SPIFFEID: in.SPIFFEID, Owner: in.Owner, Note: in.Note, CreatedBy: actorFrom(r.Context())}
	if err := s.store.CreateAgentIdentity(r.Context(), &a); err != nil {
		// A conflict is ambiguous since Phase 174, and the two cases mean opposite
		// things. If the row is one PAMv1 created for itself when this identity
		// first called — seen, unenrolled, nobody's — then registering it is the
		// operator ADOPTING it, which is exactly what this route is for, and
		// refusing would leave them unable to claim what the inventory just told
		// them about. If it is already enrolled, somebody has claimed it and a
		// second registration really is a conflict.
		if !errors.Is(err, store.ErrConflict) {
			storeError(w, err)
			return
		}
		existing, gerr := s.store.GetAgentIdentity(r.Context(), in.SPIFFEID)
		if gerr != nil || existing.Enrolled {
			storeError(w, store.ErrConflict)
			return
		}
		if eerr := s.store.EnrollAgentIdentity(r.Context(), existing.ID, in.Owner, in.Note); eerr != nil {
			storeError(w, eerr)
			return
		}
		existing.Owner, existing.Note, existing.Enrolled = in.Owner, in.Note, true
		s.audit(r.Context(), "agent.identity_enrolled",
			fmt.Sprintf("spiffe_id:%s owner:%s first_seen:%s",
				auditField(existing.SPIFFEID, maxSPIFFEIDLen), auditField(existing.Owner, 128),
				auditField(timeOrDash(existing.FirstSeen), 40)))
		writeJSON(w, http.StatusCreated, existing)
		return
	}
	s.audit(r.Context(), "agent.identity_register",
		fmt.Sprintf("spiffe_id:%s owner:%s", auditField(a.SPIFFEID, maxSPIFFEIDLen), auditField(a.Owner, 128)))
	writeJSON(w, http.StatusCreated, a)
}

// timeOrDash renders an optional timestamp for an audit detail.
func timeOrDash(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

// listAgentIdentities returns every registered SPIFFE agent identity — the
// inventory an owner review reads, and the answer to "who is accountable for
// the agents in this trust domain".
func (s *Server) listAgentIdentities(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListAgentIdentities(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	known := s.knownUsernames(r.Context())
	out := make([]agentIdentityView, 0, len(list))
	for _, a := range list {
		out = append(out, agentIdentityView{
			AgentIdentity: a,
			// An unowned row is not a typo, it is an unclaimed one — reporting
			// it as an unknown owner would bury the finding that matters.
			OwnerKnown: !a.Attributed() || ownerIsKnown(known, a.Owner),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// agentIdentityView is a registration plus whether its owner is a PAMv1 user
// (Phase 175). Derived per request rather than stored, because it is a fact
// about the user roster at this moment, not about the identity.
type agentIdentityView struct {
	store.AgentIdentity
	OwnerKnown bool `json:"owner_known"`
}

type identityOwnerIn struct {
	Owner string `json:"owner"`
}

// setAgentIdentityOwner reassigns a registration to a new accountable human.
// Handover is an update rather than a delete plus re-create so the row keeps
// saying when the identity was first registered and by whom.
func (s *Server) setAgentIdentityOwner(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in identityOwnerIn
	if !readJSON(w, r, &in) {
		return
	}
	in.Owner = strings.TrimSpace(in.Owner)
	if !checkName(w, "owner", in.Owner) {
		return
	}
	if err := s.store.SetAgentIdentityOwner(r.Context(), id, in.Owner); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "agent.identity_owner_set",
		fmt.Sprintf("identity:%d owner:%s", id, auditField(in.Owner, 128)))
	w.WriteHeader(http.StatusNoContent)
}

// deleteAgentIdentity removes a registration. It is audited as loudly as
// creating one: after this, that SPIFFE identity has no recorded owner again,
// and its parked calls can no longer be approved by anyone until one is
// recorded — a fail-closed consequence an operator should be able to trace.
func (s *Server) deleteAgentIdentity(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteAgentIdentity(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "agent.identity_remove", fmt.Sprintf("identity:%d", id))
	w.WriteHeader(http.StatusNoContent)
}

// knownUsernames returns the set of usernames PAMv1 has a user row for, so a
// listing can flag an agent whose owner is not one of them.
//
// The set is EXACT-CASE on purpose (Phase 176). Every control this report speaks
// about matches an owner as a literal string — `ListAgentKeysByOwner` and
// `ListAgentIdentitiesByOwner` are `WHERE owner = $1`, and `GetUserByUsername`
// is `WHERE username = $1` — so an owner of "Carol" against a user "carol" is
// NOT reachable by the offboarding cascade. Phase 175 shipped this check
// case-insensitively and would have reported that agent as fine: a flag that
// claims reachability the control does not have, which is the same defect class
// as a dead field that reads like a control. Note the deliberate asymmetry with
// the four-eyes comparison, which stays case-INSENSITIVE: there, matching more
// broadly REFUSES more, and refusing more is the safe direction.
//
// An owner is free text on both identity kinds, and the offboarding cascade
// matches it against a username STRING: deleting "carol" suspends the agents
// owned by "carol" and reaches nothing owned by "caro1" or by "carol " — a typo
// makes an agent no cascade can ever reach, silently, with the row still reading
// as though somebody were accountable. PAMv1 does not refuse an owner it does
// not recognise (a team address or a service account is a legitimate answer to
// "who answers for this"), so instead it says so where a human is already
// looking: the agent listings and the recertification campaign.
//
// One query for the whole listing rather than one per row. A failure returns nil,
// which the callers read as "cannot tell" and render as not-flagged: an
// unreachable user table must not turn an inventory screen into a wall of
// warnings.
func (s *Server) knownUsernames(ctx context.Context) map[string]bool {
	users, err := s.store.ListUsers(ctx, 0, 0)
	if err != nil {
		s.log.Debug("owner check: user listing failed", "err", err)
		return nil
	}
	known := make(map[string]bool, len(users))
	for _, u := range users {
		known[u.Username] = true
	}
	return known
}

// ownerIsKnown reports whether owner matches a PAMv1 user. With no roster (the
// lookup failed) it answers true, so a failure reads as "no finding" rather than
// as an accusation against every agent in the list.
func ownerIsKnown(known map[string]bool, owner string) bool {
	if known == nil {
		return true
	}
	return known[strings.TrimSpace(owner)]
}

// accountableOwners resolves every human accountable for a parked call's agent
// identity, so the four-eyes gate can refuse any of them approving it.
//
// It returns (owners, unattributed, error). `unattributed` names the first
// identity for which no owner could be established, and is the signal to refuse
// the decision: four-eyes cannot be proven when one side of it is unknown, which
// is the same stance Phase 159 took when it made an owner mandatory at agent-key
// creation. An error means the registry could not be read at all — also a
// refusal, never a pass.
//
// Two identity kinds resolve differently, which is the whole reason this
// function exists:
//
//   - A static key's accountable party is a human username already carried on
//     the identity (OnBehalfOf, from agent_keys.owner). Nothing to look up.
//   - An SVID's is a SPIFFE ID, which can never equal a person's name — the
//     comparison that made four-eyes INERT on the attested path. It is resolved
//     through the agent_identities registry.
//
// The whole delegation chain is resolved, not just the accountable party at its
// end: if a human owns any agent in the chain that produced this call, they are
// on the requesting side of it. That mirrors Phase 169's chain-following
// quarantine — an identity's delegates are its reach, for containment and for
// separation of duties alike.
func (s *Server) accountableOwners(ctx context.Context, ident broker.ApprovalIdentity) ([]string, string, error) {
	subjects := make([]string, 0, len(ident.Chain)+2)
	seen := map[string]struct{}{}
	for _, subject := range append([]string{ident.Agent, ident.OnBehalfOf}, ident.Chain...) {
		if subject == "" {
			continue
		}
		if _, dup := seen[subject]; dup {
			continue
		}
		seen[subject] = struct{}{}
		subjects = append(subjects, subject)
	}
	if len(subjects) == 0 {
		return nil, "(unnamed agent)", nil
	}
	var owners []string
	for _, subject := range subjects {
		if !isSPIFFEID(subject) {
			// A static key: the accountable human is OnBehalfOf itself. The
			// agent's own NAME is not an owner, so it is not treated as one —
			// only a subject that is genuinely a person's name counts, and for
			// this identity kind that is exactly the OnBehalfOf field.
			if subject == ident.OnBehalfOf {
				owners = append(owners, subject)
			}
			continue
		}
		reg, err := s.store.GetAgentIdentity(ctx, subject)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, subject, nil
			}
			return nil, "", err
		}
		// A row existing is not the same as somebody answering for it: since
		// Phase 174 PAMv1 creates an UNOWNED row the first time an identity
		// calls, so an inventory entry with no owner is exactly as unattributed
		// as no entry at all — and must refuse the decision the same way. The
		// alternative would be a four-eyes gate satisfied by an empty string.
		if !reg.Attributed() {
			return nil, subject, nil
		}
		owners = append(owners, reg.Owner)
	}
	if len(owners) == 0 {
		return nil, subjects[0], nil
	}
	return owners, "", nil
}

// unknownOwners returns the owners in the list that match no PAMv1 user, in
// order and without duplicates. An unreadable roster returns none: a decision
// must not be coloured — or refused — by a database hiccup.
func (s *Server) unknownOwners(ctx context.Context, owners []string) []string {
	known := s.knownUsernames(ctx)
	if known == nil {
		return nil
	}
	var out []string
	for _, o := range owners {
		if !ownerIsKnown(known, o) && !slices.Contains(out, o) {
			out = append(out, o)
		}
	}
	return out
}

// suspendOwnedIdentities is the offboarding cascade's other half: quarantine
// every SPIFFE identity a departing human owned.
//
// Its sibling suspendOwnedAgents disables the departing owner's agent KEYS, and
// reached nothing for an attested agent, which has no key row to disable. The
// equivalent control there is quarantine — the subject-keyed stop switch Phase
// 159 built precisely because that identity kind has nothing else — so the
// cascade now covers both kinds with the action each one has.
//
// Like its sibling it runs after the user row is gone, never reports failure to
// the caller, and audits every outcome: a half-finished offboarding must be
// visible in the system of record. An already-quarantined subject is left alone
// (ErrConflict is success here, not an error to report), since the agent is
// already stopped and re-recording it would only confuse the trail about who
// stopped it and why.
func (s *Server) suspendOwnedIdentities(ctx context.Context, username string) {
	ids, err := s.store.ListAgentIdentitiesByOwner(ctx, username)
	if err != nil {
		s.log.Error("could not list SPIFFE agent identities for a deleted user", "user", username, "err", err)
		s.audit(ctx, "agent.quarantine_failed",
			fmt.Sprintf("owner:%s reason:list-failed", auditField(username, 128)))
		return
	}
	for _, a := range ids {
		q := store.AgentQuarantine{
			Subject:   a.SPIFFEID,
			Reason:    "owner offboarded: " + username,
			CreatedBy: actorFrom(ctx),
		}
		switch err := s.store.QuarantineAgent(ctx, &q); {
		case err == nil:
			s.audit(ctx, "agent.quarantine",
				fmt.Sprintf("subject:%s owner:%s reason:owner-offboarded",
					auditField(a.SPIFFEID, maxSPIFFEIDLen), auditField(username, 128)))
		case errors.Is(err, store.ErrConflict):
			// Already stopped; nothing to do and nothing to report.
		default:
			s.log.Error("could not quarantine a SPIFFE identity of a deleted user",
				"spiffe_id", a.SPIFFEID, "err", err)
			s.audit(ctx, "agent.quarantine_failed",
				fmt.Sprintf("subject:%s owner:%s reason:quarantine-failed",
					auditField(a.SPIFFEID, maxSPIFFEIDLen), auditField(username, 128)))
		}
	}
}
