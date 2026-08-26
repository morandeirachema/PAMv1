// Package agentid establishes and verifies AI-agent identity for the access
// broker. Two verifiers implement the same Verifier interface: static bearer
// keys (SHA-256 hash lookup, like user tokens) and SPIFFE JWT-SVIDs (file-JWKS
// signature check with RFC 8693 delegation chains, see svid.go). MultiVerifier
// composes them so a deployment can accept both.
package agentid

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
)

// ErrUnauthenticated is returned when no verifier recognizes the presented bearer.
var ErrUnauthenticated = errors.New("agentid: unrecognized agent credential")

// Identity is a verified agent identity. OnBehalfOf and ActorChain are recorded
// in every audit entry so accountability survives delegation.
type Identity struct {
	AgentName  string
	OnBehalfOf string    // accountable owner (static key) or SVID on_behalf_of
	SPIFFEID   string    // "" for static keys
	ActorChain []string  // delegation chain, innermost..outermost
	KeyID      int64     // static agent-key row id (0 for an SVID); for revocation re-checks
	ExpiresAt  time.Time // SVID expiry (zero for a static key); for post-park re-checks
	// MayAct is the RFC 8693 §4.4 allow-list this token carried: the actors its
	// holder permits to act for it. Empty means unpinned. Only the token-exchange
	// minter reads it (exchange.go) — it restricts who may be delegated TO, never
	// what the holder itself may do.
	MayAct []string
	// TokenID is the presented token's `jti` (Phase 183), empty for a static key
	// and for an SVID whose issuer set none. It is recorded on every brokered
	// call so the mint of a delegated token — `broker.token.exchanged`, which has
	// carried its own `jti:` since Phase 161 — can be joined to the calls made
	// with it. Without it the two halves of a delegation sat in the same trail
	// with nothing linking them: an investigator could see a token issued and
	// calls arriving, and could not prove they were the same token.
	TokenID string
	// ConfirmationKey is the RFC 7800 `cnf.jkt` this token was bound to (Phase
	// 206): the RFC 7638 thumbprint of the key whose holder may present it.
	// Empty means the token is an ordinary bearer credential — every token
	// minted before this phase, and every static agent key, which has no claims
	// to carry one.
	//
	// Its presence is what makes the ingress DEMAND a proof, so a bound token
	// cannot be downgraded to a bearer one by leaving the proof off.
	ConfirmationKey string
}

// Principal is the auth.Principal the broker authorizes the call under.
func (id Identity) Principal() *auth.Principal {
	return &auth.Principal{Name: id.AgentName, Role: auth.RoleAgent}
}

// Verifier turns a presented bearer credential into a verified Identity.
type Verifier interface {
	Verify(ctx context.Context, bearer string) (*Identity, error)
}

// keyLister is the slice of store the static-key verifier needs.
type keyLister interface {
	GetAgentKeyByTokenHash(ctx context.Context, tokenHashHex string) (*store.AgentKey, error)
}

// StaticVerifier verifies opaque agent bearer keys against the store by SHA-256
// hash, mirroring how per-user tokens are resolved.
type StaticVerifier struct{ st keyLister }

// NewStaticVerifier returns a verifier backed by st.
func NewStaticVerifier(st keyLister) *StaticVerifier { return &StaticVerifier{st: st} }

// Verify resolves a bearer key to an Identity, or ErrUnauthenticated. A
// disabled, expired or unknown key is indistinguishable (fail-closed, no
// oracle): every failure returns the same error, so a caller cannot probe which
// of the three a bearer hit and learn that a name exists at all.
func (v *StaticVerifier) Verify(ctx context.Context, bearer string) (*Identity, error) {
	bearer = strings.TrimSpace(bearer)
	if bearer == "" {
		return nil, ErrUnauthenticated
	}
	k, err := v.st.GetAgentKeyByTokenHash(ctx, auth.TokenHash(bearer))
	if err != nil {
		return nil, ErrUnauthenticated
	}
	// Active() is the single definition of "this key may still authenticate"
	// (not suspended AND not past its expiry). The store filters disabled rows
	// out of this lookup already, but the expiry half has no such filter — and
	// deliberately so: it is checked here so an expired key fails on the same
	// code path a suspended one does, and so the rule lives in one place rather
	// than being half a SQL predicate and half a Go condition.
	if !k.Active(time.Now()) {
		return nil, ErrUnauthenticated
	}
	id := &Identity{AgentName: k.Name, OnBehalfOf: k.Owner, KeyID: k.ID}
	// Carry the key's expiry into the Identity so the broker's post-park
	// revalidation (api.revalidateAgent) covers static keys too. That check was
	// written for SVIDs, whose expiry is in the token; a static key's lives in
	// the row, and without copying it here a call parked before the key expired
	// would still execute after it — the exact window revalidation exists to
	// close. Left zero when the key never expires.
	if k.ExpiresAt != nil {
		id.ExpiresAt = *k.ExpiresAt
	}
	return id, nil
}
