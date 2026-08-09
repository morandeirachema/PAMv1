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

// Verify resolves a bearer key to an Identity, or ErrUnauthenticated. A disabled
// or unknown key is indistinguishable (fail-closed, no oracle).
func (v *StaticVerifier) Verify(ctx context.Context, bearer string) (*Identity, error) {
	bearer = strings.TrimSpace(bearer)
	if bearer == "" {
		return nil, ErrUnauthenticated
	}
	k, err := v.st.GetAgentKeyByTokenHash(ctx, auth.TokenHash(bearer))
	if err != nil {
		return nil, ErrUnauthenticated
	}
	return &Identity{AgentName: k.Name, OnBehalfOf: k.Owner, KeyID: k.ID}, nil
}
