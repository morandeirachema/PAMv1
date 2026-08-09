package agentid

// exchange.go is the MINTING half of delegation (Phase 57), the sibling of
// svid.go's verifying half.
//
// Phase 13 shipped the ingress: a sub-agent presenting a JWT-SVID whose nested
// RFC 8693 `act` claims name the chain of actors it works for is verified,
// depth-capped and audited. What was missing is the issuer — something has to
// MINT those tokens when an agent spawns a sub-agent, and pamv1 catalogued that
// as needing "an STS / token-exchange endpoint" from outside. It does not: the
// broker already holds an accountable identity for the delegator and already
// decides every call under policy, so the broker itself is the only party that
// can honestly issue "X may act for Y here". This is that endpoint
// ([RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693)).
//
// WHAT IT ISSUES. A broker-signed JWT-SVID for the sub-agent:
//
//	sub          the ACTOR's SPIFFE ID — SPIFFE requires `sub` to be the
//	             workload presenting the token, so the delegation trail lives in
//	             `act`, not in `sub`. This is a deliberate, documented
//	             divergence from RFC 8693 §4.1's example (which keeps the
//	             original subject in `sub`); svid.go verifies the same
//	             convention, and it is what the audit records as the actor chain.
//	act          {sub: <delegator>, act: <delegator's own act>} — the chain
//	             grows by exactly one link per exchange.
//	aud          this broker. The exchange issues for no other audience: a token
//	             minted here is not a bearer credential for anything else.
//	exp          min(now+TTL, the delegator's own exp). Delegated authority
//	             never outlives the authority it came from.
//	on_behalf_of the accountable party, informational only — the verifier
//	             recomputes it from the chain and never trusts the claim.
//
// WHAT IT REFUSES, and why each refusal is load-bearing:
//
//   - IMPERSONATION (an exchange with no actor token). RFC 8693 supports it;
//     pamv1 does not. Erasing the intermediary is the exact opposite of the
//     accountability chain the broker exists to keep.
//   - DELEGATING SOMEONE ELSE'S AUTHORITY. The delegator is the authenticated
//     caller, not a token in the request body. A party holding two captured
//     tokens cannot mint a delegation between them.
//   - `scope`. What a delegated agent may DO is decided per call by the policy
//     engine over the call's arguments — never baked into an identity token,
//     where it would be a standing grant the policy engine cannot see.
//   - A CHAIN PAST THE CAP (`PAM_BROKER_MAX_DELEGATION_DEPTH`). Enforced at
//     mint, not only at ingress, so a runaway sub-agent spawn stops here rather
//     than producing tokens that are refused later.
//   - AN ACTOR THE SUBJECT DID NOT ALLOW (`may_act`, RFC 8693 §4.4).

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/auditfmt"
)

// ExchangeGrantType is RFC 8693's grant_type URN.
const ExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

// TokenTypeJWT is RFC 8693's JWT token-type URN. It is a public identifier, not
// a credential.
const TokenTypeJWT = "urn:ietf:params:oauth:token-type:jwt" // #nosec G101 -- an RFC 8693 URN identifier, not a credential

// ExchangeError is an RFC 6749 §5.2-shaped refusal: a stable machine-readable
// code plus a description. Per RFC 8693 §2.2.2 an unacceptable subject or actor
// token surfaces as `invalid_request`, deliberately without saying which check
// failed — the caller learns that its request was refused, not how to fix a
// forgery.
type ExchangeError struct {
	Code        string // RFC 6749 §5.2 error code
	Description string
}

// Error implements error.
func (e *ExchangeError) Error() string { return e.Code + ": " + e.Description }

// exchangeErr builds an ExchangeError.
func exchangeErr(code, description string) *ExchangeError {
	return &ExchangeError{Code: code, Description: description}
}

// IssuedToken is a minted delegated SVID plus the audit facts about it. The
// token itself is never audited — only who delegated what to whom, for how long.
type IssuedToken struct {
	Token     string
	ExpiresIn int
	// Audit is the detail string recorded for the exchange.
	Audit string
}

// Exchanger mints delegated JWT-SVIDs. It is created once at startup and is safe
// for concurrent use (it holds no mutable state).
type Exchanger struct {
	signKey  ed25519.PrivateKey
	kid      string
	issuer   string
	audience string
	ttl      time.Duration
	maxDepth int
	verify   Verifier // verifies the actor's presented token
}

// ExchangerConfig is what NewExchanger needs. Verifier is the same ingress
// verifier the broker authenticates with, so an actor may present either a
// trust-domain SVID or a token this broker minted earlier (re-delegation).
type ExchangerConfig struct {
	SignKey  ed25519.PrivateKey
	Issuer   string
	Audience string
	TTL      time.Duration
	MaxDepth int
	Verifier Verifier
}

// NewExchanger builds a token-exchange minter. It fails closed on a missing key,
// audience or verifier: an exchange endpoint without an audience would issue
// tokens for anyone, and without a verifier it could not authenticate the actor.
func NewExchanger(cfg ExchangerConfig) (*Exchanger, error) {
	if len(cfg.SignKey) != ed25519.PrivateKeySize {
		return nil, errors.New("agentid: token exchange needs an ed25519 signing key")
	}
	if cfg.Audience == "" {
		return nil, errors.New("agentid: token exchange needs an audience (PAM_BROKER_AUDIENCE)")
	}
	if cfg.Verifier == nil {
		return nil, errors.New("agentid: token exchange needs a verifier for the actor token")
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 5 * time.Minute
	}
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 1
	}
	issuer := cfg.Issuer
	if issuer == "" {
		issuer = "pamv1-broker"
	}
	return &Exchanger{
		signKey:  cfg.SignKey,
		kid:      KeyID(cfg.SignKey.Public().(ed25519.PublicKey)),
		issuer:   issuer,
		audience: cfg.Audience,
		ttl:      cfg.TTL,
		maxDepth: cfg.MaxDepth,
		verify:   cfg.Verifier,
	}, nil
}

// KeyID derives the stable JWK `kid` of a broker signing key: a prefix plus the
// first bytes of the key's SHA-256. Deriving it from the key (rather than
// configuring it) means a rotated key automatically gets a new kid, so a token
// signed by the old key can never be mistaken for one signed by the new.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "pamv1-broker-" + hex.EncodeToString(sum[:8])
}

// PublicKey returns the exchanger's verification key.
func (x *Exchanger) PublicKey() ed25519.PublicKey {
	return x.signKey.Public().(ed25519.PublicKey)
}

// KeyID returns the `kid` the exchanger stamps into every token it mints.
func (x *Exchanger) KeyID() string { return x.kid }

// ExchangeRequest is a parsed RFC 8693 request. Fields the RFC defines but pamv1
// refuses (`scope`) or fixes (`resource`) are validated and rejected rather than
// silently ignored — a client that asked for something it did not get should be
// told, not left believing the token is narrower than it is.
type ExchangeRequest struct {
	GrantType          string
	ActorToken         string
	ActorTokenType     string
	SubjectToken       string
	SubjectTokenType   string
	RequestedTokenType string
	Audience           string
	Scope              string
}

// ParseExchangeForm parses an `application/x-www-form-urlencoded` body into an
// ExchangeRequest. A repeated parameter is refused rather than resolved
// last-wins: for a security-relevant request, an ambiguous body is a bug or an
// attack, and picking a winner hides both.
func ParseExchangeForm(values map[string][]string) (*ExchangeRequest, error) {
	single := func(name string) (string, error) {
		v := values[name]
		if len(v) > 1 {
			return "", exchangeErr("invalid_request", "repeated parameter "+name)
		}
		if len(v) == 0 {
			return "", nil
		}
		return strings.TrimSpace(v[0]), nil
	}
	req := &ExchangeRequest{}
	for _, f := range []struct {
		name string
		dst  *string
	}{
		{"grant_type", &req.GrantType},
		{"actor_token", &req.ActorToken},
		{"actor_token_type", &req.ActorTokenType},
		{"subject_token", &req.SubjectToken},
		{"subject_token_type", &req.SubjectTokenType},
		{"requested_token_type", &req.RequestedTokenType},
		{"audience", &req.Audience},
		{"scope", &req.Scope},
	} {
		v, err := single(f.name)
		if err != nil {
			return nil, err
		}
		*f.dst = v
	}
	return req, nil
}

// Exchange validates an RFC 8693 request and mints the delegated SVID.
//
// delegator is the AUTHENTICATED CALLER's identity — the authority being
// delegated — resolved by the same ingress every other broker call goes through.
// The request's optional subject_token, if present, must verify to that same
// identity; it exists for RFC-shaped clients that send it, not as a second way
// to name a subject.
//
// Every refusal is an *ExchangeError.
func (x *Exchanger) Exchange(ctx context.Context, req *ExchangeRequest, delegator *Identity) (*IssuedToken, error) {
	if req == nil || delegator == nil {
		return nil, exchangeErr("invalid_request", "missing request or delegator")
	}
	if req.GrantType != ExchangeGrantType {
		return nil, exchangeErr("unsupported_grant_type", "grant_type must be "+ExchangeGrantType)
	}
	if t := req.RequestedTokenType; t != "" && t != TokenTypeJWT {
		return nil, exchangeErr("invalid_request", "requested_token_type "+t+" is unsupported")
	}
	if req.ActorToken == "" {
		// The RFC allows an actor-less exchange; that is impersonation, which this
		// broker refuses by design (see the file comment).
		return nil, exchangeErr("invalid_request",
			"actor_token is required: this broker delegates (the intermediary is recorded) and never impersonates")
	}
	if t := req.ActorTokenType; t != "" && t != TokenTypeJWT {
		return nil, exchangeErr("invalid_request", "actor_token_type "+t+" is unsupported")
	}
	if t := req.SubjectTokenType; t != "" && t != TokenTypeJWT {
		return nil, exchangeErr("invalid_request", "subject_token_type "+t+" is unsupported")
	}
	if req.Scope != "" {
		return nil, exchangeErr("invalid_scope",
			"scope is not accepted: what a delegated agent may do is decided per call by policy over the call's arguments, not carried in the token")
	}
	if aud := req.Audience; aud != "" && aud != x.audience {
		return nil, exchangeErr("invalid_target", "audience "+aud+" is not issuable here")
	}
	// The delegator must itself be an SVID: the minted token's act chain is
	// verified at ingress, where every link must be a SPIFFE ID in the trust
	// domain. A static agent key has no SPIFFE ID, so delegating from one would
	// produce a token that could never be used — refuse it plainly instead.
	if delegator.SPIFFEID == "" {
		return nil, exchangeErr("invalid_request",
			"only an SVID-authenticated agent may delegate; a static agent key has no SPIFFE identity to delegate from")
	}
	if delegator.ExpiresAt.IsZero() {
		return nil, exchangeErr("invalid_request", "the delegating token has no expiry")
	}
	// An explicitly supplied subject_token must be the caller's own credential.
	if req.SubjectToken != "" {
		subject, err := x.verify.Verify(ctx, req.SubjectToken)
		if err != nil || subject.SPIFFEID != delegator.SPIFFEID {
			return nil, exchangeErr("invalid_request",
				"subject_token must be the credential you authenticated with: this broker delegates only your own authority")
		}
	}

	actor, err := x.verify.Verify(ctx, req.ActorToken)
	if err != nil {
		return nil, exchangeErr("invalid_request", "actor_token did not verify")
	}
	if actor.SPIFFEID == "" {
		return nil, exchangeErr("invalid_request", "actor_token must be a SPIFFE JWT-SVID")
	}
	if actor.SPIFFEID == delegator.SPIFFEID {
		return nil, exchangeErr("invalid_request", "an agent cannot delegate to itself")
	}
	// RFC 8693 §4.4: the delegator's own token may pin who is allowed to act for
	// it. Absent means unpinned, not "anyone is named".
	if len(delegator.MayAct) > 0 && !slices.Contains(delegator.MayAct, actor.SPIFFEID) {
		return nil, exchangeErr("invalid_request", "the delegating token's may_act claim does not name this actor")
	}

	// The chain the issued token will verify to — bounded here, fail-closed, by
	// the same cap the verifier applies.
	chain := append([]string{actor.SPIFFEID}, delegatorChain(delegator)...)
	if len(chain) > x.maxDepth {
		return nil, exchangeErr("invalid_request", "the delegation chain would exceed the configured depth")
	}

	now := time.Now()
	exp := now.Add(x.ttl)
	if delegator.ExpiresAt.Before(exp) {
		exp = delegator.ExpiresAt // delegated authority never outlives its source
	}
	if !exp.After(now) {
		return nil, exchangeErr("invalid_request", "the delegating token is expired or about to expire")
	}
	jtiRaw := make([]byte, 8)
	if _, err := rand.Read(jtiRaw); err != nil {
		return nil, exchangeErr("server_error", "could not generate a token id")
	}
	jti := hex.EncodeToString(jtiRaw)

	claims := map[string]any{
		"iss": x.issuer,
		"sub": actor.SPIFFEID,
		"aud": x.audience,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": exp.Unix(),
		"jti": jti,
		"act": nestAct(delegatorChain(delegator)),
	}
	if delegator.OnBehalfOf != "" {
		claims["on_behalf_of"] = delegator.OnBehalfOf
	}
	token, err := signJWT(x.signKey, x.kid, claims)
	if err != nil {
		return nil, exchangeErr("server_error", "could not sign the delegated token")
	}
	ttlSec := int(time.Until(exp).Round(time.Second).Seconds())
	return &IssuedToken{
		Token:     token,
		ExpiresIn: ttlSec,
		// Every field is quoted HERE rather than the whole string being quoted by
		// the caller. Whole-quoting stops a value breaking out of the record, but
		// the console un-quotes and then splits on spaces, so an inner `key:value`
		// still landed as a field — and detailFields takes last-wins, so an
		// on_behalf_of of `ops-team actor:spiffe://trusted/root` made the console
		// display a DIFFERENT actor than the one the token was minted for. The
		// refusal path beside this one already quoted per value; this is the same
		// treatment, so the delegation chain reads the same way on both.
		Audit: fmt.Sprintf("actor:%s delegator:%s on_behalf_of:%s chain:%s jti:%s expires_in:%d",
			auditfmt.Field(actor.SPIFFEID, 128), auditfmt.Field(delegator.SPIFFEID, 128),
			auditfmt.Field(delegator.OnBehalfOf, 128), auditfmt.Field(strings.Join(chain, ">"), 256),
			auditfmt.Field(jti, 64), ttlSec),
	}, nil
}

// delegatorChain returns the delegator's own actor chain, falling back to its
// SPIFFE ID for a token that carried no act claim.
func delegatorChain(id *Identity) []string {
	if len(id.ActorChain) > 0 {
		return id.ActorChain
	}
	return []string{id.SPIFFEID}
}

// nestAct turns a chain [a, b, c] into the nested RFC 8693 claim
// {sub: a, act: {sub: b, act: {sub: c}}}, which is what svid.go walks back into
// a chain on the next presentation.
func nestAct(chain []string) map[string]any {
	if len(chain) == 0 {
		return nil
	}
	act := map[string]any{"sub": chain[len(chain)-1]}
	for i := len(chain) - 2; i >= 0; i-- {
		act = map[string]any{"sub": chain[i], "act": act}
	}
	return act
}

// signJWT builds a compact EdDSA JWT. Ed25519 signs the signing input directly
// (no prehash), matching what verifySignature checks.
func signJWT(key ed25519.PrivateKey, kid string, claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": kid})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	b64 := base64.RawURLEncoding.EncodeToString
	signingInput := b64(header) + "." + b64(payload)
	sig := ed25519.Sign(key, []byte(signingInput))
	return signingInput + "." + b64(sig), nil
}
