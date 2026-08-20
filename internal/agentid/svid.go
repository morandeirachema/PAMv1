package agentid

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/jwtutil"
)

// actClaim is an RFC 8693 "act" (actor) claim, optionally nested to express a
// delegation chain (the current actor acting on behalf of an inner actor).
type actClaim struct {
	Sub string    `json:"sub"`
	Act *actClaim `json:"act"`
}

// mayActClaim is an RFC 8693 §4.4 "may_act" claim: which party (or parties) the
// token's holder permits to act for it. The RFC's example carries a single
// `sub`; a list is the natural generalization and both are accepted.
type mayActClaim struct {
	Sub json.RawMessage `json:"sub"`
}

// subjects flattens a may_act claim into the subjects it names. A malformed or
// absent claim yields nil — "unpinned" — which the minter treats as no
// restriction, so a broken claim can never widen anything: it can only fail to
// narrow, and every other gate (trust domain, depth cap, policy) still applies.
func (m *mayActClaim) subjects() []string {
	if m == nil || len(m.Sub) == 0 {
		return nil
	}
	var one string
	if json.Unmarshal(m.Sub, &one) == nil {
		if one == "" {
			return nil
		}
		return []string{one}
	}
	var many []string
	if json.Unmarshal(m.Sub, &many) != nil {
		return nil
	}
	out := make([]string, 0, len(many))
	for _, s := range many {
		if s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// SVIDVerifier verifies SPIFFE JWT-SVIDs against a trust-domain JWKS loaded from
// a file (SPIRE publishes the bundle; we verify SVIDs against it, we do not run a
// SPIRE agent). It requires the subject to be a SPIFFE ID in the configured trust
// domain, the audience to match, and the token to be unexpired (fail-closed).
// RFC 8693 nested "act" claims become a delegation actor chain bounded by maxDepth.
type SVIDVerifier struct {
	trustDomain string // e.g. "example.org" (the host of spiffe://example.org/...)
	audience    string
	maxDepth    int
	keys        map[string]crypto.PublicKey // kid -> public key
}

// NewSVIDVerifier loads the trust-domain JWKS from jwksPath and returns a
// verifier. trustDomain is the SPIFFE trust domain host, audience the required
// aud, maxDepth the delegation-depth cap (<=0 becomes 1).
func NewSVIDVerifier(jwksPath, trustDomain, audience string, maxDepth int) (*SVIDVerifier, error) {
	if trustDomain == "" {
		return nil, errors.New("agentid: svid trust domain is required")
	}
	data, err := os.ReadFile(jwksPath) // #nosec G304 -- operator-configured SVID trust-domain JWKS path
	if err != nil {
		return nil, fmt.Errorf("agentid: read svid jwks: %w", err)
	}
	var set struct {
		Keys []jwtutil.JWK `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("agentid: parse svid jwks: %w", err)
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		pub, err := publicKeyFromJWK(k)
		if err != nil {
			return nil, err
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, errors.New("agentid: svid jwks has no usable keys")
	}
	if maxDepth <= 0 {
		maxDepth = 1
	}
	return &SVIDVerifier{trustDomain: trustDomain, audience: audience, maxDepth: maxDepth, keys: keys}, nil
}

// TrustIssuer adds the broker's OWN token-exchange signing key to the verifier,
// so a delegated SVID this broker minted (exchange.go) is accepted on the next
// call — which is what makes a minted token usable at all, and what lets a
// sub-agent re-delegate one more link.
//
// Nothing else about verification changes: a self-issued token still has to name
// a subject in the trust domain, match the audience, be unexpired, and keep its
// act chain inside the depth cap. The key rides the same kid→key map the
// trust-domain bundle uses, so there is exactly one verification path rather
// than a privileged second one — and a kid that collides with a bundle key is a
// startup error, because silently shadowing a trust-domain key with the
// broker's own would be a trust substitution nobody could see.
func (v *SVIDVerifier) TrustIssuer(kid string, pub ed25519.PublicKey) error {
	if kid == "" || len(pub) != ed25519.PublicKeySize {
		return errors.New("agentid: issuer key must have a kid and be an ed25519 public key")
	}
	if _, clash := v.keys[kid]; clash {
		return fmt.Errorf("agentid: issuer kid %q collides with a trust-domain key", kid)
	}
	v.keys[kid] = pub
	return nil
}

// Verify validates a JWT-SVID and returns the delegated Identity, or
// ErrUnauthenticated. Every failure path is fail-closed and indistinguishable
// (no oracle about why a token was rejected).
func (v *SVIDVerifier) Verify(_ context.Context, bearer string) (*Identity, error) {
	bearer = strings.TrimSpace(bearer)
	parts := strings.Split(bearer, ".")
	if len(parts) != 3 {
		return nil, ErrUnauthenticated
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := jwtutil.DecodeSegment(parts[0], &hdr); err != nil {
		return nil, ErrUnauthenticated
	}
	pub, ok := v.keys[hdr.Kid]
	if !ok {
		return nil, ErrUnauthenticated
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrUnauthenticated
	}
	if !verifySignature(hdr.Alg, pub, parts[0]+"."+parts[1], sig) {
		return nil, ErrUnauthenticated
	}

	var claims struct {
		Sub string          `json:"sub"`
		Exp int64           `json:"exp"`
		Aud json.RawMessage `json:"aud"`
		Act *actClaim       `json:"act"`
		// RFC 8693 §4.4: who this token's holder allows to act for it. Carried
		// through to Identity so the token-exchange minter can enforce it
		// (exchange.go); absent means unpinned, never "anyone is named".
		MayAct *mayActClaim `json:"may_act"`
	}
	if err := jwtutil.DecodeSegment(parts[1], &claims); err != nil {
		return nil, ErrUnauthenticated
	}
	// Expiry is mandatory and enforced with a small leeway (fail closed).
	if claims.Exp == 0 || time.Now().After(time.Unix(claims.Exp, 0).Add(60*time.Second)) {
		return nil, ErrUnauthenticated
	}
	if v.audience != "" && !jwtutil.AudienceContains(claims.Aud, v.audience) {
		return nil, ErrUnauthenticated
	}
	// The subject must be a SPIFFE ID in our trust domain.
	if !v.inTrustDomain(claims.Sub) {
		return nil, ErrUnauthenticated
	}
	chain, ok := v.actorChain(claims.Sub, claims.Act)
	if !ok {
		return nil, ErrUnauthenticated // delegation too deep, or a delegate outside the trust domain
	}
	id := &Identity{AgentName: claims.Sub, SPIFFEID: claims.Sub, ActorChain: chain,
		ExpiresAt: time.Unix(claims.Exp, 0), MayAct: claims.MayAct.subjects()}
	// The accountable party is the outermost actor (the human/service the chain
	// bottoms out at), else the subject itself.
	id.OnBehalfOf = chain[len(chain)-1]
	return id, nil
}

// inTrustDomain reports whether sub is a SPIFFE ID under this verifier's trust
// domain (spiffe://<trustDomain>/<path>).
func (v *SVIDVerifier) inTrustDomain(sub string) bool {
	return strings.HasPrefix(sub, "spiffe://"+v.trustDomain+"/")
}

// actorChain builds the delegation chain from the subject plus any nested RFC
// 8693 act claims: [subject, act.sub, act.act.sub, ...]. Every delegate must be a
// SPIFFE ID in this verifier's trust domain — an out-of-domain or malformed
// act.sub is rejected (fail-closed), so a signed token can't inject a spoofed or
// foreign "accountable party" into the audit chain or the approver UI. A chain
// (counting the subject) beyond maxDepth is likewise rejected.
func (v *SVIDVerifier) actorChain(subject string, act *actClaim) ([]string, bool) {
	chain := []string{subject}
	for a := act; a != nil; a = a.Act {
		if a.Sub == "" {
			break
		}
		if !v.inTrustDomain(a.Sub) {
			return nil, false
		}
		chain = append(chain, a.Sub)
		if len(chain) > v.maxDepth {
			return nil, false
		}
	}
	return chain, true
}

// p256FromJWK rebuilds a P-256 public key from a JWK's x/y coordinates.
//
// It parses the SEC1 uncompressed encoding rather than filling
// ecdsa.PublicKey's X/Y fields directly, which Go 1.26 deprecated and
// staticcheck's SA1019 now flags. The change is not only about the warning:
// assigning coordinates constructs whatever was handed over, on-curve or not,
// while ParseUncompressedPublicKey VALIDATES the point. A trust-domain JWKS is
// operator-supplied configuration rather than attacker input, so this was never
// a live hole — but a verifier that will not build an invalid key is the right
// shape for one.
//
// RFC 7518 §6.2.1.2 requires each coordinate to be the curve's full byte length
// with leading zeros preserved (32 bytes for P-256). A shorter value is
// left-padded rather than refused, because a stripped leading zero is a common
// encoder bug and rejecting it would fail a key that is arithmetically correct;
// anything longer is refused, since that cannot be a P-256 coordinate.
func p256FromJWK(xb, yb []byte) (*ecdsa.PublicKey, error) {
	const coordLen = 32
	if len(xb) > coordLen || len(yb) > coordLen {
		return nil, errors.New("agentid: bad P-256 coordinate length")
	}
	buf := make([]byte, 1+2*coordLen)
	buf[0] = 4 // SEC1 uncompressed point
	copy(buf[1+coordLen-len(xb):], xb)
	copy(buf[1+2*coordLen-len(yb):], yb)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), buf)
	if err != nil {
		return nil, fmt.Errorf("agentid: invalid P-256 public key: %w", err)
	}
	return pub, nil
}

// verifySignature checks a JWT signature for the SPIFFE-supported algorithms
// against the JWS signing input (header.payload). JWT ECDSA signatures are raw
// r||s (not ASN.1); Ed25519 signs the input directly (no prehash).
func verifySignature(alg string, pub crypto.PublicKey, signingInput string, sig []byte) bool {
	switch alg {
	case "RS256":
		rp, ok := pub.(*rsa.PublicKey)
		if !ok {
			return false
		}
		digest := sha256.Sum256([]byte(signingInput))
		return rsa.VerifyPKCS1v15(rp, crypto.SHA256, digest[:], sig) == nil
	case "ES256":
		ep, ok := pub.(*ecdsa.PublicKey)
		if !ok || len(sig) != 64 {
			return false
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		digest := sha256.Sum256([]byte(signingInput))
		return ecdsa.Verify(ep, digest[:], r, s)
	case "EdDSA":
		ep, ok := pub.(ed25519.PublicKey)
		if !ok {
			return false
		}
		return ed25519.Verify(ep, []byte(signingInput), sig)
	default:
		return false
	}
}

// publicKeyFromJWK reconstructs a public key from a JWK (RSA, EC P-256, or
// Ed25519 OKP).
func publicKeyFromJWK(k jwtutil.JWK) (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		return jwtutil.RSAKeyFromJWK(k)
	case "EC":
		if k.Crv != "P-256" {
			return nil, fmt.Errorf("agentid: unsupported EC curve %q", k.Crv)
		}
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		yb, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, err
		}
		return p256FromJWK(xb, yb)
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("agentid: unsupported OKP curve %q", k.Crv)
		}
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		if len(xb) != ed25519.PublicKeySize {
			return nil, errors.New("agentid: bad Ed25519 key length")
		}
		return ed25519.PublicKey(xb), nil
	default:
		return nil, fmt.Errorf("agentid: unsupported key type %q", k.Kty)
	}
}

// MultiVerifier tries each verifier in order and returns the first success, so a
// deployment can accept both static agent keys and SPIFFE SVIDs.
type MultiVerifier []Verifier

// Verify returns the first verifier's success, or ErrUnauthenticated if none
// recognize the bearer.
func (m MultiVerifier) Verify(ctx context.Context, bearer string) (*Identity, error) {
	for _, v := range m {
		if id, err := v.Verify(ctx, bearer); err == nil {
			return id, nil
		}
	}
	return nil, ErrUnauthenticated
}
