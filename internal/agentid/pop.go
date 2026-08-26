package agentid

// pop.go makes a delegated token stop being a bearer token (Phase 206).
//
// THE GAP THIS CLOSES. Phase 57 built the minting half of delegation and Phase
// 181 let a delegator pin who may act for the token it hands over — but the
// token itself remained a *bearer* credential: anything that captured one (a
// proxy log, a crashed agent's environment, an over-broad container mount)
// could present it and be that sub-agent until it expired. `may_act` bounds who
// may be delegated to NEXT; it says nothing about who is holding the token now.
// The roadmap has carried "no proof-of-possession on a minted delegated token,
// so bearer remains bearer" as a named limit since the batch was planned. This
// is that.
//
// WHAT IT IS. Sender-constrained tokens, RFC 9449 (DPoP):
// https://datatracker.ietf.org/doc/html/rfc9449
//
//   - The minted token carries an RFC 7800 `cnf` (confirmation) claim whose
//     `jkt` member is the RFC 7638 SHA-256 thumbprint of a public key:
//     https://datatracker.ietf.org/doc/html/rfc7638 (OKP/Ed25519 members from
//     RFC 8037 §2: https://datatracker.ietf.org/doc/html/rfc8037#section-2).
//   - Every call presenting that token must also send a `DPoP` header holding a
//     short JWT — the PROOF — signed by the matching private key and covering
//     this request's method and URI, this token, and a fresh, one-use id.
//   - A captured token without the private key proves nothing and is refused —
//     at the ingress AND at the token exchange, which refuses a bound token as
//     actor_token outright since it cannot demand the actor's proof (T-2 of the
//     2026-08-26 audit; before that the exchange was the one door left open).
//
// WHAT IT DOES NOT CLAIM. The thumbprint is supplied by the DELEGATOR at mint
// time (`cnf_jkt`, see exchange.go), and pamv1 cannot verify that the key
// belongs to the sub-agent rather than to the delegator itself — an attestation
// that would need SPIRE, which stays out of process. That is not a weakness of
// the property actually gained: whoever the key belongs to, a token lifted off
// the wire or out of a log is useless without it. Binding narrows the blast
// radius of THEFT; it is not an additional authorization gate, and nothing here
// changes what policy allows.
//
// WHY HAND-ROLLED. Same reasoning as svid.go, and it reuses that file's key
// parsing (publicKeyFromJWK) and signature check (verifySignature) rather than
// growing a second, subtly different verifier — the failure mode this repo has
// hit before is two copies of one security check drifting apart.

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/morandeirachema/pamv1/internal/jwtutil"
)

// ProofHeader is the HTTP header an RFC 9449 proof travels in.
const ProofHeader = "DPoP"

// proofTyp is the `typ` a proof JWT must declare (RFC 9449 §4.2), which is what
// stops a token minted for some other purpose from being replayed as a proof.
const proofTyp = "dpop+jwt"

// ThumbprintLen is the length of a base64url-encoded SHA-256 JWK thumbprint —
// 43 characters, since 32 bytes encode to ceil(32/3)*4 minus the padding.
const ThumbprintLen = 43

// maxProofBytes bounds a presented proof before anything parses it. A proof is
// three small segments; a megabyte of header is an attack, not a client.
const maxProofBytes = 4096

// ErrProof is returned for every proof failure. Like the rest of this package it
// is deliberately single-valued on the wire: the caller learns that its request
// was refused, never which check caught it. The REASON is carried separately to
// the audit trail, where the responder looks — see ProofError.
var ErrProof = errors.New("agentid: proof of possession failed")

// ProofError wraps ErrProof with a short, non-secret reason for the audit trail.
// errors.Is(err, ErrProof) is true for every one of them, so a caller that only
// wants "refused" never has to enumerate reasons.
type ProofError struct{ Reason string }

// Error implements error.
func (e *ProofError) Error() string { return "agentid: proof of possession failed: " + e.Reason }

// Unwrap makes errors.Is(err, ErrProof) true.
func (e *ProofError) Unwrap() error { return ErrProof }

// proofErr builds a ProofError.
func proofErr(reason string) error { return &ProofError{Reason: reason} }

// ProofReason extracts the recorded reason from a proof failure, or "" when err
// is not one. Used by the ingress to audit WHY a bound token was refused
// without leaking that to the client.
func ProofReason(err error) string {
	var pe *ProofError
	if errors.As(err, &pe) {
		return pe.Reason
	}
	return ""
}

// JWKThumbprint computes the RFC 7638 SHA-256 JWK thumbprint of a public key,
// base64url-encoded — the value that goes in (and is compared against) a `cnf`
// claim's `jkt` member.
//
// The canonical JSON is built by hand rather than marshaled from a map. RFC 7638
// specifies the exact octets to hash — only the required members, ordered
// lexicographically, no whitespace, no escaping — and an encoder is free to make
// choices inside "valid JSON" that change those octets (Go's, for instance,
// escapes `<`, `>` and `&`). Constructing the string states the format instead
// of depending on a library agreeing with it.
//
// Every interpolated value is checked to be base64url first. That is not
// tidiness: a member value containing a quote could otherwise forge the
// canonical form of a DIFFERENT key, which is exactly the collision a
// thumbprint exists to prevent.
func JWKThumbprint(k jwtutil.JWK) (string, error) {
	var canonical string
	switch k.Kty {
	case "RSA":
		if !isBase64URL(k.E) || !isBase64URL(k.N) {
			return "", errors.New("agentid: RSA JWK is missing or has a malformed n/e")
		}
		canonical = `{"e":"` + k.E + `","kty":"RSA","n":"` + k.N + `"}`
	case "EC":
		if k.Crv != "P-256" {
			return "", errors.New("agentid: unsupported EC curve " + k.Crv)
		}
		if !isBase64URL(k.X) || !isBase64URL(k.Y) {
			return "", errors.New("agentid: EC JWK is missing or has a malformed x/y")
		}
		canonical = `{"crv":"P-256","kty":"EC","x":"` + k.X + `","y":"` + k.Y + `"}`
	case "OKP":
		if k.Crv != "Ed25519" {
			return "", errors.New("agentid: unsupported OKP curve " + k.Crv)
		}
		if !isBase64URL(k.X) {
			return "", errors.New("agentid: OKP JWK is missing or has a malformed x")
		}
		canonical = `{"crv":"Ed25519","kty":"OKP","x":"` + k.X + `"}`
	default:
		return "", errors.New("agentid: unsupported key type " + k.Kty)
	}
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// isBase64URL reports whether s is a non-empty unpadded base64url string. JWK
// members that hold key material are always encoded this way (RFC 7517 §4), so
// anything else is malformed input, not an exotic key.
func isBase64URL(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// ValidThumbprint reports whether s has the shape of a base64url SHA-256 JWK
// thumbprint. Used to refuse a malformed `cnf_jkt` at mint time rather than
// stamping a claim nothing could ever satisfy — a token bound to a thumbprint no
// key can produce is a token that is silently dead.
func ValidThumbprint(s string) bool { return len(s) == ThumbprintLen && isBase64URL(s) }

// AccessTokenHash is RFC 9449 §4.2's `ath`: the base64url-encoded SHA-256 of the
// access token's ASCII value. It binds a proof to the one token it was made
// for, so a proof captured alongside token A cannot be replayed with token B.
func AccessTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ProofChecker verifies RFC 9449 proofs and remembers the ones it has seen, so a
// captured proof cannot be replayed inside its own freshness window ON THIS
// REPLICA. The cache is an in-process map, one per api.Server, with no shared
// backing — so in a multi-replica deployment a captured token+proof pair can be
// replayed once per replica inside the ±leeway window. That is the residual an
// operator accepts by running several replicas without a shared nonce store,
// and it was undocumented until the 2026-08-26 audit (T-3). RFC 9449's
// server-issued `nonce` is the standard's answer and is not implemented. Safe
// for concurrent use.
type ProofChecker struct {
	leeway time.Duration

	mu        sync.Mutex
	seen      map[string]time.Time // jkt\x00jti -> when it expires from the window
	perKey    map[string]int       // jkt -> live entries, so one key cannot crowd out another
	lastSweep time.Time
}

// Replay-cache bounds. The window is the freshness leeway doubled (a proof is
// accepted `leeway` either side of now, so nothing older than that can come
// back), and the caps are per-KEY first: a flood of forged jti values from one
// presenter must not evict another presenter's entries and re-open replay for
// them. The global cap is only a memory backstop.
const (
	maxProofsPerKey = 512
	maxProofsTotal  = 65536
)

// NewProofChecker builds a checker accepting proofs whose `iat` is within leeway
// of now (<=0 becomes 60s, which is RFC 9449's own suggested order of magnitude
// and matches the clock leeway the SVID verifier already allows).
func NewProofChecker(leeway time.Duration) *ProofChecker {
	if leeway <= 0 {
		leeway = 60 * time.Second
	}
	return &ProofChecker{
		leeway: leeway,
		seen:   map[string]time.Time{},
		perKey: map[string]int{},
	}
}

// Verify checks a presented proof against the request it claims to cover and the
// key the access token is bound to. It returns nil only when every RFC 9449 §4.3
// check passes; every other outcome is a *ProofError wrapping ErrProof.
//
//	proof       the DPoP header's value
//	method      the request's HTTP method
//	uri         the request's target URI as the CLIENT addressed it, without
//	            query or fragment (the caller normalizes; see NormalizeURI)
//	accessToken the bearer value presented alongside it, for the `ath` binding
//	wantJKT     the `cnf.jkt` the access token carries
//
// The checks run in RFC order with one deliberate exception: the replay entry is
// recorded LAST, once everything else has passed. Recording earlier would let a
// malformed proof burn a jti and turn this cache into a way to deny service to a
// legitimate one.
func (c *ProofChecker) Verify(proof, method, uri, accessToken, wantJKT string) error {
	if !ValidThumbprint(wantJKT) {
		return proofErr("bound-thumbprint-malformed")
	}
	if proof == "" {
		return proofErr("proof-missing")
	}
	if len(proof) > maxProofBytes {
		return proofErr("proof-too-large")
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return proofErr("proof-not-a-jwt")
	}

	// RFC 9449 §4.3 (2)-(7): the header, and the signature made by the key it
	// carries. The key is taken from the proof itself and is only trusted once
	// its thumbprint matches what the TOKEN was bound to, below — a proof is
	// self-describing precisely so the server needs no key distribution.
	var hdr struct {
		Typ string          `json:"typ"`
		Alg string          `json:"alg"`
		JWK json.RawMessage `json:"jwk"`
	}
	if err := jwtutil.DecodeSegment(parts[0], &hdr); err != nil {
		return proofErr("proof-header-malformed")
	}
	if hdr.Typ != proofTyp {
		return proofErr("proof-typ-not-dpop")
	}
	if len(hdr.JWK) == 0 {
		return proofErr("proof-has-no-jwk")
	}
	if hasPrivateJWKMembers(hdr.JWK) {
		// RFC 9449 §4.3 (7). A client that sends its private key has already lost
		// the secret; accepting the proof would record a successful, "proven" call
		// made with a key the server just saw in a header.
		return proofErr("proof-jwk-carries-private-material")
	}
	var jwk jwtutil.JWK
	if err := json.Unmarshal(hdr.JWK, &jwk); err != nil {
		return proofErr("proof-jwk-malformed")
	}
	pub, err := publicKeyFromJWK(jwk)
	if err != nil {
		return proofErr("proof-jwk-unusable")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return proofErr("proof-signature-malformed")
	}
	// verifySignature refuses `none` and every symmetric alg by construction: it
	// switches on the three asymmetric algorithms this package accepts and
	// returns false for anything else, which is RFC 9449 §4.3 (5)'s requirement
	// stated as a closed set rather than as a denylist.
	if !verifySignature(hdr.Alg, pub, parts[0]+"."+parts[1], sig) {
		return proofErr("proof-signature-invalid")
	}

	var claims struct {
		JTI string `json:"jti"`
		HTM string `json:"htm"`
		HTU string `json:"htu"`
		IAT int64  `json:"iat"`
		ATH string `json:"ath"`
	}
	if err := jwtutil.DecodeSegment(parts[1], &claims); err != nil {
		return proofErr("proof-claims-malformed")
	}
	if claims.JTI == "" || claims.HTM == "" || claims.HTU == "" || claims.IAT == 0 {
		return proofErr("proof-claims-incomplete") // §4.3 (3)
	}
	if len(claims.JTI) > maxJTILen {
		// Bounded for the same reason the SVID's jti is: it is chosen by the
		// presenter and it becomes a replay-cache key.
		return proofErr("proof-jti-too-long")
	}
	if claims.HTM != method { // §4.3 (8)
		return proofErr("proof-method-mismatch")
	}
	if NormalizeURI(claims.HTU) != uri { // §4.3 (9)
		return proofErr("proof-uri-mismatch")
	}
	now := time.Now()
	iat := time.Unix(claims.IAT, 0)
	if iat.Before(now.Add(-c.leeway)) || iat.After(now.Add(c.leeway)) { // §4.3 (11)
		return proofErr("proof-stale-or-future")
	}
	// §4.3 (12): the proof must name THIS access token, and the key it is signed
	// by must be the one the token was bound to. Both comparisons are
	// constant-time — they are equality checks over secrets-adjacent values, and
	// this repo's §6 invariant is that such comparisons do not leak timing.
	if subtle.ConstantTimeCompare([]byte(claims.ATH), []byte(AccessTokenHash(accessToken))) != 1 {
		return proofErr("proof-not-bound-to-this-token")
	}
	gotJKT, err := JWKThumbprint(jwk)
	if err != nil {
		return proofErr("proof-jwk-unthumbprintable")
	}
	if subtle.ConstantTimeCompare([]byte(gotJKT), []byte(wantJKT)) != 1 {
		return proofErr("proof-key-is-not-the-bound-key")
	}
	if err := c.remember(gotJKT, claims.JTI, now); err != nil {
		return err
	}
	return nil
}

// remember records a proof id and refuses a repeat. A proof is single-use for
// the length of its freshness window; after that the window itself refuses it,
// so the entry can be dropped.
func (c *ProofChecker) remember(jkt, jti string, now time.Time) error {
	key := jkt + "\x00" + jti
	expiry := now.Add(2 * c.leeway) // the whole span an `iat` can be accepted in

	c.mu.Lock()
	defer c.mu.Unlock()
	// Sweep lazily: whenever the map has grown enough to be worth walking, or
	// once a window has passed with no growth. Sweeping on every insert would
	// make an O(n) pass out of every authenticated call.
	if len(c.seen) >= 1024 || now.Sub(c.lastSweep) > 2*c.leeway {
		c.sweepLocked(now)
	}
	if _, replayed := c.seen[key]; replayed {
		return proofErr("proof-replayed")
	}
	if c.perKey[jkt] >= maxProofsPerKey || len(c.seen) >= maxProofsTotal {
		// Fail closed, and only for the key that filled its own quota. Evicting
		// somebody's live entry to make room would silently re-open replay for
		// exactly the proof an attacker wanted forgotten, so the cache refuses
		// instead of forgetting. The per-agent rate limit above this in the
		// ingress is what keeps a legitimate agent from ever reaching the quota.
		return proofErr("proof-window-full")
	}
	c.seen[key] = expiry
	c.perKey[jkt]++
	return nil
}

// sweepLocked drops entries whose window has passed. The caller holds c.mu.
func (c *ProofChecker) sweepLocked(now time.Time) {
	for k, exp := range c.seen {
		if now.After(exp) {
			delete(c.seen, k)
			if jkt, _, ok := strings.Cut(k, "\x00"); ok {
				c.perKey[jkt]--
				if c.perKey[jkt] <= 0 {
					delete(c.perKey, jkt)
				}
			}
		}
	}
	c.lastSweep = now
}

// NormalizeURI reduces an HTTP target URI to the form `htu` is compared in:
// lowercase scheme and host, no default port, no query and no fragment (RFC 9449
// §4.3 (9), using RFC 3986 §6.2.2/§6.2.3 normalization). A value that does not
// parse as an absolute http(s) URI returns "", which can never equal a
// normalized request URI and therefore fails closed.
func NormalizeURI(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}
	// Scheme-based normalization: an explicit default port names the same
	// resource as no port at all, and clients differ on whether they write it.
	host := strings.ToLower(u.Host)
	switch scheme {
	case "http":
		host = strings.TrimSuffix(host, ":80")
	case "https":
		host = strings.TrimSuffix(host, ":443")
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path
}

// privateJWKMembers are the JWK parameters that only ever appear in a PRIVATE
// key (RFC 7517 §4 / RFC 7518 §6): the EC and OKP private scalar, the symmetric
// key, and RSA's private factors and CRT values.
var privateJWKMembers = []string{"d", "k", "p", "q", "dp", "dq", "qi", "oth"}

// hasPrivateJWKMembers reports whether a proof's embedded JWK carries private
// key material, which RFC 9449 §4.3 (7) requires the server to refuse. It reads
// the raw JSON rather than a typed struct on purpose — a struct would simply
// drop the fields it does not know about, which is the opposite of noticing them.
func hasPrivateJWKMembers(raw json.RawMessage) bool {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return false // unparsable; the typed unmarshal below refuses it anyway
	}
	for _, name := range privateJWKMembers {
		if _, present := members[name]; present {
			return true
		}
	}
	return false
}
