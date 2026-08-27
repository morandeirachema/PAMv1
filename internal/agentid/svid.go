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
	"log/slog"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/morandeirachema/pamv1/internal/jwtutil"
)

// actClaim is an RFC 8693 "act" (actor) claim, optionally nested to express a
// delegation chain (the current actor acting on behalf of an inner actor).
type actClaim struct {
	Sub string    `json:"sub"`
	Act *actClaim `json:"act"`
}

// cnfClaim is an RFC 7800 §3.1 "cnf" (confirmation) claim. Only the RFC 9449
// `jkt` member is read: PAMv1 binds tokens to a key THUMBPRINT, never to an
// embedded key, so there is nothing here to reconstruct a key from.
type cnfClaim struct {
	JKT string `json:"jkt"`
}

// thumbprint returns the bound key's thumbprint, or "" for a token that carries
// no confirmation at all.
//
// A `cnf` this verifier cannot enforce is refused by Verify rather than reduced
// to "" here, and the difference matters: treating an unreadable confirmation as
// "unbound" would DOWNGRADE a token its issuer had deliberately constrained —
// the one outcome a binding must never produce. RFC 7800 defines `jwk` and `kid`
// confirmations too; PAMv1 enforces only `jkt`, so a token using either is
// refused instead of quietly honoured as a bearer credential.
func (c *cnfClaim) thumbprint() string {
	if c == nil {
		return ""
	}
	return c.JKT
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
//
// The bundle is re-read when the file changes (Phase 224): SPIRE rotates its
// signing keys and rewrites the bundle on its own schedule, and until this
// phase a rotation meant a restart — a verifier that had read the file once at
// startup refused every SVID signed by a key it had never seen. Verify compares
// the file's modification time and size at most every recheckEvery, and
// re-reads it immediately (rate-limited) when a token names a kid it does not
// hold, which is the moment a rotation shows up. A re-read that fails — the file
// mid-rewrite, unparsable, empty, or shadowing an issuer key — keeps the LAST
// GOOD bundle and reports the error through the logger: refusing everyone
// because the issuer's file was half-written would turn a routine rotation
// into an outage, and a key that should stop being trusted is retired by the
// issuer removing it, which the next successful read honours.
type SVIDVerifier struct {
	trustDomain string // e.g. "example.org" (the host of spiffe://example.org/...)
	audience    string
	maxDepth    int
	path        string
	log         *slog.Logger

	mu     sync.RWMutex
	keys   map[string]crypto.PublicKey // kid -> public key: the bundle's keys plus the issuer's
	issuer map[string]crypto.PublicKey // TrustIssuer keys, re-applied on every reload
	// stamp is what the current keys were parsed from; a different stamp on
	// disk is what triggers a re-read.
	stamp bundleStamp
	// recheckEvery bounds how often Verify stats the file; lastCheck is the
	// last time it did, lastForced the last time an unknown kid made it re-read
	// regardless — so a stream of junk kids costs one stat per second at most.
	recheckEvery          time.Duration
	lastCheck, lastForced time.Time
}

// bundleStamp identifies a version of the bundle file without reading it.
type bundleStamp struct {
	modTime time.Time
	size    int64
}

// DefaultBundleRecheck is how often Verify compares the bundle file's stamp
// with the one it loaded. A stat, not a read; the read happens only on change.
const DefaultBundleRecheck = 30 * time.Second

// forcedRecheckMinGap bounds how often an unknown kid can make Verify re-read
// the bundle regardless of the periodic check.
const forcedRecheckMinGap = time.Second

// NewSVIDVerifier loads the trust-domain JWKS from jwksPath and returns a
// verifier. trustDomain is the SPIFFE trust domain host, audience the required
// aud, maxDepth the delegation-depth cap (<=0 becomes 1). The file is re-read
// when it changes; see the type's doc.
func NewSVIDVerifier(jwksPath, trustDomain, audience string, maxDepth int) (*SVIDVerifier, error) {
	if trustDomain == "" {
		return nil, errors.New("agentid: svid trust domain is required")
	}
	keys, stamp, err := loadBundle(jwksPath)
	if err != nil {
		return nil, err
	}
	if maxDepth <= 0 {
		maxDepth = 1
	}
	return &SVIDVerifier{
		trustDomain: trustDomain, audience: audience, maxDepth: maxDepth, path: jwksPath,
		log:  slog.Default(),
		keys: keys, issuer: map[string]crypto.PublicKey{}, stamp: stamp,
		recheckEvery: DefaultBundleRecheck, lastCheck: time.Now(),
	}, nil
}

// WithLogger sets where reloads and reload failures are reported.
func (v *SVIDVerifier) WithLogger(l *slog.Logger) *SVIDVerifier {
	if l != nil {
		v.log = l
	}
	return v
}

// SetBundleRecheck changes how often Verify stats the bundle file; zero makes
// every Verify look, which tests use to make a rotation visible at once.
func (v *SVIDVerifier) SetBundleRecheck(d time.Duration) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.recheckEvery = d
}

// loadBundle reads and parses the JWKS file, returning its keys and the stamp
// they were read under. Every failure is an error rather than an empty set: a
// bundle with no usable keys is a misconfiguration, not a trust domain with no
// members.
func loadBundle(path string) (map[string]crypto.PublicKey, bundleStamp, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-configured SVID trust-domain JWKS path
	if err != nil {
		return nil, bundleStamp{}, fmt.Errorf("agentid: read svid jwks: %w", err)
	}
	defer f.Close()
	// Stat the open handle, so the stamp belongs to the bytes read and not to
	// a file that was replaced between a stat and a read.
	info, err := f.Stat()
	if err != nil {
		return nil, bundleStamp{}, fmt.Errorf("agentid: stat svid jwks: %w", err)
	}
	stamp := bundleStamp{modTime: info.ModTime(), size: info.Size()}
	var set struct {
		Keys []jwtutil.JWK `json:"keys"`
	}
	if err := json.NewDecoder(f).Decode(&set); err != nil {
		return nil, bundleStamp{}, fmt.Errorf("agentid: parse svid jwks: %w", err)
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		pub, err := publicKeyFromJWK(k)
		if err != nil {
			return nil, bundleStamp{}, err
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, bundleStamp{}, errors.New("agentid: svid jwks has no usable keys")
	}
	return keys, stamp, nil
}

// Reload re-reads the bundle file if its stamp differs from the one the current
// keys were parsed under (always, when force is set), and swaps the keys in
// atomically. It reports whether the keys changed. On any failure the current
// keys stay in force and the error is returned — and logged, since the callers
// on the verify path have nobody to return it to.
func (v *SVIDVerifier) Reload(force bool) (changed bool, err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := time.Now()
	v.lastCheck = now
	if force {
		v.lastForced = now
	} else {
		info, serr := os.Stat(v.path)
		if serr != nil {
			v.log.Warn("svid trust bundle unreadable; keeping the last good keys", "path", v.path, "err", serr)
			return false, serr
		}
		if info.ModTime().Equal(v.stamp.modTime) && info.Size() == v.stamp.size {
			return false, nil
		}
	}
	keys, stamp, lerr := loadBundle(v.path)
	if lerr != nil {
		v.log.Warn("svid trust bundle re-read failed; keeping the last good keys", "path", v.path, "err", lerr)
		return false, lerr
	}
	for kid, pub := range v.issuer {
		if _, clash := keys[kid]; clash {
			// The same refusal TrustIssuer makes at startup: a bundle key that
			// shadows the broker's own signing kid would be a trust substitution
			// nobody could see, so the new bundle is refused whole.
			cerr := fmt.Errorf("agentid: reloaded bundle has a key colliding with issuer kid %q", kid)
			v.log.Error("svid trust bundle refused; keeping the last good keys", "path", v.path, "err", cerr)
			return false, cerr
		}
		keys[kid] = pub
	}
	if stamp == v.stamp {
		return false, nil
	}
	added, removed := diffKids(v.keys, keys)
	v.keys, v.stamp = keys, stamp
	v.log.Info("svid trust bundle reloaded", "path", v.path, "keys", len(keys)-len(v.issuer), "added", added, "removed", removed)
	return true, nil
}

// diffKids reports which kids a reload added and removed, for the log line an
// operator reads to confirm a rotation landed.
func diffKids(old, cur map[string]crypto.PublicKey) (added, removed []string) {
	for kid := range cur {
		if _, ok := old[kid]; !ok {
			added = append(added, kid)
		}
	}
	for kid := range old {
		if _, ok := cur[kid]; !ok {
			removed = append(removed, kid)
		}
	}
	return added, removed
}

// keyFor resolves a kid, re-reading the bundle when it is due and — once,
// rate-limited — when the kid is unknown, which is what a rotation looks like
// from here.
func (v *SVIDVerifier) keyFor(kid string) (crypto.PublicKey, bool) {
	v.mu.RLock()
	due := time.Since(v.lastCheck) >= v.recheckEvery
	pub, ok := v.keys[kid]
	v.mu.RUnlock()
	if due {
		_, _ = v.Reload(false)
		v.mu.RLock()
		pub, ok = v.keys[kid]
		v.mu.RUnlock()
	}
	if ok {
		return pub, true
	}
	v.mu.RLock()
	mayForce := time.Since(v.lastForced) >= forcedRecheckMinGap
	v.mu.RUnlock()
	if !mayForce {
		return nil, false
	}
	_, _ = v.Reload(true)
	v.mu.RLock()
	pub, ok = v.keys[kid]
	v.mu.RUnlock()
	return pub, ok
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
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, clash := v.keys[kid]; clash {
		return fmt.Errorf("agentid: issuer kid %q collides with a trust-domain key", kid)
	}
	v.keys[kid] = pub
	v.issuer[kid] = pub // survives every reload of the bundle
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
	pub, ok := v.keyFor(hdr.Kid)
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
		Jti string          `json:"jti"`
		Act *actClaim       `json:"act"`
		// RFC 8693 §4.4: who this token's holder allows to act for it. Carried
		// through to Identity so the token-exchange minter can enforce it
		// (exchange.go); absent means unpinned, never "anyone is named".
		MayAct *mayActClaim `json:"may_act"`
		// RFC 7800 §3.1 confirmation: the key this token is bound to, as an RFC
		// 9449 `jkt` thumbprint. Carried through to Identity so the ingress can
		// demand a proof of possession (pop.go); absent means an ordinary bearer
		// token.
		Cnf *cnfClaim `json:"cnf"`
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
	// A confirmation claim this verifier cannot enforce fails closed (Phase 206).
	if claims.Cnf != nil && !ValidThumbprint(claims.Cnf.JKT) {
		return nil, ErrUnauthenticated
	}
	chain, ok := v.actorChain(claims.Sub, claims.Act)
	if !ok {
		return nil, ErrUnauthenticated // delegation too deep, or a delegate outside the trust domain
	}
	id := &Identity{AgentName: claims.Sub, SPIFFEID: claims.Sub, ActorChain: chain,
		ExpiresAt: time.Unix(claims.Exp, 0), MayAct: claims.MayAct.subjects(),
		ConfirmationKey: claims.Cnf.thumbprint(),
		// Recorded, never trusted for a decision: `jti` is an identifier the
		// issuer chose, so it can join a mint to its uses and must not gate
		// anything. Bounded here rather than at every audit site.
		TokenID: boundedJTI(claims.Jti)}
	// The accountable party is the outermost actor (the human/service the chain
	// bottoms out at), else the subject itself.
	id.OnBehalfOf = chain[len(chain)-1]
	return id, nil
}

// maxJTILen bounds a recorded token id. A jti is an opaque identifier chosen by
// the issuer, so PAMv1 neither parses nor trusts it — but it reaches the audit
// trail, and an unbounded issuer-controlled string on the trail is a way to
// flood it.
const maxJTILen = 64

// boundedJTI truncates an over-long token id rather than dropping it: a
// truncated id still joins a mint to its uses in practice, while a dropped one
// loses the link entirely.
func boundedJTI(jti string) string {
	if len(jti) > maxJTILen {
		return jti[:maxJTILen]
	}
	return jti
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
