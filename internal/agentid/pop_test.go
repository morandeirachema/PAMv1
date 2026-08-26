package agentid

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/jwtutil"
)

// b64u is the encoding every JOSE segment and JWK member uses.
func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// TestJWKThumbprintMatchesRFC7638 checks the implementation against the worked
// example in RFC 7638 §3.1 rather than against itself:
// https://datatracker.ietf.org/doc/html/rfc7638#section-3.1
//
// This is the one assertion in the file that could not have been written by
// reading the code — the expected string comes from the standard, so a canonical
// form that was self-consistently wrong (member order, an escaped character, a
// stray space) would fail here and only here.
func TestJWKThumbprintMatchesRFC7638(t *testing.T) {
	rsa := jwtutil.JWK{
		Kty: "RSA",
		E:   "AQAB",
		N: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECP" +
			"ebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY" +
			"368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0f" +
			"M4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
	}
	got, err := JWKThumbprint(rsa)
	if err != nil {
		t.Fatal(err)
	}
	const want = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	if got != want {
		t.Fatalf("RFC 7638 thumbprint = %q, want %q", got, want)
	}
	if !ValidThumbprint(got) {
		t.Fatalf("the RFC's own thumbprint failed ValidThumbprint")
	}
}

// TestJWKThumbprintRefusesUnsafeMembers pins the guard that keeps the canonical
// JSON un-forgeable. It is built by string concatenation, so a member value
// carrying a quote could otherwise close its own field and describe a DIFFERENT
// key — two keys with one thumbprint, which is the single thing a thumbprint
// must never allow.
func TestJWKThumbprintRefusesUnsafeMembers(t *testing.T) {
	forged := jwtutil.JWK{Kty: "OKP", Crv: "Ed25519", X: `AAAA","kty":"oct`}
	if _, err := JWKThumbprint(forged); err == nil {
		t.Fatal("a JWK member containing a quote was accepted into the canonical form")
	}
	for _, k := range []jwtutil.JWK{
		{Kty: "OKP", Crv: "X25519", X: "AAAA"},        // unsupported curve
		{Kty: "EC", Crv: "P-384", X: "AA", Y: "BB"},   // unsupported curve
		{Kty: "oct", X: "AAAA"},                       // symmetric
		{Kty: "OKP", Crv: "Ed25519"},                  // missing x
		{Kty: "EC", Crv: "P-256", X: "AA"},            // missing y
		{Kty: "RSA", E: "AQAB"},                       // missing n
		{Kty: "RSA", E: "AQAB", N: "not+base64url/="}, // wrong alphabet
	} {
		if _, err := JWKThumbprint(k); err == nil {
			t.Fatalf("JWKThumbprint accepted %+v", k)
		}
	}
}

// TestNormalizeURI covers RFC 9449 §4.3 (9)'s comparison rules: query and
// fragment dropped, scheme and host case-folded, a default port removed, and
// anything that is not an absolute http(s) URI reduced to "" so it can never
// equal a real request and therefore fails closed.
func TestNormalizeURI(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://pam.example.com/v1/tool-calls", "https://pam.example.com/v1/tool-calls"},
		{"https://PAM.Example.COM/v1/tool-calls?x=1#f", "https://pam.example.com/v1/tool-calls"},
		{"HTTPS://pam.example.com:443/mcp", "https://pam.example.com/mcp"},
		{"http://pam.example.com:80/mcp", "http://pam.example.com/mcp"},
		{"https://pam.example.com:8443/mcp", "https://pam.example.com:8443/mcp"},
		{"https://pam.example.com", "https://pam.example.com/"},
		{"  https://pam.example.com/mcp  ", "https://pam.example.com/mcp"},
		// A default port belongs to ITS OWN scheme: :443 on http names a real,
		// different endpoint and must survive.
		{"http://pam.example.com:443/mcp", "http://pam.example.com:443/mcp"},
		{"/v1/tool-calls", ""},
		{"ftp://pam.example.com/x", ""},
		{"", ""},
		{"::not a url", ""},
	} {
		if got := NormalizeURI(tc.in); got != tc.want {
			t.Errorf("NormalizeURI(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// proofOpts are the knobs a test twists to build a proof that is wrong in
// exactly one way.
type proofOpts struct {
	typ     string
	alg     string
	method  string
	uri     string
	iat     time.Time
	jti     string
	ath     string
	jwkExtr map[string]any // extra JWK members, e.g. a private key parameter
	key     ed25519.PrivateKey
	pub     ed25519.PublicKey
}

// makeProof builds a signed DPoP proof, defaulting every field to a valid one so
// a test only has to state the thing it is breaking.
func makeProof(t *testing.T, o proofOpts) string {
	t.Helper()
	if o.typ == "" {
		o.typ = "dpop+jwt"
	}
	if o.alg == "" {
		o.alg = "EdDSA"
	}
	if o.iat.IsZero() {
		o.iat = time.Now()
	}
	if o.jti == "" {
		o.jti = "jti-" + b64u([]byte(time.Now().String()))[:12]
	}
	jwk := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64u(o.pub)}
	for k, v := range o.jwkExtr {
		jwk[k] = v
	}
	hdr, _ := json.Marshal(map[string]any{"typ": o.typ, "alg": o.alg, "jwk": jwk})
	claims, _ := json.Marshal(map[string]any{
		"jti": o.jti, "htm": o.method, "htu": o.uri, "iat": o.iat.Unix(), "ath": o.ath,
	})
	signing := b64u(hdr) + "." + b64u(claims)
	return signing + "." + b64u(ed25519.Sign(o.key, []byte(signing)))
}

// TestProofVerify walks every RFC 9449 §4.3 check with a proof that is correct
// except for the one thing under test, so a check that silently stopped running
// shows up as a PASS where a refusal was expected.
func TestProofVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	jkt, err := JWKThumbprint(jwtutil.JWK{Kty: "OKP", Crv: "Ed25519", X: b64u(pub)})
	if err != nil {
		t.Fatal(err)
	}
	const token = "the.access.token"
	const uri = "https://pam.example.com/v1/tool-calls"
	base := proofOpts{method: "POST", uri: uri, ath: AccessTokenHash(token), key: priv, pub: pub}

	// The happy path first: if this does not pass, every refusal below is
	// meaningless because nothing could have got through anyway.
	c := NewProofChecker(60 * time.Second)
	if err := c.Verify(makeProof(t, base), "POST", uri, token, jkt); err != nil {
		t.Fatalf("a correct proof was refused: %v", err)
	}

	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	for _, tc := range []struct {
		name       string
		proof      string
		method     string
		uri        string
		token      string
		jkt        string
		wantReason string
	}{
		{name: "no proof", proof: "", wantReason: "proof-missing"},
		{name: "not a jwt", proof: "abc.def", wantReason: "proof-not-a-jwt"},
		{name: "oversized", proof: strings.Repeat("a", maxProofBytes+1), wantReason: "proof-too-large"},
		{
			name:       "typ is not dpop+jwt",
			proof:      makeProof(t, withTyp(base, "JWT")),
			wantReason: "proof-typ-not-dpop",
		},
		{
			// RFC 9449 §4.3 (5): `none` must not verify. It is checked through the
			// same closed algorithm set svid.go uses, so a downgrade cannot enter
			// by a second door.
			name:       "alg none",
			proof:      makeProof(t, withAlg(base, "none")),
			wantReason: "proof-signature-invalid",
		},
		{
			name:       "jwk carries the private key",
			proof:      makeProof(t, withJWKExtra(base, map[string]any{"d": b64u(priv.Seed())})),
			wantReason: "proof-jwk-carries-private-material",
		},
		{
			name:       "signed by a different key",
			proof:      makeProof(t, withKey(base, otherPriv, pub)),
			wantReason: "proof-signature-invalid",
		},
		{
			name:       "signed by, and naming, a key the token is not bound to",
			proof:      makeProof(t, withKey(base, otherPriv, otherPub)),
			wantReason: "proof-key-is-not-the-bound-key",
		},
		{
			name:       "wrong method",
			proof:      makeProof(t, withMethod(base, "GET")),
			wantReason: "proof-method-mismatch",
		},
		{
			name:       "wrong uri",
			proof:      makeProof(t, withURI(base, "https://pam.example.com/v1/tool-calls/9/resume")),
			wantReason: "proof-uri-mismatch",
		},
		{
			name:       "stale",
			proof:      makeProof(t, withIAT(base, time.Now().Add(-5*time.Minute))),
			wantReason: "proof-stale-or-future",
		},
		{
			name:       "issued in the future",
			proof:      makeProof(t, withIAT(base, time.Now().Add(5*time.Minute))),
			wantReason: "proof-stale-or-future",
		},
		{
			name:       "bound to a different access token",
			proof:      makeProof(t, withATH(base, AccessTokenHash("some.other.token"))),
			wantReason: "proof-not-bound-to-this-token",
		},
		{
			name:       "no ath at all",
			proof:      makeProof(t, withATH(base, "")),
			wantReason: "proof-not-bound-to-this-token",
		},
		{
			name:       "jti too long",
			proof:      makeProof(t, withJTI(base, strings.Repeat("x", maxJTILen+1))),
			wantReason: "proof-jti-too-long",
		},
		{
			name:       "the token's own binding is malformed",
			proof:      makeProof(t, base),
			jkt:        "not-a-thumbprint",
			wantReason: "bound-thumbprint-malformed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			method, target, tok, bound := tc.method, tc.uri, tc.token, tc.jkt
			if method == "" {
				method = "POST"
			}
			if target == "" {
				target = uri
			}
			if tok == "" {
				tok = token
			}
			if bound == "" {
				bound = jkt
			}
			err := NewProofChecker(60*time.Second).Verify(tc.proof, method, target, tok, bound)
			if err == nil {
				t.Fatal("the proof was accepted")
			}
			if !errors.Is(err, ErrProof) {
				t.Fatalf("err = %v, want it to wrap ErrProof", err)
			}
			if got := ProofReason(err); got != tc.wantReason {
				t.Fatalf("reason = %q, want %q", got, tc.wantReason)
			}
		})
	}
}

// TestProofIsSingleUse is the check that makes a proof more than a signature: a
// proof captured off the wire — headers are not secret — must not work a second
// time inside its own freshness window.
func TestProofIsSingleUse(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	jkt, _ := JWKThumbprint(jwtutil.JWK{Kty: "OKP", Crv: "Ed25519", X: b64u(pub)})
	const token, uri = "tok", "https://pam.example.com/mcp"
	proof := makeProof(t, proofOpts{method: "POST", uri: uri, ath: AccessTokenHash(token),
		jti: "fixed-id", key: priv, pub: pub})

	c := NewProofChecker(60 * time.Second)
	if err := c.Verify(proof, "POST", uri, token, jkt); err != nil {
		t.Fatalf("first use refused: %v", err)
	}
	err := c.Verify(proof, "POST", uri, token, jkt)
	if ProofReason(err) != "proof-replayed" {
		t.Fatalf("replay reason = %q, want proof-replayed", ProofReason(err))
	}

	// A DIFFERENT key may reuse the same jti string: the id only has to be unique
	// per presenter, and colliding on it across keys would let one agent deny
	// service to another by guessing its ids.
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherJKT, _ := JWKThumbprint(jwtutil.JWK{Kty: "OKP", Crv: "Ed25519", X: b64u(otherPub)})
	other := makeProof(t, proofOpts{method: "POST", uri: uri, ath: AccessTokenHash(token),
		jti: "fixed-id", key: otherPriv, pub: otherPub})
	if err := c.Verify(other, "POST", uri, token, otherJKT); err != nil {
		t.Fatalf("another key's identical jti was refused: %v", err)
	}
}

// TestRejectedProofDoesNotBurnItsID pins the ordering choice in remember(): the
// replay entry is written only after every other check passes. Otherwise a
// forged proof carrying a guessed jti could pre-emptively poison it and make the
// legitimate proof that follows fail — a denial of service built out of the
// anti-replay defence itself.
func TestRejectedProofDoesNotBurnItsID(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	jkt, _ := JWKThumbprint(jwtutil.JWK{Kty: "OKP", Crv: "Ed25519", X: b64u(pub)})
	const token, uri = "tok", "https://pam.example.com/mcp"
	c := NewProofChecker(60 * time.Second)

	bad := makeProof(t, proofOpts{method: "GET", uri: uri, ath: AccessTokenHash(token),
		jti: "contested", key: priv, pub: pub})
	if err := c.Verify(bad, "POST", uri, token, jkt); err == nil {
		t.Fatal("a proof for the wrong method was accepted")
	}
	good := makeProof(t, proofOpts{method: "POST", uri: uri, ath: AccessTokenHash(token),
		jti: "contested", key: priv, pub: pub})
	if err := c.Verify(good, "POST", uri, token, jkt); err != nil {
		t.Fatalf("a valid proof was refused after a rejected one reused its id: %v", err)
	}
}

// TestReplayWindowQuotaIsPerKey proves the cache fails closed rather than
// forgetting, and that it does so only for the presenter that filled its own
// quota — a flood from one key must not evict another key's entries, because
// eviction is exactly how an attacker would get a replay accepted.
func TestReplayWindowQuotaIsPerKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	jkt, _ := JWKThumbprint(jwtutil.JWK{Kty: "OKP", Crv: "Ed25519", X: b64u(pub)})
	victimPub, victimPriv, _ := ed25519.GenerateKey(rand.Reader)
	victimJKT, _ := JWKThumbprint(jwtutil.JWK{Kty: "OKP", Crv: "Ed25519", X: b64u(victimPub)})
	const token, uri = "tok", "https://pam.example.com/mcp"
	c := NewProofChecker(time.Hour) // long window so nothing ages out mid-test

	// The victim goes first, so its entry is the oldest and would be the natural
	// eviction candidate for a cache that evicted.
	victim := makeProof(t, proofOpts{method: "POST", uri: uri, ath: AccessTokenHash(token),
		jti: "victim-1", key: victimPriv, pub: victimPub})
	if err := c.Verify(victim, "POST", uri, token, victimJKT); err != nil {
		t.Fatal(err)
	}

	for i := range maxProofsPerKey + 1 {
		p := makeProof(t, proofOpts{method: "POST", uri: uri, ath: AccessTokenHash(token),
			jti: "flood-" + b64u([]byte{byte(i), byte(i >> 8)}), key: priv, pub: pub})
		err := c.Verify(p, "POST", uri, token, jkt)
		switch {
		case i < maxProofsPerKey && err != nil:
			t.Fatalf("proof %d of the quota was refused: %v", i, err)
		case i == maxProofsPerKey && ProofReason(err) != "proof-window-full":
			t.Fatalf("the over-quota proof gave %q, want proof-window-full", ProofReason(err))
		}
	}
	// The flood refused itself, and forgot nothing belonging to anyone else.
	if err := c.Verify(victim, "POST", uri, token, victimJKT); ProofReason(err) != "proof-replayed" {
		t.Fatalf("the victim's entry was evicted by another key's flood: %v", err)
	}
}

// TestProofWindowRecoversAfterExpiry shows the quota is a window and not a
// permanent ceiling: once entries age out they are swept, and the same presenter
// can proceed.
func TestProofWindowRecoversAfterExpiry(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	jkt, _ := JWKThumbprint(jwtutil.JWK{Kty: "OKP", Crv: "Ed25519", X: b64u(pub)})
	const token, uri = "tok", "https://pam.example.com/mcp"
	c := NewProofChecker(time.Second)

	proof := makeProof(t, proofOpts{method: "POST", uri: uri, ath: AccessTokenHash(token),
		jti: "recycled", key: priv, pub: pub})
	if err := c.Verify(proof, "POST", uri, token, jkt); err != nil {
		t.Fatal(err)
	}
	// Age the entry directly rather than sleeping: the property under test is
	// that a swept entry is gone, not how long a wall clock takes to get there.
	c.mu.Lock()
	for k := range c.seen {
		c.seen[k] = time.Now().Add(-time.Minute)
	}
	c.mu.Unlock()
	c.sweepLocked(time.Now())
	if len(c.seen) != 0 || len(c.perKey) != 0 {
		t.Fatalf("sweep left %d entries and %d key counters", len(c.seen), len(c.perKey))
	}
}

// Small builders that copy the base options and change one field, so each case
// above reads as "this proof, except ...".
func withTyp(o proofOpts, v string) proofOpts    { o.typ = v; return o }
func withAlg(o proofOpts, v string) proofOpts    { o.alg = v; return o }
func withMethod(o proofOpts, v string) proofOpts { o.method = v; return o }
func withURI(o proofOpts, v string) proofOpts    { o.uri = v; return o }
func withATH(o proofOpts, v string) proofOpts    { o.ath = v; return o }
func withJTI(o proofOpts, v string) proofOpts    { o.jti = v; return o }
func withIAT(o proofOpts, v time.Time) proofOpts { o.iat = v; return o }
func withJWKExtra(o proofOpts, m map[string]any) proofOpts {
	o.jwkExtr = m
	return o
}
func withKey(o proofOpts, k ed25519.PrivateKey, pub ed25519.PublicKey) proofOpts {
	o.key, o.pub = k, pub
	return o
}
