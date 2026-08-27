package agentid_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/agentid"
)

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// makeEdDSA builds an Ed25519-signed JWT from the given claims.
func makeEdDSA(t *testing.T, priv ed25519.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	hdr := b64url([]byte(`{"alg":"EdDSA","kid":"` + kid + `","typ":"JWT"}`))
	cb, _ := json.Marshal(claims)
	signing := hdr + "." + b64url(cb)
	return signing + "." + b64url(ed25519.Sign(priv, []byte(signing)))
}

// edJWKS writes a one-key Ed25519 JWKS to a temp file and returns its path.
func edJWKS(t *testing.T, pub ed25519.PublicKey, kid string) string {
	t.Helper()
	jwks := map[string]any{"keys": []map[string]any{{"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": b64url(pub)}}}
	b, _ := json.Marshal(jwks)
	path := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestSVIDVerify covers a valid SVID, audience/expiry/trust-domain enforcement,
// a forged signature, and RFC 8693 delegation-depth capping.
func TestSVIDVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	path := edJWKS(t, pub, "k1")
	const td, aud = "example.org", "pam-broker"
	v, err := agentid.NewSVIDVerifier(path, td, aud, 2)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sub := "spiffe://example.org/ns/prod/sa/bot"

	// A valid SVID resolves to an identity carrying the SPIFFE ID.
	good := makeEdDSA(t, priv, "k1", map[string]any{"sub": sub, "aud": aud, "exp": time.Now().Add(time.Hour).Unix()})
	id, err := v.Verify(ctx, good)
	if err != nil || id.SPIFFEID != sub || id.AgentName != sub {
		t.Fatalf("valid svid: id=%+v err=%v", id, err)
	}

	// Wrong audience is rejected.
	badAud := makeEdDSA(t, priv, "k1", map[string]any{"sub": sub, "aud": "someone-else", "exp": time.Now().Add(time.Hour).Unix()})
	if _, err := v.Verify(ctx, badAud); err == nil {
		t.Fatal("wrong audience should be rejected")
	}

	// Expired is rejected (fail closed).
	expired := makeEdDSA(t, priv, "k1", map[string]any{"sub": sub, "aud": aud, "exp": time.Now().Add(-time.Hour).Unix()})
	if _, err := v.Verify(ctx, expired); err == nil {
		t.Fatal("expired svid should be rejected")
	}

	// A subject outside the trust domain is rejected.
	foreign := makeEdDSA(t, priv, "k1", map[string]any{"sub": "spiffe://evil.example/ns/x", "aud": aud, "exp": time.Now().Add(time.Hour).Unix()})
	if _, err := v.Verify(ctx, foreign); err == nil {
		t.Fatal("foreign trust domain should be rejected")
	}

	// A forged signature (flip the last byte) is rejected.
	forged := good[:len(good)-2] + string([]byte{good[len(good)-2] ^ 0x01}) + good[len(good)-1:]
	if _, err := v.Verify(ctx, forged); err == nil {
		t.Fatal("forged signature should be rejected")
	}

	// Delegation within the depth cap populates the actor chain.
	deleg := makeEdDSA(t, priv, "k1", map[string]any{
		"sub": sub, "aud": aud, "exp": time.Now().Add(time.Hour).Unix(),
		"act": map[string]any{"sub": "spiffe://example.org/user/alice"},
	})
	id, err = v.Verify(ctx, deleg)
	if err != nil || len(id.ActorChain) != 2 || id.OnBehalfOf != "spiffe://example.org/user/alice" {
		t.Fatalf("delegation: id=%+v err=%v", id, err)
	}

	// A chain deeper than maxDepth (2) is fail-closed.
	tooDeep := makeEdDSA(t, priv, "k1", map[string]any{
		"sub": sub, "aud": aud, "exp": time.Now().Add(time.Hour).Unix(),
		"act": map[string]any{"sub": "spiffe://example.org/svc/a", "act": map[string]any{"sub": "spiffe://example.org/user/bob"}},
	})
	if _, err := v.Verify(ctx, tooDeep); err == nil {
		t.Fatal("delegation past the depth cap should be rejected")
	}
}

// TestSVIDVerifyES256 covers the ECDSA P-256 verification branch.
func TestSVIDVerifyES256(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwks := map[string]any{"keys": []map[string]any{{
		"kty": "EC", "crv": "P-256", "kid": "e1",
		"x": b64url(key.X.Bytes()), "y": b64url(key.Y.Bytes()),
	}}}
	b, _ := json.Marshal(jwks)
	path := filepath.Join(t.TempDir(), "ec.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := agentid.NewSVIDVerifier(path, "example.org", "pam-broker", 1)
	if err != nil {
		t.Fatal(err)
	}

	sub := "spiffe://example.org/ns/prod/sa/ec-bot"
	hdr := b64url([]byte(`{"alg":"ES256","kid":"e1","typ":"JWT"}`))
	cb, _ := json.Marshal(map[string]any{"sub": sub, "aud": "pam-broker", "exp": time.Now().Add(time.Hour).Unix()})
	signing := hdr + "." + b64url(cb)
	digest := sha256.Sum256([]byte(signing))
	r, s, _ := ecdsa.Sign(rand.Reader, key, digest[:])
	// JWT ES256 signature is fixed-width r||s (32 bytes each).
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	token := signing + "." + b64url(sig)

	id, err := v.Verify(context.Background(), token)
	if err != nil || id.SPIFFEID != sub {
		t.Fatalf("ES256 svid: id=%+v err=%v", id, err)
	}
}

// TestSVIDAlgConfusion proves the header alg cannot be abused: alg=none and
// alg=HS256 (the public key as an HMAC secret) are both rejected.
func TestSVIDAlgConfusion(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	v, err := agentid.NewSVIDVerifier(edJWKS(t, pub, "k1"), "example.org", "pam-broker", 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	claims, _ := json.Marshal(map[string]any{"sub": "spiffe://example.org/ns/x", "aud": "pam-broker", "exp": time.Now().Add(time.Hour).Unix()})
	payload := b64url(claims)

	// alg=none with an empty signature.
	if _, err := v.Verify(ctx, b64url([]byte(`{"alg":"none","kid":"k1"}`))+"."+payload+"."); err == nil {
		t.Fatal("alg=none must be rejected")
	}
	// alg=HS256 forging a MAC with the public key.
	hsHdr := b64url([]byte(`{"alg":"HS256","kid":"k1"}`))
	mac := hmac.New(sha256.New, pub)
	mac.Write([]byte(hsHdr + "." + payload))
	if _, err := v.Verify(ctx, hsHdr+"."+payload+"."+b64url(mac.Sum(nil))); err == nil {
		t.Fatal("alg=HS256 must be rejected (no algorithm confusion)")
	}
}

// TestSVIDForeignDelegation proves a delegation act.sub outside the trust domain
// is rejected, so a signed token can't inject a spoofed accountable identity.
func TestSVIDForeignDelegation(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	v, err := agentid.NewSVIDVerifier(edJWKS(t, pub, "k1"), "example.org", "pam-broker", 3)
	if err != nil {
		t.Fatal(err)
	}
	tok := makeEdDSA(t, priv, "k1", map[string]any{
		"sub": "spiffe://example.org/ns/x", "aud": "pam-broker", "exp": time.Now().Add(time.Hour).Unix(),
		"act": map[string]any{"sub": "spiffe://foreign.org/admin"},
	})
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Fatal("a foreign-domain delegate (act.sub) must be rejected")
	}
}

// TestSVIDVerifyRS256 covers the RSA/RS256 verification branch.
func TestSVIDVerifyRS256(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks, _ := json.Marshal(map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "kid": "r1",
		"n": b64url(key.N.Bytes()), "e": b64url(big.NewInt(int64(key.E)).Bytes()),
	}}})
	path := filepath.Join(t.TempDir(), "rsa.json")
	if err := os.WriteFile(path, jwks, 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := agentid.NewSVIDVerifier(path, "example.org", "pam-broker", 1)
	if err != nil {
		t.Fatal(err)
	}
	sub := "spiffe://example.org/ns/rsa-bot"
	hdr := b64url([]byte(`{"alg":"RS256","kid":"r1"}`))
	cb, _ := json.Marshal(map[string]any{"sub": sub, "aud": "pam-broker", "exp": time.Now().Add(time.Hour).Unix()})
	signing := hdr + "." + b64url(cb)
	digest := sha256.Sum256([]byte(signing))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	id, err := v.Verify(context.Background(), signing+"."+b64url(sig))
	if err != nil || id.SPIFFEID != sub {
		t.Fatalf("RS256 svid: id=%+v err=%v", id, err)
	}
}

// --- the bundle is re-read when the file changes (Phase 224) ---

// rewriteJWKS overwrites path with a bundle holding the given ed25519 keys,
// nudging the modification time forward so a rewrite inside the same
// timestamp granularity still reads as a new version.
func rewriteJWKS(t *testing.T, path string, keys map[string]ed25519.PublicKey) {
	t.Helper()
	list := make([]map[string]string, 0, len(keys))
	for kid, pub := range keys {
		list = append(list, map[string]string{"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": b64url(pub)})
	}
	b, _ := json.Marshal(map[string]any{"keys": list})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, st.ModTime().Add(2*time.Second), st.ModTime().Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
}

func svidFor(t *testing.T, priv ed25519.PrivateKey, kid string) string {
	t.Helper()
	return makeEdDSA(t, priv, kid, map[string]any{
		"sub": "spiffe://example.org/agent/rot", "aud": "pam-broker", "exp": time.Now().Add(time.Hour).Unix(),
	})
}

// TestSVIDBundleReloadsOnRotation is the phase in one test: the issuer adds a
// key and later retires the old one, and the verifier follows without a
// restart — a token under the new key is refused only until the file changes,
// and a token under the retired key is refused as soon as it is gone.
func TestSVIDBundleReloadsOnRotation(t *testing.T) {
	pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	path := edJWKS(t, pub1, "k1")
	v, err := agentid.NewSVIDVerifier(path, "example.org", "pam-broker", 1)
	if err != nil {
		t.Fatal(err)
	}
	v.SetBundleRecheck(0)
	if _, err := v.Verify(context.Background(), svidFor(t, priv2, "k2")); err == nil {
		t.Fatal("a token under a key the bundle does not hold must be refused")
	}
	// Rotation, step one: the issuer publishes k2 beside k1.
	rewriteJWKS(t, path, map[string]ed25519.PublicKey{"k1": pub1, "k2": pub2})
	if _, err := v.Verify(context.Background(), svidFor(t, priv2, "k2")); err != nil {
		t.Fatalf("after the bundle gained k2 the verifier must accept it without a restart: %v", err)
	}
	if _, err := v.Verify(context.Background(), svidFor(t, priv1, "k1")); err != nil {
		t.Fatalf("k1 is still in the bundle and must still verify: %v", err)
	}
	// Step two: k1 is retired.
	rewriteJWKS(t, path, map[string]ed25519.PublicKey{"k2": pub2})
	if _, err := v.Verify(context.Background(), svidFor(t, priv1, "k1")); err == nil {
		t.Fatal("a key the issuer removed from the bundle must stop verifying")
	}
	if _, err := v.Verify(context.Background(), svidFor(t, priv2, "k2")); err != nil {
		t.Fatalf("k2 must keep verifying after k1's retirement: %v", err)
	}
}

// TestSVIDBundleKeepsLastGoodOnBadRewrite: a half-written or empty bundle —
// what a rotation looks like for a moment — must not turn into an outage. The
// verifier keeps the keys it had, reports the failure, and picks up the file
// once it is whole again.
func TestSVIDBundleKeepsLastGoodOnBadRewrite(t *testing.T) {
	pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
	path := edJWKS(t, pub1, "k1")
	v, err := agentid.NewSVIDVerifier(path, "example.org", "pam-broker", 1)
	if err != nil {
		t.Fatal(err)
	}
	v.SetBundleRecheck(0)
	for name, junk := range map[string]string{"garbage": "{not json", "empty set": `{"keys":[]}`} {
		if err := os.WriteFile(path, []byte(junk), 0o600); err != nil {
			t.Fatal(err)
		}
		st, _ := os.Stat(path)
		_ = os.Chtimes(path, st.ModTime().Add(2*time.Second), st.ModTime().Add(2*time.Second))
		if changed, err := v.Reload(false); err == nil || changed {
			t.Fatalf("%s: Reload must fail and change nothing: changed=%v err=%v", name, changed, err)
		}
		if _, err := v.Verify(context.Background(), svidFor(t, priv1, "k1")); err != nil {
			t.Fatalf("%s: the last good bundle must stay in force: %v", name, err)
		}
	}
	// And a file removed outright is the same case, not a reason to trust nobody.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), svidFor(t, priv1, "k1")); err != nil {
		t.Fatalf("with the bundle file gone the last good keys must still verify: %v", err)
	}
}

// TestSVIDBundleReloadPreservesIssuer: the broker's own token-exchange key,
// trusted through TrustIssuer, is not in the file and must survive every
// reload — and a rotated bundle that tries to shadow its kid is refused whole,
// the same refusal the startup path makes.
func TestSVIDBundleReloadPreservesIssuer(t *testing.T) {
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	issuerPub, issuerPriv, _ := ed25519.GenerateKey(rand.Reader)
	path := edJWKS(t, pub1, "k1")
	v, err := agentid.NewSVIDVerifier(path, "example.org", "pam-broker", 1)
	if err != nil {
		t.Fatal(err)
	}
	v.SetBundleRecheck(0)
	if err := v.TrustIssuer("broker-1", issuerPub); err != nil {
		t.Fatal(err)
	}
	rewriteJWKS(t, path, map[string]ed25519.PublicKey{"k2": pub2})
	if _, err := v.Verify(context.Background(), svidFor(t, priv2, "k2")); err != nil {
		t.Fatalf("rotated bundle: %v", err)
	}
	if _, err := v.Verify(context.Background(), svidFor(t, issuerPriv, "broker-1")); err != nil {
		t.Fatalf("the issuer key must survive a bundle reload: %v", err)
	}
	// A bundle shadowing the issuer's kid is refused; k2 stays, broker-1 stays
	// the broker's own key, and the impostor never verifies.
	impostorPub, impostorPriv, _ := ed25519.GenerateKey(rand.Reader)
	rewriteJWKS(t, path, map[string]ed25519.PublicKey{"k2": pub2, "broker-1": impostorPub})
	if changed, err := v.Reload(false); err == nil || changed {
		t.Fatalf("a bundle shadowing the issuer kid must be refused whole: changed=%v err=%v", changed, err)
	}
	if _, err := v.Verify(context.Background(), svidFor(t, impostorPriv, "broker-1")); err == nil {
		t.Fatal("a bundle key shadowing the issuer kid was trusted")
	}
	if _, err := v.Verify(context.Background(), svidFor(t, issuerPriv, "broker-1")); err != nil {
		t.Fatalf("the issuer's own key must still verify after the refused bundle: %v", err)
	}
}
