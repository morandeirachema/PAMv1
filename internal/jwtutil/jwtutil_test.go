package jwtutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
)

// TestAudienceContains covers the "aud" claim's two encodings (a single string
// and an array) and, crucially, the empty/absent/malformed cases — the guard the
// two former copies disagreed on. Moved here from the oidc package when the
// helper was consolidated.
func TestAudienceContains(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want string
		ok   bool
	}{
		{"single match", `"client-a"`, "client-a", true},
		{"single mismatch", `"client-b"`, "client-a", false},
		{"array match, first", `["client-a","other"]`, "client-a", true},
		{"array match, later", `["other","client-a"]`, "client-a", true},
		{"array mismatch", `["other","another"]`, "client-a", false},
		{"empty array", `[]`, "client-a", false},
		{"array with empty string", `[""]`, "client-a", false},
		{"absent claim", `null`, "client-a", false},
		{"nil raw", ``, "client-a", false},
		{"malformed", `{"aud":"client-a"}`, "client-a", false},
		{"number", `42`, "client-a", false},
		{"empty want against empty string", `""`, "", true},
	} {
		if got := AudienceContains(json.RawMessage(tc.raw), tc.want); got != tc.ok {
			t.Errorf("%s: AudienceContains(%s, %q) = %v, want %v", tc.name, tc.raw, tc.want, got, tc.ok)
		}
	}
}

// TestDecodeSegment round-trips a base64url JWT segment and reports a decode error
// on malformed input.
func TestDecodeSegment(t *testing.T) {
	seg := base64.RawURLEncoding.EncodeToString([]byte(`{"kid":"k1","kty":"RSA"}`))
	var k JWK
	if err := DecodeSegment(seg, &k); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if k.Kid != "k1" || k.Kty != "RSA" {
		t.Fatalf("decoded wrong JWK: %+v", k)
	}
	if err := DecodeSegment("!!not base64!!", &k); err == nil {
		t.Fatal("expected an error on malformed base64")
	}
}

// TestRSAKeyFromJWK proves a JWK's (n, e) parameters reconstruct the exact RSA
// public key they were derived from — the check both token verifiers rely on.
func TestRSAKeyFromJWK(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub := &priv.PublicKey
	eb := big.NewInt(int64(pub.E)).Bytes()
	k := JWK{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(eb),
	}
	got, err := RSAKeyFromJWK(k)
	if err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatalf("reconstructed key differs from the original")
	}
	// A malformed modulus is an error, not a silent zero key.
	if _, err := RSAKeyFromJWK(JWK{Kty: "RSA", N: "!!bad!!", E: k.E}); err == nil {
		t.Fatal("expected an error on a malformed modulus")
	}
	_ = x509.MarshalPKCS1PublicKey(got) // sanity: the result is a usable key
}
