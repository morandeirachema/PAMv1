package agentid

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// TestP256JWKRejectsAnOffCurvePoint pins what Phase 180's SA1019 fix bought
// beyond silencing the linter.
//
// Filling ecdsa.PublicKey's X/Y directly built whatever coordinates it was
// handed, on-curve or not; ParseUncompressedPublicKey validates the point. A
// trust-domain JWKS is operator-supplied configuration rather than attacker
// input, so this was never a live hole — but a verifier that refuses to build
// an invalid key is the right shape for one, and a short coordinate (a stripped
// leading zero, a common encoder bug) still has to work.
func TestP256JWKRejectsAnOffCurvePoint(t *testing.T) {
	// A point that is simply not on P-256.
	if _, err := p256FromJWK(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)); err == nil {
		t.Fatal("an off-curve point must not produce a usable public key")
	}
	// Longer than the curve's coordinate width cannot be P-256 at all.
	if _, err := p256FromJWK(make([]byte, 33), make([]byte, 32)); err == nil {
		t.Fatal("an over-long coordinate must be refused")
	}
	// A real key still parses, and so does the same key with its leading zero
	// byte stripped — which is what a sloppy encoder produces.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := key.PublicKey.Bytes() // SEC1 uncompressed: 0x04 || X || Y
	if err != nil {
		t.Fatal(err)
	}
	x, y := raw[1:33], raw[33:]
	if _, err := p256FromJWK(x, y); err != nil {
		t.Fatalf("a valid P-256 key must parse: %v", err)
	}
	if x[0] == 0 {
		if _, err := p256FromJWK(x[1:], y); err != nil {
			t.Fatalf("a left-stripped coordinate must still parse: %v", err)
		}
	}
}
