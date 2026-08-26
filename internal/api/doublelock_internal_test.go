package api

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"testing"
)

// TestDoubleLockOpensLegacyFormat proves the 2026-08-26 audit's H-3 iteration
// raise is backward compatible: a value sealed at the old 100 000 count, with
// no `i=` prefix, still verifies and decrypts. Without this, raising
// doubleLockIters would have silently bricked every existing double-locked
// credential. It is an INTERNAL test because it exercises the seal/open
// primitives directly — the one way to construct a genuinely legacy-format
// value, which the current sealDoubleLock no longer produces.
func TestDoubleLockOpensLegacyFormat(t *testing.T) {
	const pw = "correct horse battery staple"
	salt := make([]byte, doubleLockSalt)
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	vKey, aesKey := deriveDoubleLock(pw, salt, doubleLockLegacyIters)
	block, _ := aes.NewCipher(aesKey)
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, aead.NonceSize())
	ct := aead.Seal(nil, nonce, []byte("the-secret"), nil)
	saltHex := hex.EncodeToString(salt)
	legacyVerifier := saltHex + ":" + hex.EncodeToString(vKey)
	legacyEnc := saltHex + ":" + hex.EncodeToString(nonce) + ":" + hex.EncodeToString(ct)

	if !verifyDoubleLockPassword(legacyVerifier, pw) {
		t.Fatal("a legacy (unprefixed, 100k) verifier no longer matches its password")
	}
	if verifyDoubleLockPassword(legacyVerifier, "wrong password entirely") {
		t.Fatal("a wrong password matched the legacy verifier")
	}
	got, err := openDoubleLock(legacyEnc, pw)
	if err != nil || got != "the-secret" {
		t.Fatalf("legacy decrypt = %q, %v; want the-secret", got, err)
	}

	// And a value sealed by the CURRENT code carries the i= prefix and still
	// round-trips — the new and legacy formats coexist.
	v2, e2, err := sealDoubleLock("fresh-secret", pw)
	if err != nil {
		t.Fatal(err)
	}
	if v2[:2] != "i=" {
		t.Fatalf("a freshly sealed verifier has no iteration prefix: %.8s", v2)
	}
	if !verifyDoubleLockPassword(v2, pw) {
		t.Fatal("a freshly sealed verifier did not match its password")
	}
	if got, err := openDoubleLock(e2, pw); err != nil || got != "fresh-secret" {
		t.Fatalf("fresh decrypt = %q, %v; want fresh-secret", got, err)
	}
}
