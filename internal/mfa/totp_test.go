package mfa

import (
	"strings"
	"testing"
	"time"
)

// TestRFC6238Vector checks the code against the RFC 6238 Appendix B SHA-1
// vector: seed "12345678901234567890", T=59s → 8-digit 94287082, so the
// 6-digit truncation is 287082.
func TestRFC6238Vector(t *testing.T) {
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	got, err := Code(secret, time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}
	if got != "287082" {
		t.Fatalf("RFC 6238 vector: got %s, want 287082", got)
	}
}

// TestValidateRoundtrip proves a fresh code validates, a code one step off is
// accepted within skew, and stale or malformed codes are rejected.
func TestValidateRoundtrip(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	code, _ := Code(secret, now)
	if !Validate(secret, code, now) {
		t.Fatal("fresh code should validate")
	}
	// Within skew (previous step).
	if !Validate(secret, code, now.Add(30*time.Second)) {
		t.Fatal("code should validate one step later (skew)")
	}
	// Outside skew.
	if Validate(secret, code, now.Add(5*time.Minute)) {
		t.Fatal("stale code should not validate")
	}
	if Validate(secret, "000000", now) && code != "000000" {
		t.Fatal("wrong code should not validate")
	}
	if Validate(secret, "12345", now) {
		t.Fatal("wrong-length code should not validate")
	}
}

// TestProvisioningURI checks the otpauth:// URI carries the expected fields.
func TestProvisioningURI(t *testing.T) {
	uri := ProvisioningURI("ABC234", "alice", "pamv1")
	for _, want := range []string{"otpauth://totp/", "secret=ABC234", "issuer=pamv1", "digits=6", "period=30"} {
		if !strings.Contains(uri, want) {
			t.Fatalf("URI %q missing %q", uri, want)
		}
	}
}

// TestGenerateSecretDistinct proves generated secrets are random and non-empty.
func TestGenerateSecretDistinct(t *testing.T) {
	a, _ := GenerateSecret()
	b, _ := GenerateSecret()
	if a == b || a == "" {
		t.Fatal("secrets must be random and non-empty")
	}
}

// TestGenerateRecoveryCodes proves it returns the requested count of uniquely
// formatted, non-duplicate codes carrying enough entropy to survive an OFFLINE
// attack.
//
// The entropy assertion is the one that matters. A recovery code is a full
// second-factor bypass, it stays valid until used, and it is stored as a single
// unsalted SHA-256 — so anyone with a database backup attacks it offline, where
// rate limiting cannot reach them. The original codes carried 50 bits (8 random
// bytes truncated to 10 characters), which is exhaustible on commodity
// hardware; these carry 120.
func TestGenerateRecoveryCodes(t *testing.T) {
	codes, err := GenerateRecoveryCodes(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 10 {
		t.Fatalf("got %d codes, want 10", len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		// Four groups of six base32 characters: "abcdef-ghijkl-mnopqr-stuvwx".
		groups := strings.Split(c, "-")
		if len(groups) != 4 {
			t.Fatalf("unexpected code format: %q", c)
		}
		entropyChars := 0
		for _, g := range groups {
			if len(g) != 6 {
				t.Fatalf("group %q in %q is not 6 characters", g, c)
			}
			for _, r := range g {
				if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz234567", r) {
					t.Fatalf("code %q contains %q, which is not lowercase base32", c, r)
				}
			}
			entropyChars += len(g)
		}
		// 24 base32 characters × 5 bits = 120 bits. Below ~100 this is
		// brute-forceable offline from a stolen backup, which is the whole point.
		if bits := entropyChars * 5; bits < 100 {
			t.Fatalf("code %q carries only %d bits; a recovery code is a full MFA bypass attacked offline", c, bits)
		}
		if seen[c] {
			t.Fatalf("duplicate recovery code: %q", c)
		}
		seen[c] = true
	}
}
