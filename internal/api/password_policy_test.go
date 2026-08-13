package api_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/rotate"
)

// TestGeneratedPasswordFollowsConfiguredPolicy proves a rotation's generated
// secret actually reflects PAM_PASSWORD_MIN_* (Phase 120), not just the
// hardcoded 24-char/one-of-each default — length and every per-class count.
func TestGeneratedPasswordFollowsConfiguredPolicy(t *testing.T) {
	fc := &fakeConnector{}
	srv, _ := newTestServerOpts(t, nil, api.Options{
		Rotators:  map[string]rotate.Rotator{"ssh": fc},
		Verifiers: map[string]rotate.Verifier{"ssh": fc},
		PasswordPolicy: rotate.PasswordPolicy{
			MinLength: 48, MinLower: 5, MinUpper: 5, MinDigit: 5, MinSymbol: 5,
		},
	})
	credID := seedTargetCred(t, srv, "ssh", "", "original-secret")

	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/rotate", credID), testAPIKey, nil); code != http.StatusOK {
		t.Fatalf("rotate: %d %s", code, d)
	}
	pw := fc.newSecret()
	if len(pw) != 48 {
		t.Fatalf("generated password length = %d, want 48", len(pw))
	}
	const lowers, uppers, digits, symbols = "abcdefghijkmnopqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789", "-_.~"
	var nLower, nUpper, nDigit, nSymbol int
	for _, c := range pw {
		switch {
		case strings.ContainsRune(lowers, c):
			nLower++
		case strings.ContainsRune(uppers, c):
			nUpper++
		case strings.ContainsRune(digits, c):
			nDigit++
		case strings.ContainsRune(symbols, c):
			nSymbol++
		}
	}
	if nLower < 5 || nUpper < 5 || nDigit < 5 || nSymbol < 5 {
		t.Fatalf("generated password %q class counts = lower:%d upper:%d digit:%d symbol:%d, want >= 5 each", pw, nLower, nUpper, nDigit, nSymbol)
	}
}

// TestPasswordHistoryRecordedAndPruned proves PAM_PASSWORD_HISTORY_COUNT
// tracks a bounded number of a credential's past rotation hashes, pruning the
// oldest as new ones arrive (Phase 120) — checked directly against the store,
// since a rotated secret is never returned by the API.
func TestPasswordHistoryRecordedAndPruned(t *testing.T) {
	fc := &fakeConnector{}
	srv, st := newTestServerOpts(t, nil, api.Options{
		Rotators: map[string]rotate.Rotator{"ssh": fc}, Verifiers: map[string]rotate.Verifier{"ssh": fc},
		PasswordHistoryCount: 3,
	})
	credID := seedTargetCred(t, srv, "ssh", "", "original-secret")

	for i := 0; i < 5; i++ {
		if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/rotate", credID), testAPIKey, nil); code != http.StatusOK {
			t.Fatalf("rotate %d: %d %s", i, code, d)
		}
	}
	hashes, err := st.RecentPasswordHashes(context.Background(), credID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(hashes) != 3 {
		t.Fatalf("history after 5 rotations with count=3 = %d entries, want 3 (pruned)", len(hashes))
	}
	seen := map[string]bool{}
	for _, h := range hashes {
		if seen[h] {
			t.Fatalf("duplicate hash retained in history: %q", h)
		}
		seen[h] = true
	}
}

// TestPasswordHistoryDisabledByDefault proves an unconfigured deployment
// records nothing — the default (0) must not pay even the write, matching
// every unconfigured password knob's "no behavior change" guarantee.
func TestPasswordHistoryDisabledByDefault(t *testing.T) {
	fc := &fakeConnector{}
	srv, st := newTestServerOpts(t, nil, api.Options{
		Rotators: map[string]rotate.Rotator{"ssh": fc}, Verifiers: map[string]rotate.Verifier{"ssh": fc},
	})
	credID := seedTargetCred(t, srv, "ssh", "", "original-secret")

	for i := 0; i < 3; i++ {
		if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/rotate", credID), testAPIKey, nil); code != http.StatusOK {
			t.Fatalf("rotate %d: %d %s", i, code, d)
		}
	}
	hashes, err := st.RecentPasswordHashes(context.Background(), credID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(hashes) != 0 {
		t.Fatalf("history recorded with PAM_PASSWORD_HISTORY_COUNT unset: %d entries, want 0", len(hashes))
	}
}
