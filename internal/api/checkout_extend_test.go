package api_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/rotate"
)

// TestExtendCheckoutLifecycle proves an active checkout's expiry can be pushed
// out, the response reflects the new time, and a credential with no active
// lease refuses the call (Phase 120).
func TestExtendCheckoutLifecycle(t *testing.T) {
	fc := &fakeConnector{}
	srv, _ := newTestServerOpts(t, nil, api.Options{
		Rotators: map[string]rotate.Rotator{"ssh": fc}, Verifiers: map[string]rotate.Verifier{"ssh": fc},
		CheckoutMaxExtend: 4 * time.Hour,
	})
	credID := seedTargetCred(t, srv, "ssh", "", "original-secret")

	// No active lease yet: extend refuses.
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/checkout/extend", credID), testAPIKey,
		map[string]any{"minutes": 30}); code != http.StatusConflict {
		t.Fatalf("extend with no active checkout: %d %s, want 409", code, d)
	}

	status, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/checkout", credID), testAPIKey, map[string]any{"reason": "maintenance"})
	if status != http.StatusCreated {
		t.Fatalf("checkout: %d %s", status, data)
	}
	origExpiry := jsonMap(t, data)["expires_at"].(string)

	// Zero/negative minutes are refused.
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/checkout/extend", credID), testAPIKey,
		map[string]any{"minutes": 0}); code != http.StatusUnprocessableEntity {
		t.Fatalf("extend(minutes=0): %d %s, want 422", code, d)
	}

	code, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/checkout/extend", credID), testAPIKey,
		map[string]any{"minutes": 30})
	if code != http.StatusOK {
		t.Fatalf("extend: %d %s", code, data)
	}
	newExpiry := jsonMap(t, data)["expires_at"].(string)
	if newExpiry == origExpiry {
		t.Fatalf("extend did not move expires_at: still %s", newExpiry)
	}
	newT, err := time.Parse(time.RFC3339, newExpiry)
	if err != nil {
		t.Fatal(err)
	}
	origT, err := time.Parse(time.RFC3339, origExpiry)
	if err != nil {
		t.Fatal(err)
	}
	if !newT.After(origT) {
		t.Fatalf("extended expiry %s is not after the original %s", newExpiry, origExpiry)
	}

	// It is reflected in the active-checkout list.
	_, data = do(t, srv, http.MethodGet, "/api/checkouts?active=true", testAPIKey, nil)
	if !strings.Contains(string(data), newExpiry[:16]) { // minute precision, tolerant of trailing zero/offset formatting
		t.Fatalf("active checkout list does not reflect the extension: %s", data)
	}
}

// TestExtendCheckoutRespectsMaxDuration proves an extension cannot push a
// lease's TOTAL duration (from CheckedOutAt) past PAM_CHECKOUT_MAX_EXTEND_MIN
// (Phase 120) — the ceiling exists specifically so "extend" cannot become
// "make it standing."
func TestExtendCheckoutRespectsMaxDuration(t *testing.T) {
	fc := &fakeConnector{}
	srv, _ := newTestServerOpts(t, nil, api.Options{
		Rotators: map[string]rotate.Rotator{"ssh": fc}, Verifiers: map[string]rotate.Verifier{"ssh": fc},
		CheckoutMaxExtend: time.Hour,
	})
	credID := seedTargetCred(t, srv, "ssh", "", "original-secret")
	if status, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/checkout", credID), testAPIKey, nil); status != http.StatusCreated {
		t.Fatalf("checkout: %d %s", status, d)
	}

	// Asking to extend 2 hours out, against a 1-hour ceiling, is refused.
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/checkout/extend", credID), testAPIKey,
		map[string]any{"minutes": 120}); code != http.StatusUnprocessableEntity {
		t.Fatalf("extend beyond the ceiling: %d %s, want 422", code, d)
	}
	// A request comfortably inside the ceiling succeeds.
	if code, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/checkout/extend", credID), testAPIKey,
		map[string]any{"minutes": 30}); code != http.StatusOK {
		t.Fatalf("extend inside the ceiling: %d %s", code, d)
	}
}
