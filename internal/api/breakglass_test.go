package api_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/shamir"
)

// captureAlerter records alerts synchronously for assertions.
type captureAlerter struct{ ch chan alert.Event }

// Notify enqueues the alert non-blockingly for the test to assert on.
func (c captureAlerter) Notify(_ context.Context, e alert.Event) {
	select {
	case c.ch <- e:
	default:
	}
}

// TestBreakGlassQuorumUnseal verifies M-of-N shares reconstruct the key, issue a
// working break-glass admin session, and fire the unseal + access alerts.
func TestBreakGlassQuorumUnseal(t *testing.T) {
	const emergencyKey = "the-sealed-emergency-key-2026"
	alerts := captureAlerter{ch: make(chan alert.Event, 8)}

	srv, _ := newTestServerBreakGlass(t, emergencyKey, api.Options{
		BreakGlassThreshold: 3,
		BreakGlassTTL:       time.Minute,
		Alerter:             alerts,
	})

	shares, err := shamir.Split([]byte(emergencyKey), 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	unseal := func(i int) (int, map[string]any) {
		status, data := do(t, srv, http.MethodPost, "/api/breakglass/unseal", "",
			map[string]any{"share": hex.EncodeToString(shares[i])})
		return status, jsonMap(t, data)
	}

	// First two shares: quorum not yet met.
	if status, m := unseal(0); status != http.StatusOK || m["needed"].(float64) != 3 {
		t.Fatalf("share 1: %d %v", status, m)
	}
	if status, m := unseal(2); status != http.StatusOK || m["collected"].(float64) != 2 {
		t.Fatalf("share 2: %d %v", status, m)
	}

	// Third share meets quorum → a break-glass session token is issued.
	status, m := unseal(4)
	if status != http.StatusCreated {
		t.Fatalf("quorum unseal: %d %v", status, m)
	}
	token, _ := m["token"].(string)
	if token == "" || m["role"] != "admin" {
		t.Fatalf("unexpected unseal response: %v", m)
	}

	// The session works, has admin rights, and is flagged break-glass (loud
	// audit + alert on every use).
	if status, _ := do(t, srv, http.MethodGet, "/api/audit", token, nil); status != http.StatusOK {
		t.Fatalf("break-glass session should read audit: %d", status)
	}

	// Alerts fired for the unseal and for the subsequent break-glass access.
	types := map[string]bool{}
	for len(types) < 2 {
		select {
		case e := <-alerts.ch:
			types[e.Type] = true
		case <-time.After(2 * time.Second):
			t.Fatalf("missing alerts; got %v", types)
		}
	}
	if !types["breakglass.unseal"] || !types["breakglass.access"] {
		t.Fatalf("expected unseal + access alerts, got %v", types)
	}
}

// TestBreakGlassWrongSharesRejected verifies shares of a different key fail to
// unseal with 401.
func TestBreakGlassWrongSharesRejected(t *testing.T) {
	const emergencyKey = "sealed-key"
	srv, _ := newTestServerBreakGlass(t, emergencyKey, api.Options{BreakGlassThreshold: 2})
	// Shares of a *different* key won't reconstruct the configured key.
	wrong, _ := shamir.Split([]byte("not-the-key"), 3, 2)
	do(t, srv, http.MethodPost, "/api/breakglass/unseal", "", map[string]any{"share": hex.EncodeToString(wrong[0])})
	if status, _ := do(t, srv, http.MethodPost, "/api/breakglass/unseal", "",
		map[string]any{"share": hex.EncodeToString(wrong[1])}); status != http.StatusUnauthorized {
		t.Fatalf("wrong shares should be 401, got %d", status)
	}
}

// TestBreakGlassNotConfigured verifies the unseal endpoint is 404 when no quorum
// is configured.
func TestBreakGlassNotConfigured(t *testing.T) {
	srv := newTestServer(t) // no threshold
	if status, _ := do(t, srv, http.MethodPost, "/api/breakglass/unseal", "",
		map[string]any{"share": "00"}); status != http.StatusNotFound {
		t.Fatalf("unseal without config should be 404, got %d", status)
	}
}

// TestBreakGlassRotationReachesTheQuorumPath is the regression for the defect
// Phase 78 shipped and Phase 80 fixed.
//
// Phase 78 added runtime rotation of PAM_BREAK_GLASS_KEY_HASH and claimed, in
// the architecture doc and the admin guide, that "a single swap reaches every
// authentication surface". It did not. api.Server kept its OWN copy of the hash,
// decoded once at construction, and the Shamir quorum-unseal endpoint compared
// against that copy. So after a rotation the endpoint accepted shares of the
// RETIRED key -- issuing a full-admin break-glass session -- and rejected shares
// of the new one. Rotation inverted, on the one path that exists for when
// nothing else works, reachable unauthenticated.
//
// The fix deletes the second copy rather than adding a second setter: the hash
// lives once, in auth.Resolver, and this asserts both directions of the swap.
func TestBreakGlassRotationReachesTheQuorumPath(t *testing.T) {
	const oldKey, newKey = "the-retired-emergency-key", "the-rotated-emergency-key"
	srv, _, resolver := newTestServerRotatable(t, oldKey, api.Options{
		BreakGlassThreshold: 2, BreakGlassTTL: time.Minute,
	})

	unsealWith := func(t *testing.T, key string) int {
		t.Helper()
		shares, err := shamir.Split([]byte(key), 3, 2)
		if err != nil {
			t.Fatal(err)
		}
		var status int
		for i := range 2 {
			status, _ = do(t, srv, http.MethodPost, "/api/breakglass/unseal", "",
				map[string]any{"share": hex.EncodeToString(shares[i])})
		}
		return status
	}

	// Before rotating, the configured key works. (If this fails the test proves
	// nothing about rotation.)
	if got := unsealWith(t, oldKey); got != http.StatusCreated {
		t.Fatalf("pre-rotation unseal with the configured key = %d, want 201", got)
	}

	newSum := sha256.Sum256([]byte(newKey))
	if err := resolver.SetBootstrapSecrets(testAPIKey, hex.EncodeToString(newSum[:])); err != nil {
		t.Fatal(err)
	}

	if got := unsealWith(t, oldKey); got == http.StatusCreated {
		t.Fatal("the RETIRED emergency key still unseals a full-admin session after rotation")
	}
	if got := unsealWith(t, newKey); got != http.StatusCreated {
		t.Fatalf("the ROTATED emergency key does not unseal (%d) — rotation reached the direct key path only", got)
	}
}
