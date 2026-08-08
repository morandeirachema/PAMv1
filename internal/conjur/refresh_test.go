package conjur_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/morandeirachema/pamv1/internal/conjur"
)

// TestParseVarOverrides covers the per-variable map. The error cases are the
// point: a typo that is silently ignored leaves the operator concluding the
// feature does not work, which is worse than a refused start.
func TestParseVarOverrides(t *testing.T) {
	ok, err := conjur.ParseVarOverrides("PAM_API_KEY=prod/keys/api, PAM_DATABASE_URL = prod/db/url ")
	if err != nil {
		t.Fatalf("valid overrides rejected: %v", err)
	}
	if ok["PAM_API_KEY"] != "prod/keys/api" || ok["PAM_DATABASE_URL"] != "prod/db/url" {
		t.Fatalf("parsed = %v", ok)
	}
	if empty, err := conjur.ParseVarOverrides(""); err != nil || len(empty) != 0 {
		t.Fatalf("empty should parse to an empty map: %v %v", empty, err)
	}
	for _, bad := range []string{
		"PAM_API_KEY",              // no "="
		"=prod/keys/api",           // no name
		"PAM_API_KEY=",             // no id
		"PAM_NOT_A_SECRET=x/y",     // not a sourced secret
		"PAM_API_KEY_=prod/keys/a", // the typo this rejects on purpose
	} {
		if _, err := conjur.ParseVarOverrides(bad); err == nil {
			t.Errorf("ParseVarOverrides(%q) should be an error", bad)
		}
	}
}

// applier records what the refresher applied.
type applier struct {
	apiKey, bgHash string
	calls          int
	reject         error
}

func (a *applier) apply(apiKey, bgHash string) error {
	a.calls++
	if a.reject != nil {
		return a.reject
	}
	a.apiKey, a.bgHash = apiKey, bgHash
	return nil
}

// newRefresher wires a refresher over a fake Conjur holding vars, telling it
// which env names Conjur filled at boot.
func newRefresher(t *testing.T, vars map[string]string, sourced []string,
	overrides map[string]string) (*conjur.Refresher, *applier) {
	t.Helper()
	srv := fakeConjur(t, vars)
	c, err := conjur.New(conjur.Config{URL: srv.URL, Account: "default", Login: "host/x", APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	ap := &applier{}
	return conjur.NewRefresher(c, "pamv1", overrides, sourced, ap.apply, nil, nil), ap
}

const bgHashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// TestRefreshAppliesAChangedKey is the feature: rotating the bootstrap key in
// Conjur reaches a running server without a restart.
func TestRefreshAppliesAChangedKey(t *testing.T) {
	t.Setenv("PAM_API_KEY", "old-key")
	t.Setenv("PAM_BREAK_GLASS_KEY_HASH", bgHashA)
	vars := map[string]string{
		"pamv1/api-key":              "new-key",
		"pamv1/break-glass-key-hash": bgHashA,
	}
	r, ap := newRefresher(t, vars, []string{"PAM_API_KEY", "PAM_BREAK_GLASS_KEY_HASH"}, nil)

	changed, err := r.RefreshOnce(context.Background())
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if len(changed) != 1 || changed[0] != "PAM_API_KEY" {
		t.Fatalf("changed = %v, want [PAM_API_KEY]", changed)
	}
	if ap.apiKey != "new-key" {
		t.Fatalf("applied api key = %q, want new-key", ap.apiKey)
	}
	// The break-glass hash is passed through unchanged, never dropped: the pair
	// is always applied together so the two cannot drift.
	if ap.bgHash != bgHashA {
		t.Fatalf("applied break-glass hash = %q, want it carried through", ap.bgHash)
	}
	// An unchanged second tick must not re-apply — a swap per tick would be noise
	// in the audit trail and a needless write on every replica.
	if changed, err := r.RefreshOnce(context.Background()); err != nil || len(changed) != 0 {
		t.Fatalf("second tick: changed=%v err=%v, want no change", changed, err)
	}
	if ap.calls != 1 {
		t.Fatalf("applier called %d times, want 1", ap.calls)
	}
}

// TestRefreshKeepsCurrentWhenConjurHasNothing is the fail-safe that matters
// most: a policy edit or a 404 must never clear the key that lets people in, and
// must never disable break-glass.
func TestRefreshKeepsCurrentWhenConjurHasNothing(t *testing.T) {
	t.Setenv("PAM_API_KEY", "live-key")
	t.Setenv("PAM_BREAK_GLASS_KEY_HASH", bgHashA)
	for name, vars := range map[string]map[string]string{
		"missing (404)": {},
		"empty value":   {"pamv1/api-key": ""},
	} {
		r, ap := newRefresher(t, vars, []string{"PAM_API_KEY", "PAM_BREAK_GLASS_KEY_HASH"}, nil)
		changed, err := r.RefreshOnce(context.Background())
		if err != nil {
			t.Errorf("%s: unexpected error %v", name, err)
		}
		if len(changed) != 0 || ap.calls != 0 {
			t.Errorf("%s: changed=%v calls=%d — a missing variable must keep the current value",
				name, changed, ap.calls)
		}
	}
}

// TestRefreshLeavesOperatorSetValuesAlone keeps "an explicit env value wins"
// true past the first tick. Conjur only owns what it actually filled at boot.
func TestRefreshLeavesOperatorSetValuesAlone(t *testing.T) {
	t.Setenv("PAM_API_KEY", "operator-set")
	vars := map[string]string{"pamv1/api-key": "conjur-wants-this"}
	// sourced is empty: Conjur filled nothing, because the operator set it.
	r, ap := newRefresher(t, vars, nil, nil)
	changed, err := r.RefreshOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 0 || ap.calls != 0 {
		t.Fatalf("an operator-set value was overwritten: changed=%v calls=%d", changed, ap.calls)
	}
}

// TestRefreshNeverTouchesPinnedSecrets proves the honest half of the design: the
// KEK, the database URL and the audit-chain keys are not fetched at all, so a
// refresh cannot half-rotate something it has no way to complete — and the KEK
// does not cross the network every tick to produce a log line.
func TestRefreshNeverTouchesPinnedSecrets(t *testing.T) {
	t.Setenv("PAM_API_KEY", "old-key")
	asked := map[string]bool{}
	vars := map[string]string{"pamv1/api-key": "new-key"}
	srv := fakeConjurRecording(t, vars, asked)
	c, err := conjur.New(conjur.Config{URL: srv.URL, Account: "default", Login: "host/x", APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	ap := &applier{}
	r := conjur.NewRefresher(c, "pamv1", nil, []string{"PAM_API_KEY"}, ap.apply, nil, nil)
	if _, err := r.RefreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, pinned := range conjur.PinnedSecrets() {
		for id := range asked {
			if strings.Contains(id, strings.ToLower(strings.TrimPrefix(pinned, "PAM_"))) {
				t.Errorf("refresh fetched the pinned secret %s (as %q); it cannot be applied, so it must not be read", pinned, id)
			}
		}
	}
	if len(conjur.PinnedSecrets()) == 0 {
		t.Fatal("no pinned secrets — this test would pass vacuously")
	}
}

// TestRefreshRetriesAfterARejectedValue proves a value the applier refused is
// not remembered as applied. Otherwise one malformed hash in Conjur would be
// skipped forever, and fixing it upstream would never take effect.
func TestRefreshRetriesAfterARejectedValue(t *testing.T) {
	t.Setenv("PAM_API_KEY", "old-key")
	vars := map[string]string{"pamv1/api-key": "new-key"}
	r, ap := newRefresher(t, vars, []string{"PAM_API_KEY"}, nil)
	ap.reject = errTest

	if _, err := r.RefreshOnce(context.Background()); err == nil {
		t.Fatal("a rejected apply must surface as an error")
	}
	ap.reject = nil
	changed, err := r.RefreshOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 1 || ap.apiKey != "new-key" {
		t.Fatalf("the retry did not re-apply: changed=%v key=%q", changed, ap.apiKey)
	}
}

// TestRefreshUsesTheVariableOverride proves the override reaches the wire: with
// a per-variable id set, the conventional path is never requested.
func TestRefreshUsesTheVariableOverride(t *testing.T) {
	t.Setenv("PAM_API_KEY", "old-key")
	asked := map[string]bool{}
	srv := fakeConjurRecording(t, map[string]string{"prod/keys/api": "new-key"}, asked)
	c, err := conjur.New(conjur.Config{URL: srv.URL, Account: "default", Login: "host/x", APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	ap := &applier{}
	r := conjur.NewRefresher(c, "pamv1", map[string]string{"PAM_API_KEY": "prod/keys/api"},
		[]string{"PAM_API_KEY"}, ap.apply, nil, nil)
	if _, err := r.RefreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ap.apiKey != "new-key" {
		t.Fatalf("the override was not used: applied %q", ap.apiKey)
	}
	if asked["pamv1/api-key"] {
		t.Error("the conventional variable id was requested even though an override was set")
	}
}

// errTest is a stand-in for an applier refusing a value.
var errTest = errors.New("rejected")

// fakeConjurRecording is fakeConjur plus a record of which variable ids were
// actually requested, so a test can assert what was NOT fetched.
func fakeConjurRecording(t *testing.T, vars map[string]string, asked map[string]bool) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/authenticate"):
			_, _ = w.Write([]byte(`{"protected":"x","payload":"y","signature":"z"}`))
		case strings.Contains(r.URL.Path, "/secrets/"):
			i := strings.Index(r.URL.Path, "/variable/")
			id := r.URL.Path[i+len("/variable/"):]
			mu.Lock()
			asked[id] = true
			mu.Unlock()
			if v, ok := vars[id]; ok {
				_, _ = w.Write([]byte(v))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}
