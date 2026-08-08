package conjur_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/morandeirachema/pamv1/internal/conjur"
)

const bgHashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

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
		"PAM_API_KEY",                           // no "="
		"=prod/keys/api",                        // no name
		"PAM_API_KEY=",                          // no id
		"PAM_NOT_A_SECRET=x/y",                  // not a sourced secret
		"PAM_API_KEY_=prod/keys/a",              // the typo this rejects on purpose
		"PAM_API_KEY=/prod/keys/api",            // leading slash
		"PAM_API_KEY=prod/keys/api/",            // trailing slash
		"PAM_API_KEY=prod//keys/api",            // empty path segment
		"PAM_API_KEY=prod/keys/api key",         // whitespace
		"PAM_API_KEY=a/b,PAM_API_KEY=c/d",       // mapped twice
		"PAM_API_KEY=prod/keys/\x01api",         // control character
		"PAM_BREAK_GLASS_KEY_HASH=  ,PAM_x=y/z", // empty id then unknown name
	} {
		if _, err := conjur.ParseVarOverrides(bad); err == nil {
			t.Errorf("ParseVarOverrides(%q) should be an error", bad)
		}
	}
}

// recorder captures what each applier received and what the audit recorded.
type recorder struct {
	mu      sync.Mutex
	applied map[string]string
	audits  []string
	reject  map[string]error
	auditNo error
}

func newRecorder() *recorder {
	return &recorder{applied: map[string]string{}, reject: map[string]error{}}
}

func (r *recorder) applier(name string) conjur.SecretApplier {
	return func(v string) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		if err := r.reject[name]; err != nil {
			return err
		}
		r.applied[name] = v
		return nil
	}
}

func (r *recorder) audit(_ context.Context, action, detail string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.auditNo != nil {
		return r.auditNo
	}
	r.audits = append(r.audits, action+" "+detail)
	return nil
}

// build wires a refresher over a fake Conjur holding vars, with appliers for the
// two refreshable secrets.
func build(t *testing.T, vars map[string]string, asked map[string]bool) (*conjur.Refresher, *recorder) {
	t.Helper()
	srv := fakeConjurRecording(t, vars, asked)
	c, err := conjur.New(conjur.Config{URL: srv.URL, Account: "default", Login: "host/x", APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	rec := newRecorder()
	r, err := conjur.NewRefresher(context.Background(), c, conjur.RefreshOptions{
		Prefix: "pamv1",
		Appliers: map[string]conjur.SecretApplier{
			"PAM_API_KEY":              rec.applier("PAM_API_KEY"),
			"PAM_BREAK_GLASS_KEY_HASH": rec.applier("PAM_BREAK_GLASS_KEY_HASH"),
		},
		Audit: rec.audit,
	})
	if err != nil {
		t.Fatalf("NewRefresher: %v", err)
	}
	return r, rec
}

// TestRefresherOnlyOwnsWhatConjurManages proves the ownership probe, which is
// what makes the feature work at all.
//
// Ownership used to mean "Conjur FILLED this at boot", and sourcing only fills
// what the environment left empty — while docker-compose hard-requires
// PAM_API_KEY, the Kubernetes secret ships it and the OVA generates it. So the
// one secret this was built for was never refreshable in any shipped deployment,
// while the startup log said it was.
func TestRefresherOnlyOwnsWhatConjurManages(t *testing.T) {
	r, _ := build(t, map[string]string{"pamv1/api-key": "k"}, map[string]bool{})
	if got := r.Owned(); len(got) != 1 || got[0] != "PAM_API_KEY" {
		t.Fatalf("Owned() = %v, want [PAM_API_KEY]", got)
	}
}

// TestRefresherIsNilWhenConjurManagesNothing keeps a pointless ticker (and a
// pointless authenticate every interval) from running.
func TestRefresherIsNilWhenConjurManagesNothing(t *testing.T) {
	srv := fakeConjurRecording(t, map[string]string{"pamv1/master-key": "m"}, map[string]bool{})
	c, err := conjur.New(conjur.Config{URL: srv.URL, Account: "default", Login: "host/x", APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	r, err := conjur.NewRefresher(context.Background(), c, conjur.RefreshOptions{
		Prefix:   "pamv1",
		Appliers: map[string]conjur.SecretApplier{"PAM_API_KEY": func(string) error { return nil }},
		Audit:    func(context.Context, string, string) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if r != nil {
		t.Fatal("a refresher was built for a Conjur that manages none of the refreshable secrets")
	}
}

// TestRefreshNeverFetchesAPinnedSecret is the phase's headline safety claim, and
// the previous version of this test could not fail: it built its needles from
// the ENV names (`master_key`) while variable ids use hyphens
// (`pamv1/master-key`), so all four Contains checks were false no matter what.
// Removing both guards left it green. It now asserts the positive form — the set
// of ids fetched must be exactly the owned ones — which cannot pass vacuously.
func TestRefreshNeverFetchesAPinnedSecret(t *testing.T) {
	asked := map[string]bool{}
	vars := map[string]string{
		"pamv1/api-key":                "new-key",
		"pamv1/break-glass-key-hash":   bgHashA,
		"pamv1/master-key":             "the-kek",
		"pamv1/database-url":           "postgres://x",
		"pamv1/broker-audit-key":       "chain-key",
		"pamv1/broker-audit-sign-seed": "seed",
	}
	r, _ := build(t, vars, asked)
	if _, err := r.RefreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"pamv1/api-key": true, "pamv1/break-glass-key-hash": true}
	var got []string
	for id := range asked {
		got = append(got, id)
		if !want[id] {
			t.Errorf("fetched %q, which is not one of the refreshable secrets — a value that cannot be applied must not cross the network", id)
		}
	}
	sort.Strings(got)
	if len(got) != len(want) {
		t.Fatalf("fetched %v, want exactly %d refreshable ids — if this is empty the test is proving nothing", got, len(want))
	}
}

// TestRefreshAppliesAChangedKey is the feature: rotating in Conjur reaches a
// running server without a restart, once, and is recorded.
func TestRefreshAppliesAChangedKey(t *testing.T) {
	asked := map[string]bool{}
	vars := map[string]string{"pamv1/api-key": "old-key", "pamv1/break-glass-key-hash": bgHashA}
	r, rec := build(t, vars, asked)

	// Nothing changed since the probe.
	if changed, err := r.RefreshOnce(context.Background()); err != nil || len(changed) != 0 {
		t.Fatalf("first tick: changed=%v err=%v, want no change", changed, err)
	}
	vars["pamv1/api-key"] = "new-key"
	changed, err := r.RefreshOnce(context.Background())
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if len(changed) != 1 || changed[0] != "PAM_API_KEY" {
		t.Fatalf("changed = %v, want [PAM_API_KEY]", changed)
	}
	if rec.applied["PAM_API_KEY"] != "new-key" {
		t.Fatalf("applied %q, want new-key", rec.applied["PAM_API_KEY"])
	}
	if len(rec.audits) != 1 || !strings.Contains(rec.audits[0], "config.secret_refreshed") ||
		!strings.Contains(rec.audits[0], "key:PAM_API_KEY") {
		t.Fatalf("audits = %v", rec.audits)
	}
	// The value itself must never reach the trail.
	if strings.Contains(rec.audits[0], "new-key") {
		t.Fatalf("the secret VALUE was written to the audit trail: %q", rec.audits[0])
	}
	// A steady state does not re-apply or re-audit.
	if changed, _ := r.RefreshOnce(context.Background()); len(changed) != 0 || len(rec.audits) != 1 {
		t.Fatalf("second tick re-applied: changed=%v audits=%v", changed, rec.audits)
	}
}

// TestRefreshTrimsTheValue: Conjur returns the raw body, and `conjur variable
// set` with a trailing newline would otherwise silently become a different key.
func TestRefreshTrimsTheValue(t *testing.T) {
	vars := map[string]string{"pamv1/api-key": "the-key\n"}
	r, rec := build(t, vars, map[string]bool{})
	if _, err := r.RefreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The probe already trimmed, so nothing should change — and if anything is
	// applied it must be the trimmed form.
	if v, ok := rec.applied["PAM_API_KEY"]; ok && v != "the-key" {
		t.Fatalf("applied %q, want the trimmed value", v)
	}
}

// TestOneBadSecretDoesNotBlockTheOther is why appliers are per-secret. With one
// call taking both values, a malformed break-glass hash rejected the pair and
// blocked a perfectly good API-key rotation on every tick, forever.
func TestOneBadSecretDoesNotBlockTheOther(t *testing.T) {
	vars := map[string]string{"pamv1/api-key": "old-key", "pamv1/break-glass-key-hash": bgHashA}
	r, rec := build(t, vars, map[string]bool{})
	rec.reject["PAM_BREAK_GLASS_KEY_HASH"] = errors.New("must be a hex-encoded SHA-256")

	vars["pamv1/api-key"] = "new-key"
	vars["pamv1/break-glass-key-hash"] = "not-hex"
	changed, err := r.RefreshOnce(context.Background())
	if err == nil {
		t.Fatal("the rejected secret should be reported")
	}
	if len(changed) != 1 || changed[0] != "PAM_API_KEY" {
		t.Fatalf("changed = %v — the good rotation was blocked by the bad one", changed)
	}
	if rec.applied["PAM_API_KEY"] != "new-key" {
		t.Fatalf("the API key was not rotated: %q", rec.applied["PAM_API_KEY"])
	}
}

// TestRefreshIsFailClosedOnAudit: a secret change that cannot be recorded is not
// made, and is retried. Every other path that hands out or changes a secret in
// this repo follows the same rule.
func TestRefreshIsFailClosedOnAudit(t *testing.T) {
	vars := map[string]string{"pamv1/api-key": "old-key"}
	r, rec := build(t, vars, map[string]bool{})
	rec.auditNo = errors.New("audit store down")

	vars["pamv1/api-key"] = "new-key"
	if _, err := r.RefreshOnce(context.Background()); err == nil {
		t.Fatal("an unrecordable refresh must surface as an error")
	}
	if _, ok := rec.applied["PAM_API_KEY"]; ok {
		t.Fatal("the secret was applied even though the audit failed — the change outlived the evidence of it")
	}
	// And it retries rather than remembering the failure as done.
	rec.auditNo = nil
	changed, err := r.RefreshOnce(context.Background())
	if err != nil || len(changed) != 1 {
		t.Fatalf("the retry did not happen: changed=%v err=%v", changed, err)
	}
	if rec.applied["PAM_API_KEY"] != "new-key" {
		t.Fatalf("retry applied %q", rec.applied["PAM_API_KEY"])
	}
}

// TestRejectedValueIsRetried: a value the applier refused must not be recorded
// as applied, or fixing it upstream would never take effect.
func TestRejectedValueIsRetried(t *testing.T) {
	vars := map[string]string{"pamv1/api-key": "old-key"}
	r, rec := build(t, vars, map[string]bool{})
	rec.reject["PAM_API_KEY"] = errors.New("too short")

	vars["pamv1/api-key"] = "new-key"
	if _, err := r.RefreshOnce(context.Background()); err == nil {
		t.Fatal("a rejected apply must surface as an error")
	}
	rec.reject["PAM_API_KEY"] = nil
	changed, err := r.RefreshOnce(context.Background())
	if err != nil || len(changed) != 1 || rec.applied["PAM_API_KEY"] != "new-key" {
		t.Fatalf("the retry did not re-apply: changed=%v err=%v key=%q", changed, err, rec.applied["PAM_API_KEY"])
	}
}

// TestDeletedVariableKeepsTheCurrentValue is the fail-safe: a policy edit must
// not disable break-glass. (That it is now WARNED about is the other half; the
// silent version made revocation-by-deletion look like it had worked.)
func TestDeletedVariableKeepsTheCurrentValue(t *testing.T) {
	vars := map[string]string{"pamv1/api-key": "live-key"}
	r, rec := build(t, vars, map[string]bool{})
	delete(vars, "pamv1/api-key")
	changed, err := r.RefreshOnce(context.Background())
	if err != nil {
		t.Fatalf("a deleted variable is not an error: %v", err)
	}
	if len(changed) != 0 || len(rec.applied) != 0 {
		t.Fatalf("a deleted variable changed the running secret: changed=%v applied=%v", changed, rec.applied)
	}
}

// TestRefreshUsesTheVariableOverride proves the override reaches the wire.
func TestRefreshUsesTheVariableOverride(t *testing.T) {
	asked := map[string]bool{}
	srv := fakeConjurRecording(t, map[string]string{"prod/keys/api": "old-key"}, asked)
	c, err := conjur.New(conjur.Config{URL: srv.URL, Account: "default", Login: "host/x", APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	rec := newRecorder()
	r, err := conjur.NewRefresher(context.Background(), c, conjur.RefreshOptions{
		Prefix:    "pamv1",
		Overrides: map[string]string{"PAM_API_KEY": "prod/keys/api"},
		Appliers:  map[string]conjur.SecretApplier{"PAM_API_KEY": rec.applier("PAM_API_KEY")},
		Audit:     rec.audit,
	})
	if err != nil || r == nil {
		t.Fatalf("NewRefresher: %v (nil=%v)", err, r == nil)
	}
	if asked["pamv1/api-key"] {
		t.Error("the conventional variable id was requested even though an override was set")
	}
	if !asked["prod/keys/api"] {
		t.Error("the override id was never requested")
	}
}

// TestRefresherRequiresAnAuditor: a nil Auditor would make every refresh
// silently unrecorded, which is the failure the fail-closed design exists to
// avoid — so it is refused at construction rather than at 3am.
func TestRefresherRequiresAnAuditor(t *testing.T) {
	srv := fakeConjurRecording(t, map[string]string{"pamv1/api-key": "k"}, map[string]bool{})
	c, _ := conjur.New(conjur.Config{URL: srv.URL, Account: "default", Login: "host/x", APIKey: "k"})
	_, err := conjur.NewRefresher(context.Background(), c, conjur.RefreshOptions{
		Prefix:   "pamv1",
		Appliers: map[string]conjur.SecretApplier{"PAM_API_KEY": func(string) error { return nil }},
	})
	if err == nil {
		t.Fatal("a refresher without an Auditor must be refused")
	}
}

// fakeConjurRecording is fakeConjur plus a record of which variable ids were
// actually requested, so a test can assert what was and was not fetched. It
// keeps fakeConjur's assertions: a secret read must be authorized, so a client
// that forgets the token fails here rather than passing.
func fakeConjurRecording(t *testing.T, vars map[string]string, asked map[string]bool) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/authenticate"):
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			_, _ = w.Write([]byte(`{"protected":"x","payload":"y","signature":"z"}`))
		case strings.Contains(r.URL.Path, "/secrets/"):
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Token token=") {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			i := strings.Index(r.URL.Path, "/variable/")
			id := r.URL.Path[i+len("/variable/"):]
			mu.Lock()
			asked[id] = true
			v, ok := vars[id]
			mu.Unlock()
			if ok {
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
