package api_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// newLifetimeServer builds the API with its *api.Server in hand, so the test
// can drive the expiry sweep with a chosen instant.
func newLifetimeServer(t *testing.T) (*api.Server, *httptest.Server, store.Store) {
	t.Helper()
	st := memstore.New()
	masterKey, err := vault.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	bg := sha256.Sum256([]byte(breakGlassKey))
	resolver, err := auth.NewResolver(st, testAPIKey, hex.EncodeToString(bg[:]))
	if err != nil {
		t.Fatal(err)
	}
	resolver.WithProfiles(st)
	handler, err := api.New(st, v, resolver, nil, api.Options{})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return handler, srv, st
}

// TestGrantLifetimeAPI proves a grant and a safe membership accept an expiry
// and a time frame (Phase 240), refuse a past expiry or an unparsable frame
// with 422, list them back, audit them, and that the expiry sweep deletes an
// expired row and audits it.
func TestGrantLifetimeAPI(t *testing.T) {
	handler, srv, st := newLifetimeServer(t)
	targetID := seedApprovalTarget(t, srv, false)
	base := fmt.Sprintf("/api/targets/%d/grants", targetID)
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	future := time.Now().Add(time.Hour).UTC().Truncate(time.Second)

	if code, data := do(t, srv, http.MethodPost, base, testAPIKey, map[string]any{"subject_type": "user", "subject": "alice", "expires_at": past}); code != http.StatusUnprocessableEntity {
		t.Fatalf("past expiry: %d %s, want 422", code, data)
	}
	if code, data := do(t, srv, http.MethodPost, base, testAPIKey, map[string]any{"subject_type": "user", "subject": "alice", "time_frame": "Mon-Fri"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("bad frame: %d %s, want 422", code, data)
	}
	code, data := do(t, srv, http.MethodPost, base, testAPIKey, map[string]any{"subject_type": "user", "subject": "alice", "expires_at": future.Format(time.RFC3339), "time_frame": " Mon-Fri 08:00-18:00 Europe/Madrid "})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, data)
	}
	created := jsonMap(t, data)
	if created["time_frame"] != "Mon-Fri 08:00-18:00 Europe/Madrid" || created["expires_at"] == nil {
		t.Fatalf("created grant = %+v", created)
	}
	code, data = do(t, srv, http.MethodGet, base, testAPIKey, nil)
	if code != http.StatusOK || !strings.Contains(string(data), `"time_frame":"Mon-Fri 08:00-18:00 Europe/Madrid"`) || !strings.Contains(string(data), `"expires_at"`) {
		t.Fatalf("list: %d %s", code, data)
	}
	auditHas(t, st, "grant.create", "frame:")
	auditHas(t, st, "grant.create", "expires:")

	// Safe membership carries the same bounds.
	code, data = do(t, srv, http.MethodPost, "/api/safes", testAPIKey, map[string]any{"name": "prod"})
	if code != http.StatusCreated {
		t.Fatalf("create safe: %d %s", code, data)
	}
	safeID := int64(jsonMap(t, data)["id"].(float64))
	members := fmt.Sprintf("/api/safes/%d/members", safeID)
	if code, data := do(t, srv, http.MethodPost, members, testAPIKey, map[string]any{"subject_type": "user", "subject": "bob", "time_frame": "nope"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("member bad frame: %d %s", code, data)
	}
	soon := time.Now().Add(2 * time.Second).UTC()
	if code, data := do(t, srv, http.MethodPost, members, testAPIKey, map[string]any{"subject_type": "user", "subject": "bob", "expires_at": soon.Format(time.RFC3339Nano)}); code != http.StatusCreated {
		t.Fatalf("member with expiry: %d %s", code, data)
	}
	auditHas(t, st, "safe.member.add", "expires:")

	// The sweep, driven past both expiries, removes the membership (expiring
	// in 2 s) but not the hour-long grant, and audits what it removed.
	if n := handler.SweepExpiredGrants(context.Background(), time.Now().Add(10*time.Second)); n != 1 {
		t.Fatalf("sweep removed %d rows, want 1", n)
	}
	auditHas(t, st, "safe.member.expired", "user:bob")
	if code, data := do(t, srv, http.MethodGet, members, testAPIKey, nil); code != http.StatusOK || strings.Contains(string(data), `"bob"`) {
		t.Fatalf("expired member still listed: %d %s", code, data)
	}
	if code, data := do(t, srv, http.MethodGet, base, testAPIKey, nil); code != http.StatusOK || !strings.Contains(string(data), `"alice"`) {
		t.Fatalf("live grant was swept: %d %s", code, data)
	}
	if n := handler.SweepExpiredGrants(context.Background(), time.Now().Add(2*time.Hour)); n != 1 {
		t.Fatalf("second sweep removed %d rows, want the hour-long grant", n)
	}
	auditHas(t, st, "grant.expired", "user:alice")
}
