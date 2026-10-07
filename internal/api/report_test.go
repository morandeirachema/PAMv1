package api_test

import (
	"context"
	"encoding/csv"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// agedStore backdates the inventory by a year, so the unused report judges
// rows a test just created as old enough to have been used — memstore
// stamps every row with the time it was written.
type agedStore struct{ store.Store }

func (a agedStore) ListUsers(ctx context.Context, limit int, after int64) ([]store.User, error) {
	us, err := a.Store.ListUsers(ctx, limit, after)
	for i := range us {
		us[i].CreatedAt = us[i].CreatedAt.AddDate(-1, 0, 0)
	}
	return us, err
}

func (a agedStore) ListTargets(ctx context.Context, limit int, after int64) ([]store.Target, error) {
	ts, err := a.Store.ListTargets(ctx, limit, after)
	for i := range ts {
		ts[i].CreatedAt = ts[i].CreatedAt.AddDate(-1, 0, 0)
	}
	return ts, err
}

// TestReports proves Phase 277's two report routes against a seeded trail:
// the unused report lists the user and target with no use, the connection
// statistics count only opened sessions, the CSV is well-formed, each run is
// audited report.view, bad parameters are 422 and a plain user is refused.
func TestReports(t *testing.T) {
	ctx := context.Background()
	st := agedStore{memstore.New()}
	srv, _ := newTestServerStoreOpts(t, nil, st, api.Options{})
	for _, u := range []string{"alice", "zoe"} {
		if code, d := do(t, srv, http.MethodPost, "/api/users", testAPIKey, map[string]any{"username": u, "role": "user"}); code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", u, code, d)
		}
	}
	for _, n := range []string{"web-01", "idle-01"} {
		if code, d := do(t, srv, http.MethodPost, "/api/targets", testAPIKey,
			map[string]any{"name": n, "host": "10.0.0.5", "os_type": "linux", "protocol": "ssh"}); code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", n, code, d)
		}
	}
	for _, e := range []store.AuditEvent{
		{Actor: "alice", Action: "session.start", Detail: "target:web-01 host:\"10.0.0.5\":22 cred_user:root mode:interactive"},
		{Actor: "alice", Action: "rdp.connect", Detail: "target:web-01 cred_user:root recording:x clipboard:deny"},
		{Actor: "zoe", Action: "session.denied", Detail: "target:idle-01 reason:no-grant"},
	} {
		if err := st.AppendAudit(ctx, &e); err != nil {
			t.Fatal(err)
		}
	}

	code, data := do(t, srv, http.MethodGet, "/api/reports/unused?days=30", testAPIKey, nil)
	if code != http.StatusOK {
		t.Fatalf("unused: %d %s", code, data)
	}
	body := string(data)
	if !strings.Contains(body, `"username":"zoe"`) || strings.Contains(body, `"username":"alice"`) ||
		!strings.Contains(body, `"name":"idle-01"`) || strings.Contains(body, `"name":"web-01"`) {
		t.Fatalf("unused report = %s", body)
	}
	auditHas(t, st, "report.view", "report:unused days:30")

	code, data = do(t, srv, http.MethodGet, "/api/reports/connections", testAPIKey, nil)
	m := jsonMap(t, data)
	if code != http.StatusOK || m["total"] != float64(2) {
		t.Fatalf("connections: %d %s", code, data)
	}
	if days := m["by_day"].([]any); len(days) < 7 {
		t.Fatalf("a seven-day window must list every day: %v", days)
	}

	since := url.QueryEscape(time.Now().Add(-time.Hour).UTC().Format(time.RFC3339))
	code, data = do(t, srv, http.MethodGet, "/api/reports/connections?format=csv&since="+since, testAPIKey, nil)
	rows, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
	if code != http.StatusOK || err != nil || len(rows) != 3 || rows[1][2] != "web-01" || rows[2][3] != "rdp" {
		t.Fatalf("csv: %d %q err %v", code, rows, err)
	}
	auditHas(t, st, "report.view", "report:connections format:csv")

	for _, bad := range []string{
		"/api/reports/unused?days=0", "/api/reports/unused?days=367",
		"/api/reports/connections?format=xml", "/api/reports/connections?since=yesterday",
		"/api/reports/connections?since=2020-01-01T00:00:00Z&until=2022-01-01T00:00:00Z",
	} {
		if code, d := do(t, srv, http.MethodGet, bad, testAPIKey, nil); code != http.StatusUnprocessableEntity {
			t.Errorf("%s = %d %s, want 422", bad, code, d)
		}
	}

	code, data = do(t, srv, http.MethodPost, "/api/users", testAPIKey, map[string]any{"username": "op", "role": "user"})
	if code != http.StatusCreated {
		t.Fatalf("create op: %d %s", code, data)
	}
	tok := jsonMap(t, data)["token"].(string)
	for _, p := range []string{"/api/reports/unused", "/api/reports/connections"} {
		if code, _ := do(t, srv, http.MethodGet, p, tok, nil); code != http.StatusForbidden {
			t.Errorf("a plain user on %s = %d, want 403", p, code)
		}
	}
}
