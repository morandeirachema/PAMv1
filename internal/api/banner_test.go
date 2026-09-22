package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/banner"
	"github.com/morandeirachema/pamv1/internal/store"
)

// TestBannerRouteAndDesktopConsent (Phase 276): the banner route is public
// and answers per language; a desktop token is refused with the notice until
// it is acknowledged, and the acknowledgement is audited with the digest.
func TestBannerRouteAndDesktopConsent(t *testing.T) {
	b := banner.New(map[string]string{"login": "Authorized use only", "login_es": "Solo uso autorizado", "session": "This desktop is recorded"})
	srv, st := newTestServerOpts(t, nil, api.Options{Banners: b, GuacdAddr: "127.0.0.1:4822"})
	status, body := do(t, srv, http.MethodGet, "/api/banner", "", nil)
	var out map[string]string
	_ = json.Unmarshal(body, &out)
	if status != http.StatusOK || out["login"] != "Authorized use only" || out["session"] != "This desktop is recorded" {
		t.Fatalf("banner: %d %s", status, body)
	}
	status, body = do(t, srv, http.MethodGet, "/api/banner?lang=es-ES", "", nil)
	_ = json.Unmarshal(body, &out)
	if status != http.StatusOK || out["login"] != "Solo uso autorizado" {
		t.Fatalf("banner es: %d %s", status, body)
	}

	status, body = do(t, srv, http.MethodPost, "/api/targets", testAPIKey,
		map[string]any{"name": "desk", "host": "10.0.0.9", "port": 3389, "os_type": "windows", "protocol": "rdp"})
	if status != http.StatusCreated {
		t.Fatalf("create target: %d %s", status, body)
	}
	var tgt store.Target
	_ = json.Unmarshal(body, &tgt)
	status, body = do(t, srv, http.MethodPost, "/api/rdp-token", testAPIKey, map[string]any{"target_id": tgt.ID})
	var refused struct {
		ConsentRequired bool   `json:"consent_required"`
		Banner          string `json:"banner"`
	}
	_ = json.Unmarshal(body, &refused)
	if status != http.StatusPreconditionRequired || !refused.ConsentRequired || refused.Banner != "This desktop is recorded" {
		t.Fatalf("token without consent: %d %s", status, body)
	}
	status, body = do(t, srv, http.MethodPost, "/api/rdp-token", testAPIKey, map[string]any{"target_id": tgt.ID, "consent": true})
	if status != http.StatusOK || !strings.Contains(string(body), `"token"`) {
		t.Fatalf("token with consent: %d %s", status, body)
	}
	events, _ := st.ListAudit(t.Context(), 20)
	var seen bool
	for _, e := range events {
		if e.Action == "session.consent" && strings.Contains(e.Detail, "protocol:rdp mode:acknowledged banner_sha256:"+banner.Digest("This desktop is recorded")) {
			seen = true
		}
	}
	if !seen {
		t.Fatal("acknowledgement not audited")
	}
	// No session notice configured: no gate.
	srv2, _ := newTestServerOpts(t, nil, api.Options{GuacdAddr: "127.0.0.1:4822"})
	_, body = do(t, srv2, http.MethodPost, "/api/targets", testAPIKey,
		map[string]any{"name": "desk", "host": "10.0.0.9", "port": 3389, "os_type": "windows", "protocol": "rdp"})
	_ = json.Unmarshal(body, &tgt)
	if s, b := do(t, srv2, http.MethodPost, "/api/rdp-token", testAPIKey, map[string]any{"target_id": tgt.ID}); s != http.StatusOK {
		t.Fatalf("token with no notice configured: %d %s", s, b)
	}
	if s, b := do(t, srv2, http.MethodGet, "/api/banner", "", nil); s != http.StatusOK || !strings.Contains(string(b), `"login":""`) {
		t.Fatalf("banner with none configured: %d %s", s, b)
	}
}
