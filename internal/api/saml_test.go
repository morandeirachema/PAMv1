package api_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	crewjam "github.com/crewjam/saml"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/saml"
	"github.com/morandeirachema/pamv1/internal/saml/samltest"
)

// samlServer starts a real in-process SAML IdP and a PAM server configured as
// its Service Provider. The PAM server's public URL must be known before the SP
// is built (it is baked into the ACS URL the IdP posts to and the Destination
// it signs), so the listener is bound first and the httptest server is started
// on it afterwards.
func samlServer(t *testing.T) (*httptest.Server, *samltest.IdP) {
	t.Helper()
	idp := samltest.New(t)
	idp.SetSession(&crewjam.Session{
		ID: "s1", CreateTime: time.Now(), ExpireTime: time.Now().Add(time.Hour), Index: "idx-1",
		NameID: "alice@corp.test", UserName: "alice",
		CustomAttributes: []crewjam.Attribute{{
			Name:   "groups",
			Values: []crewjam.AttributeValue{{Type: "xs:string", Value: "pam-admins"}},
		}},
	})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	root := "http://" + l.Addr().String()
	sp, err := saml.New(context.Background(), saml.Config{RootURL: root, IDPMetadataURL: idp.MetadataURL()})
	if err != nil {
		t.Fatalf("saml.New: %v", err)
	}
	md, err := sp.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	idp.TrustSP(t, md)

	h := newTestHandler(t, api.Options{
		SAML:        sp,
		SAMLRoleMap: map[string]auth.Role{"pam-admins": auth.RoleAdmin},
		PortalURL:   "/",
	})
	srv := httptest.NewUnstartedServer(h)
	srv.Listener.Close()
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, idp
}

// newBrowser returns an independent simulated browser: its own cookie jar and no
// redirect following. (httptest.Server.Client() hands back one shared client,
// so noRedirect's jar swap would make two "browsers" share cookies — this test
// needs them genuinely separate to prove the cross-browser refusal does not
// burn the legitimate login.)
func newBrowser(srv *httptest.Server) *http.Client {
	c := *srv.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c.Jar, _ = cookiejar.New(nil)
	return &c
}

// samlStart hits /api/auth/saml/start with the given browser and returns the
// IdP redirect URL (asserting it is a 302 to the IdP's SSO endpoint).
func samlStart(t *testing.T, srv *httptest.Server, idp *samltest.IdP, browser *http.Client) string {
	t.Helper()
	resp, err := browser.Get(srv.URL + "/api/auth/saml/start")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, idp.Server.URL+"/sso?SAMLRequest=") {
		t.Fatalf("start should redirect to the IdP SSO endpoint, got %s", loc)
	}
	return loc
}

// postACS posts a SAMLResponse to the ACS with the given browser and returns
// the fragment values of the portal redirect (pam_token / pam_error).
func postACS(t *testing.T, srv *httptest.Server, browser *http.Client, samlResponse string) url.Values {
	t.Helper()
	resp, err := browser.PostForm(srv.URL+"/api/auth/saml/acs", url.Values{"SAMLResponse": {samlResponse}, "RelayState": {""}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("acs status = %d, want 302", resp.StatusCode)
	}
	frag, _ := url.Parse(resp.Header.Get("Location"))
	vals, _ := url.ParseQuery(frag.Fragment)
	return vals
}

// TestSAMLLoginFlow walks the whole SP-initiated flow through a real IdP: start
// → AuthnRequest redirect → the IdP signs a Response → the browser posts it to
// the ACS → a session comes back carrying the mapped admin role, and the login
// is audited with via:saml.
func TestSAMLLoginFlow(t *testing.T) {
	srv, idp := samlServer(t)
	browser := newBrowser(srv)

	redirect := samlStart(t, srv, idp, browser)
	resp := idp.Login(t, redirect)
	if resp.URL != srv.URL+"/api/auth/saml/acs" {
		t.Fatalf("idp posts to %q, want the SP ACS", resp.URL)
	}
	vals := postACS(t, srv, browser, resp.SAMLResponse)
	token := vals.Get("pam_token")
	if token == "" {
		t.Fatalf("acs did not return a token: %v", vals)
	}
	if status, _ := do(t, srv, http.MethodGet, "/api/targets", token, nil); status != http.StatusOK {
		t.Fatalf("saml session should access targets: %d", status)
	}
	if status, _ := do(t, srv, http.MethodPost, "/api/users", token,
		map[string]any{"username": "x", "role": "user"}); status != http.StatusCreated {
		t.Fatalf("saml admin should manage users: %d", status)
	}
	// The login is on the audit trail as a SAML login for that user.
	_, body := do(t, srv, http.MethodGet, "/api/audit?limit=50", token, nil)
	if !strings.Contains(string(body), "via:saml") || !strings.Contains(string(body), "alice@corp.test") {
		t.Fatalf("expected an audited saml login: %s", body)
	}
	// Replay: the same Response posted again by the same browser is refused —
	// the request ID was consumed and the cookie cleared.
	if v := postACS(t, srv, browser, resp.SAMLResponse); v.Get("pam_error") != "invalid_state" {
		t.Fatalf("replayed response should be invalid_state, got %v", v)
	}
}

// TestSAMLTamperedResponseRefused proves the API path is fail-closed on a
// Response whose signed content was altered after signing: no session, no
// login audit row, and the browser is sent back with login_failed.
func TestSAMLTamperedResponseRefused(t *testing.T) {
	srv, idp := samlServer(t)
	browser := newBrowser(srv)
	redirect := samlStart(t, srv, idp, browser)
	resp := idp.Login(t, redirect)
	tampered := samltest.Tamper(t, resp.SAMLResponse, func(doc *etree.Document) {
		doc.FindElement("//NameID").SetText("mallory@corp.test")
	})
	if v := postACS(t, srv, browser, tampered); v.Get("pam_error") != "login_failed" || v.Get("pam_token") != "" {
		t.Fatalf("tampered response should be login_failed with no token, got %v", v)
	}
	// And the burnt request ID cannot be reused with the genuine response.
	if v := postACS(t, srv, browser, resp.SAMLResponse); v.Get("pam_error") != "invalid_state" {
		t.Fatalf("state should be consumed by the failed attempt, got %v", v)
	}
	// Nothing was audited as a login.
	_, body := do(t, srv, http.MethodGet, "/api/audit?limit=50", testAPIKey, nil)
	if strings.Contains(string(body), "via:saml") {
		t.Fatalf("no saml login should be audited: %s", body)
	}
}

// TestSAMLCrossBrowserRejected is the login-CSRF defence: a valid Response for
// a login started in browser A, posted from browser B (no state cookie), is
// refused — and A's own login still succeeds afterwards, so B could not burn it.
func TestSAMLCrossBrowserRejected(t *testing.T) {
	srv, idp := samlServer(t)
	starter := newBrowser(srv)
	redirect := samlStart(t, srv, idp, starter)
	resp := idp.Login(t, redirect)

	victim := newBrowser(srv) // fresh jar
	if v := postACS(t, srv, victim, resp.SAMLResponse); v.Get("pam_error") != "invalid_state" {
		t.Fatalf("cross-browser acs should be invalid_state, got %v", v)
	}
	if v := postACS(t, srv, starter, resp.SAMLResponse); v.Get("pam_token") == "" {
		t.Fatalf("legitimate browser should still complete its login, got %v", v)
	}
}

// TestSAMLNoMappedRole verifies a valid login whose groups map to no role is
// refused with no_role — a SAML identity never gets a default role.
func TestSAMLNoMappedRole(t *testing.T) {
	srv, idp := samlServer(t)
	idp.SetSession(&crewjam.Session{
		ID: "s2", CreateTime: time.Now(), ExpireTime: time.Now().Add(time.Hour),
		NameID:           "carol@corp.test",
		CustomAttributes: []crewjam.Attribute{{Name: "groups", Values: []crewjam.AttributeValue{{Type: "xs:string", Value: "finance"}}}},
	})
	browser := newBrowser(srv)
	redirect := samlStart(t, srv, idp, browser)
	resp := idp.Login(t, redirect)
	if v := postACS(t, srv, browser, resp.SAMLResponse); v.Get("pam_error") != "no_role" {
		t.Fatalf("unmapped groups should be no_role, got %v", v)
	}
}

// TestSAMLMetadataAndNotConfigured checks the SP metadata endpoint serves the
// descriptor an IdP imports, and that all three routes are 404 without SAML.
func TestSAMLMetadataAndNotConfigured(t *testing.T) {
	srv, _ := samlServer(t)
	resp, err := srv.Client().Get(srv.URL + "/api/auth/saml/metadata")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "samlmetadata") {
		t.Fatalf("metadata status/type = %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if !strings.Contains(string(body), srv.URL+"/api/auth/saml/acs") || !strings.Contains(string(body), "EntityDescriptor") {
		t.Fatalf("metadata should carry the ACS URL: %s", body)
	}
	// The effective-config screen reports SAML on.
	_, cfg := do(t, srv, http.MethodGet, "/api/config/effective", testAPIKey, nil)
	if !strings.Contains(string(cfg), `"saml_login":true`) {
		t.Fatalf("effective config should report saml_login: %s", cfg)
	}

	plain := newTestServer(t)
	c := newBrowser(plain)
	for _, r := range []struct{ method, path string }{
		{http.MethodGet, "/api/auth/saml/start"},
		{http.MethodPost, "/api/auth/saml/acs"},
		{http.MethodGet, "/api/auth/saml/metadata"},
	} {
		req, _ := http.NewRequest(r.method, plain.URL+r.path, strings.NewReader("SAMLResponse=x"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Fatalf("%s %s without SAML = %d, want 404", r.method, r.path, res.StatusCode)
		}
	}
}
