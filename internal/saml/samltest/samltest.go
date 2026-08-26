// Package samltest runs a real SAML 2.0 Identity Provider in-process for tests:
// it publishes metadata, receives the SP's AuthnRequest over the HTTP-Redirect
// binding, and issues a genuinely XML-DSig-signed (and, when the SP advertises
// an encryption certificate, encrypted) Response for the HTTP-POST binding —
// the same code path a production IdP exercises, not a canned XML fixture.
// Tests then post that Response to PAMv1's ACS, or tamper with it first via
// Tamper to prove the SP refuses what a real attacker would send.
package samltest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	crewjam "github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
)

// IdP is a running in-process identity provider.
type IdP struct {
	// Server hosts /metadata and /sso.
	Server *httptest.Server
	// IDP is the underlying provider; tests may adjust it (e.g. Session).
	IDP *crewjam.IdentityProvider
	// Key/Cert are the IdP's signing key pair (self-signed).
	Key  *rsa.PrivateKey
	Cert *x509.Certificate

	mu      sync.Mutex
	session *crewjam.Session
	sp      *crewjam.EntityDescriptor
}

// Response is what the IdP would auto-POST to the SP: the ACS URL and the two
// form values.
type Response struct {
	URL          string `json:"url"`
	SAMLResponse string `json:"SAMLResponse"`
	RelayState   string `json:"RelayState"`
}

// New starts an IdP whose metadata is at Server.URL+"/metadata" and whose
// SingleSignOnService (HTTP-Redirect and HTTP-POST bindings) is at
// Server.URL+"/sso". Call TrustSP with the SP's metadata before logging in,
// and SetSession to choose what the next assertion says.
func New(t *testing.T) *IdP {
	t.Helper()
	key, cert := SelfSigned(t, "samltest-idp")
	i := &IdP{Key: key, Cert: cert}
	i.IDP = &crewjam.IdentityProvider{
		Key:                     key,
		Certificate:             cert,
		Logger:                  logger.DefaultLogger,
		ServiceProviderProvider: i,
		SessionProvider:         i,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/metadata", i.IDP.ServeMetadata)
	mux.HandleFunc("/sso", i.IDP.ServeSSO)
	i.Server = httptest.NewServer(mux)
	t.Cleanup(i.Server.Close)
	base, _ := url.Parse(i.Server.URL)
	md := *base
	md.Path = "/metadata"
	sso := *base
	sso.Path = "/sso"
	i.IDP.MetadataURL = md
	i.IDP.SSOURL = sso
	i.session = &crewjam.Session{
		ID: "sess-1", CreateTime: time.Now(), ExpireTime: time.Now().Add(time.Hour), Index: "idx-1",
		NameID: "alice@corp.test", UserName: "alice",
	}
	return i
}

// MetadataURL returns the IdP metadata URL the SP is configured with.
func (i *IdP) MetadataURL() string { return i.IDP.MetadataURL.String() }

// EntityID returns the IdP's entity ID (its metadata URL, per crewjam).
func (i *IdP) EntityID() string { return i.IDP.MetadataURL.String() }

// TrustSP registers the SP metadata document the IdP will issue assertions
// for — audience, ACS endpoint and (if present) encryption certificate all
// come from it, exactly as when an administrator imports the SP metadata.
func (i *IdP) TrustSP(t *testing.T, spMetadataXML []byte) {
	t.Helper()
	ed := &crewjam.EntityDescriptor{}
	if err := xmlUnmarshal(spMetadataXML, ed); err != nil {
		t.Fatalf("samltest: parse sp metadata: %v", err)
	}
	i.mu.Lock()
	i.sp = ed
	i.mu.Unlock()
}

// SetSession sets what the next assertion carries (subject, attributes).
func (i *IdP) SetSession(s *crewjam.Session) {
	i.mu.Lock()
	i.session = s
	i.mu.Unlock()
}

// GetServiceProvider implements crewjam.ServiceProviderProvider.
func (i *IdP) GetServiceProvider(_ *http.Request, serviceProviderID string) (*crewjam.EntityDescriptor, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.sp == nil || i.sp.EntityID != serviceProviderID {
		return nil, os.ErrNotExist
	}
	return i.sp, nil
}

// GetSession implements crewjam.SessionProvider: the user is always already
// logged in at the IdP, so no interactive step is simulated.
func (i *IdP) GetSession(_ http.ResponseWriter, _ *http.Request, _ *crewjam.IdpAuthnRequest) *crewjam.Session {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.session
}

// Login drives the IdP half of an SP-initiated login: it hands the SP's
// redirect URL (the AuthnRequest, HTTP-Redirect binding) to the IdP and returns
// the Response the IdP would auto-POST to the ACS. It performs exactly the
// steps IdentityProvider.ServeSSO does — parse, validate, look up the session,
// make the assertion, build the POST binding — but returns the form values
// directly instead of rendering the auto-submit HTML page.
func (i *IdP) Login(t *testing.T, redirectURL string) Response {
	t.Helper()
	req, err := crewjam.NewIdpAuthnRequest(i.IDP, httptest.NewRequest(http.MethodGet, redirectURL, nil))
	if err != nil {
		t.Fatalf("samltest: parse authn request: %v", err)
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("samltest: validate authn request: %v", err)
	}
	session := i.GetSession(nil, req.HTTPRequest, req)
	if err := (crewjam.DefaultAssertionMaker{}).MakeAssertion(req, session); err != nil {
		t.Fatalf("samltest: make assertion: %v", err)
	}
	form, err := req.PostBinding()
	if err != nil {
		t.Fatalf("samltest: post binding: %v", err)
	}
	return Response{URL: form.URL, SAMLResponse: form.SAMLResponse, RelayState: form.RelayState}
}

// Tamper decodes a SAMLResponse form value, lets fn edit the XML document, and
// re-encodes it — the tool for "what if an attacker changed X after signing".
func Tamper(t *testing.T, samlResponse string, fn func(doc *etree.Document)) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		t.Fatalf("samltest: tamper decode: %v", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatalf("samltest: tamper parse: %v", err)
	}
	fn(doc)
	out, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("samltest: tamper write: %v", err)
	}
	return base64.StdEncoding.EncodeToString(out)
}

// SelfSigned generates an RSA-2048 key and a self-signed certificate for cn.
func SelfSigned(t *testing.T, cn string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

// PEM returns the key pair as PEM blocks (PKCS#1 key, X.509 certificate) — the
// shape PAM_SAML_SP_KEY_FILE / PAM_SAML_SP_CERT_FILE hold.
func PEM(key *rsa.PrivateKey, cert *x509.Certificate) (keyPEM, certPEM []byte) {
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return keyPEM, certPEM
}

// xmlUnmarshal parses an SP metadata document.
func xmlUnmarshal(data []byte, v *crewjam.EntityDescriptor) error {
	return xml.Unmarshal(data, v)
}
