// Package saml implements the SAML 2.0 Web Browser SSO profile with PAMv1 in
// the Service Provider (SP) role, so a deployment can sign in against an IdP
// that speaks SAML but not OIDC — on-prem ADFS being the canonical case, along
// with Okta, OneLogin and Entra ID's SAML applications (Phase 151).
//
// The flow is SP-initiated only: PAMv1 mints an AuthnRequest, sends the browser
// to the IdP over the HTTP-Redirect binding, and receives the signed Response
// back at its Assertion Consumer Service (ACS) over the HTTP-POST binding.
// IdP-initiated logins, the artifact binding and single logout are deliberately
// out of scope for this first version — an unsolicited Response has no
// request ID to bind to a browser, which is exactly the login-CSRF hole the
// SP-initiated flow's state cookie closes.
//
// # Why this package leans on a library
//
// Every other protocol client in this tree is hand-rolled, including OIDC's
// RS256 ID-token verification, which is genuinely small: split on ".", verify
// one signature over exact fixed bytes, decode JSON. SAML's XML-DSig has no
// equivalent "exact fixed bytes" step — the signature covers a *canonicalized*
// (Exclusive C14N) form of the XML, and canonicalization together with
// <Reference URI="#id"> resolution and the enveloped-signature transform is
// precisely where the well-known XML Signature Wrapping vulnerability class
// lives: a validly-signed decoy assertion travels alongside a forged one, and
// the code that verifies and the code that processes walk the DOM
// differently. That is a different order of problem than "a JWT with more
// steps" and clears this codebase's own stated bar for reaching for a library
// ("where crypto-verification risk is high") more clearly than WebAuthn did in
// Phase 124. This package therefore delegates the XML-DSig verification, the
// XML round-trip validation and the assertion condition checks to
// github.com/crewjam/saml (which in turn uses russellhaering/goxmldsig for
// canonicalization and signature verification), and keeps for itself only the
// pamv1-specific decisions: what enables the feature, how the IdP metadata is
// sourced, which attribute is the username, which attributes carry the groups
// that map to roles, and how the resulting claims are shaped for the API
// layer. Nothing here re-implements a signature check.
package saml

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	crewjam "github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

// maxMetadataBytes bounds an IdP metadata document, whether fetched from
// PAM_SAML_IDP_METADATA_URL or read from PAM_SAML_IDP_METADATA_FILE — the same
// 1 MiB cap the OIDC discovery/JWKS reads use. Real metadata is a few KiB; a
// federation aggregate can be larger but is not what a single-IdP SP consumes.
const maxMetadataBytes = 1 << 20

// MaxResponseBytes bounds a posted SAMLResponse before it is base64-decoded and
// XML-parsed. Signed assertions with a few dozen attributes are a few KiB; the
// API layer applies this cap to the ACS request body via http.MaxBytesReader.
const MaxResponseBytes = 1 << 20

// StatePath is the URL path prefix under which the API layer mounts the three
// SAML routes (start, ACS, metadata) — exposed so the state cookie's Path can be
// scoped to it and nowhere else.
const StatePath = "/api/auth/saml/"

// DefaultGroupAttributes are the attribute names (matched against both an
// attribute's Name and its FriendlyName, case-insensitively) whose values are
// read as group/role claims when PAM_SAML_GROUP_ATTR is not set. They cover
// what the common IdPs emit by default: Okta/OneLogin/generic ("groups",
// "memberOf", "role"), ADFS's Token-Groups and Role claim types, and Entra ID's
// SAML groups claim.
var DefaultGroupAttributes = []string{
	"groups",
	"memberOf",
	"role",
	"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
	"http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
	"http://schemas.xmlsoap.org/claims/Group",
}

// Config describes one SAML Service Provider. Exactly one of IDPMetadataURL and
// IDPMetadataXML must be set; RootURL is required; the SP key pair is optional.
type Config struct {
	// RootURL is PAMv1's externally visible base URL as the browser and the IdP
	// see it, e.g. "https://pam.example.com". The ACS URL and the SP metadata
	// URL are derived from it (RootURL + StatePath + "acs" / "metadata"), so it
	// must be the public origin, not an internal listener address, when PAMv1
	// sits behind a reverse proxy.
	RootURL string
	// EntityID is the SP's own identifier as registered at the IdP. Empty
	// defaults to the SP metadata URL, which is the SAML convention and what
	// most IdPs expect when they import metadata.
	EntityID string
	// IDPMetadataURL is where the IdP publishes its metadata (ADFS:
	// https://<adfs>/FederationMetadata/2007-06/FederationMetadata.xml). It is
	// fetched once when the provider is built (and again on every hot-swap);
	// this is the only outbound call the SP ever makes.
	IDPMetadataURL string
	// IDPMetadataXML is the IdP metadata document itself, for deployments that
	// cannot fetch it (air-gapped sites, or an IdP whose metadata endpoint is
	// not reachable from PAMv1). Either an <EntityDescriptor> or an
	// <EntitiesDescriptor> aggregate containing exactly one IdP is accepted.
	IDPMetadataXML []byte
	// SPKeyPEM / SPCertPEM optionally give the SP an RSA key pair. When both are
	// set, AuthnRequests are signed (RSA-SHA256, for IdPs configured to require
	// it) and the certificate is published in the SP metadata for encryption,
	// so an IdP that encrypts assertions to the SP can be used. Without them the
	// SP still verifies every IdP signature — the pair only adds the two
	// SP-side operations.
	SPKeyPEM  []byte
	SPCertPEM []byte
	// NameAttr, when set, names the assertion attribute (Name or FriendlyName)
	// whose first value becomes the PAMv1 username, e.g. an ADFS UPN claim
	// "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn". Empty uses
	// the assertion's Subject NameID, which is what most IdPs already populate
	// with the email or UPN.
	NameAttr string
	// GroupAttrs lists the attribute names whose values are the group/role
	// claims mapped to PAMv1 roles. Empty uses DefaultGroupAttributes.
	GroupAttrs []string
	// HTTPClient is used for the one metadata fetch; nil uses a 10 s-timeout
	// default.
	HTTPClient *http.Client
}

// Provider is a configured SAML Service Provider. It is immutable once built
// and safe for concurrent use.
type Provider struct {
	sp         crewjam.ServiceProvider
	nameAttr   string
	groupAttrs map[string]bool
	signsReqs  bool
}

// Claims are the validated fields PAMv1 reads from a SAML assertion, shaped like
// oidc.Claims so the API layer's role mapping and session issuance treat both
// SSO paths identically.
type Claims struct {
	// NameID is the assertion Subject's NameID.
	NameID string
	// Name is the username PAMv1 will record: the configured NameAttr's first
	// value, or NameID when no attribute is configured (or it is absent).
	Name string
	// Groups are the values of every matching group attribute, in document
	// order — the strings auth.MatchedRoles maps to roles.
	Groups []string
	// SessionIndex is the IdP's session handle from the AuthnStatement, kept
	// for audit; PAMv1 does not use it for logout (SLO is out of scope).
	SessionIndex string
}

// New validates cfg, sources the IdP metadata (fetch or inline), loads the
// optional SP key pair and returns a ready Provider. It makes at most one
// outbound call — the metadata fetch — and none afterwards.
func New(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.RootURL == "" {
		return nil, errors.New("saml: root url is required")
	}
	root, err := url.Parse(strings.TrimRight(cfg.RootURL, "/"))
	if err != nil || root.Scheme == "" || root.Host == "" {
		return nil, fmt.Errorf("saml: root url %q must be an absolute http(s) URL", cfg.RootURL)
	}
	if (cfg.IDPMetadataURL == "") == (len(cfg.IDPMetadataXML) == 0) {
		return nil, errors.New("saml: exactly one of idp metadata url and idp metadata xml is required")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	var idpMeta *crewjam.EntityDescriptor
	if cfg.IDPMetadataURL != "" {
		idpMeta, err = fetchMetadata(ctx, hc, cfg.IDPMetadataURL)
	} else {
		idpMeta, err = ParseMetadata(cfg.IDPMetadataXML)
	}
	if err != nil {
		return nil, err
	}
	if len(idpMeta.IDPSSODescriptors) == 0 {
		return nil, errors.New("saml: idp metadata carries no IDPSSODescriptor")
	}

	acs := *root
	acs.Path = root.Path + StatePath + "acs"
	meta := *root
	meta.Path = root.Path + StatePath + "metadata"

	p := &Provider{
		sp: crewjam.ServiceProvider{
			EntityID:          cfg.EntityID,
			MetadataURL:       meta,
			AcsURL:            acs,
			IDPMetadata:       idpMeta,
			AuthnNameIDFormat: crewjam.UnspecifiedNameIDFormat,
			// An unsolicited Response has no InResponseTo to bind to the browser
			// that started the login; refusing it is what makes the state cookie
			// a real login-CSRF defence rather than a formality.
			AllowIDPInitiated: false,
		},
		nameAttr:   cfg.NameAttr,
		groupAttrs: map[string]bool{},
	}
	groups := cfg.GroupAttrs
	if len(groups) == 0 {
		groups = DefaultGroupAttributes
	}
	for _, g := range groups {
		if g = strings.TrimSpace(g); g != "" {
			p.groupAttrs[strings.ToLower(g)] = true
		}
	}

	if (len(cfg.SPKeyPEM) == 0) != (len(cfg.SPCertPEM) == 0) {
		return nil, errors.New("saml: sp key and sp certificate must be set together")
	}
	if len(cfg.SPKeyPEM) > 0 {
		pair, err := tls.X509KeyPair(cfg.SPCertPEM, cfg.SPKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("saml: sp key pair: %w", err)
		}
		key, ok := pair.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("saml: sp key must be RSA")
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("saml: sp certificate: %w", err)
		}
		p.sp.Key = key
		p.sp.Certificate = leaf
		p.sp.SignatureMethod = dsig.RSASHA256SignatureMethod
		p.signsReqs = true
	}
	// The redirect binding is the SP-initiated request path; refuse to build a
	// provider whose IdP does not offer it rather than fail on the first login.
	if p.sp.GetSSOBindingLocation(crewjam.HTTPRedirectBinding) == "" {
		return nil, errors.New("saml: idp metadata offers no HTTP-Redirect SingleSignOnService binding")
	}
	return p, nil
}

// EntityID returns the SP entity ID the IdP must have registered.
func (p *Provider) EntityID() string {
	if p.sp.EntityID != "" {
		return p.sp.EntityID
	}
	return p.sp.MetadataURL.String()
}

// IDPEntityID returns the IdP's entity ID from its metadata — the Issuer every
// accepted Response must carry.
func (p *Provider) IDPEntityID() string { return p.sp.IDPMetadata.EntityID }

// ACSURL returns the Assertion Consumer Service URL the IdP posts to.
func (p *Provider) ACSURL() string { return p.sp.AcsURL.String() }

// SignsRequests reports whether AuthnRequests are signed (an SP key pair is
// configured).
func (p *Provider) SignsRequests() bool { return p.signsReqs }

// Metadata renders the SP's own metadata document, for the IdP administrator to
// import (ADFS "Add Relying Party Trust", Okta/Entra "upload metadata"). It
// carries the entity ID, the ACS URL (HTTP-POST binding) and, when an SP key
// pair is configured, the certificate for signing and encryption.
func (p *Provider) Metadata() ([]byte, error) {
	md := p.sp.Metadata()
	// The SP never resolves artifacts and never handles logout: advertise only
	// the HTTP-POST ACS so an IdP cannot be configured to send what PAMv1
	// refuses. Cutting the descriptor down here, rather than accepting whatever
	// the library advertises, keeps the metadata honest about the code path.
	for i := range md.SPSSODescriptors {
		d := &md.SPSSODescriptors[i]
		var acs []crewjam.IndexedEndpoint
		for _, e := range d.AssertionConsumerServices {
			if e.Binding == crewjam.HTTPPostBinding {
				acs = append(acs, e)
			}
		}
		d.AssertionConsumerServices = acs
		d.SingleLogoutServices = nil
	}
	buf, err := xml.MarshalIndent(md, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), buf...), nil
}

// StartURL builds a fresh AuthnRequest and returns the IdP redirect URL
// (HTTP-Redirect binding, signed when an SP key pair is configured) together
// with the request ID the caller must remember: the Response's InResponseTo has
// to match it, which is what ties the completed login back to the browser that
// started it.
func (p *Provider) StartURL() (redirect string, requestID string, err error) {
	req, err := p.sp.MakeAuthenticationRequest(
		p.sp.GetSSOBindingLocation(crewjam.HTTPRedirectBinding),
		crewjam.HTTPRedirectBinding, crewjam.HTTPPostBinding)
	if err != nil {
		return "", "", fmt.Errorf("saml: authn request: %w", err)
	}
	u, err := req.Redirect("", &p.sp)
	if err != nil {
		return "", "", fmt.Errorf("saml: authn request: %w", err)
	}
	return u.String(), req.ID, nil
}

// ParseResponse validates a posted SAMLResponse (the base64 form value) end to
// end — XML round-trip validity, the XML-DSig signature on the Response or the
// Assertion (or the decrypted Assertion when the SP holds a key) against the
// IdP's metadata certificate, Destination == ACS URL, Issuer == IdP entity ID,
// InResponseTo == requestID, IssueInstant/NotBefore/NotOnOrAfter within
// tolerance, and AudienceRestriction == SP entity ID — and returns the claims
// PAMv1 reads from it. On failure the returned error is safe to log: it carries
// the library's private diagnostic, never the assertion contents.
func (p *Provider) ParseResponse(samlResponse string, requestID string) (*Claims, error) {
	if len(samlResponse) > MaxResponseBytes {
		return nil, errors.New("saml: response too large")
	}
	raw, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return nil, fmt.Errorf("saml: response is not base64: %w", err)
	}
	// currentURL is the ACS URL itself: behind a reverse proxy the request's own
	// URL is the internal listener's, and the Destination the IdP wrote is the
	// public ACS URL the SP metadata advertised — the value the check must use.
	assertion, err := p.sp.ParseXMLResponse(raw, []string{requestID}, p.sp.AcsURL)
	if err != nil {
		var ire *crewjam.InvalidResponseError
		if errors.As(err, &ire) && ire.PrivateErr != nil {
			return nil, fmt.Errorf("saml: response rejected: %w", ire.PrivateErr)
		}
		return nil, fmt.Errorf("saml: response rejected: %w", err)
	}
	return p.claims(assertion), nil
}

// claims extracts the username, groups and session index from a validated
// assertion according to the configured attribute names.
func (p *Provider) claims(a *crewjam.Assertion) *Claims {
	c := &Claims{}
	if a.Subject != nil && a.Subject.NameID != nil {
		c.NameID = a.Subject.NameID.Value
	}
	c.Name = c.NameID
	if len(a.AuthnStatements) > 0 {
		c.SessionIndex = a.AuthnStatements[0].SessionIndex
	}
	want := strings.ToLower(p.nameAttr)
	for _, st := range a.AttributeStatements {
		for _, attr := range st.Attributes {
			name, friendly := strings.ToLower(attr.Name), strings.ToLower(attr.FriendlyName)
			if want != "" && (name == want || (friendly != "" && friendly == want)) {
				for _, v := range attr.Values {
					if v.Value != "" {
						c.Name = v.Value
						break
					}
				}
			}
			if p.groupAttrs[name] || (friendly != "" && p.groupAttrs[friendly]) {
				for _, v := range attr.Values {
					if v.Value != "" {
						c.Groups = append(c.Groups, v.Value)
					}
				}
			}
		}
	}
	return c
}

// ParseMetadata parses an IdP metadata document. Both a bare <EntityDescriptor>
// and an <EntitiesDescriptor> aggregate are accepted; in the aggregate case the
// (single) entity carrying an IDPSSODescriptor is returned. Kept local rather
// than imported from the library's samlsp middleware package, whose cookie/JWT
// session machinery PAMv1 does not use.
func ParseMetadata(data []byte) (*crewjam.EntityDescriptor, error) {
	if len(data) > maxMetadataBytes {
		return nil, errors.New("saml: idp metadata too large")
	}
	entity := &crewjam.EntityDescriptor{}
	err := xml.Unmarshal(data, entity)
	if err != nil && strings.Contains(err.Error(), "<EntitiesDescriptor>") {
		entities := &crewjam.EntitiesDescriptor{}
		if err := xml.Unmarshal(data, entities); err != nil {
			return nil, fmt.Errorf("saml: idp metadata: %w", err)
		}
		var found *crewjam.EntityDescriptor
		for i := range entities.EntityDescriptors {
			if len(entities.EntityDescriptors[i].IDPSSODescriptors) > 0 {
				if found != nil {
					return nil, errors.New("saml: idp metadata aggregate carries more than one IdP; supply the single entity")
				}
				found = &entities.EntityDescriptors[i]
			}
		}
		if found == nil {
			return nil, errors.New("saml: idp metadata aggregate carries no IdP")
		}
		return found, nil
	}
	if err != nil {
		return nil, fmt.Errorf("saml: idp metadata: %w", err)
	}
	if entity.EntityID == "" {
		return nil, errors.New("saml: idp metadata has no entityID")
	}
	return entity, nil
}

// fetchMetadata GETs and parses the IdP metadata, bounded to maxMetadataBytes.
func fetchMetadata(ctx context.Context, hc *http.Client, rawURL string) (*crewjam.EntityDescriptor, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("saml: idp metadata url: %w", err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("saml: fetch idp metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("saml: fetch idp metadata: status %s", resp.Status)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(resp.Body, maxMetadataBytes+1)); err != nil {
		return nil, fmt.Errorf("saml: fetch idp metadata: %w", err)
	}
	return ParseMetadata(buf.Bytes())
}
