package saml_test

import (
	"context"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	crewjam "github.com/crewjam/saml"
	"github.com/crewjam/saml/xmlenc"

	"github.com/morandeirachema/pamv1/internal/saml"
	"github.com/morandeirachema/pamv1/internal/saml/samltest"
)

const spRoot = "https://pam.example.com"

// newSP builds a Provider against a fresh in-process IdP and registers the SP's
// metadata with it, returning both. extra lets a test adjust the SP config
// (key pair, attribute names) before it is built.
func newSP(t *testing.T, extra func(*saml.Config)) (*saml.Provider, *samltest.IdP) {
	t.Helper()
	idp := samltest.New(t)
	cfg := saml.Config{RootURL: spRoot, IDPMetadataURL: idp.MetadataURL()}
	if extra != nil {
		extra(&cfg)
	}
	sp, err := saml.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("saml.New: %v", err)
	}
	md, err := sp.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	idp.TrustSP(t, md)
	return sp, idp
}

// login runs the SP-initiated request through the IdP and returns the request
// ID the SP minted plus the IdP's Response.
func login(t *testing.T, sp *saml.Provider, idp *samltest.IdP) (string, samltest.Response) {
	t.Helper()
	redirect, requestID, err := sp.StartURL()
	if err != nil {
		t.Fatalf("StartURL: %v", err)
	}
	if requestID == "" || !strings.HasPrefix(redirect, idp.Server.URL+"/sso?") {
		t.Fatalf("bad start: id=%q redirect=%q", requestID, redirect)
	}
	return requestID, idp.Login(t, redirect)
}

// TestConfigValidation pins the fail-loud construction rules: no root URL, a
// relative root URL, both/neither metadata sources, and a lone SP key.
func TestConfigValidation(t *testing.T) {
	ctx := context.Background()
	for name, cfg := range map[string]saml.Config{
		"no root":       {IDPMetadataXML: []byte("<x/>")},
		"relative root": {RootURL: "/pam", IDPMetadataXML: []byte("<x/>")},
		"no metadata":   {RootURL: spRoot},
		"both metadata": {RootURL: spRoot, IDPMetadataURL: "https://idp/md", IDPMetadataXML: []byte("<x/>")},
		"bad xml":       {RootURL: spRoot, IDPMetadataXML: []byte("not xml")},
	} {
		if _, err := saml.New(ctx, cfg); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	idp := samltest.New(t)
	if _, err := saml.New(ctx, saml.Config{RootURL: spRoot, IDPMetadataURL: idp.MetadataURL(), SPKeyPEM: []byte("k")}); err == nil {
		t.Error("lone sp key should be refused")
	}
}

// TestMetadata checks the SP descriptor: entity ID defaults to the metadata
// URL, exactly one ACS (HTTP-POST) is advertised, no SLO, and — with a key
// pair — a certificate is published.
func TestMetadata(t *testing.T) {
	sp, _ := newSP(t, nil)
	if got, want := sp.EntityID(), spRoot+"/api/auth/saml/metadata"; got != want {
		t.Fatalf("entity id = %q, want %q", got, want)
	}
	if got, want := sp.ACSURL(), spRoot+"/api/auth/saml/acs"; got != want {
		t.Fatalf("acs = %q, want %q", got, want)
	}
	md, err := sp.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(md); err != nil {
		t.Fatal(err)
	}
	acs := doc.FindElements("//AssertionConsumerService")
	if len(acs) != 1 || acs[0].SelectAttrValue("Binding", "") != crewjam.HTTPPostBinding {
		t.Fatalf("want exactly one HTTP-POST ACS, got %d", len(acs))
	}
	if len(doc.FindElements("//SingleLogoutService")) != 0 {
		t.Fatal("SLO must not be advertised")
	}
	if len(doc.FindElements("//KeyDescriptor")) != 0 {
		t.Fatal("no key pair configured, no KeyDescriptor expected")
	}
	if sp.SignsRequests() {
		t.Fatal("SignsRequests should be false without a key pair")
	}

	key, cert := samltest.SelfSigned(t, "sp")
	k, c := samltest.PEM(key, cert)
	sp2, _ := newSP(t, func(cfg *saml.Config) { cfg.SPKeyPEM, cfg.SPCertPEM = k, c; cfg.EntityID = "urn:pamv1:sp" })
	if sp2.EntityID() != "urn:pamv1:sp" || !sp2.SignsRequests() {
		t.Fatalf("explicit entity id / signing not honoured")
	}
	md2, _ := sp2.Metadata()
	if !strings.Contains(string(md2), "<KeyDescriptor") || !strings.Contains(string(md2), `use="encryption"`) {
		t.Fatalf("metadata should publish the SP certificate for encryption:\n%s", md2)
	}
	// Authenticated encryption is offered ahead of AES-CBC, so an IdP that
	// follows the SP's order encrypts the assertion with AES-GCM (Phase 288).
	gcm, cbc := strings.Index(string(md2), "xmlenc11#aes256-gcm"), strings.Index(string(md2), "xmlenc#aes128-cbc")
	if gcm < 0 || cbc < 0 || gcm > cbc {
		t.Fatalf("metadata should list AES-GCM before AES-CBC:\n%s", md2)
	}
	redirect, _, err := sp2.StartURL()
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(redirect)
	if u.Query().Get("Signature") == "" || u.Query().Get("SigAlg") == "" {
		t.Fatalf("signed AuthnRequest expected in redirect: %s", redirect)
	}
}

// TestLoginRoundTrip is the happy path against the real IdP: a signed Response
// validates and yields NameID, the default group attributes and the session
// index; the same Response then also proves the request-ID binding.
func TestLoginRoundTrip(t *testing.T) {
	sp, idp := newSP(t, nil)
	idp.SetSession(&crewjam.Session{
		ID: "s", CreateTime: time.Now(), ExpireTime: time.Now().Add(time.Hour), Index: "idx-42",
		NameID: "alice@corp.test", UserName: "alice",
		CustomAttributes: []crewjam.Attribute{{
			Name:   "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
			Values: []crewjam.AttributeValue{{Type: "xs:string", Value: "pam-admins"}, {Type: "xs:string", Value: "staff"}},
		}},
	})
	requestID, resp := login(t, sp, idp)
	if resp.URL != sp.ACSURL() {
		t.Fatalf("idp would post to %q, want %q", resp.URL, sp.ACSURL())
	}
	claims, err := sp.ParseResponse(resp.SAMLResponse, requestID)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if claims.NameID != "alice@corp.test" || claims.Name != "alice@corp.test" {
		t.Fatalf("subject = %+v", claims)
	}
	if strings.Join(claims.Groups, ",") != "pam-admins,staff" {
		t.Fatalf("groups = %v", claims.Groups)
	}
	if claims.SessionIndex != "idx-42" {
		t.Fatalf("session index = %q", claims.SessionIndex)
	}
	// Wrong request ID (InResponseTo mismatch) is refused.
	if _, err := sp.ParseResponse(resp.SAMLResponse, "id-other"); err == nil {
		t.Fatal("response for another request must be refused")
	}
}

// TestNameAndGroupAttributes proves the configured username attribute and an
// explicit group attribute list are honoured (matched by FriendlyName too).
func TestNameAndGroupAttributes(t *testing.T) {
	sp, idp := newSP(t, func(cfg *saml.Config) {
		cfg.NameAttr = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"
		cfg.GroupAttrs = []string{"http://schemas.xmlsoap.org/claims/Group", "tokenGroups"}
	})
	idp.SetSession(&crewjam.Session{
		ID: "s", CreateTime: time.Now(), ExpireTime: time.Now().Add(time.Hour),
		NameID: "opaque-persistent-id",
		CustomAttributes: []crewjam.Attribute{
			{Name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", Values: []crewjam.AttributeValue{{Type: "xs:string", Value: "bob@corp.test"}}},
			{Name: "urn:oid:1.2.3", FriendlyName: "tokenGroups", Values: []crewjam.AttributeValue{{Type: "xs:string", Value: "Domain Admins"}}},
			// Would match the default set, but the explicit list excludes it.
			{Name: "groups", Values: []crewjam.AttributeValue{{Type: "xs:string", Value: "ignored"}}},
		},
	})
	requestID, resp := login(t, sp, idp)
	claims, err := sp.ParseResponse(resp.SAMLResponse, requestID)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if claims.Name != "bob@corp.test" || claims.NameID != "opaque-persistent-id" {
		t.Fatalf("name attr not honoured: %+v", claims)
	}
	if strings.Join(claims.Groups, ",") != "Domain Admins" {
		t.Fatalf("groups = %v", claims.Groups)
	}
}

// TestEncryptedAssertion gives the SP a key pair; the IdP then encrypts the
// assertion to the SP's published certificate and the SP must decrypt it and
// still verify the signature underneath.
func TestEncryptedAssertion(t *testing.T) {
	key, cert := samltest.SelfSigned(t, "sp")
	k, c := samltest.PEM(key, cert)
	sp, idp := newSP(t, func(cfg *saml.Config) { cfg.SPKeyPEM, cfg.SPCertPEM = k, c })
	requestID, resp := login(t, sp, idp)
	raw := samltest.Tamper(t, resp.SAMLResponse, func(doc *etree.Document) {
		if doc.FindElement("//EncryptedAssertion") == nil {
			t.Fatal("idp should have encrypted the assertion to the SP certificate")
		}
		// The IdP follows the order the SP metadata lists, which puts
		// authenticated encryption first (Phase 288).
		if alg := encryptionAlgorithms(doc); len(alg) == 0 || !strings.HasSuffix(alg[0], "#aes256-gcm") {
			t.Fatalf("assertion should be encrypted with AES-256-GCM, got %v", alg)
		}
	})
	claims, err := sp.ParseResponse(raw, requestID)
	if err != nil {
		t.Fatalf("ParseResponse(encrypted): %v", err)
	}
	if claims.NameID != "alice@corp.test" {
		t.Fatalf("claims = %+v", claims)
	}
}

// encryptionAlgorithms lists the EncryptionMethod algorithms of an encrypted
// assertion in document order: the data cipher, then the key transport.
func encryptionAlgorithms(doc *etree.Document) []string {
	var out []string
	for _, el := range doc.FindElements("//EncryptedAssertion//EncryptionMethod") {
		out = append(out, el.SelectAttrValue("Algorithm", ""))
	}
	return out
}

// TestEncryptedAssertionKeyTransport pins which key transports the SP
// decrypts. RSA-OAEP is accepted with either digest an IdP is likely to use.
// RSA PKCS#1 v1.5 (rsa-1_5) is refused: it is open to Bleichenbacher padding
// oracles, the library does not register it for decryption, and PAMv1 does
// not opt back in. The assertion is validly signed and encrypted to the SP's
// own certificate in every case, so the refusal is the algorithm's.
func TestEncryptedAssertionKeyTransport(t *testing.T) {
	key, cert := samltest.SelfSigned(t, "sp")
	k, c := samltest.PEM(key, cert)
	for name, tc := range map[string]struct {
		enc  xmlenc.Encrypter
		want string
		ok   bool
	}{
		"rsa-oaep-mgf1p, sha-1": {xmlenc.OAEP(), "xmlenc#rsa-oaep-mgf1p", true},
		"rsa-oaep, sha-256":     {xmlenc.OAEP_SHA256(), "xmlenc11#rsa-oaep", true},
		"rsa-1_5":               {xmlenc.PKCS1v15(), "xmlenc#rsa-1_5", false},
	} {
		t.Run(name, func(t *testing.T) {
			sp, idp := newSP(t, func(cfg *saml.Config) { cfg.SPKeyPEM, cfg.SPCertPEM = k, c })
			idp.IDP.AssertionEncrypter = tc.enc
			requestID, resp := login(t, sp, idp)
			raw := samltest.Tamper(t, resp.SAMLResponse, func(doc *etree.Document) {
				alg := encryptionAlgorithms(doc)
				if len(alg) < 2 || !strings.HasSuffix(alg[1], tc.want) {
					t.Fatalf("key transport should be %s, got %v", tc.want, alg)
				}
			})
			claims, err := sp.ParseResponse(raw, requestID)
			if tc.ok && (err != nil || claims.NameID != "alice@corp.test") {
				t.Fatalf("refused: %+v, %v", claims, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("accepted: %+v", claims)
			}
			if !tc.ok && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refused, but not for the key transport: %v", err)
			}
		})
	}
}

// TestTamperedResponsesRefused is the security core: a Response altered after
// signing (attribute value, subject), one with its signatures stripped, one
// for a different audience, one from an unknown issuer, and one whose
// assertion is a decoy wrapped around a forged one must all be refused.
func TestTamperedResponsesRefused(t *testing.T) {
	sp, idp := newSP(t, nil)
	idp.SetSession(&crewjam.Session{
		ID: "s", CreateTime: time.Now(), ExpireTime: time.Now().Add(time.Hour),
		NameID:           "alice@corp.test",
		CustomAttributes: []crewjam.Attribute{{Name: "groups", Values: []crewjam.AttributeValue{{Type: "xs:string", Value: "pam-users"}}}},
	})
	requestID, resp := login(t, sp, idp)
	// Sanity: untouched, it validates.
	if _, err := sp.ParseResponse(resp.SAMLResponse, requestID); err != nil {
		t.Fatalf("baseline should validate: %v", err)
	}
	cases := map[string]func(doc *etree.Document){
		"group value escalated": func(doc *etree.Document) {
			doc.FindElement("//AttributeValue").SetText("pam-admins")
		},
		"subject swapped": func(doc *etree.Document) {
			doc.FindElement("//NameID").SetText("admin@corp.test")
		},
		"signatures stripped": func(doc *etree.Document) {
			for _, sig := range doc.FindElements("//Signature") {
				sig.Parent().RemoveChild(sig)
			}
		},
		"audience changed": func(doc *etree.Document) {
			doc.FindElement("//Audience").SetText("https://other-sp.example.com/metadata")
		},
		"issuer changed": func(doc *etree.Document) {
			for _, is := range doc.FindElements("//Issuer") {
				is.SetText("https://evil-idp.example.com/metadata")
			}
		},
		"expired conditions": func(doc *etree.Document) {
			doc.FindElement("//Conditions").CreateAttr("NotOnOrAfter", time.Now().Add(-time.Hour).UTC().Format(time.RFC3339))
		},
		"assertion duplicated with forged copy": func(doc *etree.Document) {
			// Signature-wrapping shape: keep the signed assertion, add an
			// unsigned twin with an escalated group in front of it.
			orig := doc.FindElement("//Assertion")
			forged := orig.Copy()
			for _, sig := range forged.FindElements(".//Signature") {
				sig.Parent().RemoveChild(sig)
			}
			forged.FindElement(".//AttributeValue").SetText("pam-admins")
			forged.CreateAttr("ID", "id-forged")
			orig.Parent().InsertChildAt(orig.Index(), forged)
		},
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			tampered := samltest.Tamper(t, resp.SAMLResponse, fn)
			claims, err := sp.ParseResponse(tampered, requestID)
			if err == nil {
				t.Fatalf("tampered response accepted: %+v", claims)
			}
		})
	}
	// Garbage and oversized inputs fail cleanly.
	if _, err := sp.ParseResponse("!!not base64!!", requestID); err == nil {
		t.Fatal("non-base64 accepted")
	}
	if _, err := sp.ParseResponse(strings.Repeat("A", saml.MaxResponseBytes+1), requestID); err == nil {
		t.Fatal("oversized accepted")
	}
}

// TestParseMetadata covers the inline-XML source, including the
// EntitiesDescriptor aggregate wrapper, and the no-IdP / no-redirect-binding
// refusals.
func TestParseMetadata(t *testing.T) {
	idp := samltest.New(t)
	// Fetch the real metadata bytes so the inline path is exercised on the same
	// document the URL path parses.
	res, err := idp.Server.Client().Get(idp.MetadataURL())
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	xmlDoc := string(raw)
	if _, err := saml.New(context.Background(), saml.Config{RootURL: spRoot, IDPMetadataXML: []byte(xmlDoc)}); err != nil {
		t.Fatalf("inline EntityDescriptor: %v", err)
	}
	// Wrapped in an aggregate.
	body := xmlDoc[strings.Index(xmlDoc, "<EntityDescriptor"):]
	agg := `<?xml version="1.0"?><EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` + body + `</EntitiesDescriptor>`
	if _, err := saml.New(context.Background(), saml.Config{RootURL: spRoot, IDPMetadataXML: []byte(agg)}); err != nil {
		t.Fatalf("aggregate metadata: %v", err)
	}
	// An aggregate with no IdP in it.
	none := `<?xml version="1.0"?><EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><EntityDescriptor entityID="x"/></EntitiesDescriptor>`
	if _, err := saml.ParseMetadata([]byte(none)); err == nil {
		t.Fatal("aggregate without an IdP accepted")
	}
	// An IdP with only a POST binding cannot serve the redirect flow.
	post := strings.ReplaceAll(xmlDoc, crewjam.HTTPRedirectBinding, "urn:example:no-such-binding")
	if _, err := saml.New(context.Background(), saml.Config{RootURL: spRoot, IDPMetadataXML: []byte(post)}); err == nil {
		t.Fatal("idp without HTTP-Redirect SSO binding accepted")
	}
}

// TestSignatureWrappingClassic is the textbook XML Signature Wrapping shape:
// the Response-level signature is removed (leaving only the assertion's own
// signature, which many IdPs emit) and an unsigned, escalated twin of the
// assertion is inserted ahead of the signed one. Whatever the SP does, the
// claims it acts on must never be the forged ones.
func TestSignatureWrappingClassic(t *testing.T) {
	sp, idp := newSP(t, nil)
	idp.SetSession(&crewjam.Session{
		ID: "s", CreateTime: time.Now(), ExpireTime: time.Now().Add(time.Hour),
		NameID:           "alice@corp.test",
		CustomAttributes: []crewjam.Attribute{{Name: "groups", Values: []crewjam.AttributeValue{{Type: "xs:string", Value: "pam-users"}}}},
	})
	requestID, resp := login(t, sp, idp)
	wrapped := samltest.Tamper(t, resp.SAMLResponse, func(doc *etree.Document) {
		root := doc.Root()
		for _, sig := range root.ChildElements() {
			if sig.Tag == "Signature" {
				root.RemoveChild(sig)
			}
		}
		orig := doc.FindElement("//Assertion")
		forged := orig.Copy()
		for _, sig := range forged.FindElements(".//Signature") {
			sig.Parent().RemoveChild(sig)
		}
		forged.FindElement(".//AttributeValue").SetText("pam-admins")
		forged.FindElement(".//NameID").SetText("admin@corp.test")
		forged.CreateAttr("ID", "id-forged")
		root.InsertChildAt(orig.Index(), forged)
	})
	// Sanity: with only the response signature stripped (no forgery), the
	// assertion-signed document is still valid — the shape real IdPs send.
	onlyAssertionSigned := samltest.Tamper(t, resp.SAMLResponse, func(doc *etree.Document) {
		root := doc.Root()
		for _, sig := range root.ChildElements() {
			if sig.Tag == "Signature" {
				root.RemoveChild(sig)
			}
		}
	})
	if _, err := sp.ParseResponse(onlyAssertionSigned, requestID); err != nil {
		t.Fatalf("assertion-only signature should validate: %v", err)
	}
	claims, err := sp.ParseResponse(wrapped, requestID)
	if err != nil {
		return // refused outright: fine
	}
	if claims.NameID != "alice@corp.test" || strings.Join(claims.Groups, ",") != "pam-users" {
		t.Fatalf("forged assertion's claims were used: %+v", claims)
	}
}

// TestAdvisoryGO20266909 pins the two flaws of GO-2026-6909 as fixed in the
// crewjam/saml release PAMv1 builds against (fixed in v0.5.2; go.mod pins
// v0.6.3 since Phase 288), on assertions the IdP has validly signed, so
// nothing is refused for a broken signature. A signed
// assertion missing an optional element the checks need must be refused, not
// panic the handler; and a NameID from a foreign XML namespace must never
// become the authenticated subject. On v0.5.1 the Subject, Conditions and
// SubjectConfirmationData cases panic and the NameID is spoofed; the Issuer
// case never was vulnerable (the advisory's wording; Issuer is a value field)
// but is the precondition it names, so it stays. The vulnerability database
// lists no fixed version yet, so govulncheck still reports the advisory; this
// test is why CI accepts it (.github/govulncheck-accepted.txt, Phase 287).
func TestAdvisoryGO20266909(t *testing.T) {
	remove := func(path string) func(*etree.Element) {
		return func(a *etree.Element) {
			el := a.FindElement(path)
			if el == nil {
				t.Fatalf("assertion has no %s to remove", path)
			}
			el.Parent().RemoveChild(el)
		}
	}
	run := func(t *testing.T, reshape func(*etree.Element)) (*saml.Claims, error) {
		t.Helper()
		sp, idp := newSP(t, nil)
		idp.Reshape = reshape
		requestID, resp := login(t, sp, idp)
		return sp.ParseResponse(resp.SAMLResponse, requestID)
	}
	// Sanity: a reshape that changes nothing still validates, so the refusals
	// below come from the shape and not from how the harness signs.
	if claims, err := run(t, func(*etree.Element) {}); err != nil || claims.NameID != "alice@corp.test" {
		t.Fatalf("unchanged signed assertion should validate: %+v, %v", claims, err)
	}
	for name, reshape := range map[string]func(*etree.Element){
		"no Issuer":                  remove("./Issuer"),
		"no Subject":                 remove("./Subject"),
		"no Conditions":              remove("./Conditions"),
		"no SubjectConfirmationData": remove(".//SubjectConfirmationData"),
	} {
		t.Run(name, func(t *testing.T) {
			if claims, err := run(t, reshape); err == nil {
				t.Fatalf("signed assertion with %s accepted: %+v", name, claims)
			}
		})
	}
	t.Run("foreign-namespace NameID", func(t *testing.T) {
		claims, err := run(t, func(a *etree.Element) {
			subject := a.FindElement("./Subject")
			nameID := subject.FindElement("./NameID")
			foreign := etree.NewElement("x:NameID")
			foreign.CreateAttr("xmlns:x", "urn:example:foreign")
			foreign.SetText("admin@corp.test")
			subject.InsertChildAt(nameID.Index(), foreign)
			subject.RemoveChild(nameID)
		})
		if err != nil {
			return // refused outright: fine
		}
		if claims.NameID == "admin@corp.test" || claims.Name == "admin@corp.test" {
			t.Fatalf("foreign-namespace NameID became the subject: %+v", claims)
		}
	})
}

// TestAssertionShape pins what crewjam/saml v0.6.3 decides about the shape of
// an assertion the IdP has validly signed, where it differs from v0.5.2
// (Phase 288). The signature is good in every case, so each verdict is the
// library's reading of the Web Browser SSO profile and nothing else. Stricter
// than before: a login needs an AuthnStatement, a Subject identifier, SAML
// 2.0, and an IssueInstant that is not in the future. Looser than before, and
// what the profile says: one valid bearer SubjectConfirmation is enough, and
// an omitted Conditions NotOnOrAfter is no expiry — bounded by the bearer
// confirmation's own NotOnOrAfter, which the last refusals prove still binds.
func TestAssertionShape(t *testing.T) {
	stamp := func(d time.Duration) string { return time.Now().Add(d).UTC().Format(time.RFC3339) }
	remove := func(path string) func(*etree.Element) {
		return func(a *etree.Element) {
			el := a.FindElement(path)
			if el == nil {
				t.Fatalf("assertion has no %s to remove", path)
			}
			el.Parent().RemoveChild(el)
		}
	}
	noConditionsExpiry := func(a *etree.Element) {
		if a.FindElement("./Conditions").RemoveAttr("NotOnOrAfter") == nil {
			t.Fatal("Conditions has no NotOnOrAfter to remove")
		}
	}
	// otherRecipient copies the bearer confirmation and addresses the copy to
	// another service provider; the original stays unless replace is set.
	otherRecipient := func(replace bool) func(*etree.Element) {
		return func(a *etree.Element) {
			subject := a.FindElement("./Subject")
			orig := subject.FindElement("./SubjectConfirmation")
			other := orig.Copy()
			other.FindElement("./SubjectConfirmationData").CreateAttr("Recipient", "https://other.example.com/acs")
			subject.AddChild(other)
			if replace {
				subject.RemoveChild(orig)
			}
		}
	}
	run := func(t *testing.T, reshape func(*etree.Element)) (*saml.Claims, error) {
		t.Helper()
		sp, idp := newSP(t, nil)
		idp.Reshape = reshape
		requestID, resp := login(t, sp, idp)
		return sp.ParseResponse(resp.SAMLResponse, requestID)
	}

	for name, reshape := range map[string]func(*etree.Element){
		"no AuthnStatement":       remove("./AuthnStatement"),
		"no Subject identifier":   remove("./Subject/NameID"),
		"SAML 1.1":                func(a *etree.Element) { a.CreateAttr("Version", "1.1") },
		"IssueInstant in an hour": func(a *etree.Element) { a.CreateAttr("IssueInstant", stamp(time.Hour)) },
		"the only bearer confirmation is for another recipient": otherRecipient(true),
		"no Conditions expiry, bearer confirmation expired": func(a *etree.Element) {
			noConditionsExpiry(a)
			a.FindElement(".//SubjectConfirmationData").CreateAttr("NotOnOrAfter", stamp(-time.Hour))
		},
	} {
		t.Run("refused/"+name, func(t *testing.T) {
			if claims, err := run(t, reshape); err == nil {
				t.Fatalf("accepted: %+v", claims)
			}
		})
	}

	for name, reshape := range map[string]func(*etree.Element){
		"no Conditions expiry":                               noConditionsExpiry,
		"a second bearer confirmation for another recipient": otherRecipient(false),
		"a holder-of-key confirmation beside the bearer one": func(a *etree.Element) {
			subject := a.FindElement("./Subject")
			hok := subject.FindElement("./SubjectConfirmation").Copy()
			hok.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key")
			hok.RemoveChild(hok.FindElement("./SubjectConfirmationData"))
			subject.AddChild(hok)
		},
	} {
		t.Run("accepted/"+name, func(t *testing.T) {
			claims, err := run(t, reshape)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if claims.NameID != "alice@corp.test" {
				t.Fatalf("claims = %+v", claims)
			}
		})
	}
}
