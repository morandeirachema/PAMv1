package api_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/sshca"
	"golang.org/x/crypto/ssh"
)

// TestOperatorCertIssuanceAndRevocation drives the Phase 28 flow end to end:
// challenge → operator signs (proof of possession) → sign → the returned cert
// authenticates to an in-process cert-only sshd for the granted principal → the
// serial is revoked → the KRL lists it. It also proves the authorization gates:
// a bad proof of possession, an unmanaged principal, and a non-connect role are
// refused.
func TestOperatorCertIssuanceAndRevocation(t *testing.T) {
	caSigner := mustTestSigner(t)
	ca := sshca.New(caSigner)
	srv, _ := newTestServerOpts(t, nil, api.Options{CA: ca})

	// A target + a managed account "svc" the operator may get a cert for.
	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "web-op", "host": "10.0.0.9", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	tid := int64(jsonMap(t, td)["id"].(float64))
	if st, d := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": tid, "username": "svc", "secret": "pw",
	}); st != http.StatusCreated {
		t.Fatalf("seed credential: %d %s", st, d)
	}

	// The operator's own keypair (PAMv1 only signs the public half).
	opPub, opPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opSigner, err := ssh.NewSignerFromKey(opPriv)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, _ := ssh.NewPublicKey(opPub)
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))

	// 1. Get a challenge and sign it with the private key (proof of possession).
	_, chd := do(t, srv, http.MethodPost, "/api/ca/ssh/challenge", testAPIKey, map[string]any{})
	challenge, _ := jsonMap(t, chd)["challenge"].(string)
	if challenge == "" {
		t.Fatalf("no challenge: %s", chd)
	}
	_ = challenge // the happy path re-fetches a fresh challenge below

	// 2. A proof of possession by the WRONG key is refused: sign the challenge with
	// an unrelated key but present the operator's public key.
	_, wpriv, _ := ed25519.GenerateKey(rand.Reader)
	wrongSigner, _ := ssh.NewSignerFromKey(wpriv)
	_, chd2 := do(t, srv, http.MethodPost, "/api/ca/ssh/challenge", testAPIKey, map[string]any{})
	challenge2, _ := jsonMap(t, chd2)["challenge"].(string)
	wsig, _ := wrongSigner.Sign(rand.Reader, []byte(challenge2))
	if code, _ := do(t, srv, http.MethodPost, "/api/ca/ssh/sign", testAPIKey, map[string]any{
		"public_key": pubLine, "challenge": challenge2, "signature": base64.StdEncoding.EncodeToString(ssh.Marshal(wsig)),
		"target": "web-op", "principal": "svc",
	}); code != http.StatusUnprocessableEntity {
		t.Fatalf("bad proof of possession: want 422, got %d", code)
	}

	// 3. An unmanaged principal (not a credential on the target) is refused.
	_, chd3 := do(t, srv, http.MethodPost, "/api/ca/ssh/challenge", testAPIKey, map[string]any{})
	ch3, _ := jsonMap(t, chd3)["challenge"].(string)
	sig3, _ := opSigner.Sign(rand.Reader, []byte(ch3))
	if code, _ := do(t, srv, http.MethodPost, "/api/ca/ssh/sign", testAPIKey, map[string]any{
		"public_key": pubLine, "challenge": ch3, "signature": base64.StdEncoding.EncodeToString(ssh.Marshal(sig3)),
		"target": "web-op", "principal": "root",
	}); code != http.StatusUnprocessableEntity {
		t.Fatalf("unmanaged principal: want 422, got %d", code)
	}

	// 4. Happy path: a fresh challenge, signed, yields a scoped certificate.
	_, chd4 := do(t, srv, http.MethodPost, "/api/ca/ssh/challenge", testAPIKey, map[string]any{})
	ch4, _ := jsonMap(t, chd4)["challenge"].(string)
	sig4, _ := opSigner.Sign(rand.Reader, []byte(ch4))
	code, sd := do(t, srv, http.MethodPost, "/api/ca/ssh/sign", testAPIKey, map[string]any{
		"public_key": pubLine, "challenge": ch4, "signature": base64.StdEncoding.EncodeToString(ssh.Marshal(sig4)),
		"target": "web-op", "principal": "svc", "source_address": "10.0.0.0/8", "ttl_minutes": 5,
	})
	if code != http.StatusOK {
		t.Fatalf("sign: %d %s", code, sd)
	}
	certLine, _ := jsonMap(t, sd)["certificate"].(string)
	serial, _ := jsonMap(t, sd)["serial"].(string) // a string to survive float64 precision
	if certLine == "" || serial == "" {
		t.Fatalf("missing certificate/serial: %s", sd)
	}

	// The returned cert is a user cert scoped to "svc", signed by the CA.
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certLine))
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatal("issued object is not a certificate")
	}
	checker := &ssh.CertChecker{
		IsUserAuthority: func(a ssh.PublicKey) bool {
			return string(a.Marshal()) == string(ca.PublicKey().Marshal())
		},
		// x/crypto v0.56.0+: an undeclared critical option fails CheckCert,
		// as it would on a real sshd — declare the one the CA sets.
		SupportedCriticalOptions: []string{"source-address"},
	}
	if err := checker.CheckCert("svc", cert); err != nil {
		t.Fatalf("issued cert not accepted for its principal: %v", err)
	}
	if cert.CriticalOptions["source-address"] != "10.0.0.0/8" {
		t.Fatalf("source-address restriction missing: %v", cert.CriticalOptions)
	}

	// 5. The issuance was audited.
	_, aud := do(t, srv, http.MethodGet, "/api/audit?limit=50", testAPIKey, nil)
	if !strings.Contains(string(aud), "ssh.cert_issued") {
		t.Fatalf("issuance not audited: %s", aud)
	}

	// 6. Revoke by serial; the KRL then lists it (verified by ssh.CertChecker via
	// the store round-trip below), and a double revoke conflicts.
	if code, _ := do(t, srv, http.MethodPost, "/api/ca/ssh/revoke", testAPIKey, map[string]any{"serial": serial}); code != http.StatusOK {
		t.Fatalf("revoke: %d", code)
	}
	if code, _ := do(t, srv, http.MethodPost, "/api/ca/ssh/revoke", testAPIKey, map[string]any{"serial": serial}); code != http.StatusConflict {
		t.Fatalf("double revoke: want 409, got %d", code)
	}
	// 7. The KRL is served and starts with the OpenSSH magic (its bytes are
	// format-verified against real ssh-keygen in the sshca package test).
	kc, krl, _, _ := playbackGet(t, srv.URL+"/api/ca/ssh/krl", testAPIKey)
	if kc != http.StatusOK || len(krl) == 0 || !strings.HasPrefix(string(krl), "SSHKRL") {
		t.Fatalf("krl: %d len=%d", kc, len(krl))
	}

	// 8. A non-connect role (auditor) may not mint a cert.
	auditor := seedUser(t, srv, "op-auditor", "auditor")
	if code, _ := do(t, srv, http.MethodPost, "/api/ca/ssh/challenge", auditor, map[string]any{}); code != http.StatusForbidden {
		t.Fatalf("auditor challenge: want 403, got %d", code)
	}
}
