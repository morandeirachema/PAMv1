package sshca

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// testCA builds a CertAuthority backed by a fresh ed25519 key.
func testCA(t *testing.T) *CertAuthority {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return New(signer)
}

// TestIssueUserSignsValidCert proves a minted certificate is a user cert, signed
// by the CA, scoped to the requested principal, unexpired, and accepted by an
// ssh.CertChecker that trusts the CA — the exact check a ZSP-configured sshd runs.
func TestIssueUserSignsValidCert(t *testing.T) {
	ca := testCA(t)
	signer, cert, err := ca.IssueUser("root", 2*time.Minute, "pamv1:alice@web-01")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if cert.CertType != ssh.UserCert {
		t.Fatalf("cert type = %d, want UserCert", cert.CertType)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "root" {
		t.Fatalf("principals = %v, want [root]", cert.ValidPrincipals)
	}
	if cert.KeyId != "pamv1:alice@web-01" {
		t.Fatalf("key id = %q", cert.KeyId)
	}
	// The presented signer must carry the certificate (so the upstream sees a cert).
	if _, ok := signer.PublicKey().(*ssh.Certificate); !ok {
		t.Fatal("signer public key is not a certificate")
	}

	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return keysEqual(auth, ca.PublicKey())
		},
	}
	if err := checker.CheckCert("root", cert); err != nil {
		t.Fatalf("valid cert rejected by checker: %v", err)
	}
	// A different principal must be refused.
	if err := checker.CheckCert("admin", cert); err == nil {
		t.Fatal("cert accepted for a principal it was not issued for")
	}
}

// TestIssueUserSerialsAreUnique confirms successive certificates get distinct,
// increasing serials (audit correlation).
func TestIssueUserSerialsAreUnique(t *testing.T) {
	ca := testCA(t)
	_, c1, err := ca.IssueUser("root", time.Minute, "id1")
	if err != nil {
		t.Fatal(err)
	}
	_, c2, err := ca.IssueUser("root", time.Minute, "id2")
	if err != nil {
		t.Fatal(err)
	}
	if c2.Serial <= c1.Serial {
		t.Fatalf("serials not increasing: %d then %d", c1.Serial, c2.Serial)
	}
}

// TestIssueUserExpires proves a short-TTL certificate is rejected once its
// validity window has passed — the property that makes access non-standing. A
// certificate valid for one minute is checked against a clock an hour ahead.
func TestIssueUserExpires(t *testing.T) {
	ca := testCA(t)
	_, cert, err := ca.IssueUser("root", time.Minute, "id")
	if err != nil {
		t.Fatal(err)
	}
	future := &ssh.CertChecker{
		Clock:           func() time.Time { return time.Now().Add(time.Hour) },
		IsUserAuthority: func(auth ssh.PublicKey) bool { return keysEqual(auth, ca.PublicKey()) },
	}
	if err := future.CheckCert("root", cert); err == nil {
		t.Fatal("an expired certificate must be rejected")
	}
	// The same cert is accepted at the present time (sanity: it is only expiry).
	now := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool { return keysEqual(auth, ca.PublicKey()) },
	}
	if err := now.CheckCert("root", cert); err != nil {
		t.Fatalf("cert should be valid now: %v", err)
	}
}

// keysEqual compares two SSH public keys by their wire encoding.
func keysEqual(a, b ssh.PublicKey) bool {
	am, bm := a.Marshal(), b.Marshal()
	if len(am) != len(bm) {
		return false
	}
	for i := range am {
		if am[i] != bm[i] {
			return false
		}
	}
	return true
}

// TestIssueForKeyScopedCert proves an operator-supplied public key is signed into
// a user cert scoped to the requested principal with the source-address critical
// option, accepted by a CA-trusting checker for that principal only.
func TestIssueForKeyScopedCert(t *testing.T) {
	ca := testCA(t)
	// The operator's own key (PAMv1 never sees the private half beyond this test).
	opPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(opPub)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.IssueForKey(sshPub, IssueOpts{
		Principals: []string{"svc"}, TTL: 5 * time.Minute, KeyID: "pamv1:alice@web",
		SourceAddress: "10.0.0.0/8",
	})
	if err != nil {
		t.Fatalf("IssueForKey: %v", err)
	}
	if !keysEqual(cert.Key, sshPub) {
		t.Fatal("certificate does not certify the operator's key")
	}
	if cert.CriticalOptions["source-address"] != "10.0.0.0/8" {
		t.Fatalf("source-address not set: %v", cert.CriticalOptions)
	}
	checker := &ssh.CertChecker{IsUserAuthority: func(a ssh.PublicKey) bool { return keysEqual(a, ca.PublicKey()) }}
	if err := checker.CheckCert("svc", cert); err != nil {
		t.Fatalf("valid operator cert rejected: %v", err)
	}
	if err := checker.CheckCert("root", cert); err == nil {
		t.Fatal("operator cert accepted for an un-issued principal")
	}
	// An empty principal set is refused.
	if _, err := ca.IssueForKey(sshPub, IssueOpts{}); err == nil {
		t.Fatal("issuing with no principal must fail")
	}
}

// TestChallengeRoundTrip proves a proof-of-possession challenge verifies only for
// the CA that minted it and only while unexpired.
func TestChallengeRoundTrip(t *testing.T) {
	ca := testCA(t)
	ch := ca.MintChallenge(time.Minute)
	if !ca.VerifyChallenge(ch) {
		t.Fatal("fresh challenge did not verify")
	}
	// A different CA must not accept it (different derived MAC key).
	if testCA(t).VerifyChallenge(ch) {
		t.Fatal("challenge verified against a different CA")
	}
	// Tampered challenge is rejected.
	if ca.VerifyChallenge(ch + "x") {
		t.Fatal("tampered challenge verified")
	}
	// Expired challenge is rejected.
	if ca.VerifyChallenge(ca.MintChallenge(-time.Second)) {
		t.Fatal("expired challenge verified")
	}
}

// TestKRLRevokesViaSSHKeygen verifies the generated KRL against the real OpenSSH
// tool: a cert whose serial is revoked is reported revoked by `ssh-keygen -Q`,
// and a cert not in the KRL is not. Skipped when ssh-keygen is unavailable
// (the KRL byte format is what an operator installs as sshd RevokedKeys, so the
// honest verification is against OpenSSH itself).
func TestKRLRevokesViaSSHKeygen(t *testing.T) {
	kg, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not available; KRL is verified against OpenSSH in CI")
	}
	ca := testCA(t)
	opPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(opPub)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.IssueForKey(sshPub, IssueOpts{Principals: []string{"svc"}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "id-cert.pub")
	if err := os.WriteFile(certPath, ssh.MarshalAuthorizedKey(cert), 0o600); err != nil {
		t.Fatal(err)
	}

	// A KRL revoking the cert's serial: ssh-keygen -Q reports it revoked (non-zero).
	revoking := filepath.Join(dir, "revoking.krl")
	if err := os.WriteFile(revoking, ca.KRL([]uint64{cert.Serial}, 1, time.Now()), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(kg, "-Q", "-f", revoking, certPath).CombinedOutput() // #nosec G204 -- kg is ssh-keygen from LookPath; paths are test temp files
	if err == nil {
		t.Fatalf("ssh-keygen accepted a revoked cert (want non-zero): %s", out)
	}
	if !strings.Contains(strings.ToLower(string(out)), "revoked") {
		t.Fatalf("ssh-keygen output did not report revocation: %s", out)
	}

	// A KRL revoking a DIFFERENT serial: the cert is not revoked (exit 0).
	other := filepath.Join(dir, "other.krl")
	if err := os.WriteFile(other, ca.KRL([]uint64{cert.Serial + 1}, 2, time.Now()), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(kg, "-Q", "-f", other, certPath).CombinedOutput(); err != nil { // #nosec G204 -- ssh-keygen on test temp files
		t.Fatalf("ssh-keygen reported a non-revoked cert as revoked: %s (%v)", out, err)
	}
}
