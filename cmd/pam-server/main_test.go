package main

// These tests close the last test gap SECURITY-GAPS.md recorded: the wiring
// layer itself. Every other package proves its own behavior; what was unproven
// was the startup path that assembles them — key custody, the fail-closed
// deny-file handling, listener wiring, and the utility flags. The style is the
// repo's usual one: no mocks on the security-critical path. run() is started
// for real (in-memory store, loopback listeners on ephemeral ports) and shut
// down with a real SIGTERM, and every fail-closed startup error is triggered
// through the environment exactly as a misconfigured deployment would hit it.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/config"
	"github.com/morandeirachema/pamv1/internal/shamir"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/store/pgstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// discardLogger returns a logger that swallows everything, for the build*
// helpers that want a *slog.Logger but whose log lines are not under test.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// mustMasterKey generates a real vault master key (32 bytes, urlsafe base64),
// failing the test rather than returning an error.
func mustMasterKey(t *testing.T) string {
	t.Helper()
	key, err := vault.GenerateMasterKey()
	if err != nil {
		t.Fatalf("generate master key: %v", err)
	}
	return key
}

// clearPAMEnv blanks every PAM_* variable inherited from the environment, so a
// developer's shell (which may export PAM_MASTER_KEY and friends for the local
// demo) cannot leak configuration into a test. config.Load treats an empty
// value as unset, so blanking is equivalent to unsetting; t.Setenv restores the
// original values when the test ends.
func clearPAMEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		if name, _, ok := strings.Cut(kv, "="); ok && strings.HasPrefix(name, "PAM_") {
			t.Setenv(name, "")
		}
	}
}

// setMinimalEnv gives run() the smallest environment that starts: a real master
// key, an API key long enough for any store, the in-memory store, a temp
// recording dir (so no `recordings/` directory is created in the source tree),
// and both proxies off. Tests override individual variables on top.
func setMinimalEnv(t *testing.T) {
	t.Helper()
	clearPAMEnv(t)
	t.Setenv("PAM_MASTER_KEY", mustMasterKey(t))
	t.Setenv("PAM_API_KEY", "test-api-key-0123456789abcdef")
	t.Setenv("PAM_DATABASE_URL", "memory")
	t.Setenv("PAM_RECORDING_DIR", t.TempDir())
	t.Setenv("PAM_SSH_ADDR", "off")
	t.Setenv("PAM_DB_ADDR", "off")
	t.Setenv("PAM_MSSQL_ADDR", "off")
}

// captureStdout runs f with os.Stdout redirected into a pipe and returns what
// it printed. The helpers under test print with fmt.Println, which writes to
// the process-global os.Stdout, so swapping the variable is the only seam.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	f()
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	return string(out)
}

// stdinFrom makes os.Stdin read the given string for the rest of the test, for
// the flags (-hashkey, -split-key) that consume an emergency key from stdin.
func stdinFrom(t *testing.T, s string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if _, err := w.WriteString(s); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close stdin writer: %v", err)
	}
	orig := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = orig })
}

// freeAddr reserves and immediately releases an ephemeral loopback port,
// returning "127.0.0.1:N" for a listener the test wants run() itself to bind.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release port: %v", err)
	}
	return addr
}

// heldAddr binds an ephemeral loopback port and keeps it bound for the whole
// test, so pointing run() at it produces a deterministic bind failure.
func heldAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hold port: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

// writeTemp writes content to name under a fresh temp dir and returns its path.
func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// b64Bytes returns n random bytes in standard base64 — the encoding
// PAM_AUDIT_HMAC_KEY, PAM_AUDIT_SIGN_SEED and the broker key variables expect.
func b64Bytes(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// minimalPolicy is the smallest broker policy file internal/policy accepts.
const minimalPolicy = "rules:\n  - id: r1\n    effect: allow\n"

// selfSignedCert writes a throwaway self-signed certificate and key for
// 127.0.0.1 and returns their paths, for the native-TLS serving branch.
func selfSignedCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "tls.crt")
	keyPath = filepath.Join(dir, "tls.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// TestBuildInfo pins the default build identity: a binary compiled without the
// release ldflags must report "dev (none)" — the honest answer for a
// self-compiled build — rather than something that looks released.
func TestBuildInfo(t *testing.T) {
	if got := buildInfo(); got != "dev (none)" {
		t.Fatalf("buildInfo() = %q, want %q", got, "dev (none)")
	}
}

// TestSplitAndTrim checks the comma-list helper used for allowed protocols and
// alert recipients: whitespace is trimmed and empty entries vanish, so a
// trailing comma in an env var cannot smuggle an empty "allowed protocol" in.
func TestSplitAndTrim(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{" , , ", nil},
		{"ssh", []string{"ssh"}},
		{" ssh , rdp ,,winrm ", []string{"ssh", "rdp", "winrm"}},
	}
	for _, c := range cases {
		got := splitAndTrim(c.in)
		if len(got) != len(c.want) {
			t.Fatalf("splitAndTrim(%q) = %v, want %v", c.in, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("splitAndTrim(%q) = %v, want %v", c.in, got, c.want)
			}
		}
	}
}

// TestGetenvInt checks the tolerant integer reader behind the Shamir share
// counts: unset and unparsable values fall back to the default instead of
// failing, because -split-key runs interactively where a loud default beats a
// refusal.
func TestGetenvInt(t *testing.T) {
	t.Setenv("PAM_TEST_GETENV_INT", "")
	if got := getenvInt("PAM_TEST_GETENV_INT", 5); got != 5 {
		t.Fatalf("unset: got %d, want 5", got)
	}
	t.Setenv("PAM_TEST_GETENV_INT", "7")
	if got := getenvInt("PAM_TEST_GETENV_INT", 5); got != 7 {
		t.Fatalf("set: got %d, want 7", got)
	}
	t.Setenv("PAM_TEST_GETENV_INT", "seven")
	if got := getenvInt("PAM_TEST_GETENV_INT", 5); got != 5 {
		t.Fatalf("unparsable: got %d, want 5", got)
	}
}

// TestRoleMap checks the group→role mapping builder shared by the LDAP, Entra
// and OIDC wiring: keys are lower-cased (directory names are case-insensitive)
// and empty slots are skipped rather than mapped.
func TestRoleMap(t *testing.T) {
	m := roleMap("CN=Admins,DC=x", "", "Auditors", "approvers")
	if len(m) != 3 {
		t.Fatalf("got %d entries, want 3: %v", len(m), m)
	}
	if _, ok := m["cn=admins,dc=x"]; !ok {
		t.Fatalf("admin key not lower-cased: %v", m)
	}
	if _, ok := m[""]; ok {
		t.Fatalf("empty slot must not be mapped: %v", m)
	}
}

// TestParseEd25519PubKeys checks the rotated-out checkpoint-signer list parser:
// well-formed keys (with sloppy spacing) decode, empty input means no keys, and
// anything that is not exactly a 32-byte base64 key is refused loudly — a
// silently dropped verifier key would un-verify old audit checkpoints.
func TestParseEd25519PubKeys(t *testing.T) {
	k1, k2 := b64Bytes(t, 32), b64Bytes(t, 32)
	keys, err := parseEd25519PubKeys(" " + k1 + " , " + k2 + " ,")
	if err != nil || len(keys) != 2 {
		t.Fatalf("valid list: keys=%d err=%v", len(keys), err)
	}
	if keys, err := parseEd25519PubKeys(""); err != nil || keys != nil {
		t.Fatalf("empty: keys=%v err=%v", keys, err)
	}
	if _, err := parseEd25519PubKeys("!!!not-base64!!!"); err == nil {
		t.Fatal("bad base64 accepted")
	}
	if _, err := parseEd25519PubKeys(b64Bytes(t, 16)); err == nil {
		t.Fatal("16-byte key accepted; ed25519 public keys are 32 bytes")
	}
}

// TestKekOptionsFromEnv checks that the "" and "NEW_" prefixes read disjoint
// variable sets — the property the whole -rotate-kek workflow rests on, since
// both KEKs are configured side by side in one environment.
func TestKekOptionsFromEnv(t *testing.T) {
	clearPAMEnv(t)
	t.Setenv("PAM_MASTER_KEY", "current-key")
	t.Setenv("PAM_NEW_MASTER_KEY", "new-key")
	t.Setenv("PAM_NEW_KEK_PROVIDER", "vault-transit")
	t.Setenv("PAM_NEW_KEK_TRANSIT_ADDR", "https://vault.example")

	cur := kekOptionsFromEnv("")
	if cur.Provider != "local" || cur.MasterKey != "current-key" {
		t.Fatalf("current KEK options: %+v", cur)
	}
	next := kekOptionsFromEnv("NEW_")
	if next.Provider != "vault-transit" || next.MasterKey != "new-key" || next.TransitAddr != "https://vault.example" {
		t.Fatalf("new KEK options: %+v", next)
	}
}

// TestBuildBroker checks the broker assembly: disabled cleanly when no policy
// file is configured, fail-loud on a bad policy or malformed audit keys (a
// broker that started without its verifiable-audit keys would defeat the point
// of having them), fully wired on explicit env values, and — when the keys are
// not set — resolved from shared custody so every replica converges on ONE
// chain key and ONE signer identity instead of each inventing its own.
func TestBuildBroker(t *testing.T) {
	ctx := context.Background()
	log := discardLogger()
	newVault := func(t *testing.T) *vault.Vault {
		t.Helper()
		v, err := vault.New(mustMasterKey(t))
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	t.Run("disabled", func(t *testing.T) {
		engine, key, signer, err := buildBroker(ctx, memstore.New(), newVault(t), &config.Config{}, log)
		if engine != nil || key != nil || signer != nil || err != nil {
			t.Fatalf("want all nil when no policy file, got %v %v %v %v", engine, key, signer, err)
		}
	})
	t.Run("policy file missing", func(t *testing.T) {
		cfg := &config.Config{BrokerPolicyFile: filepath.Join(t.TempDir(), "nope.yaml")}
		if _, _, _, err := buildBroker(ctx, memstore.New(), newVault(t), cfg, log); err == nil {
			t.Fatal("missing policy file accepted")
		}
	})
	t.Run("bad audit key", func(t *testing.T) {
		cfg := &config.Config{
			BrokerPolicyFile: writeTemp(t, "policy.yaml", minimalPolicy),
			BrokerAuditKey:   b64Bytes(t, 8), // wrong size
		}
		_, _, _, err := buildBroker(ctx, memstore.New(), newVault(t), cfg, log)
		if err == nil || !strings.Contains(err.Error(), "PAM_BROKER_AUDIT_KEY") {
			t.Fatalf("want audit-key size error, got %v", err)
		}
	})
	t.Run("bad sign seed", func(t *testing.T) {
		cfg := &config.Config{
			BrokerPolicyFile:    writeTemp(t, "policy.yaml", minimalPolicy),
			BrokerAuditKey:      b64Bytes(t, 32),
			BrokerAuditSignSeed: "not-base64!!!",
		}
		_, _, _, err := buildBroker(ctx, memstore.New(), newVault(t), cfg, log)
		if err == nil || !strings.Contains(err.Error(), "PAM_BROKER_AUDIT_SIGN_SEED") {
			t.Fatalf("want sign-seed error, got %v", err)
		}
	})
	t.Run("valid env values", func(t *testing.T) {
		cfg := &config.Config{
			BrokerPolicyFile:    writeTemp(t, "policy.yaml", minimalPolicy),
			BrokerAuditKey:      b64Bytes(t, 32),
			BrokerAuditSignSeed: b64Bytes(t, 32),
		}
		engine, key, signer, err := buildBroker(ctx, memstore.New(), newVault(t), cfg, log)
		if err != nil {
			t.Fatalf("valid broker config rejected: %v", err)
		}
		if engine == nil || len(key) != 32 || signer == nil {
			t.Fatalf("incomplete broker wiring: engine=%v keylen=%d signer=%v", engine, len(key), signer)
		}
	})
	t.Run("unset keys come from shared custody and converge", func(t *testing.T) {
		st, v := memstore.New(), newVault(t)
		cfg := &config.Config{BrokerPolicyFile: writeTemp(t, "policy.yaml", minimalPolicy)}
		engine, key1, signer1, err := buildBroker(ctx, st, v, cfg, log)
		if err != nil {
			t.Fatalf("custody path failed: %v", err)
		}
		if engine == nil || len(key1) != 32 || signer1 == nil {
			t.Fatalf("incomplete custody wiring: engine=%v keylen=%d signer=%v", engine, len(key1), signer1)
		}
		// A second resolution against the SAME store — another replica, or a
		// restart — must yield the identical chain key and signer identity;
		// divergence would make honest events read as tampering.
		_, key2, signer2, err := buildBroker(ctx, st, v, cfg, log)
		if err != nil {
			t.Fatalf("second custody resolution failed: %v", err)
		}
		if string(key1) != string(key2) || !signer1.Equal(signer2) {
			t.Fatal("two replicas resolved different broker audit keys from one store")
		}
		// A different store is a different deployment: keys must differ.
		_, key3, _, err := buildBroker(ctx, memstore.New(), v, cfg, log)
		if err != nil {
			t.Fatalf("fresh-store custody failed: %v", err)
		}
		if string(key1) == string(key3) {
			t.Fatal("two independent deployments generated the same chain key")
		}
	})
	t.Run("env key with custody seed mixes", func(t *testing.T) {
		envKey := b64Bytes(t, 32)
		cfg := &config.Config{
			BrokerPolicyFile: writeTemp(t, "policy.yaml", minimalPolicy),
			BrokerAuditKey:   envKey,
		}
		_, key, signer, err := buildBroker(ctx, memstore.New(), newVault(t), cfg, log)
		if err != nil {
			t.Fatalf("mixed sources rejected: %v", err)
		}
		if base64.StdEncoding.EncodeToString(key) != envKey {
			t.Fatal("explicit env HMAC key was not honored over custody")
		}
		if signer == nil {
			t.Fatal("custody seed did not produce a signer")
		}
	})
	t.Run("env values seed custody so unsetting them cannot fork the chain", func(t *testing.T) {
		st, v := memstore.New(), newVault(t)
		cfg := &config.Config{
			BrokerPolicyFile:    writeTemp(t, "policy.yaml", minimalPolicy),
			BrokerAuditKey:      b64Bytes(t, 32),
			BrokerAuditSignSeed: b64Bytes(t, 32),
		}
		_, key1, signer1, err := buildBroker(ctx, st, v, cfg, log)
		if err != nil {
			t.Fatalf("env boot failed: %v", err)
		}
		// The same store without the env values — the upgrade path that used to
		// fork the chain — must resolve the identical key and signer from the
		// custody rows the first boot wrote through.
		bare := &config.Config{BrokerPolicyFile: cfg.BrokerPolicyFile}
		_, key2, signer2, err := buildBroker(ctx, st, v, bare, log)
		if err != nil {
			t.Fatalf("custody boot after env boot failed: %v", err)
		}
		if string(key1) != string(key2) || !signer1.Equal(signer2) {
			t.Fatal("unsetting the env keys resolved a different key: the chain would fork")
		}
	})
	t.Run("explicit HMAC key that disagrees with custody is fatal", func(t *testing.T) {
		st, v := memstore.New(), newVault(t)
		cfg := &config.Config{BrokerPolicyFile: writeTemp(t, "policy.yaml", minimalPolicy)}
		if _, _, _, err := buildBroker(ctx, st, v, cfg, log); err != nil { // custody generates both keys
			t.Fatalf("custody boot failed: %v", err)
		}
		cfg.BrokerAuditKey = b64Bytes(t, 32) // different from what custody holds
		_, _, _, err := buildBroker(ctx, st, v, cfg, log)
		if err == nil || !strings.Contains(err.Error(), "refusing to fork") {
			t.Fatalf("mismatched explicit HMAC key accepted: %v", err)
		}
	})
	t.Run("explicit sign seed rotates custody instead of resurrecting later", func(t *testing.T) {
		st, v := memstore.New(), newVault(t)
		cfg := &config.Config{BrokerPolicyFile: writeTemp(t, "policy.yaml", minimalPolicy)}
		_, _, signer0, err := buildBroker(ctx, st, v, cfg, log) // custody-held seed
		if err != nil {
			t.Fatal(err)
		}
		cfg.BrokerAuditSignSeed = b64Bytes(t, 32)
		_, _, signer1, err := buildBroker(ctx, st, v, cfg, log) // the documented rotation
		if err != nil {
			t.Fatalf("sign-seed rotation refused: %v", err)
		}
		if signer1.Equal(signer0) {
			t.Fatal("rotation did not change the signer")
		}
		cfg.BrokerAuditSignSeed = "" // variable dropped after the rotation
		_, _, signer2, err := buildBroker(ctx, st, v, cfg, log)
		if err != nil {
			t.Fatalf("custody boot after rotation failed: %v", err)
		}
		if !signer2.Equal(signer1) {
			t.Fatal("custody resurrected the rotated-out signer")
		}
	})
}

// TestBuildAlerter checks the alert fan-out assembly, and above all the
// air-gap rule: with PAM_OT_AIRGAP set every outbound channel must collapse to
// the no-op notifier no matter what else is configured.
func TestBuildAlerter(t *testing.T) {
	log := discardLogger()
	isNoop := func(n alert.Notifier) bool { _, ok := n.(alert.Noop); return ok }
	t.Run("air-gap wins over configured channels", func(t *testing.T) {
		if got := buildAlerter(&config.Config{AirGap: true, AlertWebhook: "https://hook.example"}, log); !isNoop(got) {
			t.Fatalf("air-gap still built an outbound alerter: %T", got)
		}
	})
	t.Run("none configured", func(t *testing.T) {
		if got := buildAlerter(&config.Config{}, log); !isNoop(got) {
			t.Fatalf("no channels configured but got %T", got)
		}
	})
	t.Run("single webhook plus plain-http warning", func(t *testing.T) {
		if got := buildAlerter(&config.Config{AlertWebhook: "http://hooks.example/x"}, log); isNoop(got) {
			t.Fatal("webhook config produced the no-op alerter")
		}
	})
	t.Run("syslog with scheme prefix", func(t *testing.T) {
		if got := buildAlerter(&config.Config{AlertSyslog: "tcp://siem.example:6514"}, log); isNoop(got) {
			t.Fatal("syslog config produced the no-op alerter")
		}
	})
	t.Run("partial email is dropped", func(t *testing.T) {
		got := buildAlerter(&config.Config{AlertEmailSMTP: "smtp.example:587", AlertEmailFrom: "pam@example"}, log)
		if !isNoop(got) {
			t.Fatalf("email without recipients still built a channel: %T", got)
		}
	})
	t.Run("multiple channels fan out", func(t *testing.T) {
		cfg := &config.Config{
			AlertWebhook:   "https://hooks.example/x",
			AlertSyslog:    "udp://siem.example:514",
			AlertEmailSMTP: "smtp.example:587", AlertEmailFrom: "pam@example", AlertEmailTo: "a@example, b@example",
		}
		if got := buildAlerter(cfg, log); isNoop(got) {
			t.Fatal("three channels produced the no-op alerter")
		}
	})
}

// TestBuildAuthenticator checks the password identity-source assembly: none
// configured yields a nil chain (password login off), a misconfigured source is
// fail-loud, and LDAP doubles as the directory source for reconciliation.
func TestBuildAuthenticator(t *testing.T) {
	log := discardLogger()
	t.Run("none", func(t *testing.T) {
		authn, dir, err := buildAuthenticator(&config.Config{}, log)
		if authn != nil || dir != nil || err != nil {
			t.Fatalf("want all nil, got %v %v %v", authn, dir, err)
		}
	})
	t.Run("ldap requires ldaps", func(t *testing.T) {
		_, _, err := buildAuthenticator(&config.Config{LDAPURL: "ldap://dc.example"}, log)
		if err == nil || !strings.Contains(err.Error(), "ldap") {
			t.Fatalf("plaintext LDAP accepted: %v", err)
		}
	})
	t.Run("entra incomplete", func(t *testing.T) {
		_, _, err := buildAuthenticator(&config.Config{EntraTenantID: "tenant"}, log)
		if err == nil || !strings.Contains(err.Error(), "entra") {
			t.Fatalf("tenant without client id accepted: %v", err)
		}
	})
	t.Run("ldap and entra wired", func(t *testing.T) {
		cfg := &config.Config{
			LDAPURL: "ldaps://dc.example", LDAPBaseDN: "dc=example,dc=org", LDAPGroupAdmin: "cn=admins",
			EntraTenantID: "tenant", EntraClientID: "client", EntraClientSecret: "secret", EntraRoleAdmin: "pam-admins",
		}
		authn, dir, err := buildAuthenticator(cfg, log)
		if err != nil {
			t.Fatalf("valid config rejected: %v", err)
		}
		if authn == nil {
			t.Fatal("no authenticator chain built")
		}
		if dir == nil {
			t.Fatal("LDAP did not become the directory source")
		}
	})
}

// TestBuildOIDC checks the SSO provider assembly: off when no issuer, explicit
// endpoints skip discovery entirely, discovery is used (and its failure is
// fatal) when endpoints are not given, and provider validation still applies.
func TestBuildOIDC(t *testing.T) {
	ctx := context.Background()
	log := discardLogger()
	t.Run("disabled", func(t *testing.T) {
		p, err := buildOIDC(ctx, &config.Config{}, log)
		if p != nil || err != nil {
			t.Fatalf("want nil,nil, got %v %v", p, err)
		}
	})
	t.Run("explicit endpoints", func(t *testing.T) {
		cfg := &config.Config{
			OIDCIssuer: "https://idp.example", OIDCClientID: "pam", OIDCRedirectURL: "https://pam.example/cb",
			OIDCAuthURL: "https://idp.example/a", OIDCTokenURL: "https://idp.example/t", OIDCJWKSURL: "https://idp.example/j",
			OIDCScopes: "openid profile",
		}
		p, err := buildOIDC(ctx, cfg, log)
		if err != nil || p == nil {
			t.Fatalf("explicit endpoints rejected: %v %v", p, err)
		}
	})
	t.Run("discovery", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"authorization_endpoint":"https://idp.example/a","token_endpoint":"https://idp.example/t","jwks_uri":"https://idp.example/j"}`))
		})
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		cfg := &config.Config{OIDCIssuer: srv.URL, OIDCClientID: "pam", OIDCRedirectURL: "https://pam.example/cb"}
		p, err := buildOIDC(ctx, cfg, log)
		if err != nil || p == nil {
			t.Fatalf("discovery path failed: %v %v", p, err)
		}
	})
	t.Run("discovery unreachable", func(t *testing.T) {
		cfg := &config.Config{OIDCIssuer: "http://127.0.0.1:1", OIDCClientID: "pam", OIDCRedirectURL: "https://pam.example/cb"}
		_, err := buildOIDC(ctx, cfg, log)
		if err == nil || !strings.Contains(err.Error(), "oidc discovery") {
			t.Fatalf("want discovery error, got %v", err)
		}
	})
	t.Run("missing client id", func(t *testing.T) {
		cfg := &config.Config{
			OIDCIssuer:  "https://idp.example",
			OIDCAuthURL: "https://idp.example/a", OIDCTokenURL: "https://idp.example/t", OIDCJWKSURL: "https://idp.example/j",
		}
		_, err := buildOIDC(ctx, cfg, log)
		if err == nil || !strings.Contains(err.Error(), "is required") {
			t.Fatalf("want validation error, got %v", err)
		}
	})
}

// TestRunHealthcheck exercises the container liveness probe against real HTTP
// servers: plain HTTP, the all-interfaces→loopback rewrite, the HTTPS switch
// (taken purely from the TLS env vars, since the probe authenticates nothing),
// and each failure mode a broken deployment would produce.
func TestRunHealthcheck(t *testing.T) {
	healthz := func(code int) http.Handler {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) })
		return mux
	}
	t.Run("ok", func(t *testing.T) {
		clearPAMEnv(t)
		srv := httptest.NewServer(healthz(http.StatusOK))
		t.Cleanup(srv.Close)
		t.Setenv("PAM_LISTEN_ADDR", strings.TrimPrefix(srv.URL, "http://"))
		if err := runHealthcheck(); err != nil {
			t.Fatalf("healthy server reported unhealthy: %v", err)
		}
	})
	t.Run("all-interfaces bind probes loopback", func(t *testing.T) {
		clearPAMEnv(t)
		srv := httptest.NewServer(healthz(http.StatusOK))
		t.Cleanup(srv.Close)
		_, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
		if err != nil {
			t.Fatalf("split host port: %v", err)
		}
		t.Setenv("PAM_LISTEN_ADDR", "0.0.0.0:"+port)
		if err := runHealthcheck(); err != nil {
			t.Fatalf("0.0.0.0 bind not rewritten to loopback: %v", err)
		}
	})
	t.Run("non-200", func(t *testing.T) {
		clearPAMEnv(t)
		srv := httptest.NewServer(healthz(http.StatusInternalServerError))
		t.Cleanup(srv.Close)
		t.Setenv("PAM_LISTEN_ADDR", strings.TrimPrefix(srv.URL, "http://"))
		err := runHealthcheck()
		if err == nil || !strings.Contains(err.Error(), "healthz returned 500") {
			t.Fatalf("want 500 error, got %v", err)
		}
	})
	t.Run("bad addr", func(t *testing.T) {
		clearPAMEnv(t)
		t.Setenv("PAM_LISTEN_ADDR", "no-port-here")
		if err := runHealthcheck(); err == nil {
			t.Fatal("unparsable PAM_LISTEN_ADDR accepted")
		}
	})
	t.Run("connection refused", func(t *testing.T) {
		clearPAMEnv(t)
		t.Setenv("PAM_LISTEN_ADDR", "127.0.0.1:1")
		if err := runHealthcheck(); err == nil {
			t.Fatal("dead server reported healthy")
		}
	})
	t.Run("https when TLS configured", func(t *testing.T) {
		clearPAMEnv(t)
		srv := httptest.NewTLSServer(healthz(http.StatusOK))
		t.Cleanup(srv.Close)
		t.Setenv("PAM_LISTEN_ADDR", strings.TrimPrefix(srv.URL, "https://"))
		// The probe switches scheme on the presence of the variables alone —
		// it never reads the files — so placeholder paths are enough.
		t.Setenv("PAM_TLS_CERT", "present")
		t.Setenv("PAM_TLS_KEY", "present")
		if err := runHealthcheck(); err != nil {
			t.Fatalf("TLS server reported unhealthy: %v", err)
		}
	})
}

// TestRunGenKey proves -genkey emits a usable master key: urlsafe base64
// decoding to exactly 32 bytes — the format vault.NewLocalKEK requires.
func TestRunGenKey(t *testing.T) {
	out := captureStdout(t, func() {
		if err := runGenKey(); err != nil {
			t.Errorf("runGenKey: %v", err)
		}
	})
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(out))
	if err != nil || len(raw) != 32 {
		t.Fatalf("emitted key %q is not 32 urlsafe-base64 bytes (err=%v)", strings.TrimSpace(out), err)
	}
}

// TestRunHashKey proves -hashkey emits exactly the SHA-256 the server expects
// in PAM_BREAK_GLASS_KEY_HASH (whitespace-trimmed input), and refuses an empty
// stdin — hashing "" would mint a valid-looking but unusable break-glass hash.
func TestRunHashKey(t *testing.T) {
	t.Run("empty stdin refused", func(t *testing.T) {
		stdinFrom(t, "  \n")
		if err := runHashKey(); err == nil || !strings.Contains(err.Error(), "no key on stdin") {
			t.Fatalf("want empty-stdin refusal, got %v", err)
		}
	})
	t.Run("hashes trimmed key", func(t *testing.T) {
		stdinFrom(t, "  emergency-key-42\n")
		out := captureStdout(t, func() {
			if err := runHashKey(); err != nil {
				t.Errorf("runHashKey: %v", err)
			}
		})
		sum := sha256.Sum256([]byte("emergency-key-42"))
		if got := strings.TrimSpace(out); got != hex.EncodeToString(sum[:]) {
			t.Fatalf("hash mismatch: got %s", got)
		}
	})
}

// TestRunSplitKey proves -split-key emits shares that actually reconstruct the
// key (any threshold-sized subset), honors the share-count variables, and
// refuses impossible geometry and empty input.
func TestRunSplitKey(t *testing.T) {
	t.Run("empty stdin refused", func(t *testing.T) {
		clearPAMEnv(t)
		stdinFrom(t, "")
		if err := runSplitKey(); err == nil || !strings.Contains(err.Error(), "no key on stdin") {
			t.Fatalf("want empty-stdin refusal, got %v", err)
		}
	})
	t.Run("default 5 shares reconstruct with any 3", func(t *testing.T) {
		clearPAMEnv(t)
		stdinFrom(t, "the-sealed-emergency-key\n")
		out := captureStdout(t, func() {
			if err := runSplitKey(); err != nil {
				t.Errorf("runSplitKey: %v", err)
			}
		})
		lines := strings.Fields(strings.TrimSpace(out))
		if len(lines) != 5 {
			t.Fatalf("got %d shares, want 5:\n%s", len(lines), out)
		}
		shares := make([][]byte, 3)
		for i := range shares {
			raw, err := hex.DecodeString(lines[i])
			if err != nil {
				t.Fatalf("share %d is not hex: %v", i, err)
			}
			shares[i] = raw
		}
		key, err := shamir.Combine(shares)
		if err != nil || string(key) != "the-sealed-emergency-key" {
			t.Fatalf("3 shares did not reconstruct the key: %q %v", key, err)
		}
	})
	t.Run("share count from env", func(t *testing.T) {
		clearPAMEnv(t)
		t.Setenv("PAM_BREAK_GLASS_SHARES", "3")
		t.Setenv("PAM_BREAK_GLASS_THRESHOLD", "2")
		stdinFrom(t, "k\n")
		out := captureStdout(t, func() {
			if err := runSplitKey(); err != nil {
				t.Errorf("runSplitKey: %v", err)
			}
		})
		if lines := strings.Fields(strings.TrimSpace(out)); len(lines) != 3 {
			t.Fatalf("got %d shares, want 3", len(lines))
		}
	})
	t.Run("threshold above share count refused", func(t *testing.T) {
		clearPAMEnv(t)
		t.Setenv("PAM_BREAK_GLASS_SHARES", "2")
		t.Setenv("PAM_BREAK_GLASS_THRESHOLD", "3")
		stdinFrom(t, "k\n")
		if err := runSplitKey(); err == nil {
			t.Fatal("2 shares with threshold 3 accepted")
		}
	})
}

// TestWarnSealedRecordings checks the -rotate-kek retention warning: it must
// fire exactly when sealed recordings exist (their data key is wrapped by the
// old KEK inside the file) and stay silent otherwise — including when the
// recordings directory does not exist yet.
func TestWarnSealedRecordings(t *testing.T) {
	t.Run("no dir configured", func(t *testing.T) {
		if out := captureStdout(t, func() { warnSealedRecordings("", "kek-a") }); out != "" {
			t.Fatalf("unexpected output: %q", out)
		}
	})
	t.Run("dir missing", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "never-created")
		if out := captureStdout(t, func() { warnSealedRecordings(dir, "kek-a") }); out != "" {
			t.Fatalf("unexpected output: %q", out)
		}
	})
	t.Run("counts only sealed files", func(t *testing.T) {
		dir := t.TempDir()
		// A sealed recording starts with the 9-byte magic "#pamrec1 "; a plain
		// asciicast does not; subdirectories are skipped.
		if err := os.WriteFile(filepath.Join(dir, "sealed.cast"), []byte("#pamrec1 wrapped-key\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "plain.cast"), []byte(`{"version": 2}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(dir, "archive"), 0o700); err != nil {
			t.Fatal(err)
		}
		out := captureStdout(t, func() { warnSealedRecordings(dir, "kek-old") })
		if !strings.Contains(out, "1 sealed recording(s)") || !strings.Contains(out, "kek-old") {
			t.Fatalf("warning missing or wrong:\n%s", out)
		}
	})
	t.Run("silent when none sealed", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "plain.cast"), []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
		if out := captureStdout(t, func() { warnSealedRecordings(dir, "kek-a") }); out != "" {
			t.Fatalf("unexpected output: %q", out)
		}
	})
}

// TestApplyStoredConfig checks the Phase-12 overlay of DB-persisted settings:
// plain values apply, secret values decrypt through the vault with the
// config AAD, and both a broken ciphertext and a malformed value are fatal —
// silently skipping a stored setting would make the portal lie about config.
func TestApplyStoredConfig(t *testing.T) {
	ctx := context.Background()
	newFixture := func(t *testing.T) (*memstore.Memstore, *vault.Vault, *config.Config) {
		st := memstore.New()
		v, err := vault.New(mustMasterKey(t))
		if err != nil {
			t.Fatalf("vault: %v", err)
		}
		return st, v, &config.Config{}
	}
	t.Run("no settings is a no-op", func(t *testing.T) {
		st, v, cfg := newFixture(t)
		if err := applyStoredConfig(ctx, st, v, cfg, discardLogger()); err != nil {
			t.Fatalf("empty store: %v", err)
		}
	})
	t.Run("plain and secret settings apply", func(t *testing.T) {
		st, v, cfg := newFixture(t)
		if err := st.PutSetting(ctx, &store.Setting{Key: "PAM_MFA_REQUIRED", Value: "true"}); err != nil {
			t.Fatal(err)
		}
		enc, err := v.Encrypt(ctx, "bind-secret", store.ConfigAAD("PAM_LDAP_BIND_PASSWORD"))
		if err != nil {
			t.Fatal(err)
		}
		if err := st.PutSetting(ctx, &store.Setting{Key: "PAM_LDAP_BIND_PASSWORD", Value: enc, Secret: true}); err != nil {
			t.Fatal(err)
		}
		if err := applyStoredConfig(ctx, st, v, cfg, discardLogger()); err != nil {
			t.Fatalf("apply: %v", err)
		}
		if !cfg.MFARequired {
			t.Fatal("plain setting not applied")
		}
		if cfg.LDAPBindPassword != "bind-secret" {
			t.Fatal("secret setting not decrypted into config")
		}
	})
	t.Run("undecryptable secret is fatal", func(t *testing.T) {
		st, v, cfg := newFixture(t)
		if err := st.PutSetting(ctx, &store.Setting{Key: "PAM_LDAP_BIND_PASSWORD", Value: "v2:not-a-real-token", Secret: true}); err != nil {
			t.Fatal(err)
		}
		err := applyStoredConfig(ctx, st, v, cfg, discardLogger())
		if err == nil || !strings.Contains(err.Error(), "decrypt config setting") {
			t.Fatalf("want decrypt error, got %v", err)
		}
	})
	t.Run("malformed value is fatal", func(t *testing.T) {
		st, v, cfg := newFixture(t)
		if err := st.PutSetting(ctx, &store.Setting{Key: "PAM_CHECKOUT_TTL_MIN", Value: "thirty"}); err != nil {
			t.Fatal(err)
		}
		if err := applyStoredConfig(ctx, st, v, cfg, discardLogger()); err == nil {
			t.Fatal("malformed integer accepted")
		}
	})
}

// TestRunRotateKEKErrors walks -rotate-kek's guard rails: both KEKs must be
// valid, the new one must actually be configured, and the store must be real
// PostgreSQL — rotating the demo memory store would "succeed" while protecting
// nothing.
func TestRunRotateKEKErrors(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"bad current KEK", map[string]string{"PAM_MASTER_KEY": "too-short"}, "current KEK"},
		{"new key missing", map[string]string{}, "PAM_NEW_MASTER_KEY is required"},
		{"bad new KEK", map[string]string{"PAM_NEW_MASTER_KEY": "also-bad"}, "new KEK"},
		{"memory store refused", map[string]string{"PAM_NEW_MASTER_KEY": "@GENKEY@", "PAM_DATABASE_URL": "memory"}, "must point at a PostgreSQL database"},
		{"unparsable database url", map[string]string{"PAM_NEW_MASTER_KEY": "@GENKEY@", "PAM_DATABASE_URL": "://not-a-url"}, "connect to postgres"},
		{"unreachable database", map[string]string{"PAM_NEW_MASTER_KEY": "@GENKEY@", "PAM_DATABASE_URL": "postgres://u:p@127.0.0.1:1/pam"}, "connect to postgres"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clearPAMEnv(t)
			t.Setenv("PAM_MASTER_KEY", mustMasterKey(t))
			for k, val := range c.env {
				if val == "@GENKEY@" {
					val = mustMasterKey(t)
				}
				t.Setenv(k, val)
			}
			err := runRotateKEK()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want error containing %q, got %v", c.want, err)
			}
		})
	}
}

// TestRunRotateKEKAgainstPostgres proves the shipped -rotate-kek tool end to
// end, the way an operator would run it: a credential is vaulted under the old
// KEK in a live PostgreSQL, the tool runs purely off the environment, and
// afterwards the secret decrypts under the new KEK and no longer under the old
// one — plus the sealed-recordings retention warning fires. It skips unless
// PAM_TEST_DATABASE_URL points at a database (CI's pgstore job provides one).
func TestRunRotateKEKAgainstPostgres(t *testing.T) {
	url := os.Getenv("PAM_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("PAM_TEST_DATABASE_URL not set; skipping live Postgres KEK-rotation test")
	}
	ctx := context.Background()

	// Start from an empty dataset: -rotate-kek re-encrypts every secret it
	// finds, so rows left by other suites (with placeholder ciphertexts no key
	// can decrypt) would fail the rotation for reasons unrelated to it.
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	st, err := pgstore.Open(ctx, url) // runs migrations, so TRUNCATE finds its tables
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	if _, err := pool.Exec(ctx,
		`TRUNCATE targets, credentials, audit_events, mfa_enrollments, settings, key_material
		 RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	oldKey, newKey := mustMasterKey(t), mustMasterKey(t)
	oldVault, err := vault.New(oldKey)
	if err != nil {
		t.Fatal(err)
	}
	target := &store.Target{Name: "rotate-kek-target", Host: "127.0.0.1", Port: 22, OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, target); err != nil {
		t.Fatalf("create target: %v", err)
	}
	cred := &store.Credential{TargetID: target.ID, Username: "root", SecretType: "password"}
	if err := st.CreateCredential(ctx, cred); err != nil {
		t.Fatalf("create credential: %v", err)
	}
	aad := store.CredentialAAD(target.ID, cred.ID)
	enc, err := oldVault.Encrypt(ctx, "hunter2-vaulted", aad)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateCredentialSecretEnc(ctx, cred.ID, enc); err != nil {
		t.Fatalf("store secret: %v", err)
	}

	recDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(recDir, "sealed.cast"), []byte("#pamrec1 wrapped\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	clearPAMEnv(t)
	t.Setenv("PAM_MASTER_KEY", oldKey)
	t.Setenv("PAM_NEW_MASTER_KEY", newKey)
	t.Setenv("PAM_DATABASE_URL", url)
	t.Setenv("PAM_RECORDING_DIR", recDir)

	out := captureStdout(t, func() {
		if err := runRotateKEK(); err != nil {
			t.Errorf("runRotateKEK: %v", err)
		}
	})
	if !strings.Contains(out, "rotated") {
		t.Fatalf("no rotation summary printed:\n%s", out)
	}
	if !strings.Contains(out, "sealed recording(s)") {
		t.Fatalf("sealed-recordings retention warning missing:\n%s", out)
	}

	rotated, err := st.GetCredential(ctx, cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	newVault, err := vault.New(newKey)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := newVault.Decrypt(ctx, rotated.SecretEnc, aad)
	if err != nil || pt != "hunter2-vaulted" {
		t.Fatalf("secret does not decrypt under the new KEK: %q %v", pt, err)
	}
	if _, err := oldVault.Decrypt(ctx, rotated.SecretEnc, aad); err == nil {
		t.Fatal("secret still decrypts under the OLD KEK; rotation was a no-op")
	}
}

// TestRunErrors drives run() through every fail-closed startup path reachable
// without external infrastructure, each triggered through the environment the
// way a real misconfigured deployment would trigger it. The assertions are on
// error substrings because those messages are the operator's only diagnostic.
func TestRunErrors(t *testing.T) {
	cases := []struct {
		name  string
		env   map[string]string
		setup func(t *testing.T) map[string]string
		want  string
	}{
		{
			name: "conjur provider without url",
			env:  map[string]string{"PAM_SECRETS_PROVIDER": "conjur"},
			want: "conjur",
		},
		{
			name: "conjur unreachable fails loud",
			env: map[string]string{
				"PAM_CONJUR_URL": "http://127.0.0.1:1", "PAM_CONJUR_AUTHN_LOGIN": "host/pam", "PAM_CONJUR_API_KEY": "k",
			},
			want: "conjur",
		},
		{
			name: "invalid config",
			env:  map[string]string{"PAM_MFA_REQUIRED": "notabool"},
			want: "config",
		},
		{
			name: "bad master key",
			env:  map[string]string{"PAM_MASTER_KEY": "not-a-real-key"},
			want: "PAM_MASTER_KEY must be 32 bytes",
		},
		{
			name: "postgres unreachable",
			env:  map[string]string{"PAM_DATABASE_URL": "postgres://u:p@127.0.0.1:1/pam"},
			want: "connect to postgres",
		},
		{
			name: "audit hmac key malformed",
			env:  map[string]string{"PAM_AUDIT_HMAC_KEY": "!!!"},
			want: "PAM_AUDIT_HMAC_KEY must be base64 of 32 bytes",
		},
		{
			name: "audit sign seed without chain",
			env:  map[string]string{"PAM_AUDIT_SIGN_SEED": "x"},
			want: "requires PAM_AUDIT_HMAC_KEY",
		},
		{
			name:  "audit sign seed malformed",
			setup: func(t *testing.T) map[string]string { return map[string]string{"PAM_AUDIT_HMAC_KEY": b64Bytes(t, 32)} },
			env:   map[string]string{"PAM_AUDIT_SIGN_SEED": "!!!"},
			want:  "PAM_AUDIT_SIGN_SEED must be base64 of 32 bytes",
		},
		{
			name: "break-glass hash malformed",
			env:  map[string]string{"PAM_BREAK_GLASS_KEY_HASH": "zz"},
			want: "hex-encoded SHA-256",
		},
		{
			name: "ldap must be ldaps",
			env:  map[string]string{"PAM_LDAP_URL": "ldap://dc.example"},
			want: "ldap",
		},
		{
			name: "entra incomplete",
			env:  map[string]string{"PAM_ENTRA_TENANT_ID": "tenant"},
			want: "entra",
		},
		{
			name: "oidc discovery unreachable",
			env:  map[string]string{"PAM_OIDC_ISSUER": "http://127.0.0.1:1"},
			want: "oidc discovery",
		},
		{
			name: "command deny file missing",
			env:  map[string]string{"PAM_COMMAND_DENY_FILE": "/nonexistent/deny.txt"},
			want: "command deny file",
		},
		{
			name: "command deny file without patterns fails closed",
			setup: func(t *testing.T) map[string]string {
				return map[string]string{"PAM_COMMAND_DENY_FILE": writeTemp(t, "deny.txt", "# comments only\n")}
			},
			want: "yielded no usable patterns",
		},
		{
			name: "command deny file bad pattern",
			setup: func(t *testing.T) map[string]string {
				return map[string]string{"PAM_COMMAND_DENY_FILE": writeTemp(t, "deny.txt", "(\n")}
			},
			want: "command deny file",
		},
		{
			name: "sftp path deny file missing",
			env:  map[string]string{"PAM_SSH_SFTP_DENY_FILE": "/nonexistent/paths.txt"},
			want: "sftp path deny file",
		},
		{
			name: "sftp path deny file without patterns fails closed",
			setup: func(t *testing.T) map[string]string {
				return map[string]string{"PAM_SSH_SFTP_DENY_FILE": writeTemp(t, "paths.txt", "\n\n")}
			},
			want: "yielded no usable patterns",
		},
		{
			name: "db step-up file without patterns fails closed",
			setup: func(t *testing.T) map[string]string {
				return map[string]string{"PAM_DB_STEPUP_FILE": writeTemp(t, "stepup.txt", "# none\n")}
			},
			want: "yielded no usable patterns",
		},
		{
			name: "known_hosts missing",
			env:  map[string]string{"PAM_SSH_KNOWN_HOSTS": "/nonexistent/known_hosts"},
			want: "ssh known_hosts",
		},
		{
			name: "broker policy malformed",
			setup: func(t *testing.T) map[string]string {
				return map[string]string{
					"PAM_BROKER_POLICY_FILE":     writeTemp(t, "policy.yaml", "rules: []\n"),
					"PAM_BROKER_AUDIT_KEY":       b64Bytes(t, 32),
					"PAM_BROKER_AUDIT_SIGN_SEED": b64Bytes(t, 32),
				}
			},
			want: "policy",
		},
		{
			name: "broker previous signer keys malformed",
			env:  map[string]string{"PAM_BROKER_AUDIT_SIGN_PREV": "!!!"},
			want: "PAM_BROKER_AUDIT_SIGN_PREV",
		},
		{
			name: "svid jwks unreadable",
			env: map[string]string{
				"PAM_BROKER_TRUST_DOMAIN_JWKS": "/nonexistent/jwks.json",
				"PAM_BROKER_TRUST_DOMAIN":      "example.org",
				"PAM_BROKER_AUDIENCE":          "pamv1",
			},
			want: "broker SVID verifier",
		},
		{
			// Token exchange mints identities that only exist inside the SVID
			// world, so enabling it without a trust domain could never issue
			// anything. Fail loud rather than serve an endpoint that refuses
			// every request (Phase 57).
			name: "token exchange without a trust domain",
			env:  map[string]string{"PAM_BROKER_TOKEN_EXCHANGE": "true"},
			want: "PAM_BROKER_TOKEN_EXCHANGE",
		},
		{
			name: "token exchange without the broker",
			setup: func(t *testing.T) map[string]string {
				return map[string]string{
					"PAM_BROKER_TOKEN_EXCHANGE":    "true",
					"PAM_BROKER_TRUST_DOMAIN_JWKS": writeTemp(t, "jwks.json", `{"keys":[]}`),
					"PAM_BROKER_TRUST_DOMAIN":      "example.org",
					"PAM_BROKER_AUDIENCE":          "pamv1",
				}
			},
			want: "PAM_BROKER_TOKEN_EXCHANGE",
		},
		{
			name: "ticket pattern invalid",
			env:  map[string]string{"PAM_TICKET_PATTERN": "["},
			want: "PAM_TICKET_PATTERN",
		},
		{
			name: "audit forwarder bad ca",
			env: map[string]string{
				"PAM_AUDIT_FORWARD_ADDR":  "127.0.0.1:6514",
				"PAM_AUDIT_FORWARD_PROTO": "tls",
				"PAM_AUDIT_FORWARD_CA":    "/nonexistent/ca.pem",
			},
			want: "audit forwarder",
		},
		{
			name: "require https without tls",
			env:  map[string]string{"PAM_REQUIRE_HTTPS": "true"},
			want: "PAM_REQUIRE_HTTPS is set but native TLS is not configured",
		},
		{
			name: "db proxy tls certs unreadable",
			env: map[string]string{
				"PAM_TLS_CERT": "/nonexistent/tls.crt",
				"PAM_TLS_KEY":  "/nonexistent/tls.key",
			},
			setup: func(t *testing.T) map[string]string {
				return map[string]string{"PAM_DB_ADDR": freeAddr(t)}
			},
			want: "db proxy tls",
		},
		{
			name: "db client tls required but absent",
			env:  map[string]string{"PAM_REQUIRE_DB_CLIENT_TLS": "true"},
			setup: func(t *testing.T) map[string]string {
				return map[string]string{"PAM_DB_ADDR": freeAddr(t)}
			},
			want: "PAM_REQUIRE_DB_CLIENT_TLS is set but no TLS is configured",
		},
		{
			// The shared database TLS requirement must bind the SQL Server
			// listener too, not just PostgreSQL's.
			name: "db client tls required but absent (mssql listener alone)",
			env:  map[string]string{"PAM_REQUIRE_DB_CLIENT_TLS": "true"},
			setup: func(t *testing.T) map[string]string {
				return map[string]string{"PAM_MSSQL_ADDR": freeAddr(t)}
			},
			want: "PAM_REQUIRE_DB_CLIENT_TLS is set but no TLS is configured",
		},
		{
			name: "db upstream ca missing",
			env:  map[string]string{"PAM_DB_UPSTREAM_CA": "/nonexistent/ca.pem"},
			setup: func(t *testing.T) map[string]string {
				return map[string]string{"PAM_DB_ADDR": freeAddr(t)}
			},
			want: "db upstream ca",
		},
		{
			name: "db upstream ca has no certificates",
			setup: func(t *testing.T) map[string]string {
				return map[string]string{
					"PAM_DB_ADDR":        freeAddr(t),
					"PAM_DB_UPSTREAM_CA": writeTemp(t, "ca.pem", "not a pem at all"),
				}
			},
			want: "no certificates found",
		},
		{
			name: "ssh jump key unreadable",
			env: map[string]string{
				"PAM_SSH_JUMP_HOST": "10.0.0.1:22",
				"PAM_SSH_JUMP_KEY":  "/nonexistent/jump.pem",
			},
			setup: func(t *testing.T) map[string]string {
				return map[string]string{
					"PAM_SSH_ADDR":     freeAddr(t),
					"PAM_SSH_HOST_KEY": filepath.Join(t.TempDir(), "host.pem"),
				}
			},
			want: "ssh jump key",
		},
		{
			name: "http listen address in use",
			setup: func(t *testing.T) map[string]string {
				return map[string]string{"PAM_LISTEN_ADDR": heldAddr(t)}
			},
			want: "address already in use",
		},
		{
			name: "ssh proxy address in use",
			setup: func(t *testing.T) map[string]string {
				return map[string]string{
					"PAM_LISTEN_ADDR":  freeAddr(t),
					"PAM_SSH_ADDR":     heldAddr(t),
					"PAM_SSH_HOST_KEY": filepath.Join(t.TempDir(), "host.pem"),
				}
			},
			want: "ssh proxy",
		},
		{
			name: "database proxy address in use",
			setup: func(t *testing.T) map[string]string {
				return map[string]string{
					"PAM_LISTEN_ADDR": freeAddr(t),
					"PAM_DB_ADDR":     heldAddr(t),
				}
			},
			want: "database proxy",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			setMinimalEnv(t)
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			if c.setup != nil {
				for k, v := range c.setup(t) {
					t.Setenv(k, v)
				}
			}
			done := make(chan error, 1)
			go func() { done <- run() }()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), c.want) {
					t.Fatalf("want error containing %q, got %v", c.want, err)
				}
			case <-time.After(30 * time.Second):
				// Unstick the server so the test binary can exit either way.
				_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
				t.Fatalf("run() did not fail within 30s (want error containing %q)", c.want)
			}
		})
	}
}

// TestSSHCAKeyUnreadable proves an existing-but-unreadable CA key file is fatal
// (unlike a failed mirror write, which only warns): starting with a CA the
// process cannot read would mint no certificates while claiming ZSP is on.
func TestSSHCAKeyUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; file permissions are not enforced")
	}
	setMinimalEnv(t)
	caPath := writeTemp(t, "ca.pem", "unreadable")
	if err := os.Chmod(caPath, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PAM_SSH_CA_KEY", caPath)
	done := make(chan error, 1)
	go func() { done <- run() }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "ssh ca key") {
			t.Fatalf("want ssh ca key error, got %v", err)
		}
	case <-time.After(30 * time.Second):
		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
		t.Fatal("run() did not fail within 30s")
	}
}

// waitHealthz polls url until it returns 200 or the deadline passes, proving
// the server under test actually reached its serving state.
func waitHealthz(t *testing.T, client *http.Client, url string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server never became healthy at %s", url)
}

// shutDown sends the process a real SIGTERM — the signal a container runtime
// sends — and requires run() to return the given error within the deadline.
func shutDown(t *testing.T, done <-chan error) {
	t.Helper()
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("graceful shutdown returned %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("run() did not return after SIGTERM")
	}
}

// TestRunServesAndShutsDownGracefully boots the full server — in-memory store,
// both proxies on ephemeral ports, tamper-evident audit chain, command/SFTP/
// step-up controls, broker policy, SSH CA, LDAP+Entra+OIDC identity wiring and
// the background workers — waits until /healthz answers, verifies the
// -healthcheck utility against the live server, then shuts it down with a real
// SIGTERM and requires a clean exit. This is the end-to-end proof that the
// wiring layer assembles and disassembles without leaking a listener.
func TestRunServesAndShutsDownGracefully(t *testing.T) {
	setMinimalEnv(t)
	listenAddr := freeAddr(t)
	t.Setenv("PAM_LISTEN_ADDR", listenAddr)
	t.Setenv("PAM_SSH_ADDR", freeAddr(t))
	t.Setenv("PAM_SSH_HOST_KEY", filepath.Join(t.TempDir(), "host.pem"))
	t.Setenv("PAM_DB_ADDR", freeAddr(t))
	t.Setenv("PAM_MSSQL_ADDR", freeAddr(t))
	t.Setenv("PAM_SSH_CA_KEY", filepath.Join(t.TempDir(), "ca.pem"))
	t.Setenv("PAM_AUDIT_HMAC_KEY", b64Bytes(t, 32))
	t.Setenv("PAM_AUDIT_SIGN_SEED", b64Bytes(t, 32))
	t.Setenv("PAM_COMMAND_DENY_FILE", writeTemp(t, "deny.txt", "^rm -rf /\n"))
	t.Setenv("PAM_SSH_SFTP_DENY_FILE", writeTemp(t, "paths.txt", "id_rsa\n"))
	t.Setenv("PAM_DB_STEPUP_FILE", writeTemp(t, "stepup.txt", "^DROP \n"))
	// The broker audit keys are deliberately NOT set: this boot proves they are
	// generated under shared custody (sealed into key_material) when absent.
	t.Setenv("PAM_BROKER_POLICY_FILE", writeTemp(t, "policy.yaml", minimalPolicy))
	t.Setenv("PAM_TICKET_PATTERN", "^CHG[0-9]+$")
	t.Setenv("PAM_BREAK_GLASS_KEY_HASH", func() string {
		sum := sha256.Sum256([]byte("sealed-emergency-key"))
		return hex.EncodeToString(sum[:])
	}())
	t.Setenv("PAM_ALERT_WEBHOOK", "https://hooks.example/pam")
	t.Setenv("PAM_LDAP_URL", "ldaps://dc.example")
	t.Setenv("PAM_LDAP_BASE_DN", "dc=example,dc=org")
	t.Setenv("PAM_LDAP_GROUP_ADMIN", "cn=pam-admins")
	t.Setenv("PAM_ENTRA_TENANT_ID", "tenant")
	t.Setenv("PAM_ENTRA_CLIENT_ID", "client")
	t.Setenv("PAM_ENTRA_CLIENT_SECRET", "secret")
	t.Setenv("PAM_ENTRA_ROLE_ADMIN", "pam-admins")
	t.Setenv("PAM_OIDC_ISSUER", "https://idp.example")
	t.Setenv("PAM_OIDC_CLIENT_ID", "pam")
	t.Setenv("PAM_OIDC_REDIRECT_URL", "https://pam.example/cb")
	t.Setenv("PAM_OIDC_AUTH_URL", "https://idp.example/a")
	t.Setenv("PAM_OIDC_TOKEN_URL", "https://idp.example/t")
	t.Setenv("PAM_OIDC_JWKS_URL", "https://idp.example/j")
	t.Setenv("PAM_ROTATE_INTERVAL_MIN", "60")
	t.Setenv("PAM_ANALYTICS_INTERVAL_MIN", "60")
	t.Setenv("PAM_VENDOR_SWEEP_INTERVAL_MIN", "60")

	done := make(chan error, 1)
	go func() { done <- run() }()
	waitHealthz(t, http.DefaultClient, "http://"+listenAddr+"/healthz")

	// The shipped liveness probe must agree with a live server.
	if err := runHealthcheck(); err != nil {
		t.Fatalf("-healthcheck against the live server: %v", err)
	}
	shutDown(t, done)
}

// TestRunServesTLS boots the server with native TLS (a throwaway self-signed
// certificate) and proves both the HTTPS serving branch and the -healthcheck
// scheme switch against it, then shuts down cleanly.
func TestRunServesTLS(t *testing.T) {
	setMinimalEnv(t)
	certPath, keyPath := selfSignedCert(t)
	listenAddr := freeAddr(t)
	t.Setenv("PAM_LISTEN_ADDR", listenAddr)
	t.Setenv("PAM_TLS_CERT", certPath)
	t.Setenv("PAM_TLS_KEY", keyPath)
	t.Setenv("PAM_REQUIRE_HTTPS", "true")

	done := make(chan error, 1)
	go func() { done <- run() }()
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- test client probing a throwaway self-signed local server
	}}
	waitHealthz(t, client, "https://"+listenAddr+"/healthz")

	if err := runHealthcheck(); err != nil {
		t.Fatalf("-healthcheck against the live TLS server: %v", err)
	}
	shutDown(t, done)
}
