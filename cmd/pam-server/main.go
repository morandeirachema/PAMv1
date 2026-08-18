// pam-server runs the pamv1 API and portal.
//
// Utility flags:
//
//	-genkey       print a fresh vault master key (PAM_MASTER_KEY) and exit
//	-hashkey      read an emergency break-glass key from stdin and print its
//	              SHA-256 hex (PAM_BREAK_GLASS_KEY_HASH); the plaintext key is
//	              then sealed offline (envelope / safe) and never stored.
//	-healthcheck  probe the local /healthz endpoint and exit 0 if healthy
//	              (used by the container HEALTHCHECK on the shell-less image).
package main

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/morandeirachema/pamv1/internal/agentid"
	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/analytics"
	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/auditchain"
	"github.com/morandeirachema/pamv1/internal/auditfwd"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/cmdguard"
	"github.com/morandeirachema/pamv1/internal/config"
	"github.com/morandeirachema/pamv1/internal/conjur"
	"github.com/morandeirachema/pamv1/internal/icap"
	"github.com/morandeirachema/pamv1/internal/k8s"
	"github.com/morandeirachema/pamv1/internal/keycustody"
	"github.com/morandeirachema/pamv1/internal/logging"
	"github.com/morandeirachema/pamv1/internal/maint"
	"github.com/morandeirachema/pamv1/internal/oidc"
	"github.com/morandeirachema/pamv1/internal/policy"
	"github.com/morandeirachema/pamv1/internal/posture"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/recording"
	"github.com/morandeirachema/pamv1/internal/rotate"
	"github.com/morandeirachema/pamv1/internal/saml"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/shamir"
	"github.com/morandeirachema/pamv1/internal/sshca"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/store/pgstore"
	"github.com/morandeirachema/pamv1/internal/ticket"
	"github.com/morandeirachema/pamv1/internal/vault"
	"github.com/morandeirachema/pamv1/internal/vendor"
	"github.com/morandeirachema/pamv1/internal/winrm"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Build metadata, set at link time by the release build:
//
//	go build -ldflags="-X main.version=v0.10.0 -X main.commit=$(git rev-parse --short HEAD)"
//
// They are plain package-level variables rather than constants because that is
// the only thing `-X` can write to. An unset build reports "dev", which is the
// honest answer for a binary someone compiled themselves.
//
// This exists because "which build is this?" was previously unanswerable for a
// running pam-server — no flag, no log line, no metric — and for a security
// product that is a poor position to be in during an incident.
var (
	version = "dev"
	commit  = "none"
)

// buildInfo renders the version and commit as a single human-readable string.
func buildInfo() string { return version + " (" + commit + ")" }

// main parses the utility flags and dispatches: -genkey prints a fresh vault
// master key, -hashkey prints the SHA-256 of a break-glass key read from stdin,
// -rotate-kek re-encrypts secrets under a new master key, -split-key emits
// Shamir shares of a break-glass key, and the default path runs the server.
func main() {
	genkey := flag.Bool("genkey", false, "print a new vault master key and exit")
	hashkey := flag.Bool("hashkey", false, "read a break-glass key from stdin, print its SHA-256 hex and exit")
	rotateKEK := flag.Bool("rotate-kek", false, "re-encrypt every vaulted secret under a new KEK and exit (any provider, via PAM_KEK_*/PAM_NEW_KEK_* — also how you migrate local\u21c4KMS\u21c4HSM)")
	splitKey := flag.Bool("split-key", false, "read a break-glass key from stdin and print N Shamir shares (PAM_BREAK_GLASS_SHARES / _THRESHOLD)")
	healthcheck := flag.Bool("healthcheck", false, "probe the local /healthz endpoint and exit 0 if healthy (for container HEALTHCHECK)")
	showVersion := flag.Bool("version", false, "print the build version and commit, then exit")
	flag.Parse()

	switch {
	case *showVersion:
		fmt.Println("pam-server", buildInfo())
	case *genkey:
		if err := runGenKey(); err != nil {
			fatal(err)
		}
	case *hashkey:
		if err := runHashKey(); err != nil {
			fatal(err)
		}
	case *rotateKEK:
		if err := runRotateKEK(); err != nil {
			fatal(err)
		}
	case *splitKey:
		if err := runSplitKey(); err != nil {
			fatal(err)
		}
	case *healthcheck:
		if err := runHealthcheck(); err != nil {
			fatal(err)
		}
	default:
		if err := run(); err != nil {
			fatal(err)
		}
	}
}

// runGenKey prints a freshly generated vault master key (the PAM_MASTER_KEY
// value) to stdout.
func runGenKey() error {
	key, err := vault.GenerateMasterKey()
	if err != nil {
		return err
	}
	fmt.Println(key)
	return nil
}

// runHashKey reads the emergency break-glass key from stdin and prints its
// SHA-256 as hex — the only form of it the server is ever configured with
// (PAM_BREAK_GLASS_KEY_HASH). An empty stdin is refused: hashing the empty
// string would yield a syntactically valid but unusable break-glass hash.
func runHashKey() error {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	key := strings.TrimSpace(string(data))
	if key == "" {
		return fmt.Errorf("no key on stdin (would hash the empty string, yielding an unusable break-glass hash)")
	}
	sum := sha256.Sum256([]byte(key))
	fmt.Println(hex.EncodeToString(sum[:]))
	return nil
}

// runHealthcheck probes the local liveness endpoint and exits non-zero unless it
// returns 200. It exists so a container HEALTHCHECK works on the distroless image
// (which has no shell or curl): `pam-server -healthcheck` targets the configured
// PAM_LISTEN_ADDR on the loopback.
func runHealthcheck() error {
	addr := os.Getenv("PAM_LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("PAM_LISTEN_ADDR %q: %w", addr, err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1" // the server binds all interfaces; probe loopback
	}
	// Match the scheme the server actually serves: when native TLS is configured
	// the server speaks HTTPS, so an http:// probe would mark a healthy TLS server
	// unhealthy. The probe targets loopback for liveness only, so it does not verify
	// the certificate (InsecureSkipVerify is safe here — it authenticates nothing).
	scheme := "http"
	client := &http.Client{Timeout: 3 * time.Second}
	if os.Getenv("PAM_TLS_CERT") != "" && os.Getenv("PAM_TLS_KEY") != "" {
		scheme = "https"
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // #nosec G402 -- loopback liveness probe only; authenticates nothing
	}
	resp, err := client.Get(scheme + "://" + net.JoinHostPort(host, port) + "/healthz") // #nosec G704 -- host is the configured PAM_LISTEN_ADDR on loopback, not user input
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz returned %d", resp.StatusCode)
	}
	return nil
}

// applyStoredConfig overlays DB-persisted configuration overrides (Phase 12) onto
// cfg, decrypting secret settings with the vault. Overrides cover identity
// backends, SSO, and operational policy; bootstrap/transport settings are not
// overridable. Applied at startup, so changes take effect on the next restart.
func applyStoredConfig(ctx context.Context, st store.Store, v *vault.Vault, cfg *config.Config, log *slog.Logger) error {
	settings, err := st.ListSettings(ctx)
	if err != nil {
		return fmt.Errorf("load config overrides: %w", err)
	}
	if len(settings) == 0 {
		return nil
	}
	kv := make(map[string]string, len(settings))
	for _, s := range settings {
		val := s.Value
		if s.Secret {
			pt, derr := v.Decrypt(ctx, s.Value, store.ConfigAAD(s.Key))
			if derr != nil {
				return fmt.Errorf("decrypt config setting %s: %w", s.Key, derr)
			}
			val = pt
		}
		kv[s.Key] = val
	}
	if err := config.ApplyOverrides(cfg, kv); err != nil {
		return err
	}
	log.Info("applied stored configuration overrides", "count", len(kv))
	return nil
}

// buildBroker loads the AI-agent access-broker policy and resolves its
// audit-chain keys when PAM_BROKER_POLICY_FILE is set (all-nil when the broker
// is disabled). Each key comes from its environment variable when set — the
// operator-controlled path, which is also how a signing-key rotation is driven —
// and otherwise from shared custody: generated once, sealed under the KEK in
// the store's key_material, and converged on by every replica, exactly like the
// SSH host and CA keys. A replica with its own chain key would make honest
// events read as tampering, so "each replica invents one" is never an
// acceptable fallback.
func buildBroker(ctx context.Context, st store.Store, v *vault.Vault, cfg *config.Config, log *slog.Logger) (*policy.Engine, []byte, ed25519.PrivateKey, error) {
	if cfg.BrokerPolicyFile == "" {
		return nil, nil, nil, nil
	}
	engine, err := policy.LoadFile(cfg.BrokerPolicyFile)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := brokerKeyBytes(ctx, st, v, cfg.BrokerAuditKey, "PAM_BROKER_AUDIT_KEY",
		keycustody.NameBrokerAuditKey, auditchain.KeySize, auditchain.GenerateKeyText, log)
	if err != nil {
		return nil, nil, nil, err
	}
	seed, err := brokerKeyBytes(ctx, st, v, cfg.BrokerAuditSignSeed, "PAM_BROKER_AUDIT_SIGN_SEED",
		keycustody.NameBrokerAuditSignSeed, ed25519.SeedSize, auditchain.GenerateSignSeedText, log)
	if err != nil {
		return nil, nil, nil, err
	}
	return engine, key, ed25519.NewKeyFromSeed(seed), nil
}

// brokerKeyBytes resolves one broker audit key to its raw bytes and keeps the
// environment and shared custody telling the same story.
//
// Env set: the value is decoded (fatal if malformed) and written through to
// shared custody — seeding it on first sight, so a replica without the variable,
// or a later boot after it is unset, converges on this same key instead of
// silently generating a different one and forking the chain (the pre-write-through
// failure mode: an upgraded deployment unsetting its previously mandatory keys
// would have had its entire honest history read as tampering). If custody already
// holds a DIFFERENT value the two sources disagree, and the response depends on
// which key this is:
//   - the HMAC chain key: fatal. Two chain keys is two histories; whichever wins,
//     honest events under the other verify as tampered. The operator either unsets
//     the variable (adopting the cluster key) or restores the matching value.
//   - the signing seed: the env value wins and custody is CONVERGED to it — an
//     explicit new seed is the documented signing-key-rotation path, and leaving
//     the old seed in custody would silently resurrect the rotated-out signer on
//     the first boot without the variable. The old public key stays verifiable
//     via PAM_BROKER_AUDIT_SIGN_PREV.
//
// Env unset: the shared-custody value (generated on first use, adopted by every
// other replica and restart). Both sources carry standard-base64 text of exactly
// size bytes; anything else is a fatal misconfig, because starting the broker
// with a garbled audit key would fork the chain.
func brokerKeyBytes(ctx context.Context, st store.Store, v *vault.Vault, envValue, envName, custodyName string, size int, generate func() ([]byte, error), log *slog.Logger) ([]byte, error) {
	// Trimmed once so decode, custody seeding and the mismatch comparison all see
	// the same text (base64 decoding tolerates a trailing newline; a comparison
	// that didn't would misread it as a different key).
	envValue = strings.TrimSpace(envValue)
	if envValue != "" {
		raw, err := base64.StdEncoding.DecodeString(envValue)
		if err != nil || len(raw) != size {
			return nil, fmt.Errorf("%s must be base64 of %d bytes", envName, size)
		}
		stored, _, kerr := keycustody.Ensure(ctx, st, v, custodyName, "", func() ([]byte, error) { return []byte(envValue), nil })
		if stored == nil {
			return nil, fmt.Errorf("broker audit key custody (%s): %w", custodyName, kerr)
		}
		if strings.TrimSpace(string(stored)) != envValue {
			if custodyName == keycustody.NameBrokerAuditKey {
				return nil, fmt.Errorf("%s does not match the chain key this cluster already holds in shared custody: refusing to fork the broker audit chain — unset %s to adopt the cluster key, or restore the matching value", envName, envName)
			}
			if cerr := keycustody.Converge(ctx, st, v, custodyName, []byte(envValue)); cerr != nil {
				return nil, fmt.Errorf("broker audit key custody (%s): converge to the explicit %s: %w", custodyName, envName, cerr)
			}
			log.Warn("signing-key rotation: shared custody converged to the explicit seed; the replaced signer verifies only via PAM_BROKER_AUDIT_SIGN_PREV", "name", custodyName, "env", envName)
		}
		return raw, nil
	}
	stored, adopted, kerr := keycustody.Ensure(ctx, st, v, custodyName, "", generate)
	if stored == nil {
		return nil, fmt.Errorf("broker audit key custody (%s): %w", custodyName, kerr)
	}
	if adopted {
		log.Info("adopted the cluster's broker audit key from shared custody", "name", custodyName)
	} else {
		log.Info("generated a broker audit key into shared custody", "name", custodyName)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(stored)))
	if err != nil || len(raw) != size {
		return nil, fmt.Errorf("broker audit key custody (%s): stored value is not base64 of %d bytes", custodyName, size)
	}
	return raw, nil
}

// parseEd25519PubKeys decodes a comma-separated list of base64 ed25519 public
// keys (32 bytes each), for the rotated-out checkpoint signers still trusted
// during a signing-key rotation overlap. An empty string yields no keys.
func parseEd25519PubKeys(s string) ([]ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var out []ed25519.PublicKey
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(part)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("each key must be base64 of %d bytes", ed25519.PublicKeySize)
		}
		out = append(out, ed25519.PublicKey(raw))
	}
	return out, nil
}

// runRotateKEK re-encrypts every vaulted secret from the CURRENT KEK to a NEW one
// and records the rotation in the audit trail. The current KEK is read from the
// usual PAM_KEK_*/PAM_MASTER_KEY variables (any provider — local, vault-transit,
// aws-kms, pkcs11); the new KEK from the parallel PAM_NEW_KEK_*/PAM_NEW_MASTER_KEY
// set (provider defaults to "local", so the classic PAM_NEW_MASTER_KEY workflow
// still works). This makes provider migration (e.g. local→aws-kms) and recovery
// from a compromised KEK possible with the shipped tooling. Run it offline, then
// point the live PAM_KEK_*/PAM_MASTER_KEY at the new KEK and restart.
func runRotateKEK() error {
	oldKEK, err := vault.NewKEK(kekOptionsFromEnv(""))
	if err != nil {
		return fmt.Errorf("current KEK: %w", err)
	}
	newOpts := kekOptionsFromEnv("NEW_")
	if newOpts.Provider == "local" && newOpts.MasterKey == "" {
		return fmt.Errorf("PAM_NEW_MASTER_KEY is required for a local new KEK (generate one with -genkey), or set PAM_NEW_KEK_PROVIDER")
	}
	newKEK, err := vault.NewKEK(newOpts)
	if err != nil {
		return fmt.Errorf("new KEK: %w", err)
	}
	oldV, newV := vault.NewWithKEK(oldKEK), vault.NewWithKEK(newKEK)

	dbURL := os.Getenv("PAM_DATABASE_URL")
	if dbURL == "" || dbURL == "memory" {
		return fmt.Errorf("PAM_DATABASE_URL must point at a PostgreSQL database")
	}
	ctx := context.Background()
	st, err := pgstore.Open(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("connect to postgres: %w", err)
	}
	defer st.Close()

	n, err := maint.RotateVaultKEK(ctx, st, oldV, newV)
	if err != nil {
		return fmt.Errorf("rotation failed after %d secrets: %w", n, err)
	}
	// Record the completed rotation in the system-of-record.
	_ = st.AppendAudit(ctx, &store.AuditEvent{
		Actor:  "kek-rotation",
		Action: "vault.kek_rotated",
		Detail: fmt.Sprintf("from:%s to:%s secrets:%d", oldKEK.ID(), newKEK.ID(), n),
	})
	fmt.Printf("rotated %d secrets from KEK %q to %q; now point PAM_KEK_*/PAM_MASTER_KEY at the new KEK and restart\n", n, oldKEK.ID(), newKEK.ID())
	recDir := os.Getenv("PAM_RECORDING_DIR")
	if recDir == "" {
		recDir = "recordings" // same default as config.Load
	}
	warnSealedRecordings(recDir, oldKEK.ID())
	return nil
}

// warnSealedRecordings tells the operator, loudly and at the moment it matters,
// that a sealed recording's data key is wrapped inside the FILE by whichever KEK
// was current when it was written — so the old KEK cannot simply be discarded
// after a rotation.
//
// It is a warning rather than a re-wrap on purpose: rewriting a recording's
// header would change the bytes on disk, and the SHA-256 of those exact bytes is
// what the audit trail and the recording hash chain record. Re-wrapping would
// therefore make every archived recording read as "never audited" — destroying
// the tamper evidence the sealing exists to provide, in order to save a key.
// Keeping the old KEK for the retention window is the cheaper, honest trade.
func warnSealedRecordings(dir, oldKEKID string) {
	if dir == "" {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return // no recordings directory yet; nothing to warn about
	}
	sealed := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// OpenInRoot refuses to escape dir even if a name somehow contained a
		// traversal, which os.Open + filepath.Join would happily follow. ReadDir
		// only ever yields base names, so this is belt-and-braces — but it is the
		// belt-and-braces the compiler enforces rather than a comment claiming it.
		f, oerr := os.OpenInRoot(dir, e.Name())
		if oerr != nil {
			continue
		}
		hdr := make([]byte, recording.HeaderLen)
		nRead, _ := io.ReadFull(f, hdr)
		f.Close()
		if nRead == len(hdr) && recording.IsSealed(hdr) {
			sealed++
		}
	}
	if sealed == 0 {
		return
	}
	fmt.Printf(`
WARNING: %d sealed recording(s) in %s still need KEK %q.

A sealed recording carries its own data key wrapped INSIDE THE FILE by the KEK
that was current when it was written, so rotating the KEK does not re-wrap them
and this tool deliberately does not try: rewriting a recording would change its
bytes and invalidate the SHA-256 held in the audit trail and the recording hash
chain, which is the tamper evidence the sealing exists to provide.

Keep the old KEK available for at least as long as you retain these recordings,
or they become permanently unreadable.
`, sealed, dir, oldKEKID)
}

// kekOptionsFromEnv reads a KEK option set from PAM_<prefix>KEK_* variables
// (prefix "" for the current KEK, "NEW_" for the rotation target), so both sides
// of a KEK rotation support every provider, not just the local master key.
func kekOptionsFromEnv(prefix string) vault.KEKOptions {
	env := func(suffix string) string { return os.Getenv("PAM_" + prefix + suffix) }
	provider := env("KEK_PROVIDER")
	if provider == "" {
		provider = "local"
	}
	return vault.KEKOptions{
		Provider:         provider,
		MasterKey:        env("MASTER_KEY"),
		TransitAddr:      env("KEK_TRANSIT_ADDR"),
		TransitToken:     env("KEK_TRANSIT_TOKEN"),
		TransitKey:       env("KEK_TRANSIT_KEY"),
		AWSRegion:        env("KEK_AWS_REGION"),
		AWSKMSKeyID:      env("KEK_AWS_KEY_ID"),
		PKCS11Module:     env("KEK_PKCS11_MODULE"),
		PKCS11Pin:        env("KEK_PKCS11_PIN"),
		PKCS11KeyLabel:   env("KEK_PKCS11_KEY_LABEL"),
		PKCS11TokenLabel: env("KEK_PKCS11_TOKEN_LABEL"),
	}
}

// buildVault constructs the vault from the loaded config: it opens the pluggable
// KEK (local / Vault-Transit / AWS-KMS / PKCS#11) and wraps it. Split out of run
// so the startup sequence reads as a list of steps rather than a wall of KEK
// options.
func buildVault(cfg *config.Config, log *slog.Logger) (*vault.Vault, error) {
	kek, err := vault.NewKEK(vault.KEKOptions{
		Provider:         cfg.KEKProvider,
		MasterKey:        cfg.MasterKey,
		TransitAddr:      cfg.TransitAddr,
		TransitToken:     cfg.TransitToken,
		TransitKey:       cfg.TransitKey,
		AWSRegion:        cfg.AWSRegion,
		AWSKMSKeyID:      cfg.AWSKMSKeyID,
		PKCS11Module:     cfg.PKCS11Module,
		PKCS11Pin:        cfg.PKCS11Pin,
		PKCS11KeyLabel:   cfg.PKCS11KeyLabel,
		PKCS11TokenLabel: cfg.PKCS11TokenLabel,
	})
	if err != nil {
		return nil, err
	}
	log.Info("vault ready", "kek", kek.ID())
	return vault.NewWithKEK(kek), nil
}

// enableAuditChain wires optional tamper-evidence onto the primary audit trail:
// an HMAC key chains every event, and an ed25519 seed additionally signs the
// truncation-detecting checkpoints. Both keys are validated to their exact size —
// fail loud rather than silently run unchained — and the sign seed requires the
// HMAC key (a checkpoint needs a chain). It returns the parsed signing key (nil
// when unconfigured).
func enableAuditChain(cfg *config.Config, st store.Store, log *slog.Logger) (ed25519.PrivateKey, error) {
	if cfg.AuditHMACKey == "" {
		if cfg.AuditSignSeed != "" {
			return nil, fmt.Errorf("PAM_AUDIT_SIGN_SEED requires PAM_AUDIT_HMAC_KEY (checkpoints need the chain)")
		}
		return nil, nil
	}
	ak, derr := base64.StdEncoding.DecodeString(cfg.AuditHMACKey)
	if derr != nil || len(ak) != auditchain.KeySize {
		return nil, fmt.Errorf("PAM_AUDIT_HMAC_KEY must be base64 of %d bytes", auditchain.KeySize)
	}
	st.EnableAuditChain(ak)
	log.Info("primary audit trail is tamper-evident (HMAC-chained)")
	if cfg.AuditSignSeed == "" {
		return nil, nil
	}
	seed, serr := base64.StdEncoding.DecodeString(cfg.AuditSignSeed)
	if serr != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("PAM_AUDIT_SIGN_SEED must be base64 of %d bytes", ed25519.SeedSize)
	}
	log.Info("audit-chain checkpoints are signed (GET /api/audit/head)")
	return ed25519.NewKeyFromSeed(seed), nil
}

// startSessionBuses wires the three cross-replica buses that share one custody
// key — the kill bus (Phase 34), the live-monitoring relay (Phase 55) and the
// step-up decision bus (Phase 56) — and returns the live Cluster, or nil when
// the shared key is unavailable, which leaves every bus replica-local. Every
// failure is best-effort and logged: single-replica degradation is the designed
// fallback, not an error that should stop startup. The key lives in shared
// custody (KEK-sealed in the store, converged on by every replica, re-wrapped by
// -rotate-kek); it is deliberately not configurable, because the transport has
// no access control and relaying session content without it would put live
// privileged output on a channel any database session can read.
func startSessionBuses(ctx context.Context, st store.Store, v *vault.Vault, log *slog.Logger,
	sessions *session.Registry, liveHub *session.Hub, stepUp *session.StepUp, replicaName string) *session.Cluster {
	startKillBus := func(busKey []byte, audit func(context.Context, string, string)) {
		if err := sessions.StartKillBus(ctx, st, session.KillBusConfig{BusKey: busKey, Audit: audit}); err != nil {
			log.Warn("session kill bus unavailable; kill-switch is replica-local", "err", err)
		}
	}
	busKey, _, bkerr := keycustody.Ensure(ctx, st, v, keycustody.NameLiveBusKey, "", func() ([]byte, error) {
		k := make([]byte, session.LiveBusKeySize)
		if _, rerr := rand.Read(k); rerr != nil {
			return nil, rerr
		}
		return []byte(base64.StdEncoding.EncodeToString(k)), nil
	})
	if bkerr != nil {
		log.Warn("live-bus key custody failed; the kill-switch, session listing and live watch all stay replica-local", "err", bkerr)
		return nil
	}
	relayAudit := func(actx context.Context, action, detail string) {
		if aerr := st.AppendAudit(actx, &store.AuditEvent{
			Actor: "relay", Action: action, Detail: detail, TS: time.Now().UTC(),
		}); aerr != nil {
			log.Error("relay audit append failed", "action", action, "err", aerr)
		}
	}
	rawBusKey, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(busKey)))
	if derr != nil || len(rawBusKey) != session.LiveBusKeySize {
		log.Warn("live-bus key in custody is malformed; session listing and live watch stay replica-local")
		return nil
	}
	var cluster *session.Cluster
	c, cerr := session.StartCluster(ctx, session.ClusterConfig{
		Store: st, Registry: sessions, Hub: liveHub, Replica: replicaName, BusKey: rawBusKey,
		Audit: relayAudit,
	})
	if cerr != nil {
		log.Warn("session live bus unavailable; session listing and live watch are replica-local", "err", cerr)
	} else {
		cluster = c
	}
	// The kill bus shares the key: an unsealed one is a remote session-termination
	// primitive with nothing authenticating it. It and the step-up bus start even
	// if StartCluster failed — they degrade independently.
	startKillBus(rawBusKey, relayAudit)
	if serr := stepUp.StartBus(ctx, st, session.StepUpBusConfig{
		BusKey: rawBusKey, Replica: replicaName, Audit: relayAudit,
	}); serr != nil {
		log.Warn("step-up decision bus unavailable; step-up listing and decisions are replica-local", "err", serr)
	}
	return cluster
}

// fatal prints err to stderr prefixed with "pam-server:" and exits with status 1.
func fatal(err error) {
	fmt.Fprintln(os.Stderr, "pam-server:", err)
	os.Exit(1)
}

// runSplitKey reads the break-glass key from stdin and prints N Shamir shares
// (hex, one per line), of which PAM_BREAK_GLASS_THRESHOLD reconstruct the key.
// Distribute one share to each custodian; the server holds none.
func runSplitKey() error {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	key := []byte(strings.TrimSpace(string(data)))
	if len(key) == 0 {
		return fmt.Errorf("no key on stdin")
	}
	n, err := getenvInt("PAM_BREAK_GLASS_SHARES", 5)
	if err != nil {
		return err
	}
	m, err := getenvInt("PAM_BREAK_GLASS_THRESHOLD", 3)
	if err != nil {
		return err
	}
	shares, err := shamir.Split(key, n, m)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "# %d shares; any %d reconstruct the key. Distribute one per custodian.\n", n, m)
	for _, s := range shares {
		fmt.Println(hex.EncodeToString(s))
	}
	return nil
}

// getenvInt returns the integer value of the named environment variable, or def
// when the variable is unset. A set-but-unparseable value is an error rather
// than a silent fallback to the default: the caller is the -split-key key
// ceremony, and a typo must not quietly produce a share set with a different
// quorum than the operator asked for. (config.Load refuses bad values for the
// same variables the same way when the server starts.)
func getenvInt(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer, got %q", key, v)
	}
	return n, nil
}

// buildAuthenticator wires the enabled password identity sources (on-prem AD via
// LDAP and/or Microsoft Entra ID) into a single Authenticator (nil if none), and
// returns the LDAP directory source (for identity reconciliation) when LDAP is
// configured.
func buildAuthenticator(cfg *config.Config, log *slog.Logger) (auth.Authenticator, auth.DirectorySource, error) {
	var sources []auth.Authenticator
	var directory auth.DirectorySource

	if cfg.LDAPURL != "" {
		ldapAuth, err := auth.NewLDAPAuthenticator(auth.LDAPConfig{
			URL:                cfg.LDAPURL,
			BindDN:             cfg.LDAPBindDN,
			BindPassword:       cfg.LDAPBindPassword,
			BaseDN:             cfg.LDAPBaseDN,
			UserFilter:         cfg.LDAPUserFilter,
			InsecureSkipVerify: cfg.LDAPInsecureSkipVerify,
			GroupRoleMap:       roleMap(cfg.LDAPGroupAdmin, cfg.LDAPGroupUser, cfg.LDAPGroupAuditor, cfg.LDAPGroupApprover),
		})
		if err != nil {
			return nil, nil, fmt.Errorf("ldap: %w", err)
		}
		sources = append(sources, ldapAuth)
		directory = ldapAuth
		log.Info("active directory login enabled", "url", cfg.LDAPURL, "insecure_skip_verify", cfg.LDAPInsecureSkipVerify)
	}

	if cfg.EntraTenantID != "" {
		entraAuth, err := auth.NewEntraAuthenticator(auth.EntraConfig{
			TenantID:      cfg.EntraTenantID,
			ClientID:      cfg.EntraClientID,
			ClientSecret:  cfg.EntraClientSecret,
			Scope:         cfg.EntraScope,
			AuthorityHost: cfg.EntraAuthorityHost,
			RoleMap:       roleMap(cfg.EntraRoleAdmin, cfg.EntraRoleUser, cfg.EntraRoleAuditor, cfg.EntraRoleApprover),
		})
		if err != nil {
			return nil, nil, fmt.Errorf("entra: %w", err)
		}
		sources = append(sources, entraAuth)
		log.Info("entra id login enabled", "tenant", cfg.EntraTenantID)
	}

	return auth.NewChain(sources...), directory, nil
}

// buildOIDC constructs the OIDC provider when PAM_OIDC_ISSUER is set, filling in
// the authorize/token/JWKS endpoints from discovery when not given explicitly.
func buildOIDC(ctx context.Context, cfg *config.Config, log *slog.Logger) (*oidc.Provider, error) {
	if cfg.OIDCIssuer == "" {
		return nil, nil
	}
	authURL, tokenURL, jwksURL := cfg.OIDCAuthURL, cfg.OIDCTokenURL, cfg.OIDCJWKSURL
	if authURL == "" || tokenURL == "" || jwksURL == "" {
		a, t, j, err := oidc.Discover(ctx, nil, cfg.OIDCIssuer)
		if err != nil {
			return nil, fmt.Errorf("oidc discovery: %w", err)
		}
		authURL, tokenURL, jwksURL = a, t, j
	}
	var scopes []string
	if cfg.OIDCScopes != "" {
		scopes = strings.Fields(cfg.OIDCScopes)
	}
	p, err := oidc.NewProvider(oidc.Config{
		Issuer: cfg.OIDCIssuer, ClientID: cfg.OIDCClientID, ClientSecret: cfg.OIDCClientSecret,
		RedirectURL: cfg.OIDCRedirectURL, AuthURL: authURL, TokenURL: tokenURL, JWKSURL: jwksURL,
		Scopes: scopes,
	})
	if err != nil {
		return nil, err
	}
	log.Info("oidc login enabled", "issuer", cfg.OIDCIssuer)
	return p, nil
}

// buildSAML constructs the SAML 2.0 Service Provider when PAM_SAML_SP_URL is set
// (Phase 151) — the same "presence enables" idiom buildOIDC uses. The IdP
// metadata comes from exactly one of PAM_SAML_IDP_METADATA_URL (fetched here,
// the SP's only outbound call) or PAM_SAML_IDP_METADATA_FILE; the optional
// PAM_SAML_SP_KEY_FILE/_CERT_FILE pair turns on AuthnRequest signing and
// encrypted-assertion decryption. Any misconfiguration is a startup (or
// hot-swap) error rather than a first-login surprise.
func buildSAML(ctx context.Context, cfg *config.Config, log *slog.Logger) (*saml.Provider, error) {
	if cfg.SAMLSPURL == "" {
		return nil, nil
	}
	sc := saml.Config{
		RootURL:        cfg.SAMLSPURL,
		EntityID:       cfg.SAMLSPEntityID,
		IDPMetadataURL: cfg.SAMLIDPMetadataURL,
		NameAttr:       cfg.SAMLNameAttr,
	}
	if cfg.SAMLGroupAttr != "" {
		sc.GroupAttrs = splitAndTrim(cfg.SAMLGroupAttr)
	}
	if cfg.SAMLIDPMetadataFile != "" {
		b, err := os.ReadFile(cfg.SAMLIDPMetadataFile) // #nosec G304 -- operator-supplied path from PAM_SAML_IDP_METADATA_FILE (env/IaC-only, never a stored override)
		if err != nil {
			return nil, fmt.Errorf("saml: read idp metadata file: %w", err)
		}
		sc.IDPMetadataXML = b
	}
	if cfg.SAMLSPKeyFile != "" || cfg.SAMLSPCertFile != "" {
		if cfg.SAMLSPKeyFile == "" || cfg.SAMLSPCertFile == "" {
			return nil, fmt.Errorf("saml: PAM_SAML_SP_KEY_FILE and PAM_SAML_SP_CERT_FILE must be set together")
		}
		key, err := os.ReadFile(cfg.SAMLSPKeyFile) // #nosec G304 -- operator-supplied path from PAM_SAML_SP_KEY_FILE (env/IaC-only, never a stored override)
		if err != nil {
			return nil, fmt.Errorf("saml: read sp key file: %w", err)
		}
		cert, err := os.ReadFile(cfg.SAMLSPCertFile) // #nosec G304 -- operator-supplied path from PAM_SAML_SP_CERT_FILE (env/IaC-only, never a stored override)
		if err != nil {
			return nil, fmt.Errorf("saml: read sp certificate file: %w", err)
		}
		sc.SPKeyPEM, sc.SPCertPEM = key, cert
	}
	p, err := saml.New(ctx, sc)
	if err != nil {
		return nil, err
	}
	log.Info("saml login enabled", "sp_entity_id", p.EntityID(), "idp_entity_id", p.IDPEntityID(),
		"acs", p.ACSURL(), "signs_requests", p.SignsRequests())
	return p, nil
}

// buildWebAuthn constructs the WebAuthn relying party when PAM_WEBAUTHN_RP_ID
// is set — the same "presence enables" idiom buildOIDC uses, deliberately
// with no separate boolean flag.
func buildWebAuthn(cfg *config.Config, log *slog.Logger) (*webauthn.WebAuthn, error) {
	if cfg.WebAuthnRPID == "" {
		return nil, nil
	}
	if cfg.WebAuthnRPOrigin == "" {
		return nil, fmt.Errorf("PAM_WEBAUTHN_RP_ID is set but PAM_WEBAUTHN_RP_ORIGIN is not")
	}
	w, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.WebAuthnRPID,
		RPDisplayName: "pamv1",
		RPOrigins:     []string{cfg.WebAuthnRPOrigin},
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn: %w", err)
	}
	log.Info("webauthn login enabled", "rp_id", cfg.WebAuthnRPID, "rp_origin", cfg.WebAuthnRPOrigin)
	return w, nil
}

// roleMap builds a lower-cased key → role map for the four role slots, skipping
// empty entries. Keys are group DNs (LDAP) or app-role/group ids (Entra).
func roleMap(admin, user, auditor, approver string) map[string]auth.Role {
	m := map[string]auth.Role{}
	add := func(key string, role auth.Role) {
		if key != "" {
			m[strings.ToLower(key)] = role
		}
	}
	add(admin, auth.RoleAdmin)
	add(user, auth.RoleUser)
	add(auditor, auth.RoleAuditor)
	add(approver, auth.RoleApprover)
	return m
}

// run loads configuration and starts the server: it builds the vault KEK,
// opens the store (Postgres or the in-memory demo store), wires the identity
// resolver, password authenticators and optional OIDC provider, configures
// alerting and upstream SSH host-key verification, constructs the API/portal
// handler, optionally launches the credential-lifecycle worker and the SSH
// proxy, then serves HTTP(S) until interrupted and shuts down gracefully.
func run() error {
	// Optionally source pamv1's own bootstrap secrets from CyberArk Conjur
	// (Phase 18) before reading the environment. A no-op unless PAM_CONJUR_URL is
	// set; SOPS/env remains the default. Fail-loud so a configured-but-unreachable
	// Conjur never starts the server with empty secrets.
	conjurClient, conjurFilled, err := conjur.Source(context.Background())
	if err != nil {
		return fmt.Errorf("conjur secret source: %w", err)
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	logging.Setup(cfg.LogLevel, cfg.LogFormat)
	log := logging.Component("server")

	v, err := buildVault(cfg, log)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var st store.Store
	if cfg.DatabaseURL == "memory" {
		log.Warn("using ephemeral in-memory store; data is lost on restart (demo mode)")
		st = memstore.New()
	} else {
		st, err = pgstore.Open(ctx, cfg.DatabaseURL)
		if err != nil {
			return fmt.Errorf("connect to postgres: %w", err)
		}
	}
	defer st.Close()

	// Optional tamper-evidence on the primary audit trail (HMAC chain + signed
	// checkpoints); nil signing key when unconfigured.
	auditSignKey, err := enableAuditChain(cfg, st, log)
	if err != nil {
		return err
	}

	// Phase 12: overlay DB-persisted configuration onto the env-derived config
	// before building the identity backends and policy-driven components, so
	// stored settings take effect (identity/SSO/policy only; bootstrap/transport
	// stay environment-only). base keeps the pristine env baseline so the hot-swap
	// reconfigure closure can rebuild from env + the current overrides.
	base := *cfg
	if err := applyStoredConfig(ctx, st, v, cfg, log); err != nil {
		return err
	}

	resolver, err := auth.NewResolver(st, cfg.APIKey, cfg.BreakGlassKeyHash)
	if err != nil {
		return err
	}
	resolver.WithProfiles(st) // Phase 12: resolve custom permission profiles

	authn, directory, err := buildAuthenticator(cfg, log)
	if err != nil {
		return err
	}

	oidcProvider, err := buildOIDC(ctx, cfg, log)
	if err != nil {
		return err
	}
	samlProvider, err := buildSAML(ctx, cfg, log)
	if err != nil {
		return err
	}
	webAuthnProvider, err := buildWebAuthn(cfg, log)
	if err != nil {
		return err
	}

	sessions := session.NewRegistry()
	sessions.SetLimits(cfg.MaxSessionsPerUser, cfg.MaxSessionsTotal)
	maxRecBytes := int64(cfg.MaxRecordingMB) * 1024 * 1024
	liveHub := session.NewHub()
	// Removing a session from the registry ends its live watch streams, so a
	// supervisor's SSE pane reports the end instead of going silent forever.
	sessions.AttachHub(liveHub)
	shares := session.NewShareRegistry() // Phase 116: live session-sharing input mux
	// Phase 153: the ONE live registry of connected outbound-only endpoint
	// agents, shared by the SSH proxy (which registers tunnels and dials
	// through them) and the API (which reports status and kicks on revoke).
	// nil keeps the feature off end to end: the agent login is refused and
	// the routes are not registered.
	var endpointAgents *session.EndpointAgents
	if cfg.EndpointAgentsEnabled {
		endpointAgents = session.NewEndpointAgents()
		log.Info("outbound-only endpoint agents enabled (PAM_ENDPOINT_AGENTS_ENABLED)")
	}
	replicaName, _ := os.Hostname()
	// The step-up coordinator exists before the buses because the decision bus
	// shares their custody key; its guard file is compiled further down with the
	// others.
	stepUp := session.NewStepUp()
	// Cross-replica kill bus (34), live-monitoring relay (55) and step-up decision
	// bus (56) — all sharing one custody key; nil cluster leaves them replica-local.
	cluster := startSessionBuses(ctx, st, v, log, sessions, liveHub, stepUp, replicaName)

	// Command control (Phase 16): compile the deny file, if configured, into ONE
	// guard shared by the SSH proxy, the database proxy and the API server — so the
	// same policy covers every path where a discrete command is visible, including
	// the REST WinRM endpoint and the agent broker's exec tools. Fail-loud on a bad
	// pattern.
	var cmdGuard *cmdguard.Guard
	if cfg.CommandDenyFile != "" {
		denyBytes, derr := os.ReadFile(cfg.CommandDenyFile)
		if derr != nil {
			return fmt.Errorf("command deny file %q: %w", cfg.CommandDenyFile, derr)
		}
		cmdGuard, derr = cmdguard.New(cmdguard.ParseDeny(string(denyBytes)))
		if errors.Is(derr, cmdguard.ErrNoPatterns) {
			// Fail closed: the operator asked for this control, so silently
			// running without it is the one outcome that must not happen. An
			// empty file usually means an unmounted ConfigMap or a bad path.
			return fmt.Errorf("command deny file %q yielded no usable patterns; PAM_COMMAND_DENY_FILE is set, so refusing to start without the control it asks for", cfg.CommandDenyFile)
		}
		if derr != nil {
			return fmt.Errorf("command deny file %q: %w", cfg.CommandDenyFile, derr)
		}
		log.Info("command control enabled", "patterns", cmdGuard.Size())
	}

	// Command allow-list (Phase 131): once configured, narrows every path
	// cmdGuard already covers to ONLY the listed commands — deny still wins
	// when both would match. Same file format, same fail-loud-on-bad-pattern
	// loading as the deny file; a separate *cmdguard.Guard value, not a mode
	// flag on cmdGuard, so a deployment that never sets this stays exactly
	// deny-only.
	var cmdAllowGuard *cmdguard.Guard
	if cfg.CommandAllowFile != "" {
		allowBytes, aerr := os.ReadFile(cfg.CommandAllowFile)
		if aerr != nil {
			return fmt.Errorf("command allow file %q: %w", cfg.CommandAllowFile, aerr)
		}
		cmdAllowGuard, aerr = cmdguard.New(cmdguard.ParseDeny(string(allowBytes)))
		if errors.Is(aerr, cmdguard.ErrNoPatterns) {
			return fmt.Errorf("command allow file %q yielded no usable patterns; PAM_COMMAND_ALLOW_FILE is set, so refusing to start without the control it asks for", cfg.CommandAllowFile)
		}
		if aerr != nil {
			return fmt.Errorf("command allow file %q: %w", cfg.CommandAllowFile, aerr)
		}
		log.Info("command allow-list enabled", "patterns", cmdAllowGuard.Size())
	}

	// SFTP path policy (Phase 51): the same regex-denylist engine, matched against
	// file paths instead of commands, so one semantic covers both. Fail-loud on a
	// bad pattern — an operator who configured a path deny and got none would not
	// find out until a file left the building.
	var sftpPathGuard *cmdguard.Guard
	if cfg.SSHSFTPDenyFile != "" {
		pathBytes, derr := os.ReadFile(cfg.SSHSFTPDenyFile)
		if derr != nil {
			return fmt.Errorf("sftp path deny file %q: %w", cfg.SSHSFTPDenyFile, derr)
		}
		sftpPathGuard, derr = cmdguard.New(cmdguard.ParseDeny(string(pathBytes)))
		if errors.Is(derr, cmdguard.ErrNoPatterns) {
			// Fail closed: the operator asked for this control, so silently
			// running without it is the one outcome that must not happen. An
			// empty file usually means an unmounted ConfigMap or a bad path.
			return fmt.Errorf("sftp path deny file %q yielded no usable patterns; PAM_SSH_SFTP_DENY_FILE is set, so refusing to start without the control it asks for", cfg.SSHSFTPDenyFile)
		}
		if derr != nil {
			return fmt.Errorf("sftp path deny file %q: %w", cfg.SSHSFTPDenyFile, derr)
		}
		log.Info("sftp path control enabled", "patterns", sftpPathGuard.Size())
	}

	// SFTP content capture (Phase 59): record the bytes of every file moved over
	// SFTP into per-file artifacts beside the session recordings. The enum was
	// already validated fail-loud by config.Load; parsing again here converts it
	// to the proxy's type and keeps a second line of defense.
	sftpCapture, err := proxy.ParseSFTPCaptureMode(cfg.SSHSFTPCapture)
	if err != nil {
		return fmt.Errorf("PAM_SSH_SFTP_CAPTURE: %w", err)
	}
	if sftpCapture != proxy.SFTPCaptureOff {
		log.Info("sftp content capture enabled", "mode", string(sftpCapture), "max_mb", cfg.SSHSFTPCaptureMaxMB)
	}

	// In-session step-up (Phase 30): SQL statements matching the step-up file pause
	// for a supervisor's live decision. The coordinator (created above, where the
	// decision bus attaches) is shared by the DB proxy (which awaits) and the API
	// (which decides).
	var stepupGuard *cmdguard.Guard
	if cfg.DBStepUpFile != "" {
		suBytes, derr := os.ReadFile(cfg.DBStepUpFile)
		if derr != nil {
			return fmt.Errorf("db step-up file %q: %w", cfg.DBStepUpFile, derr)
		}
		stepupGuard, derr = cmdguard.New(cmdguard.ParseDeny(string(suBytes)))
		if errors.Is(derr, cmdguard.ErrNoPatterns) {
			return fmt.Errorf("db step-up file %q yielded no usable patterns; PAM_DB_STEPUP_FILE is set, so refusing to start without the control it asks for", cfg.DBStepUpFile)
		}
		if derr != nil {
			return fmt.Errorf("db step-up file %q: %w", cfg.DBStepUpFile, derr)
		}
		if stepupGuard != nil {
			log.Info("database in-session step-up enabled", "patterns", stepupGuard.Size())
		}
	}

	winrmClient := winrm.Client{HTTPS: cfg.WinRMHTTPS, Insecure: cfg.WinRMInsecure, NTLM: cfg.WinRMNTLM, Timeout: 30 * time.Second}

	alerter := buildAlerter(cfg, log)

	// Upstream SSH host-key verification (shared by the proxy and the rotation
	// connector). Empty PAM_SSH_KNOWN_HOSTS = trust any key (insecure, logged).
	var upstreamHostKey ssh.HostKeyCallback
	if cfg.SSHKnownHosts != "" {
		cb, herr := knownhosts.New(cfg.SSHKnownHosts)
		if herr != nil {
			return fmt.Errorf("ssh known_hosts %q: %w", cfg.SSHKnownHosts, herr)
		}
		upstreamHostKey = cb
		log.Info("upstream SSH host keys pinned", "known_hosts", cfg.SSHKnownHosts)
	}

	brokerPolicy, brokerAuditKey, brokerSignKey, err := buildBroker(ctx, st, v, cfg, log)
	if err != nil {
		return err
	}
	// Rotated-out checkpoint signers still trusted during a signing-key rotation
	// overlap (Phase 27): comma-separated base64 ed25519 public keys.
	brokerSignPrevKeys, err := parseEd25519PubKeys(cfg.BrokerAuditSignPrev)
	if err != nil {
		return fmt.Errorf("PAM_BROKER_AUDIT_SIGN_PREV: %w", err)
	}

	// SPIFFE JWT-SVID agent identity (Phase 13d): accepted alongside static agent
	// keys when a trust-domain JWKS is configured. Load-time failure is fatal.
	var svidVerifier agentid.Verifier
	var brokerTokenKey ed25519.PrivateKey
	if cfg.BrokerTrustDomainJWKS != "" {
		sv, err := agentid.NewSVIDVerifier(cfg.BrokerTrustDomainJWKS, cfg.BrokerTrustDomain, cfg.BrokerAudience, cfg.BrokerMaxDelegation)
		if err != nil {
			return fmt.Errorf("broker SVID verifier: %w", err)
		}
		// Token exchange (Phase 57): the broker signs delegated SVIDs with a
		// shared-custody ed25519 key and must therefore TRUST that key at ingress —
		// otherwise it would mint tokens it could not itself accept. Wired here,
		// where the concrete verifier exists; the API only ever sees the interface.
		if cfg.BrokerTokenExchange {
			seed, serr := brokerKeyBytes(ctx, st, v, cfg.BrokerTokenSignSeed, "PAM_BROKER_TOKEN_SIGN_SEED",
				keycustody.NameBrokerTokenSignSeed, ed25519.SeedSize, auditchain.GenerateSignSeedText, log)
			if serr != nil {
				return serr
			}
			brokerTokenKey = ed25519.NewKeyFromSeed(seed)
			pub := brokerTokenKey.Public().(ed25519.PublicKey)
			if terr := sv.TrustIssuer(agentid.KeyID(pub), pub); terr != nil {
				return fmt.Errorf("broker token exchange: %w", terr)
			}
			log.Info("agent broker issues delegated SVIDs (RFC 8693 token exchange)",
				"kid", agentid.KeyID(pub), "ttl", cfg.BrokerExchangeTTL)
		}
		svidVerifier = sv
		log.Info("agent broker accepts SPIFFE SVIDs", "trust_domain", cfg.BrokerTrustDomain, "max_delegation", cfg.BrokerMaxDelegation)
	}

	// Kubernetes broker TLS trust (Phase 155): a pinned CA bundle, or the system
	// roots. Unlike the database proxy's upstream leg there is no trust-any
	// fallback — the Kubernetes API is always TLS and every request carries a
	// bearer token, so verification is ON by default and only
	// PAM_K8S_INSECURE_SKIP_VERIFY (loudly logged) turns it off.
	k8sCfg := k8s.Config{
		InsecureSkipVerify: cfg.K8sInsecureSkipVerify,
		Timeout:            time.Duration(cfg.K8sTimeoutSec) * time.Second,
		MaxResponseBytes:   int64(cfg.K8sMaxResponseKB) * 1024,
	}
	if cfg.K8sCAFile != "" {
		pem, rerr := os.ReadFile(cfg.K8sCAFile) // #nosec G304 -- operator-supplied path from PAM_K8S_CA_FILE (env/IaC-only)
		if rerr != nil {
			return fmt.Errorf("kubernetes ca: %w", rerr)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("kubernetes ca: no certificates found in %s", cfg.K8sCAFile)
		}
		k8sCfg.CAs = pool
		log.Info("kubernetes api servers verified against a pinned CA bundle", "file", cfg.K8sCAFile)
	}
	if cfg.K8sInsecureSkipVerify {
		log.Warn("kubernetes API server certificates are NOT verified (PAM_K8S_INSECURE_SKIP_VERIFY); the vaulted bearer token is exposed to anyone who can answer for the API server")
	}

	// reconfigure reproduces the hot-swappable RuntimeConfig from the pristine env
	// baseline plus the current DB overrides, so PUT/DELETE /api/config can rebuild
	// the identity backends and operational policy without a restart (Phase 12).
	reconfigure := func(ctx context.Context) (*api.RuntimeConfig, error) {
		c := base
		if err := applyStoredConfig(ctx, st, v, &c, log); err != nil {
			return nil, err
		}
		an, dir, err := buildAuthenticator(&c, log)
		if err != nil {
			return nil, err
		}
		op, err := buildOIDC(ctx, &c, log)
		if err != nil {
			return nil, err
		}
		sp, err := buildSAML(ctx, &c, log)
		if err != nil {
			return nil, err
		}
		return &api.RuntimeConfig{
			Authn:            an,
			Directory:        dir,
			OIDC:             op,
			OIDCRoleMap:      roleMap(c.OIDCRoleAdmin, c.OIDCRoleUser, c.OIDCRoleAuditor, c.OIDCRoleApprover),
			SAML:             sp,
			SAMLRoleMap:      roleMap(c.SAMLRoleAdmin, c.SAMLRoleUser, c.SAMLRoleAuditor, c.SAMLRoleApprover),
			MFARequired:      c.MFARequired,
			RevealDisabled:   c.RevealDisabled,
			ApprovalRequired: c.RequireApproval,
			ApprovalWindow:   c.ApprovalWindow,
			CheckoutTTL:      c.CheckoutTTL,
			AllowedProtocols: splitAndTrim(c.AllowedProtocols),
		}, nil
	}

	ticketProvider, err := buildTicketProvider(cfg)
	if err != nil {
		return err
	}
	ticketValidator, err := ticket.New(cfg.TicketPattern, ticketProvider)
	if err != nil {
		return err
	}
	if name := ticketValidator.Provider(); name != "" {
		log.Info("ITSM ticket gate enabled", "provider", name,
			"binds_actor", cfg.TicketBindActor, "enforces_window", cfg.TicketRequireWindow)
	}

	// Connect-time ticket re-check (Phase 60). Resolved to a single value here
	// so every gate — the API, the viewer and the three proxies — is handed the
	// same answer: nil means "validate at request time only", which is the
	// pre-Phase-60 behaviour and the default.
	var ticketRecheck store.TicketChecker
	if cfg.RevalidateTicket && ticketValidator.Enabled() {
		ticketRecheck = ticketValidator
		log.Info("ITSM tickets are re-validated at connect time", "webhook", cfg.TicketValidateURL != "")
	}

	// Live device posture (Phase 133): resolved to a single value here so
	// every gate — the API and the three session proxies — checks the same
	// webhook, the same shared-value idiom as ticketRecheck just above.
	postureAttestor := posture.NewAttestor(cfg.PostureAttestURL)
	if postureAttestor.Enabled() {
		log.Info("device posture checking enabled")
	}

	// ICAP file-transfer scanning (Phase 143): resolved once here, same
	// shared-value idiom as postureAttestor above. cfg's own validation
	// already confirmed the URL's shape, so a construction error here would
	// mean the two disagree, not that the deployment is misconfigured.
	icapClient, err := icap.NewClient(cfg.ICAPURL)
	if err != nil {
		return fmt.Errorf("icap client: %w", err)
	}
	if icapClient.Enabled() {
		log.Info("ICAP file-transfer scanning enabled")
	}

	// Zero Standing Privilege (Phase 22): load (or create) the SSH certificate
	// authority when PAM_SSH_CA_KEY is set. Shared by the proxy (which mints
	// short-lived certificates JIT) and the API (which publishes its public key).
	var sshCA *sshca.CertAuthority
	if cfg.SSHCAKeyPath != "" {
		caPEM, adopted, kerr := keycustody.Ensure(ctx, st, v, keycustody.NameSSHCAKey, cfg.SSHCAKeyPath, sshca.GenerateKeyPEM)
		if caPEM == nil {
			return fmt.Errorf("ssh ca key: %w", kerr)
		}
		if kerr != nil {
			log.Warn("ssh ca key custody", "err", kerr) // mirror failed; the key itself is fine
		}
		sshCA, err = sshca.FromPEM(caPEM)
		if err != nil {
			return fmt.Errorf("ssh ca key: %w", err)
		}
		if adopted {
			log.Info("adopted the cluster's SSH certificate authority from shared custody")
		}
		log.Info("zero standing privilege enabled (SSH certificate authority)",
			"fingerprint", sshCA.Fingerprint(), "cert_ttl", cfg.SSHCertTTL.String())
	}

	// Privileged threat analytics (Phase 23): a behavioral risk scorer over the
	// audit trail. Always available as a read-only endpoint; the background worker
	// runs when PAM_ANALYTICS_INTERVAL_MIN > 0. The off-hours signal is evaluated
	// in the configured timezone (config.Load has already validated it).
	analyticsLoc := time.UTC
	if cfg.AnalyticsTimezone != "" {
		if loc, lerr := time.LoadLocation(cfg.AnalyticsTimezone); lerr == nil {
			analyticsLoc = loc
		}
	}
	analyticsEngine := analytics.New(analytics.Config{
		BusinessStart: cfg.AnalyticsBusinessStart,
		BusinessEnd:   cfg.AnalyticsBusinessEnd,
		Location:      analyticsLoc,
	})

	if cfg.AppSecretsEnabled {
		log.Warn("application-secrets API enabled (Conjur-style secret delivery to apps); front it with TLS")
	}

	handler, err := api.New(st, v, resolver, authn, api.Options{
		Sessions:                sessions,
		Live:                    liveHub,
		Shares:                  shares,
		ShareInviteTTL:          cfg.ShareInviteTTL,
		ShareGuestSessionTTL:    cfg.ShareGuestSessionTTL,
		ApprovalInviteTTL:       cfg.ApprovalInviteTTL,
		ShareSMTPAddr:           cfg.AlertEmailSMTP,
		ShareSMTPFrom:           cfg.AlertEmailFrom,
		ShareSMTPUser:           cfg.AlertEmailUser,
		ShareSMTPPass:           cfg.AlertEmailPass,
		Cluster:                 cluster,
		StepUp:                  stepUp,
		SSHHostKeyCallback:      upstreamHostKey,
		MFARequired:             cfg.MFARequired,
		BuildVersion:            version,
		BuildCommit:             commit,
		RecordingDir:            cfg.RecordingDir,
		RequireRecording:        cfg.RequireRecording,
		EncryptRecordings:       cfg.EncryptRecordings,
		OpaqueRecordingNames:    cfg.OpaqueRecordingNames,
		RDPClipboardAudit:       cfg.RDPClipboardAudit,
		WinRM:                   winrmClient,
		OIDC:                    oidcProvider,
		WebAuthn:                webAuthnProvider,
		OIDCRoleMap:             roleMap(cfg.OIDCRoleAdmin, cfg.OIDCRoleUser, cfg.OIDCRoleAuditor, cfg.OIDCRoleApprover),
		SAML:                    samlProvider,
		SAMLRoleMap:             roleMap(cfg.SAMLRoleAdmin, cfg.SAMLRoleUser, cfg.SAMLRoleAuditor, cfg.SAMLRoleApprover),
		PortalURL:               cfg.PortalURL,
		GuacdAddr:               cfg.GuacdAddr,
		GuacdRecordingPath:      cfg.GuacdRecordingPath,
		GuacdRDPSecurity:        cfg.GuacdRDPSecurity,
		GuacdIgnoreCert:         cfg.GuacdIgnoreCert,
		RDPClipboard:            cfg.RDPClipboard,
		AuthRatePerMin:          cfg.AuthRatePerMin,
		CommandGuard:            cmdGuard,
		CommandAllowGuard:       cmdAllowGuard,
		TrustedProxyHops:        cfg.TrustedProxyHops,
		RevealDisabled:          cfg.RevealDisabled,
		BreakGlassThreshold:     cfg.BreakGlassThreshold,
		BreakGlassTTL:           cfg.BreakGlassTTL,
		Alerter:                 alerter,
		RequireApproval:         cfg.RequireApproval,
		ApprovalWindow:          cfg.ApprovalWindow,
		TicketValidator:         ticketValidator,
		RequireTicket:           cfg.RequireTicket,
		RevalidateTicket:        cfg.RevalidateTicket,
		ApprovalsRequired:       cfg.ApprovalsRequired,
		RequireReason:           cfg.RequireReason,
		OneTimeAccess:           cfg.OneTimeAccess,
		AirGap:                  cfg.AirGap,
		CheckoutTTL:             cfg.CheckoutTTL,
		CheckoutMaxExtend:       cfg.CheckoutMaxExtend,
		AllowedProtocols:        splitAndTrim(cfg.AllowedProtocols),
		Directory:               directory,
		Reconfigure:             reconfigure,
		AuditSignKey:            auditSignKey,
		BrokerPolicy:            brokerPolicy,
		BrokerAuditKey:          brokerAuditKey,
		BrokerAuditSignKey:      brokerSignKey,
		BrokerTokenTTL:          cfg.BrokerTokenTTL,
		BrokerMaxArgBytes:       cfg.BrokerMaxArgBytes,
		BrokerMaxResultBytes:    cfg.BrokerMaxResultBytes,
		BrokerRatePerMin:        cfg.BrokerRatePerMin,
		BrokerCheckpointEvery:   cfg.BrokerCheckpointEvery,
		BrokerAuditSignPrevKeys: brokerSignPrevKeys,
		BrokerSVIDVerifier:      svidVerifier,
		BrokerTokenSignKey:      brokerTokenKey,
		BrokerExchangeTTL:       cfg.BrokerExchangeTTL,
		BrokerAudience:          cfg.BrokerAudience,
		CertRemindDays:          cfg.CertRemindDays,
		PasswordPolicy: rotate.PasswordPolicy{
			MinLength: cfg.PasswordMinLength, MinLower: cfg.PasswordMinLower,
			MinUpper: cfg.PasswordMinUpper, MinDigit: cfg.PasswordMinDigit, MinSymbol: cfg.PasswordMinSymbol,
		},
		PasswordHistoryCount:      cfg.PasswordHistoryCount,
		CredentialFileMaxKB:       cfg.CredentialFileMaxKB,
		ExtensionTokenTTL:         time.Duration(cfg.ExtensionTokenTTLHours) * time.Hour,
		BrokerMaxDelegation:       cfg.BrokerMaxDelegation,
		CA:                        sshCA,
		SSHOperatorCertTTL:        cfg.SSHOperatorCertTTL,
		VendorAttestor:            vendor.NewAttestor(cfg.VendorAttestURL),
		PostureAttestor:           postureAttestor,
		DeviceHeader:              cfg.DeviceHeader,
		Analytics:                 analyticsEngine,
		AnalyticsWindow:           cfg.AnalyticsWindow,
		AnalyticsAutoKill:         cfg.AnalyticsAutoKill,
		AnalyticsBaseline:         time.Duration(cfg.AnalyticsBaselineDays) * 24 * time.Hour,
		AnalyticsAutoStepUp:       cfg.AnalyticsAutoStepUp,
		AppSecretsEnabled:         cfg.AppSecretsEnabled,
		ScimEnabled:               cfg.ScimEnabled,
		EndpointAgents:            endpointAgents,
		K8s:                       k8sCfg,
		SessionForensics:          cfg.SessionForensics,
		SessionForensicsMaxEvents: cfg.SessionForensicsMaxEvents,
		SessionForensicsTimeout:   time.Duration(cfg.SessionForensicsTimeoutSec) * time.Second,
	})
	if err != nil {
		return err
	}
	if cfg.MFARequired {
		log.Info("MFA is required for password logins")
	}

	if cfg.RotateInterval > 0 {
		go handler.RunLifecycleWorker(ctx, api.RotationPolicy{
			Interval: cfg.RotateInterval,
			MaxAge:   cfg.RotateMaxAge,
		})
	}
	// Unconditional: expired login sessions accumulate in every deployment, with
	// or without the agent broker, and this loop is what bounds them. It was
	// previously started only when a broker policy file was configured, which
	// meant the common deployment had no garbage collection at all.
	go handler.RunGC(ctx)
	// Recurring certification campaigns (Phase 68). Started unconditionally and
	// with no interval to configure: it does nothing at all until somebody makes
	// a campaign recurring, and a recertification schedule that only runs when a
	// second environment variable was also remembered is a control that lapses
	// exactly where it matters. The leader lock keeps N replicas to one spawn.
	go handler.RunCampaignScheduler(ctx)
	// Recurring access requests (Phase 120) — same reasoning as the campaign
	// scheduler above, its own worker: unconditional, no interval to
	// configure, does nothing until a request is filed with recur_days set.
	go handler.RunAccessRequestScheduler(ctx)
	// Runtime secret refresh (Phase 78, rebuilt in Phase 80). Opt-in, and NOT
	// leader-locked: every replica holds its own copy of these comparison values,
	// so every replica has to re-read them itself — a leader-only refresh would
	// leave the rest of the cluster authenticating against the retired key.
	if err := startSecretRefresh(ctx, cfg, conjurClient, conjurFilled, resolver, st, handler, alerter, log); err != nil {
		return err
	}
	if cfg.AnalyticsInterval > 0 {
		go handler.RunAnalyticsWorker(ctx, cfg.AnalyticsInterval)
	}
	if cfg.VendorSweepInterval > 0 {
		go handler.RunVendorSweeper(ctx, cfg.VendorSweepInterval)
	}
	// Retention (Phase 36): prune aged recordings and audit rows.
	go handler.RunRetentionWorker(ctx, time.Duration(cfg.RetentionIntervalHours)*time.Hour, api.RetentionPolicy{
		RecordingDays: cfg.RecordingRetentionDays,
		AuditDays:     cfg.AuditRetentionDays,
		AuditChained:  cfg.AuditHMACKey != "",
		ArchiveDir:    cfg.RetentionArchiveDir,
	})
	// SIEM audit forwarding (Phase 35): stream every audit event to a collector.
	if cfg.AuditForwardAddr != "" {
		fwd, ferr := auditfwd.New(st, auditfwd.Config{
			Network:   cfg.AuditForwardProto,
			Addr:      cfg.AuditForwardAddr,
			Format:    auditfwd.Format(cfg.AuditForwardFormat),
			TLSCAFile: cfg.AuditForwardCA,
		})
		if ferr != nil {
			return fmt.Errorf("audit forwarder: %w", ferr)
		}
		go fwd.Run(ctx, time.Duration(cfg.AuditForwardIntervalSec)*time.Second)
		log.Info("audit SIEM forwarding enabled", "addr", cfg.AuditForwardAddr, "proto", cfg.AuditForwardProto, "format", cfg.AuditForwardFormat)
	}

	// errc receives the first fatal listener error (HTTP or SSH proxy); either
	// aborts startup loudly instead of running half a control plane.
	errc := make(chan error, 1)

	// proxyDone closes when the SSH proxy has fully drained; shutdown waits on it
	// so in-flight sessions' closing audit events and recordings are flushed
	// before the process (and the store) exits. Closed immediately when the proxy
	// is disabled so the shutdown wait is a no-op.
	proxyDone := make(chan struct{})
	if cfg.SSHAddr == "off" {
		close(proxyDone)
	}
	// mssqlProxyDone mirrors dbProxyDone for the SQL Server proxy (Phase 53).
	mssqlProxyDone := make(chan struct{})
	if cfg.MSSQLAddr == "off" {
		close(mssqlProxyDone)
	}
	// dbProxyDone mirrors proxyDone for the PostgreSQL session proxy (Phase 15).
	dbProxyDone := make(chan struct{})
	if cfg.DBAddr == "off" {
		close(dbProxyDone)
	}
	if cfg.SSHAddr != "off" {
		// Shared custody (Phase 42): every replica ends up serving the SAME host key,
		// so an operator hitting a different pod does not get a host-key-changed
		// warning that is indistinguishable from a MITM.
		hostPEM, adopted, kerr := keycustody.Ensure(ctx, st, v, keycustody.NameSSHHostKey, cfg.SSHHostKeyPath, proxy.GenerateHostKeyPEM)
		if hostPEM == nil {
			return fmt.Errorf("ssh host key: %w", kerr)
		}
		if kerr != nil {
			log.Warn("ssh host key custody", "err", kerr)
		}
		hostKey, err := proxy.HostKeyFromPEM(hostPEM)
		if err != nil {
			return fmt.Errorf("ssh host key: %w", err)
		}
		if adopted {
			log.Info("adopted the cluster's SSH host key from shared custody")
		}
		var onSessionEnd func(int64)
		if cfg.RotateAfterSession {
			onSessionEnd = func(credID int64) { handler.RotateCredentialByID(context.Background(), credID) }
			log.Info("post-session credential rotation enabled")
		}
		// Post-session forensic reconstruction (Phase 157). Wired only when
		// enabled, so a deployment that has not opted in has no hook at all
		// rather than a hook that returns early.
		var onForensics func(proxy.SessionForensics)
		if cfg.SessionForensics {
			onForensics = func(f proxy.SessionForensics) {
				handler.CollectSessionForensics(context.Background(), api.SessionForensicsRequest{
					TargetID: f.TargetID, CredentialID: f.CredentialID, Actor: f.Actor,
					SessionID: f.SessionID, Started: f.Started, Ended: f.Ended,
				})
			}
			log.Info("post-session forensic reconstruction enabled (PAM_SESSION_FORENSICS)",
				"max_events", cfg.SessionForensicsMaxEvents, "timeout_sec", cfg.SessionForensicsTimeoutSec)
		}
		var proxyWinRM winrm.Runner
		if cfg.ProxyWinRM {
			proxyWinRM = winrmClient
			log.Info("interactive WinRM shell through the proxy enabled")
		}
		var jump *proxy.JumpConfig
		if cfg.SSHJumpHost != "" {
			keyPEM, jerr := os.ReadFile(cfg.SSHJumpKey)
			if jerr != nil {
				return fmt.Errorf("ssh jump key %q: %w", cfg.SSHJumpKey, jerr)
			}
			jump = &proxy.JumpConfig{Addr: cfg.SSHJumpHost, User: cfg.SSHJumpUser, KeyPEM: string(keyPEM), HostKey: upstreamHostKey}
		}
		px, err := proxy.New(st, v, resolver, proxy.Config{
			HostKey:              hostKey,
			RecordingDir:         cfg.RecordingDir,
			Sessions:             sessions,
			RequireApproval:      cfg.RequireApproval,
			UpstreamHostKey:      upstreamHostKey,
			OnSessionEnd:         onSessionEnd,
			OnSessionForensics:   onForensics,
			OnBreakGlass:         handler.NoteBreakGlassSignal,
			AllowedProtocols:     splitAndTrim(cfg.AllowedProtocols),
			WinRMRunner:          proxyWinRM,
			Jump:                 jump,
			RequireRecording:     cfg.RequireRecording,
			RequireSupervision:   cfg.RequireSupervision,
			SupervisionTimeout:   cfg.SupervisionTimeout,
			CommandGuard:         cmdGuard,
			CommandAllowGuard:    cmdAllowGuard,
			Live:                 liveHub,
			Shares:               shares,
			EndpointAgents:       endpointAgents,
			CA:                   sshCA,
			CertTTL:              cfg.SSHCertTTL,
			AuthRatePerMin:       cfg.ProxyAuthRatePerMin,
			MaxRecordingBytes:    maxRecBytes,
			EncryptRecordings:    cfg.EncryptRecordings,
			OpaqueRecordingNames: cfg.OpaqueRecordingNames,
			SFTPMode:             proxy.SFTPMode(cfg.SSHSFTPMode),
			SFTPPathGuard:        sftpPathGuard,
			TicketCheck:          ticketRecheck,
			PostureAttestor:      postureAttestor,
			SFTPCapture:          sftpCapture,
			SFTPCaptureMaxBytes:  int64(cfg.SSHSFTPCaptureMaxMB) * 1024 * 1024,
			PortForward:          cfg.SSHPortForward,
			ICAPClient:           icapClient,
		})
		if err != nil {
			return err
		}
		go func() {
			defer close(proxyDone)
			if err := px.ListenAndServe(ctx, cfg.SSHAddr); err != nil && ctx.Err() == nil {
				// A bind/listener failure (not graceful shutdown) is fatal: the PAM
				// must not run without its session broker.
				log.Error("ssh proxy stopped", "err", err)
				select {
				case errc <- fmt.Errorf("ssh proxy: %w", err):
				default:
				}
			}
		}()
	}

	// Database session proxies (Phase 15 PostgreSQL, Phase 53 SQL Server). Both
	// legs' TLS is built ONCE here and shared: two independent parses of the same
	// certificate and CA bundle could disagree, and an operator reasonably
	// expects one database TLS posture, not one per protocol.
	var dbClientTLS, dbUpstreamTLS *tls.Config
	if cfg.DBAddr != "off" || cfg.MSSQLAddr != "off" {
		if cfg.TLSCert != "" && cfg.TLSKey != "" {
			cert, cerr := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
			if cerr != nil {
				return fmt.Errorf("db proxy tls: %w", cerr)
			}
			dbClientTLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
		}
		if cfg.RequireDBClientTLS && dbClientTLS == nil {
			return errors.New("PAM_REQUIRE_DB_CLIENT_TLS is set but no TLS is configured for the database proxy operator leg; set PAM_TLS_CERT and PAM_TLS_KEY")
		}
		// Upstream (target) TLS verification for the credential-bearing leg: a
		// pinned CA bundle or verification against the system roots. Unset leaves
		// the legacy trust-any-with-warning behavior.
		if cfg.DBUpstreamCA != "" {
			pem, rerr := os.ReadFile(cfg.DBUpstreamCA)
			if rerr != nil {
				return fmt.Errorf("db upstream ca: %w", rerr)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return fmt.Errorf("db upstream ca: no certificates found in %s", cfg.DBUpstreamCA)
			}
			dbUpstreamTLS = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
		} else if cfg.DBUpstreamTLSVerify {
			dbUpstreamTLS = &tls.Config{MinVersion: tls.VersionTLS12}
		}
	}

	// PostgreSQL session proxy (Phase 15): brokers postgres targets with JIT
	// credential injection and per-statement query audit, on its own listener.
	if cfg.DBAddr != "off" {
		var dbOnSessionEnd func(int64)
		if cfg.RotateAfterSession {
			dbOnSessionEnd = func(credID int64) { handler.RotateCredentialByID(context.Background(), credID) }
		}
		dbx, err := proxy.NewDB(st, v, resolver, proxy.DBConfig{
			RecordingDir:         cfg.RecordingDir,
			Sessions:             sessions,
			RequireApproval:      cfg.RequireApproval,
			TicketCheck:          ticketRecheck,
			PostureAttestor:      postureAttestor,
			AllowedProtocols:     splitAndTrim(cfg.AllowedProtocols),
			RequireRecording:     cfg.RequireRecording,
			ClientTLS:            dbClientTLS,
			OnSessionEnd:         dbOnSessionEnd,
			OnBreakGlass:         handler.NoteBreakGlassSignal,
			CommandGuard:         cmdGuard,
			CommandAllowGuard:    cmdAllowGuard,
			Live:                 liveHub,
			AuthRatePerMin:       cfg.ProxyAuthRatePerMin,
			MaxRecordingBytes:    maxRecBytes,
			EncryptRecordings:    cfg.EncryptRecordings,
			OpaqueRecordingNames: cfg.OpaqueRecordingNames,
			UpstreamTLS:          dbUpstreamTLS,
			StepUpGuard:          stepupGuard,
			StepUp:               stepUp,
			StepUpTTL:            cfg.DBStepUpTTL,
		})
		if err != nil {
			return err
		}
		go func() {
			defer close(dbProxyDone)
			if err := dbx.ListenAndServe(ctx, cfg.DBAddr); err != nil && ctx.Err() == nil {
				log.Error("database proxy stopped", "err", err)
				select {
				case errc <- fmt.Errorf("database proxy: %w", err):
				default:
				}
			}
		}()
	}

	// SQL Server session proxy (Phase 53): the TDS sibling of the PostgreSQL
	// listener above — same gates, same guards, same recording and live hub, a
	// different wire protocol.
	if cfg.MSSQLAddr != "off" {
		var msOnSessionEnd func(int64)
		if cfg.RotateAfterSession {
			msOnSessionEnd = func(credID int64) { handler.RotateCredentialByID(context.Background(), credID) }
		}
		mx, err := proxy.NewMSSQL(st, v, resolver, proxy.MSSQLConfig{
			RecordingDir:         cfg.RecordingDir,
			Sessions:             sessions,
			RequireApproval:      cfg.RequireApproval,
			TicketCheck:          ticketRecheck,
			PostureAttestor:      postureAttestor,
			AllowedProtocols:     splitAndTrim(cfg.AllowedProtocols),
			RequireRecording:     cfg.RequireRecording,
			ClientTLS:            dbClientTLS,
			OnSessionEnd:         msOnSessionEnd,
			OnBreakGlass:         handler.NoteBreakGlassSignal,
			CommandGuard:         cmdGuard,
			CommandAllowGuard:    cmdAllowGuard,
			Live:                 liveHub,
			AuthRatePerMin:       cfg.ProxyAuthRatePerMin,
			MaxRecordingBytes:    maxRecBytes,
			EncryptRecordings:    cfg.EncryptRecordings,
			OpaqueRecordingNames: cfg.OpaqueRecordingNames,
			UpstreamTLS:          dbUpstreamTLS,
			StepUpGuard:          stepupGuard,
			StepUp:               stepUp,
			StepUpTTL:            cfg.DBStepUpTTL,
		})
		if err != nil {
			return err
		}
		go func() {
			defer close(mssqlProxyDone)
			if err := mx.ListenAndServe(ctx, cfg.MSSQLAddr); err != nil && ctx.Err() == nil {
				log.Error("sql server proxy stopped", "err", err)
				select {
				case errc <- fmt.Errorf("sql server proxy: %w", err):
				default:
				}
			}
		}()
	}

	return serveAndShutDown(ctx, stop, cfg, handler, log, errc, []proxyDrain{
		{"ssh proxy", proxyDone},
		{"database proxy", dbProxyDone},
		{"sql server proxy", mssqlProxyDone},
	})
}

// proxyDrain names one session listener whose graceful stop must finish before
// the store is closed under it.
type proxyDrain struct {
	name string
	done <-chan struct{}
}

// serveAndShutDown runs the API/portal listener until it fails or ctx is
// cancelled, then shuts it down and drains the session proxies.
//
// Split out of run() because it is the one part of that wiring genuinely
// separable: everything above it builds forty locals feeding one 65-field
// Options literal, so extracting THAT would return the same forty under a new
// name. This takes what it needs and nothing else.
//
// The drains are a slice rather than three copy-pasted selects. They were three
// near-identical blocks — the shape that loses a listener the day a fourth is
// added, which is the same hazard the two database proxies carry and now have a
// test for.
func serveAndShutDown(ctx context.Context, stop func(), cfg *config.Config, handler http.Handler,
	log *slog.Logger, errc chan error, drains []proxyDrain) error {
	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	tlsEnabled := cfg.TLSCert != "" && cfg.TLSKey != ""
	// Fail closed on plaintext transport when the operator demands HTTPS: the
	// bootstrap key and revealed secrets travel over this channel, so refuse to
	// start rather than silently serve them in the clear.
	if cfg.RequireHTTPS && !tlsEnabled {
		return errors.New("PAM_REQUIRE_HTTPS is set but native TLS is not configured; set PAM_TLS_CERT and PAM_TLS_KEY (or terminate TLS at a trusted proxy and unset PAM_REQUIRE_HTTPS)")
	}
	if tlsEnabled {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		log.Warn("serving the API/portal over PLAINTEXT HTTP; set PAM_TLS_CERT/KEY or PAM_REQUIRE_HTTPS, or terminate TLS at a trusted proxy")
	}
	go func() {
		if tlsEnabled {
			errc <- srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			errc <- srv.ListenAndServe()
		}
	}()
	log.Info("pam-server listening", "version", version, "commit", commit, "addr", cfg.ListenAddr, "tls", tlsEnabled,
		"breakglass", cfg.BreakGlassKeyHash != "", "log_level", cfg.LogLevel)

	// drainProxies cancels the run context (so each proxy's Serve returns) and
	// waits, bounded, for every one to finish flushing session audit and
	// recordings before the deferred st.Close() runs — on either exit path.
	drainProxies := func() {
		stop() // cancel ctx so the proxies drain
		for _, d := range drains {
			select {
			case <-d.done:
			case <-time.After(10 * time.Second):
				log.Warn("proxy drain timed out", "proxy", d.name)
			}
		}
	}

	select {
	case err := <-errc:
		// A listener failed. Shut the HTTP server and drain the proxy before
		// returning, so the store isn't closed under live sessions.
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		drainProxies()
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := srv.Shutdown(shutCtx)
		drainProxies()
		return err
	}
}

// buildAlerter assembles the configured real-time alert channels (webhook,
// syslog, email) into one Notifier, fanning out when several are set. Air-gap
// mode disables all outbound alerting.
func buildAlerter(cfg *config.Config, log *slog.Logger) alert.Notifier {
	if cfg.AirGap {
		log.Info("air-gap mode: outbound alerting disabled")
		return alert.Noop{}
	}
	var ns []alert.Notifier
	if cfg.AlertWebhook != "" {
		if !strings.HasPrefix(cfg.AlertWebhook, "https://") && !strings.HasPrefix(cfg.AlertWebhook, "http://127.0.0.1") {
			log.Warn("alert webhook is not https; break-glass alerts will transit in cleartext", "url_scheme", "http")
		}
		ns = append(ns, alert.NewWebhook(cfg.AlertWebhook))
		log.Info("alert channel enabled", "kind", "webhook")
	}
	if cfg.AlertSyslog != "" {
		network, addr := "udp", cfg.AlertSyslog
		for _, p := range []string{"udp", "tcp"} {
			if rest, ok := strings.CutPrefix(addr, p+"://"); ok {
				network, addr = p, rest
			}
		}
		ns = append(ns, alert.NewSyslog(network, addr, "pamv1"))
		log.Info("alert channel enabled", "kind", "syslog", "addr", addr)
	}
	if cfg.AlertEmailSMTP != "" && cfg.AlertEmailFrom != "" && cfg.AlertEmailTo != "" {
		to := splitAndTrim(cfg.AlertEmailTo)
		ns = append(ns, alert.NewEmail(cfg.AlertEmailSMTP, cfg.AlertEmailFrom, to, cfg.AlertEmailUser, cfg.AlertEmailPass))
		log.Info("alert channel enabled", "kind", "email", "recipients", len(to))
	}
	switch len(ns) {
	case 0:
		return alert.Noop{}
	case 1:
		return ns[0]
	default:
		return alert.Multi(ns)
	}
}

// splitAndTrim splits a comma-separated list, dropping empty/whitespace entries.
func splitAndTrim(csv string) []string {
	var out []string
	for _, p := range strings.Split(csv, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// startSecretRefresh wires the opt-in Conjur secret refresher, or explains why
// it did not.
//
// Every branch that declines to start it says so. The first version logged only
// on the success path, so an operator who set PAM_CONJUR_REFRESH_MIN without
// Conjur configured — or with a typo in PAM_CONJUR_URL — got a clean startup, no
// refresh, and nothing anywhere saying why. "Watching nothing happen" is the
// outcome this whole feature is supposed to prevent.
func startSecretRefresh(ctx context.Context, cfg *config.Config, client *conjur.Client,
	filled []string, resolver *auth.Resolver, st store.Store, handler *api.Server,
	alerter alert.Notifier, log *slog.Logger) error {
	if cfg.ConjurRefreshMin <= 0 {
		return nil
	}
	if client == nil {
		log.Warn("PAM_CONJUR_REFRESH_MIN is set but Conjur is not configured; no secret will be refreshed",
			"hint", "set PAM_CONJUR_URL (or PAM_SECRETS_PROVIDER=conjur) — refresh sources from Conjur only")
		return nil
	}
	overrides, err := conjur.ParseVarOverrides(os.Getenv("PAM_CONJUR_VARS"))
	if err != nil {
		return err
	}

	// The appliers ARE the definition of what can be refreshed. A secret absent
	// from this map is never fetched, never applied and never audited — which is
	// what stops a "refreshed" event being recorded for something that reached no
	// consumer.
	appliers := map[string]conjur.SecretApplier{
		"PAM_API_KEY": func(v string) error {
			// The same rule Load enforces at startup. Without it a running server
			// would adopt a bootstrap key the next restart refuses to boot with.
			if verr := config.ValidateBootstrapAPIKey(v, cfg.DatabaseURL); verr != nil {
				return verr
			}
			return resolver.SetBootstrapAPIKey(v)
		},
		"PAM_BREAK_GLASS_KEY_HASH": resolver.SetBreakGlassHash,
	}

	refresher, err := conjur.NewRefresher(ctx, client, conjur.RefreshOptions{
		Prefix:    cmp.Or(os.Getenv("PAM_CONJUR_POLICY_PREFIX"), "pamv1"),
		Overrides: overrides,
		Appliers:  appliers,
		Audit: func(actx context.Context, action, detail string) error {
			return st.AppendAudit(actx, &store.AuditEvent{
				// Self-describing like every other background writer
				// (system-scheduler, system-analytics, kek-rotation, relay); a bare
				// "system" is not in the documented actor vocabulary.
				Actor: "system-conjur", Action: action, Detail: detail,
			})
		},
		OnError: func(actx context.Context, rerr error) {
			handler.Metrics().SecretRefreshFailed()
			if alerter != nil {
				alerter.Notify(actx, alert.Event{
					Type: "config.secret_refresh_failed", Actor: "system-conjur",
					Detail: "source:conjur error:" + rerr.Error(), Time: time.Now().UTC(),
				})
			}
		},
		Log: log,
	})
	if err != nil {
		return fmt.Errorf("conjur secret refresh: %w", err)
	}
	if refresher == nil {
		log.Warn("runtime secret refresh is enabled but Conjur manages none of the refreshable secrets; nothing will be refreshed",
			"refreshable", strings.Join(sortedKeys(appliers), ","),
			"hint", "create those variables under PAM_CONJUR_POLICY_PREFIX, or map them with PAM_CONJUR_VARS")
		return nil
	}

	owned := refresher.Owned()
	// Name what will ACTUALLY be refreshed, not what could be in principle. The
	// first version printed the static list, so it promised rotations that every
	// tick then skipped.
	log.Info("runtime secret refresh enabled",
		"every_min", cfg.ConjurRefreshMin,
		"refreshes", strings.Join(owned, ","),
		"restart_required_for", strings.Join(pinnedSecrets(appliers), ","))
	for _, env := range owned {
		if !slices.Contains(filled, env) {
			log.Warn("a refreshable secret is set in the environment AND managed in Conjur; enabling refresh means Conjur wins for it",
				"var", env)
		}
	}
	go refresher.Run(ctx, time.Duration(cfg.ConjurRefreshMin)*time.Minute)
	return nil
}

// sortedKeys lists an applier map's names, sorted, for logging.
func sortedKeys(m map[string]conjur.SecretApplier) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// pinnedSecrets lists the bootstrap secrets a restart is the only way to change
// — derived from the appliers, so the two lists cannot drift apart.
func pinnedSecrets(appliers map[string]conjur.SecretApplier) []string {
	var out []string
	for _, name := range conjur.AllSecrets() {
		if appliers[name] == nil {
			out = append(out, name)
		}
	}
	return out
}

// buildTicketProvider selects the ITSM connector from PAM_TICKET_PROVIDER.
//
// The default is the generic webhook when only PAM_TICKET_VALIDATE_URL is set,
// so an existing deployment keeps working untouched. The first-class connectors
// exist because a 2xx webhook can only answer "does this ticket exist" — it
// cannot check the change's state, its approved window, or whether the ticket
// names the person connecting, and without that last one a valid change number
// is a password shared with everyone in the change queue.
func buildTicketProvider(cfg *config.Config) (ticket.Provider, error) {
	pc := ticket.ProviderConfig{
		BaseURL:       cfg.TicketURL,
		User:          cfg.TicketUser,
		Token:         cfg.TicketToken,
		AllowedStates: cfg.TicketStates,
		ActorFields:   cfg.TicketActorFields,
		RequireWindow: cfg.TicketRequireWindow,
		BindActor:     cfg.TicketBindActor,
	}
	switch cfg.TicketProvider {
	case "servicenow":
		if cfg.TicketURL == "" {
			return nil, errors.New("PAM_TICKET_PROVIDER=servicenow requires PAM_TICKET_URL (e.g. https://acme.service-now.com)")
		}
		return ticket.NewServiceNow(pc), nil
	case "jira":
		if cfg.TicketURL == "" {
			return nil, errors.New("PAM_TICKET_PROVIDER=jira requires PAM_TICKET_URL (e.g. https://acme.atlassian.net)")
		}
		return ticket.NewJira(pc), nil
	case "webhook":
		if cfg.TicketValidateURL == "" {
			return nil, errors.New("PAM_TICKET_PROVIDER=webhook requires PAM_TICKET_VALIDATE_URL")
		}
		return ticket.NewWebhook(cfg.TicketValidateURL, nil), nil
	case "":
		// Unset: the webhook if one is configured, otherwise format-only (or
		// nothing). This is the pre-Phase-84 behaviour, unchanged.
		if cfg.TicketValidateURL != "" {
			return ticket.NewWebhook(cfg.TicketValidateURL, nil), nil
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("PAM_TICKET_PROVIDER must be webhook, servicenow or jira (got %q)", cfg.TicketProvider)
	}
}
