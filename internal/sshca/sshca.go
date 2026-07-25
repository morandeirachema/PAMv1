// Package sshca implements a Zero Standing Privilege (ZSP) SSH certificate
// authority. Instead of storing a long-lived password or private key for a
// privileged account, pamv1 signs a short-lived SSH *user certificate*
// just-in-time for each proxied session. The target trusts only the pamv1 CA
// (its public key installed as an OpenSSH TrustedUserCAKeys), so the account
// has no standing secret at all — the certificate is minted fresh per session
// and expires in minutes. This is the Teleport / CyberArk ZSP model applied to
// pamv1's existing JIT proxy chokepoint.
//
// The CA private key never signs anything but short-TTL user certificates, and
// the per-session client keypair is generated in memory, used for one dial, and
// discarded — no secret is ever persisted for the account.
package sshca

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// encodePEM serializes a PEM block to its textual encoding.
func encodePEM(b *pem.Block) []byte { return pem.EncodeToMemory(b) }

// clockSkew is how far before "now" a minted certificate becomes valid, to
// tolerate small clock differences between pamv1 and the target.
const clockSkew = 1 * time.Minute

// CertAuthority signs short-lived SSH user certificates. It holds the CA
// private key and a monotonically increasing serial counter (unique per issued
// certificate, for audit correlation).
type CertAuthority struct {
	signer ssh.Signer
	serial atomic.Uint64
	chOnce sync.Once
	chKey  []byte // HMAC key for proof-of-possession challenges (derived from the CA key)
}

// New builds a CertAuthority from an existing SSH signer (the CA private key).
func New(signer ssh.Signer) *CertAuthority {
	ca := &CertAuthority{signer: signer}
	// Seed the serial from the wall clock so certificate serials do not restart
	// from a low value (and collide with a prior run) across restarts. The value
	// is only for audit correlation, not security.
	ca.serial.Store(uint64(time.Now().UnixNano()))
	return ca
}

// LoadOrCreate parses an OpenSSH CA private key from path, generating and
// persisting a fresh ed25519 key (0600) when the file does not yet exist — so
// the CA public key stays stable across restarts (targets pin it). An empty
// path is an error: a ZSP CA must be persistent to be useful.
func LoadOrCreate(path string) (*CertAuthority, error) {
	if path == "" {
		return nil, errors.New("sshca: a persistent key path is required")
	}
	data, err := os.ReadFile(path)
	if err == nil {
		signer, perr := ssh.ParsePrivateKey(data)
		if perr != nil {
			return nil, fmt.Errorf("sshca: parse CA key %q: %w", path, perr)
		}
		return New(signer), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, encodePEM(block), 0o600); err != nil {
		return nil, fmt.Errorf("sshca: write CA key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	return New(signer), nil
}

// PublicKey returns the CA's SSH public key (what a target trusts).
func (ca *CertAuthority) PublicKey() ssh.PublicKey { return ca.signer.PublicKey() }

// AuthorizedKey returns the CA public key as an OpenSSH authorized_keys line
// (trailing newline trimmed), ready to drop into a target's TrustedUserCAKeys.
func (ca *CertAuthority) AuthorizedKey() string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ca.signer.PublicKey())))
}

// Fingerprint returns the CA public key's SHA-256 fingerprint (for display).
func (ca *CertAuthority) Fingerprint() string {
	return ssh.FingerprintSHA256(ca.signer.PublicKey())
}

// IssueUser mints a short-lived SSH user certificate for principal, valid for
// ttl, and returns a signer that authenticates with it. A fresh ephemeral
// keypair backs each certificate: the private key lives only in the returned
// signer (one dial, then discarded), so no standing secret exists for the
// account. keyID is stamped into the certificate (pamv1 records the actor and
// target there) for audit correlation on the target's sshd logs. The returned
// certificate is also handed back so the caller can audit its serial/validity.
func (ca *CertAuthority) IssueUser(principal string, ttl time.Duration, keyID string) (ssh.Signer, *ssh.Certificate, error) {
	if principal == "" {
		return nil, nil, errors.New("sshca: empty certificate principal")
	}
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	userSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	cert := &ssh.Certificate{
		Key:             userSigner.PublicKey(),
		Serial:          ca.serial.Add(1),
		CertType:        ssh.UserCert,
		KeyId:           keyID,
		ValidPrincipals: []string{principal},
		ValidAfter:      uint64(now.Add(-clockSkew).Unix()),
		ValidBefore:     uint64(now.Add(ttl).Unix()),
		Permissions: ssh.Permissions{
			Extensions: standardExtensions(),
		},
	}
	if err := cert.SignCert(rand.Reader, ca.signer); err != nil {
		return nil, nil, fmt.Errorf("sshca: sign certificate: %w", err)
	}
	certSigner, err := ssh.NewCertSigner(cert, userSigner)
	if err != nil {
		return nil, nil, fmt.Errorf("sshca: cert signer: %w", err)
	}
	return certSigner, cert, nil
}

// IssueOpts scopes an operator-facing certificate (Phase 28). The operator holds
// the private key; pamv1 signs only their public key, so no secret is generated
// or stored. Principals must be non-empty; SourceAddress / ForceCommand become
// OpenSSH critical options that a target's sshd enforces.
type IssueOpts struct {
	Principals    []string      // ValidPrincipals the cert authorizes login as
	TTL           time.Duration // validity (clamped by the caller); default 2m
	KeyID         string        // key-id stamped for audit correlation (actor·target)
	SourceAddress string        // optional "source-address" critical option (comma CIDR list)
	ForceCommand  string        // optional "force-command" critical option
}

// IssueForKey signs a caller-supplied public key into a short-lived user
// certificate scoped by opts, and returns the signed certificate (the operator
// already holds the matching private key). Unlike IssueUser this generates no key
// and stores no secret; the certificate simply expires. The serial (unique per
// issue, shared with the proxy's ZSP minting) is the handle for later revocation.
func (ca *CertAuthority) IssueForKey(pub ssh.PublicKey, opts IssueOpts) (*ssh.Certificate, error) {
	if pub == nil {
		return nil, errors.New("sshca: nil public key")
	}
	if len(opts.Principals) == 0 {
		return nil, errors.New("sshca: at least one certificate principal is required")
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	crit := map[string]string{}
	if opts.SourceAddress != "" {
		crit["source-address"] = opts.SourceAddress
	}
	if opts.ForceCommand != "" {
		crit["force-command"] = opts.ForceCommand
	}
	now := time.Now()
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          ca.serial.Add(1),
		CertType:        ssh.UserCert,
		KeyId:           opts.KeyID,
		ValidPrincipals: append([]string(nil), opts.Principals...),
		ValidAfter:      uint64(now.Add(-clockSkew).Unix()),
		ValidBefore:     uint64(now.Add(ttl).Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: crit,
			Extensions:      standardExtensions(),
		},
	}
	if err := cert.SignCert(rand.Reader, ca.signer); err != nil {
		return nil, fmt.Errorf("sshca: sign certificate: %w", err)
	}
	return cert, nil
}

// challengeMACKey derives a stable, secret HMAC key for proof-of-possession
// challenges from the CA private key (a signature over a fixed label). For the
// ed25519 CA key LoadOrCreate generates by default — and any deterministic signer
// (ed25519, RSA PKCS#1v1.5) — every replica sharing the CA key derives the SAME
// key, so a challenge minted on one replica verifies on another. A randomized
// signer (ECDSA) would derive a per-process key, so multi-replica deployments on
// an ECDSA CA should use a sticky session for the challenge→sign round-trip. A
// party without the CA private key cannot forge a challenge either way. (Safe to
// reuse the CA key here because nothing else ever signs raw caller-chosen bytes
// with it — the label is fixed and server-controlled.)
func (ca *CertAuthority) challengeMACKey() []byte {
	ca.chOnce.Do(func() {
		sig, err := ca.signer.Sign(rand.Reader, []byte("pamv1-ssh-cert-challenge-key-v1"))
		if err != nil {
			// Fall back to a per-process random key (challenges then don't cross
			// replicas — acceptable, they are short-lived).
			k := make([]byte, 32)
			_, _ = rand.Read(k)
			ca.chKey = k
			return
		}
		sum := sha256.Sum256(sig.Blob)
		ca.chKey = sum[:]
	})
	return ca.chKey
}

// MintChallenge returns an opaque, self-authenticating proof-of-possession
// challenge valid for ttl: the operator signs it with their private key and
// returns the signature to /sign, proving they hold the key they want certified.
// The challenge carries its own expiry and HMAC, so verification is stateless
// (no server-side nonce store) and HA-safe.
func (ca *CertAuthority) MintChallenge(ttl time.Duration) string {
	if ttl == 0 {
		ttl = 2 * time.Minute
	}
	payload := make([]byte, 8+16)
	binary.BigEndian.PutUint64(payload[:8], uint64(time.Now().Add(ttl).Unix()))
	_, _ = rand.Read(payload[8:])
	mac := hmac.New(sha256.New, ca.challengeMACKey())
	mac.Write(payload)
	token := append(payload, mac.Sum(nil)[:16]...)
	return "pamv1chal-" + base64.RawURLEncoding.EncodeToString(token)
}

// VerifyChallenge reports whether challenge is one this CA minted and has not
// expired. It does NOT verify the operator's signature — the caller does that
// against the presented public key.
func (ca *CertAuthority) VerifyChallenge(challenge string) bool {
	const prefix = "pamv1chal-"
	if !strings.HasPrefix(challenge, prefix) {
		return false
	}
	token, err := base64.RawURLEncoding.DecodeString(challenge[len(prefix):])
	if err != nil || len(token) != 8+16+16 {
		return false
	}
	payload, tag := token[:24], token[24:]
	mac := hmac.New(sha256.New, ca.challengeMACKey())
	mac.Write(payload)
	if subtle.ConstantTimeCompare(mac.Sum(nil)[:16], tag) != 1 {
		return false
	}
	exp := int64(binary.BigEndian.Uint64(payload[:8]))
	return time.Now().Unix() < exp
}

// KRL builds an OpenSSH Key Revocation List revoking the given certificate
// serials, scoped to this CA (per PROTOCOL.krl). A target installs it via sshd's
// RevokedKeys so a still-valid certificate can be cut off before it expires. An
// empty serial list yields a valid KRL that revokes nothing.
func (ca *CertAuthority) KRL(serials []uint64, krlVersion uint64, now time.Time) []byte {
	var b []byte
	b = append(b, []byte("SSHKRL\n\x00")...) // magic (8 bytes)
	b = putU32(b, 1)                         // format_version
	b = putU64(b, krlVersion)                // krl_version
	b = putU64(b, uint64(now.Unix()))        // generated_date
	b = putU64(b, 0)                         // flags
	b = putString(b, nil)                    // reserved
	b = putString(b, []byte("pamv1"))        // comment

	if len(serials) > 0 {
		// CERTIFICATES section body: ca_key, reserved, then a SERIAL_LIST subsection.
		var body []byte
		body = putString(body, ca.signer.PublicKey().Marshal())
		body = putString(body, nil) // reserved
		var serialData []byte
		for _, s := range serials {
			serialData = putU64(serialData, s)
		}
		body = append(body, 0x20) // KRL_SECTION_CERT_SERIAL_LIST
		body = putString(body, serialData)

		b = append(b, 0x01) // KRL_SECTION_CERTIFICATES
		b = putString(b, body)
	}
	return b
}

// putU32 / putU64 / putString append SSH-wire primitives (big-endian ints, and
// a uint32-length-prefixed byte string) used by the KRL encoder.
func putU32(b []byte, v uint32) []byte {
	var x [4]byte
	binary.BigEndian.PutUint32(x[:], v)
	return append(b, x[:]...)
}

func putU64(b []byte, v uint64) []byte {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], v)
	return append(b, x[:]...)
}

func putString(b, s []byte) []byte {
	b = putU32(b, uint32(len(s)))
	return append(b, s...)
}

// standardExtensions returns the permissive extension set OpenSSH grants a user
// certificate by default, so an interactive session (pty, shell, exec) works.
func standardExtensions() map[string]string {
	return map[string]string{
		"permit-X11-forwarding":   "",
		"permit-agent-forwarding": "",
		"permit-port-forwarding":  "",
		"permit-pty":              "",
		"permit-user-rc":          "",
	}
}
