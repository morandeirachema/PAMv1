package api

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/sshca"
	"github.com/morandeirachema/pamv1/internal/store"
	"golang.org/x/crypto/ssh"
)

// sshCAPublicKey publishes the Zero Standing Privilege SSH certificate-authority
// public key (Phase 22) so an operator can trust it on their targets. Installing
// this key as the target's OpenSSH TrustedUserCAKeys lets the account accept the
// short-lived certificates pamv1 mints just-in-time — no standing secret is ever
// stored for the account. Returns 404 when ZSP is not enabled (no CA configured).
func (s *Server) sshCAPublicKey(w http.ResponseWriter, r *http.Request) {
	if s.sshCA == nil {
		writeError(w, http.StatusNotFound, "zero standing privilege is not enabled (set PAM_SSH_CA_KEY)")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"type":        "ssh_ca",
		"public_key":  s.sshCA.AuthorizedKey(),
		"fingerprint": s.sshCA.Fingerprint(),
		"install_hint": "Install on each target: write this line to /etc/ssh/pamv1_ca.pub, " +
			"add `TrustedUserCAKeys /etc/ssh/pamv1_ca.pub` to sshd_config, and reload sshd. " +
			"Then create an ssh_ca credential for the account and connect through the proxy.",
	})
}

// sshCertChallengeTTL bounds a proof-of-possession challenge's lifetime.
const sshCertChallengeTTL = 2 * time.Minute

// sshCACertChallenge mints a proof-of-possession challenge (Phase 28): the
// operator signs it with the private key they want certified and returns the
// signature to /sign, proving they hold the key. Requires CapConnect.
func (s *Server) sshCACertChallenge(w http.ResponseWriter, r *http.Request) {
	if s.sshCA == nil {
		writeError(w, http.StatusNotFound, "the SSH certificate authority is not enabled (set PAM_SSH_CA_KEY)")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge":  s.sshCA.MintChallenge(sshCertChallengeTTL),
		"expires_in": int(sshCertChallengeTTL.Seconds()),
		"hint":       "Sign the challenge bytes with your SSH private key and POST public_key + challenge + signature to /api/ca/ssh/sign.",
	})
}

type signCertIn struct {
	PublicKey     string `json:"public_key"`     // operator's public key, authorized_keys form
	Challenge     string `json:"challenge"`      // from /api/ca/ssh/challenge
	Signature     string `json:"signature"`      // base64 ssh signature over the challenge bytes
	Target        string `json:"target"`         // target the cert authorizes access to
	Principal     string `json:"principal"`      // login account (must be a credential username on the target)
	SourceAddress string `json:"source_address"` // optional source-address critical option (CIDR list)
	TTLMinutes    int    `json:"ttl_minutes"`    // requested validity (clamped to the operator-cert cap)
}

// signOperatorCert signs an operator's own SSH public key into a short-lived
// certificate scoped to a target account (Phase 28). The operator proves
// possession of the private key (challenge + signature), passes the same connect
// authorization as the proxy (per-target grants + the approval gate — a one-time
// approval is consumed), and the principal must be a managed account on the
// target. The certificate is recorded so its serial can later be revoked via the
// KRL. Requires CapConnect.
func (s *Server) signOperatorCert(w http.ResponseWriter, r *http.Request) {
	if s.sshCA == nil {
		writeError(w, http.StatusNotFound, "the SSH certificate authority is not enabled (set PAM_SSH_CA_KEY)")
		return
	}
	var in signCertIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.Target == "" || in.Principal == "" || in.PublicKey == "" {
		writeError(w, http.StatusUnprocessableEntity, "target, principal and public_key are required")
		return
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(in.PublicKey))
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "public_key is not a valid SSH public key")
		return
	}
	if _, isCert := pub.(*ssh.Certificate); isCert {
		writeError(w, http.StatusUnprocessableEntity, "present a bare public key, not a certificate")
		return
	}
	// Proof of possession: the challenge must be one we minted (unexpired) and the
	// signature over it must verify against the presented public key.
	if !s.sshCA.VerifyChallenge(in.Challenge) {
		writeError(w, http.StatusUnprocessableEntity, "invalid or expired challenge")
		return
	}
	sig, err := decodeSSHSignature(in.Signature)
	if err != nil || pub.Verify([]byte(in.Challenge), sig) != nil {
		s.audit(r.Context(), "ssh.cert_denied", "target:"+in.Target+" reason:proof-of-possession-failed")
		writeError(w, http.StatusUnprocessableEntity, "signature does not prove possession of the private key")
		return
	}

	target, err := s.targetByName(r.Context(), in.Target)
	if err != nil {
		writeError(w, http.StatusNotFound, "unknown target")
		return
	}
	if target.Protocol != "ssh" {
		writeError(w, http.StatusUnprocessableEntity, "target protocol is not ssh")
		return
	}
	if !s.protocolAllowed("ssh") {
		writeError(w, http.StatusForbidden, "ssh is not allowed by policy")
		return
	}
	// The principal must be a managed account on the target, so an operator can't
	// mint a cert for an arbitrary login (e.g. root) the vault doesn't govern.
	// Checked BEFORE the approval gate below, so a bad principal is rejected without
	// consuming a one-time access approval.
	creds, err := s.store.ListCredentials(r.Context(), target.ID, 0, 0)
	if err != nil {
		storeError(w, err)
		return
	}
	if !credentialUsernameExists(creds, in.Principal) {
		writeError(w, http.StatusUnprocessableEntity, "principal is not a managed account on this target")
		return
	}
	// Same connect authorization as any other path to this target (grants ∪ safes,
	// approval — which may consume a one-time request — and the vendor gate for the
	// requested principal account).
	if !s.gateCredentialAccess(w, r, target, in.Principal, "ssh.cert_issue") {
		return
	}

	ttl := s.sshOperatorCertTTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if in.TTLMinutes > 0 && time.Duration(in.TTLMinutes)*time.Minute < ttl {
		ttl = time.Duration(in.TTLMinutes) * time.Minute // honor a shorter request; never longer than the cap
	}
	actor := actorFrom(r.Context())
	keyID := fmt.Sprintf("pamv1:%s@%s", actor, target.Name)
	cert, err := s.sshCA.IssueForKey(pub, sshca.IssueOpts{
		Principals:    []string{in.Principal},
		TTL:           ttl,
		KeyID:         keyID,
		SourceAddress: strings.TrimSpace(in.SourceAddress),
	})
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	validBefore := time.Unix(int64(cert.ValidBefore), 0).UTC()
	rec := store.SSHCert{Serial: int64(cert.Serial), KeyID: keyID, Principal: in.Principal, Actor: actor, ValidBefore: &validBefore}
	if err := s.store.RecordSSHCert(r.Context(), &rec); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "ssh.cert_issued", fmt.Sprintf("serial:%d principal:%s target:%s valid_before:%s source_address:%q",
		cert.Serial, in.Principal, target.Name, validBefore.Format(time.RFC3339), in.SourceAddress))
	writeJSON(w, http.StatusOK, map[string]any{
		"certificate": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert))),
		// Serial is a string: a uint64 seeded from a nanosecond clock exceeds an IEEE
		// double's exact-integer range, so a JSON number would corrupt the revocation
		// handle in any client that parses numbers as floats.
		"serial":       strconv.FormatUint(cert.Serial, 10),
		"principal":    in.Principal,
		"valid_before": validBefore,
		"note":         "Save this to id_key-cert.pub next to your private key; ssh uses it automatically. To revoke it early, ask a target manager to POST its serial to /api/ca/ssh/revoke.",
	})
}

type revokeCertIn struct {
	// Serial is accepted as a string (the sign response returns it as one) to
	// avoid the float64 precision loss a large uint64 JSON number would suffer.
	Serial string `json:"serial"`
}

// revokeOperatorCert marks a certificate serial revoked so the next KRL cuts it
// off before expiry. Requires CapManageTargets.
func (s *Server) revokeOperatorCert(w http.ResponseWriter, r *http.Request) {
	var in revokeCertIn
	if !readJSON(w, r, &in) {
		return
	}
	serial, err := strconv.ParseUint(strings.TrimSpace(in.Serial), 10, 64)
	if err != nil || serial == 0 {
		writeError(w, http.StatusUnprocessableEntity, "serial is required (decimal string)")
		return
	}
	err = s.store.RevokeSSHCert(r.Context(), int64(serial), actorFrom(r.Context()), time.Now())
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "unknown certificate serial")
		return
	}
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "certificate is already revoked")
		return
	}
	if err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "ssh.cert_revoked", fmt.Sprintf("serial:%d", serial))
	writeJSON(w, http.StatusOK, map[string]any{"serial": in.Serial, "revoked": true})
}

// sshCAKRL returns the OpenSSH Key Revocation List of revoked operator
// certificates, for a target to install as sshd's RevokedKeys. Requires
// CapReadInventory.
func (s *Server) sshCAKRL(w http.ResponseWriter, r *http.Request) {
	if s.sshCA == nil {
		writeError(w, http.StatusNotFound, "the SSH certificate authority is not enabled (set PAM_SSH_CA_KEY)")
		return
	}
	revoked, err := s.store.ListRevokedSSHCertSerials(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	serials := make([]uint64, len(revoked))
	for i, v := range revoked {
		serials[i] = uint64(v)
	}
	krl := s.sshCA.KRL(serials, uint64(time.Now().Unix()), time.Now())
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=pamv1-ssh.krl")
	_, _ = w.Write(krl)
}

// decodeSSHSignature decodes a base64 ssh-wire signature blob into an ssh.Signature.
func decodeSSHSignature(b64 string) (*ssh.Signature, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, err
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(raw, &sig); err != nil {
		return nil, err
	}
	return &sig, nil
}

// credentialUsernameExists reports whether creds includes one with the username.
func credentialUsernameExists(creds []store.Credential, username string) bool {
	for i := range creds {
		if creds[i].Username == username {
			return true
		}
	}
	return false
}
