package api

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"

	"github.com/morandeirachema/pamv1/internal/store"
)

// doublelock.go implements DoubleLock (Phase 135): a per-credential second
// password, held by a named person, additionally required (on top of normal
// RBAC) to reveal or check out that credential's plaintext — so even a
// compromised admin account can't read a Double-Locked secret alone.
//
// Deliberately independent of the vault/KEK layer, not an AAD tweak on the
// existing v2: envelope: DoubleLockEnc is a second ciphertext of the same
// secret, encrypted here with a key derived directly from the password
// (PBKDF2, no KEK involved at all). That was a build-time discovery, not the
// original plan: mixing a password tag into vault.Encrypt's AAD would have
// worked for reveal/checkout, but -rotate-kek re-wraps every KEK-protected
// artifact exhaustively (see internal/maint/rotate.go) and has no way to
// obtain a credential's DoubleLock password to redo that AAD — the same
// tension sealed session recordings already have with KEK rotation. Keeping
// DoubleLockEnc entirely outside the KEK sidesteps it: -rotate-kek never
// needs to know it exists, and it doesn't.
//
// SecretEnc itself is never touched by any of this: the session-proxy JIT-
// decrypt path always uses it, unmodified, with the standard AAD — a
// Double-Locked credential connects through the proxy exactly like any
// other, since the operator never sees the plaintext there either way. Only
// the two paths that DO hand plaintext to a caller — reveal and checkout —
// are gated.

const (
	// doubleLockIters is the PBKDF2 iteration count for a NEWLY sealed
	// DoubleLock. Raised to the OWASP PBKDF2-HMAC-SHA256 figure by the
	// 2026-08-26 audit (H-3), which found the previous 100 000 — with the old
	// comment reasoning it "does not need to match OWASP guidance" — protecting
	// a copy of a privileged secret at rest, keyed by a password the code
	// validated only for being non-empty. That comment was wrong: DoubleLockEnc
	// is deliberately outside the KEK, so a database-only compromise yields an
	// offline-crackable copy, and this password is the ONLY thing standing in
	// front of it. The iteration count is now stored per record (see
	// sealDoubleLock's format), so raising this does not break existing values;
	// they open at whatever count they were sealed with.
	doubleLockIters       = 600_000
	doubleLockLegacyIters = 100_000 // records with no stored count predate H-3
	doubleLockSalt        = 16      // bytes
	doubleLockKey         = 32      // bytes (AES-256)
	// doubleLockMinLen is the floor for a DoubleLock password. The real defense
	// against the offline attack is entropy, not iteration count: a long
	// passphrase is infeasible to brute-force at any reasonable cost, while a
	// short human password falls to a GPU regardless of PBKDF2 rounds. This is
	// the minimum; PAM_DOUBLELOCK_MIN_LENGTH can raise it.
	doubleLockMinLen = 16
)

// deriveDoubleLock returns the two independent PBKDF2 outputs DoubleLock
// needs from one (password, salt) pair: a verifier (checked first, cheap to
// compare, never used for the real decrypt) and an AES-256 key (used only
// once the verifier has already matched). Purpose-suffixing the password
// domain-separates the two outputs from a shared salt.
func deriveDoubleLock(password string, salt []byte, iters int) (verifier, key []byte) {
	verifier = pbkdf2.Key([]byte(password+"|verify"), salt, iters, doubleLockKey, sha256.New)
	key = pbkdf2.Key([]byte(password+"|key"), salt, iters, doubleLockKey, sha256.New)
	return verifier, key
}

// dlParams strips an optional `i=<n>;` iteration-count prefix from a stored
// DoubleLock string, returning the count and the remainder. A value with no
// prefix predates the 2026-08-26 audit and was sealed at the legacy count — the
// `i=` marker can never be confused with the hex salt that otherwise leads these
// strings, since hex never begins with `i`. This is what lets doubleLockIters
// rise without a migration: every record carries the count it was sealed with.
func dlParams(stored string) (iters int, rest string) {
	if body, ok := strings.CutPrefix(stored, "i="); ok {
		if n, tail, ok := strings.Cut(body, ";"); ok {
			if v, err := strconv.Atoi(n); err == nil && v > 0 {
				return v, tail
			}
		}
	}
	return doubleLockLegacyIters, stored
}

// sealDoubleLock encrypts plaintext under a key derived from password,
// returning the stored verifier and ciphertext strings (each
// hex(salt):hex(...), self-contained — no shared state between the two).
func sealDoubleLock(plaintext, password string) (verifier, enc string, err error) {
	salt := make([]byte, doubleLockSalt)
	if _, err := rand.Read(salt); err != nil {
		return "", "", err
	}
	verifierKey, aesKey := deriveDoubleLock(password, salt, doubleLockIters)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", "", err
	}
	ct := aead.Seal(nil, nonce, []byte(plaintext), nil)
	prefix := "i=" + strconv.Itoa(doubleLockIters) + ";"
	saltHex := hex.EncodeToString(salt)
	verifier = prefix + saltHex + ":" + hex.EncodeToString(verifierKey)
	enc = prefix + saltHex + ":" + hex.EncodeToString(nonce) + ":" + hex.EncodeToString(ct)
	return verifier, enc, nil
}

// verifyDoubleLockPassword reports whether password matches verifier, in
// constant time. Checked before ever attempting the real decrypt, so a wrong
// password can be reported cleanly and distinctly from a corrupted enc value.
func verifyDoubleLockPassword(verifier, password string) bool {
	iters, body := dlParams(verifier)
	saltHex, wantHex, ok := strings.Cut(body, ":")
	if !ok {
		return false
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		return false
	}
	got, _ := deriveDoubleLock(password, salt, iters)
	return subtle.ConstantTimeCompare(got, want) == 1
}

var errDoubleLockCorrupt = errors.New("doublelock: corrupted ciphertext")

// openDoubleLock decrypts enc with password, assuming the caller has already
// confirmed the password via verifyDoubleLockPassword — a failure here means
// a genuinely corrupted or tampered value, not a wrong password.
func openDoubleLock(enc, password string) (string, error) {
	iters, body := dlParams(enc)
	parts := strings.SplitN(body, ":", 3)
	if len(parts) != 3 {
		return "", errDoubleLockCorrupt
	}
	salt, err1 := hex.DecodeString(parts[0])
	nonce, err2 := hex.DecodeString(parts[1])
	ct, err3 := hex.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return "", errDoubleLockCorrupt
	}
	_, aesKey := deriveDoubleLock(password, salt, iters)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", errDoubleLockCorrupt
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", errDoubleLockCorrupt
	}
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", errDoubleLockCorrupt
	}
	return string(pt), nil
}

// errDoubleLockRequired is returned by doubleLockReveal when the credential
// is double-locked and the caller supplied no password or the wrong one —
// distinct from a plain decrypt failure so callers can map it to 403 instead
// of 500.
var errDoubleLockRequired = errors.New("this credential is double-locked; supply the correct password in X-DoubleLock-Password")

// doubleLockReveal returns the plaintext for c: SecretEnc under the standard
// AAD when DoubleLock is off (unchanged behavior), or — when on — the
// caller's X-DoubleLock-Password header verified and DoubleLockEnc decrypted
// in its place. Audits internally (the wording is identical for every
// caller); does NOT write the HTTP response, since callers differ in what
// else they must do on failure (checkout rolls back the lease it already
// created). op names the caller for audit details ("reveal" or "checkout").
func (s *Server) doubleLockReveal(r *http.Request, c *store.Credential, op string) (string, error) {
	if c.DoubleLockHolder == "" {
		secret, err := s.vault.Decrypt(r.Context(), c.SecretEnc, store.CredentialAAD(c.TargetID, c.ID))
		if err != nil {
			s.audit(r.Context(), "credential.decrypt_failed", fmt.Sprintf("credential:%d target:%d op:%s", c.ID, c.TargetID, op))
			return "", errDecryptFailed
		}
		return secret, nil
	}
	password := r.Header.Get("X-DoubleLock-Password")
	if password == "" || !verifyDoubleLockPassword(c.DoubleLockVerifier, password) {
		s.audit(r.Context(), "credential.doublelock_denied", fmt.Sprintf("credential:%d target:%d op:%s", c.ID, c.TargetID, op))
		return "", errDoubleLockRequired
	}
	secret, err := openDoubleLock(c.DoubleLockEnc, password)
	if err != nil {
		// The password verifier already matched above, so this is a genuinely
		// corrupted DoubleLockEnc, not a wrong password.
		s.audit(r.Context(), "credential.decrypt_failed", fmt.Sprintf("credential:%d target:%d op:%s_doublelock", c.ID, c.TargetID, op))
		return "", errDecryptFailed
	}
	return secret, nil
}

// writeDoubleLockError maps doubleLockReveal's sentinel errors to the right
// HTTP status: 403 when the (missing/wrong) password is the whole reason,
// 500 for a genuine decrypt failure.
func writeDoubleLockError(w http.ResponseWriter, err error) {
	if errors.Is(err, errDoubleLockRequired) {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	writeError(w, http.StatusInternalServerError, "decryption failed")
}

type doubleLockIn struct {
	Holder   string `json:"holder"`
	Password string `json:"password"`
}

// doubleLockMinLen is the enforced minimum DoubleLock password length: the
// configured value when it is set higher than the built-in floor, else the
// floor. It is never below doubleLockMinLen so a misconfiguration cannot weaken
// the control below what the audit set.
func (s *Server) doubleLockMinLen() int {
	if s.doubleLockMin > doubleLockMinLen {
		return s.doubleLockMin
	}
	return doubleLockMinLen
}

// setDoubleLock enables DoubleLock on a credential: from now on, reveal and
// checkout additionally require this password. Requires re-reading the
// current plaintext (via the standard SecretEnc decrypt — unaffected by
// this) to re-seal it into DoubleLockEnc, so it needs the same access as
// reveal itself.
func (s *Server) setDoubleLock(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in doubleLockIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.Holder == "" || in.Password == "" {
		writeError(w, http.StatusUnprocessableEntity, "holder and password are required")
		return
	}
	// The DoubleLock password is the ONLY key protecting DoubleLockEnc, a copy
	// of the secret that lives outside the KEK — so its entropy, not the PBKDF2
	// count, is what defeats an offline attack after a database compromise. A
	// minimum length is enforced (2026-08-26 audit, H-3); before it, any
	// non-empty string was accepted.
	if minLen := s.doubleLockMinLen(); len([]rune(in.Password)) < minLen {
		writeError(w, http.StatusUnprocessableEntity,
			fmt.Sprintf("the double-lock password must be at least %d characters — it is the only key protecting this secret at rest", minLen))
		return
	}
	c, target, ok := s.loadCredentialTarget(w, r, id)
	if !ok {
		return
	}
	if c.IsZSP() {
		writeError(w, http.StatusUnprocessableEntity, "this credential has no stored secret (zero standing privilege) to double-lock")
		return
	}
	if !s.gateCredentialAccess(w, r, target, c.Username, "credential.doublelock_enable") {
		return
	}
	secret, err := s.vault.Decrypt(r.Context(), c.SecretEnc, store.CredentialAAD(c.TargetID, c.ID))
	if err != nil {
		s.audit(r.Context(), "credential.decrypt_failed", fmt.Sprintf("credential:%d target:%d op:doublelock_enable", c.ID, c.TargetID))
		writeError(w, http.StatusInternalServerError, "decryption failed")
		return
	}
	verifier, enc, err := sealDoubleLock(secret, in.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encryption failed")
		return
	}
	if err := s.store.SetCredentialDoubleLock(r.Context(), c.ID, in.Holder, verifier, enc); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "credential.doublelock_enabled",
		fmt.Sprintf("credential:%d target:%d holder:%s", c.ID, c.TargetID, auditField(in.Holder, 128)))
	w.WriteHeader(http.StatusNoContent)
}

// clearDoubleLock disables DoubleLock — requires the current password, so an
// admin alone cannot strip the protection without the holder's cooperation;
// that requirement is the entire point of the feature.
func (s *Server) clearDoubleLock(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	c, target, ok := s.loadCredentialTarget(w, r, id)
	if !ok {
		return
	}
	if c.DoubleLockHolder == "" {
		writeError(w, http.StatusUnprocessableEntity, "this credential is not double-locked")
		return
	}
	if !s.gateCredentialAccess(w, r, target, c.Username, "credential.doublelock_disable") {
		return
	}
	if !verifyDoubleLockPassword(c.DoubleLockVerifier, in.Password) {
		s.audit(r.Context(), "credential.doublelock_denied",
			fmt.Sprintf("credential:%d target:%d op:disable", c.ID, c.TargetID))
		writeError(w, http.StatusForbidden, "wrong DoubleLock password")
		return
	}
	if err := s.store.ClearCredentialDoubleLock(r.Context(), c.ID); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "credential.doublelock_disabled", fmt.Sprintf("credential:%d target:%d", c.ID, c.TargetID))
	w.WriteHeader(http.StatusNoContent)
}
