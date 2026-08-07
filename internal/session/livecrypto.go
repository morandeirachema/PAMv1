package session

// livecrypto.go authenticates and encrypts the cross-replica live-monitoring bus.
//
// WHY THIS EXISTS. Phase 55 relays a watched session's output between replicas
// through the store, which for PostgreSQL means LISTEN/NOTIFY — and PostgreSQL
// has no privilege model for notification channels: the documentation states
// plainly that notifications are visible to all users, and LISTEN requires no
// privilege at all. So with a plaintext bus, anything that could open a session
// to the pamv1 database could:
//
//   - announce interest (`NOTIFY pam_live_interest, '<session id>'`) and thereby
//     make the hosting replica start streaming a live privileged session's output
//     to the bus, then read it — a full terminal, every SQL statement verbatim,
//     every WinRM command and its output. Unaudited, because nothing on that path
//     went through an authorization gate;
//   - inject frames, writing FABRICATED output into a supervisor's live pane, or
//     an end marker that closes their watch while the session runs on.
//
// That narrowed a boundary the project deliberately built: the vault's KEK lives
// outside the database, so a database-only compromise had yielded ciphertext.
//
// WHAT THIS DOES. One AES-256-GCM key, held in shared custody (KEK-sealed in the
// store, converged on by every replica, re-wrapped by -rotate-kek) exactly like
// the SSH host key and the broker's audit keys — so it lives in the database only
// as ciphertext, and a database observer never has it.
//
//   - Frames are SEALED, not merely signed: an observer with a database session
//     gets no session content even while a legitimate supervisor is watching.
//   - Interest announcements are sealed too, and carry a timestamp, so they cannot
//     be forged to start a tap and a captured one cannot be replayed later.
//
// RESIDUAL, stated rather than glossed: an attacker who can read the bus can
// still replay a frame it captured moments ago into a watcher's pane, and can see
// the SIZE and TIMING of relayed traffic. Closing that needs per-session sequence
// state on both sides, which is a heavier machine than the exposure warrants; the
// recording on disk remains the faithful, hash-chained copy either way.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// LiveBusKeySize is the length of the live-bus key, in bytes (AES-256).
const LiveBusKeySize = 32

// interestSkew bounds how far an interest announcement's timestamp may be from
// this replica's clock. It is generous enough for ordinary NTP drift between
// pods and far shorter than the window a captured announcement would otherwise
// stay usable for.
const interestSkew = 2 * time.Minute

// errLiveAuth is returned when a bus payload fails to authenticate. Callers drop
// the payload; they never distinguish a forgery from a corrupt message, because
// the response is the same and the difference is not theirs to know.
var errLiveAuth = errors.New("session: live-bus payload failed authentication")

// liveSealer seals and opens live-bus payloads under one AES-256-GCM key.
type liveSealer struct{ aead cipher.AEAD }

// newLiveSealer builds a sealer from a 32-byte key.
func newLiveSealer(key []byte) (*liveSealer, error) {
	if len(key) != LiveBusKeySize {
		return nil, fmt.Errorf("session: live-bus key must be %d bytes, got %d", LiveBusKeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &liveSealer{aead: aead}, nil
}

// seal encrypts plaintext, binding it to aad so a frame cannot be replayed as a
// different session's frame or a different kind of message. The nonce is random
// per call and prefixed to the ciphertext.
func (s *liveSealer) seal(aad string, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plaintext, []byte(aad)), nil
}

// open reverses seal, returning errLiveAuth for anything that does not
// authenticate under the same key and aad.
func (s *liveSealer) open(aad string, blob []byte) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(blob) < n {
		return nil, errLiveAuth
	}
	out, err := s.aead.Open(nil, blob[:n], blob[n:], []byte(aad))
	if err != nil {
		return nil, errLiveAuth
	}
	return out, nil
}

// frameAAD binds a sealed frame to its session id and kind.
func frameAAD(id, kind string) string { return "pamv1-live-frame|" + id + "|" + kind }

// sealFrame returns f with its payload encrypted. The id and kind stay in the
// clear because the transport routes on them and the receiver needs them to
// choose the AAD — they are bound INTO the ciphertext, so neither can be altered
// without the seal failing.
func (s *liveSealer) sealFrame(f LiveFrame) (LiveFrame, error) {
	sealed, err := s.seal(frameAAD(f.ID, f.Kind), f.Data)
	if err != nil {
		return LiveFrame{}, err
	}
	f.Data = sealed
	return f, nil
}

// openFrame reverses sealFrame.
func (s *liveSealer) openFrame(f LiveFrame) (LiveFrame, error) {
	plain, err := s.open(frameAAD(f.ID, f.Kind), f.Data)
	if err != nil {
		return LiveFrame{}, err
	}
	f.Data = plain
	return f, nil
}

// sealInterest builds an authenticated interest announcement for a session id:
// "<id>.<base64(sealed timestamp)>". The id travels in the clear because the
// receiver needs it to pick the AAD, and it is bound into the ciphertext.
func (s *liveSealer) sealInterest(id string, now time.Time) (string, error) {
	blob, err := s.seal("pamv1-live-interest|"+id, []byte(strconv.FormatInt(now.Unix(), 10)))
	if err != nil {
		return "", err
	}
	return id + "." + base64.RawURLEncoding.EncodeToString(blob), nil
}

// openInterest verifies an announcement and returns the session id it vouches
// for. A payload whose timestamp is outside interestSkew is refused, so an
// announcement captured from the bus cannot be replayed later to reopen a tap.
func (s *liveSealer) openInterest(payload string, now time.Time) (string, error) {
	id, b64, ok := strings.Cut(payload, ".")
	if !ok || id == "" {
		return "", errLiveAuth
	}
	blob, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return "", errLiveAuth
	}
	plain, err := s.open("pamv1-live-interest|"+id, blob)
	if err != nil {
		return "", err
	}
	secs, err := strconv.ParseInt(string(plain), 10, 64)
	if err != nil {
		return "", errLiveAuth
	}
	if d := now.Sub(time.Unix(secs, 0)); d > interestSkew || d < -interestSkew {
		return "", errLiveAuth
	}
	return id, nil
}

// stepUpStmtAAD binds a sealed pending-pause statement to the row's identity
// fields, so a database writer can neither read the statement, forge a row that
// a supervisor would see, nor re-label a captured one with a different session,
// operator or replica — any tamper makes the open fail and the row is skipped.
func stepUpStmtAAD(id, actor, replica string) string {
	return "pamv1-stepup-stmt|" + id + "|" + actor + "|" + replica
}

// sealStepUpStatement encrypts a paused statement for the shared step-up
// inventory, returning the base64 form the row stores.
func (s *liveSealer) sealStepUpStatement(id, actor, replica, statement string) (string, error) {
	blob, err := s.seal(stepUpStmtAAD(id, actor, replica), []byte(statement))
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(blob), nil
}

// openStepUpStatement reverses sealStepUpStatement. errLiveAuth means the row
// is not vouched for by the cluster's key — fabricated or tampered — and must
// not be shown to a supervisor.
func (s *liveSealer) openStepUpStatement(id, actor, replica, sealed string) (string, error) {
	blob, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		return "", errLiveAuth
	}
	plain, err := s.open(stepUpStmtAAD(id, actor, replica), blob)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// stepUpDecisionAAD binds a sealed decision to the session it releases, the
// PAUSE of that session it was made about, the verdict and the decider — so a
// captured seal cannot be re-pointed at another session or pause, flipped from
// deny to approve, or re-attributed.
//
// The pause is in the AAD, not merely in the payload, because it is the field a
// replay would want to change: with the session id alone binding it, a captured
// decision stayed applicable to every later pause of the same session for as
// long as its timestamp was fresh.
func stepUpDecisionAAD(d StepUpDecision) string {
	return "pamv1-stepup-decision|" + d.SessionID + "|" + strconv.FormatInt(d.Pause, 10) +
		"|" + strconv.FormatBool(d.Approve) + "|" + d.Decider
}

// sealStepUpDecision returns d with its Seal set: a timestamp sealed under the
// bus key and bound to the decision's fields. Authenticity and freshness are
// what matter, as with a kill — the fields have to stay readable for the
// transport and the audit record.
func (s *liveSealer) sealStepUpDecision(d StepUpDecision, now time.Time) (StepUpDecision, error) {
	d.Seal = ""
	blob, err := s.seal(stepUpDecisionAAD(d), []byte(strconv.FormatInt(now.Unix(), 10)))
	if err != nil {
		return StepUpDecision{}, err
	}
	d.Seal = base64.RawURLEncoding.EncodeToString(blob)
	return d, nil
}

// openStepUpDecision verifies a decision's seal and freshness. A decision whose
// seal is missing, forged, re-pointed at other fields, or older than
// interestSkew is refused — so a database observer can neither invent a release
// nor replay one beyond the window.
//
// Freshness alone does not stop a replay INSIDE the window, which is why the
// decision also names the pause it was made about (StepUpDecision.Pause, bound
// into the AAD above): the applying replica refuses one whose pause it has
// already resolved. Freshness bounds how long a captured message survives; the
// pause binding is what makes it apply to exactly one statement.
func (s *liveSealer) openStepUpDecision(d StepUpDecision, now time.Time) error {
	if d.Seal == "" {
		return errLiveAuth
	}
	blob, err := base64.RawURLEncoding.DecodeString(d.Seal)
	if err != nil {
		return errLiveAuth
	}
	bare := d
	bare.Seal = ""
	plain, err := s.open(stepUpDecisionAAD(bare), blob)
	if err != nil {
		return err
	}
	secs, err := strconv.ParseInt(string(plain), 10, 64)
	if err != nil {
		return errLiveAuth
	}
	if delta := now.Sub(time.Unix(secs, 0)); delta > interestSkew || delta < -interestSkew {
		return errLiveAuth
	}
	return nil
}

// killAAD binds a sealed kill selector to the fields it targets, so a captured
// seal cannot be re-pointed at a different session, actor or target.
func killAAD(sel KillSelector) string {
	return "pamv1-kill|" + sel.ID + "|" + sel.Actor + "|" + sel.Target
}

// sealKill returns sel with its Seal set: a timestamp sealed under the bus key and
// bound to the selector's fields. Authenticity and freshness are what matter here,
// not confidentiality — a kill selector names a session, and the fields have to
// stay readable for the transport and the audit record.
func (s *liveSealer) sealKill(sel KillSelector, now time.Time) (KillSelector, error) {
	sel.Seal = ""
	blob, err := s.seal(killAAD(sel), []byte(strconv.FormatInt(now.Unix(), 10)))
	if err != nil {
		return KillSelector{}, err
	}
	sel.Seal = base64.RawURLEncoding.EncodeToString(blob)
	return sel, nil
}

// openKill verifies a selector's seal and its freshness. A selector whose seal is
// missing, forged, re-pointed at other fields, or older than interestSkew is
// refused — so a database observer can neither invent a kill nor replay one it
// captured earlier.
func (s *liveSealer) openKill(sel KillSelector, now time.Time) error {
	if sel.Seal == "" {
		return errLiveAuth
	}
	blob, err := base64.RawURLEncoding.DecodeString(sel.Seal)
	if err != nil {
		return errLiveAuth
	}
	bare := sel
	bare.Seal = ""
	plain, err := s.open(killAAD(bare), blob)
	if err != nil {
		return err
	}
	secs, err := strconv.ParseInt(string(plain), 10, 64)
	if err != nil {
		return errLiveAuth
	}
	if d := now.Sub(time.Unix(secs, 0)); d > interestSkew || d < -interestSkew {
		return errLiveAuth
	}
	return nil
}
