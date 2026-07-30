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
