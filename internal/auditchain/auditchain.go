// Package auditchain implements the broker's tamper-evident, keyed-HMAC
// hash-chained audit log. Each appended event's HMAC covers the previous event's
// HMAC and the event's semantic content, so any content edit, reorder, or
// mid-history deletion breaks the chain; tail truncation is caught by an
// ed25519-signed head checkpoint. The broker is the sole writer, and a mutex
// serializes appends so rows chain in a deterministic order.
//
// The event timestamp is recorded but deliberately NOT part of the HMAC input,
// so the chain survives a database timestamp-precision round-trip; content,
// ordering, and truncation are all still covered.
package auditchain

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

// KeySize is the required HMAC key length in bytes.
const KeySize = 32

// GenerateKeyText returns a fresh chain HMAC key — KeySize random bytes — as
// standard-base64 text, the same form PAM_BROKER_AUDIT_KEY carries. Text rather
// than raw bytes because the caller stores it under key custody, where every
// value is a printable artifact (the SSH keys are PEM), and because it keeps
// one decode path whether the key came from the environment or from custody.
func GenerateKeyText() ([]byte, error) {
	return generateB64(KeySize)
}

// GenerateSignSeedText returns a fresh ed25519 checkpoint-signing seed as
// standard-base64 text, the same form PAM_BROKER_AUDIT_SIGN_SEED carries.
func GenerateSignSeedText() ([]byte, error) {
	return generateB64(ed25519.SeedSize)
}

// generateB64 returns n cryptographically random bytes encoded as
// standard-base64 text.
func generateB64(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return []byte(base64.StdEncoding.EncodeToString(b)), nil
}

// CheckpointAction is the audit action of an in-chain signed checkpoint event
// (Phase 27). A checkpoint is a normal chain event whose detail carries an
// ed25519 signature over the running head at its position, so a verifier reading
// only the chain gets periodic independent anchors — a mid-history edit fails the
// nearest checkpoint's signature even if the HMAC key leaked.
const CheckpointAction = "broker.audit.checkpoint"

// Chain appends and verifies broker audit events against a store.
type Chain struct {
	mu         sync.Mutex
	key        []byte
	signKey    ed25519.PrivateKey
	verifyKeys []ed25519.PublicKey // trusted checkpoint signers: current + rotated-out previous
	cpEvery    int                 // emit an in-chain checkpoint every N events (0 = disabled)
	sinceCP    int                 // events appended since the last checkpoint
	st         store.Store
	head       []byte // last event's HMAC, kept in memory
}

// New builds a Chain, seeding its in-memory head from the store's latest event.
// The HMAC key must be KeySize bytes and signKey a valid ed25519 private key. The
// current signing key's public half is trusted for checkpoint verification;
// WithRotation adds rotated-out predecessors, WithCheckpointEvery enables periodic
// in-chain checkpoints.
func New(ctx context.Context, key []byte, signKey ed25519.PrivateKey, st store.Store) (*Chain, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("auditchain: HMAC key must be %d bytes, got %d", KeySize, len(key))
	}
	if len(signKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("auditchain: invalid ed25519 signing key")
	}
	c := &Chain{key: key, signKey: signKey, st: st}
	c.verifyKeys = []ed25519.PublicKey{signKey.Public().(ed25519.PublicKey)}
	head, err := st.GetBrokerAuditHead(ctx)
	if err != nil {
		return nil, err
	}
	if head != nil {
		c.head = head.HMAC
	}
	return c, nil
}

// WithRotation trusts additional (rotated-out) public keys when verifying
// checkpoints, so checkpoints signed before a signing-key rotation still verify
// during the overlap window. The current signing key stays trusted. Duplicates
// and the current key are ignored.
func (c *Chain) WithRotation(prev ...ed25519.PublicKey) *Chain {
	for _, p := range prev {
		if len(p) != ed25519.PublicKeySize {
			continue
		}
		dup := false
		for _, e := range c.verifyKeys {
			if e.Equal(p) {
				dup = true
				break
			}
		}
		if !dup {
			c.verifyKeys = append(c.verifyKeys, p)
		}
	}
	return c
}

// WithCheckpointEvery makes the chain append a signed in-chain checkpoint after
// every n appended events (0 disables it). The checkpoint is best-effort: a
// checkpoint-append failure never fails the event that triggered it.
func (c *Chain) WithCheckpointEvery(n int) *Chain {
	if n > 0 {
		c.cpEvery = n
	}
	return c
}

// TrustedKeys returns the public keys trusted to sign checkpoints (current first,
// then rotated-out predecessors), for JWKS publication.
func (c *Chain) TrustedKeys() []ed25519.PublicKey {
	out := make([]ed25519.PublicKey, len(c.verifyKeys))
	copy(out, c.verifyKeys)
	return out
}

// KeyID returns the short fingerprint identifying an ed25519 public key in
// checkpoints and JWKS (hex of the first 8 bytes of its SHA-256).
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// Append chains and persists ev; its PrevHash/HMAC (and ID/TS from the store) are
// set on the returned copy. The HMAC is computed from the head the store reads
// back under its append lock, not from c.head, so concurrent writers (rolling
// deploy, HA) can't fork the chain; c.head is kept only as an advisory hint. When
// periodic checkpoints are enabled (WithCheckpointEvery), a signed in-chain
// checkpoint is appended after every N events (best-effort — never fails ev).
func (c *Chain) Append(ctx context.Context, ev store.BrokerAuditEvent) (store.BrokerAuditEvent, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out, err := c.appendLocked(ctx, ev)
	if err != nil {
		return store.BrokerAuditEvent{}, err
	}
	// A checkpoint event does not itself count toward the next checkpoint (avoids
	// self-triggering recursion).
	if out.Action != CheckpointAction && c.cpEvery > 0 {
		c.sinceCP++
		if c.sinceCP >= c.cpEvery {
			c.sinceCP = 0
			if _, cerr := c.appendCheckpointLocked(ctx, time.Now()); cerr != nil {
				return out, nil // checkpoint is best-effort; the event itself is durable
			}
		}
	}
	return out, nil
}

// appendLocked performs one linked store append; the caller holds c.mu.
func (c *Chain) appendLocked(ctx context.Context, ev store.BrokerAuditEvent) (store.BrokerAuditEvent, error) {
	out, err := c.st.AppendBrokerAuditLinked(ctx, func(head *store.BrokerAuditEvent) store.BrokerAuditEvent {
		var prev []byte
		if head != nil {
			prev = head.HMAC
		}
		ev.HMAC = c.mac(prev, ev)
		// Store an empty (non-nil) prev_hash at genesis so a NOT NULL column
		// accepts it; verify recomputes from the running head, so the value is
		// informational.
		ev.PrevHash = prev
		if ev.PrevHash == nil {
			ev.PrevHash = []byte{}
		}
		return ev
	})
	if err != nil {
		return store.BrokerAuditEvent{}, err
	}
	c.head = out.HMAC
	return out, nil
}

// appendCheckpointLocked appends a signed in-chain checkpoint anchoring the head
// the STORE reads back under its append lock (the real previous row), not the
// triggering event's head. This keeps the anchor correct under multi-writer / HA
// operation: if another replica appends between the triggering event and this
// checkpoint, the checkpoint still signs the actual running head at its own
// position, so VerifyFloor never raises a false tamper alarm. The caller holds c.mu.
func (c *Chain) appendCheckpointLocked(ctx context.Context, now time.Time) (store.BrokerAuditEvent, error) {
	kid := KeyID(c.signKey.Public().(ed25519.PublicKey))
	ts := now.UTC().Format(time.RFC3339)
	out, err := c.st.AppendBrokerAuditLinked(ctx, func(head *store.BrokerAuditEvent) store.BrokerAuditEvent {
		var prev []byte
		var anchorID int64
		if head != nil {
			prev, anchorID = head.HMAC, head.ID
		}
		cp := inChainCheckpoint{
			LastID: anchorID,
			Head:   hex.EncodeToString(prev),
			KID:    kid,
			Sig:    base64.StdEncoding.EncodeToString(ed25519.Sign(c.signKey, checkpointMsg(anchorID, prev))),
			TS:     ts,
		}
		detail, _ := json.Marshal(cp)
		ev := store.BrokerAuditEvent{Actor: "system", Action: CheckpointAction, Detail: string(detail)}
		ev.HMAC = c.mac(prev, ev)
		ev.PrevHash = prev
		if ev.PrevHash == nil {
			ev.PrevHash = []byte{}
		}
		return ev
	})
	if err != nil {
		return store.BrokerAuditEvent{}, err
	}
	c.head = out.HMAC
	return out, nil
}

// inChainCheckpoint is the JSON payload stored in a checkpoint event's detail: an
// ed25519 signature over the running head at LastID, plus the signer fingerprint.
type inChainCheckpoint struct {
	LastID int64  `json:"last_id"`
	Head   string `json:"head"` // hex HMAC anchored
	KID    string `json:"kid"`  // signer fingerprint (see KeyID)
	Sig    string `json:"sig"`  // base64 ed25519 over checkpointMsg(last_id, head)
	TS     string `json:"ts"`
}

// Verify walks the whole chain oldest-first, recomputing each HMAC. It returns
// ok=false and the id of the first event whose HMAC does not reproduce (a
// content edit or a mid-history deletion).
func (c *Chain) Verify(ctx context.Context) (ok bool, brokeAtID int64, err error) {
	r, err := c.VerifyFloor(ctx, 0)
	if err != nil {
		return false, 0, err
	}
	return r.OK, r.BrokeAtID, nil
}

// VerifyResult reports a full chain verification (Phase 27): the HMAC walk, the
// in-chain signed checkpoints, and — when a floor is supplied — tail-truncation
// detection.
type VerifyResult struct {
	OK            bool  `json:"ok"`             // HMAC chain reproduces (no edit / mid-history deletion)
	BrokeAtID     int64 `json:"broke_at_id"`    // first event whose HMAC failed (0 if none)
	Count         int64 `json:"count"`          // events in the chain now
	Checkpoints   int   `json:"checkpoints"`    // in-chain signed checkpoints found
	BadCheckpoint int64 `json:"bad_checkpoint"` // first checkpoint event whose signature failed or was untrusted (0 = none)
	Truncated     bool  `json:"truncated"`      // Count is below the requested min-entries floor
}

// VerifyFloor walks the chain, recomputing each HMAC (edit / mid-deletion
// detection) and independently verifying every in-chain checkpoint's ed25519
// signature against the trusted key set and the running head at its position (so
// a forged checkpoint, or one signed by an untrusted key, is caught). When
// minEntries > 0 it also reports Truncated if the chain now holds fewer events —
// the tail-truncation floor an auditor drives from a previously archived
// checkpoint count. OK is true only when the HMAC chain reproduces AND every
// checkpoint verified AND the floor (if any) is met.
func (c *Chain) VerifyFloor(ctx context.Context, minEntries int64) (VerifyResult, error) {
	events, err := c.st.ListBrokerAudit(ctx, 0)
	if err != nil {
		return VerifyResult{}, err
	}
	res := VerifyResult{OK: true, Count: int64(len(events))}
	var head []byte
	var maxID int64
	for i := range events {
		ev := events[i]
		if !hmac.Equal(c.mac(head, ev), ev.HMAC) {
			res.OK, res.BrokeAtID = false, ev.ID
			return res, nil
		}
		if ev.Action == CheckpointAction {
			res.Checkpoints++
			// The checkpoint anchors `head` — the running head of every event
			// BEFORE it. Verify its signature against a trusted key and that the
			// anchored head matches; a mismatch means a forged/untrusted checkpoint.
			if !c.checkpointValid(ev, head) && res.BadCheckpoint == 0 {
				res.OK, res.BadCheckpoint = false, ev.ID
			}
		}
		if ev.ID > maxID {
			maxID = ev.ID
		}
		head = ev.HMAC
	}
	// The floor is compared against the highest event ID, not the row count: an
	// archived checkpoint records a BIGSERIAL upper bound (Count == LastID), and a
	// rolled-back insert leaves an ID gap — so a true row count would raise a false
	// truncation alarm. Tail truncation drops the highest IDs, which this catches.
	if minEntries > 0 && maxID < minEntries {
		res.OK, res.Truncated = false, true
	}
	return res, nil
}

// checkpointValid reports whether a checkpoint event's stored signature verifies
// against a trusted key and anchors the given running head.
func (c *Chain) checkpointValid(ev store.BrokerAuditEvent, runningHead []byte) bool {
	var cp inChainCheckpoint
	if err := json.Unmarshal([]byte(strings.TrimSpace(ev.Detail)), &cp); err != nil {
		return false
	}
	anchored, err := hex.DecodeString(cp.Head)
	if err != nil || !hmac.Equal(anchored, runningHead) {
		return false // the checkpoint anchors a head other than the actual chain state
	}
	sig, err := base64.StdEncoding.DecodeString(cp.Sig)
	if err != nil {
		return false
	}
	msg := checkpointMsg(cp.LastID, anchored)
	for _, pub := range c.verifyKeys {
		if KeyID(pub) == cp.KID && ed25519.Verify(pub, msg, sig) {
			return true
		}
	}
	return false // no trusted key matches the fingerprint / signature
}

// Checkpoint is a signed anchor of the chain at a point in time. An auditor
// stores it and later detects tail truncation if the current chain no longer
// reproduces this (LastID, Head), verified against the broker's ed25519 public key.
type Checkpoint struct {
	LastID    int64     `json:"last_id"`
	Count     int64     `json:"count"`
	Head      []byte    `json:"head"`      // last event's HMAC (base64 in JSON)
	TS        time.Time `json:"ts"`        // when the checkpoint was produced
	Signature []byte    `json:"signature"` // ed25519 over (last_id || head)
	PublicKey []byte    `json:"public_key"`
}

// Head returns a freshly signed checkpoint of the chain's current head.
func (c *Chain) Head(ctx context.Context, now time.Time) (Checkpoint, error) {
	head, err := c.st.GetBrokerAuditHead(ctx)
	if err != nil {
		return Checkpoint{}, err
	}
	var lastID int64
	var h []byte
	if head != nil {
		lastID, h = head.ID, head.HMAC
	}
	return SignCheckpoint(c.signKey, lastID, h, now), nil
}

// SignCheckpoint builds an ed25519-signed Checkpoint anchoring a hash chain at
// (lastID, head). Shared by the broker chain and the primary audit trail: an
// auditor stores the returned checkpoint and later detects tail truncation if the
// current chain no longer reproduces this signed (LastID, Head). Count mirrors
// LastID (a BIGSERIAL upper bound, not an exact row count — rolled-back inserts
// leave gaps; truncation detection relies on the signed LastID/Head).
func SignCheckpoint(signKey ed25519.PrivateKey, lastID int64, head []byte, now time.Time) Checkpoint {
	cp := Checkpoint{
		LastID:    lastID,
		Count:     lastID,
		Head:      head,
		TS:        now.UTC(),
		PublicKey: signKey.Public().(ed25519.PublicKey),
	}
	cp.Signature = ed25519.Sign(signKey, checkpointMsg(cp.LastID, cp.Head))
	return cp
}

// mac computes HMAC-SHA256(key, prev || canonical(ev)).
func (c *Chain) mac(prev []byte, ev store.BrokerAuditEvent) []byte {
	m := hmac.New(sha256.New, c.key)
	m.Write(prev)
	m.Write(canonical(ev))
	return m.Sum(nil)
}

// canonical is the deterministic serialization of an event's semantic content
// (not id/ts/prev_hash/hmac) that the chain protects.
func canonical(ev store.BrokerAuditEvent) []byte {
	b, _ := json.Marshal(struct {
		Actor      string `json:"actor"`
		OnBehalfOf string `json:"on_behalf_of"`
		ActorChain string `json:"actor_chain"`
		Action     string `json:"action"`
		Detail     string `json:"detail"`
		Scope      string `json:"scope"`
	}{ev.Actor, ev.OnBehalfOf, ev.ActorChain, ev.Action, ev.Detail, ev.Scope})
	return b
}

// checkpointMsg is the ed25519-signed message: big-endian last_id followed by head.
func checkpointMsg(lastID int64, head []byte) []byte {
	msg := make([]byte, 8, 8+len(head))
	binary.BigEndian.PutUint64(msg, uint64(lastID))
	return append(msg, head...)
}
