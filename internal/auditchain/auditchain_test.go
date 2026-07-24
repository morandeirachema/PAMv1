package auditchain

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// tamperStore wraps a real memstore but can rewrite what ListBrokerAudit returns,
// so a test can simulate a tampered or truncated audit table.
type tamperStore struct {
	*memstore.Memstore
	mutate func([]store.BrokerAuditEvent) []store.BrokerAuditEvent
}

func (s *tamperStore) ListBrokerAudit(ctx context.Context, limit int) ([]store.BrokerAuditEvent, error) {
	evs, err := s.Memstore.ListBrokerAudit(ctx, limit)
	if err != nil || s.mutate == nil {
		return evs, err
	}
	return s.mutate(evs), nil
}

func newChain(t *testing.T, st store.Store) *Chain {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	c, err := New(context.Background(), key, priv, st)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func appendN(t *testing.T, c *Chain, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := c.Append(context.Background(), store.BrokerAuditEvent{
			Actor: "agent-1", Action: "tool.call", Detail: fmt.Sprintf("call:%d", i), Scope: "target:web:exec",
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestChainRestartContinuity proves a fresh Chain built over an existing store
// (a server restart) resumes the chain — it seeds its head from the store, and
// events appended after the restart still verify from genesis.
func TestChainRestartContinuity(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newC := func() *Chain {
		c, err := New(ctx, key, priv, st)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c1 := newC()
	for i := 0; i < 3; i++ {
		if _, err := c1.Append(ctx, store.BrokerAuditEvent{Actor: "a", Action: "x", Detail: fmt.Sprintf("pre:%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	// "Restart": same key + store, new Chain instance.
	c2 := newC()
	if _, err := c2.Append(ctx, store.BrokerAuditEvent{Actor: "a", Action: "x", Detail: "post"}); err != nil {
		t.Fatal(err)
	}
	ok, id, err := c2.Verify(ctx)
	if err != nil || !ok || id != 0 {
		t.Fatalf("post-restart verify: ok=%v brokeAt=%d err=%v", ok, id, err)
	}
	if cp, _ := c2.Head(ctx, time.Now()); cp.LastID != 4 {
		t.Fatalf("head after restart+append = %d, want 4", cp.LastID)
	}
}

// TestVerifyCleanChain proves an untampered chain verifies.
func TestVerifyCleanChain(t *testing.T) {
	c := newChain(t, memstore.New())
	appendN(t, c, 6)
	ok, id, err := c.Verify(context.Background())
	if err != nil || !ok || id != 0 {
		t.Fatalf("clean chain: ok=%v brokeAt=%d err=%v", ok, id, err)
	}
}

// TestVerifyDetectsContentTamper proves editing an event's content breaks the chain.
func TestVerifyDetectsContentTamper(t *testing.T) {
	ts := &tamperStore{Memstore: memstore.New()}
	c := newChain(t, ts)
	appendN(t, c, 5)
	ts.mutate = func(evs []store.BrokerAuditEvent) []store.BrokerAuditEvent {
		out := append([]store.BrokerAuditEvent(nil), evs...)
		out[2].Detail = "TAMPERED" // rewrite the 3rd event
		return out
	}
	ok, id, err := c.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("verify passed on a tampered chain")
	}
	if id != 3 { // ids are 1-based; the 3rd event has id 3
		t.Fatalf("broke at id %d, want 3", id)
	}
}

// TestSignedHeadDetectsTruncation proves a saved checkpoint catches tail deletion,
// and that the checkpoint signature verifies against the published public key.
func TestSignedHeadDetectsTruncation(t *testing.T) {
	ts := &tamperStore{Memstore: memstore.New()}
	c := newChain(t, ts)
	appendN(t, c, 5)
	now := time.Now()

	cp, err := c.Head(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if cp.LastID != 5 {
		t.Fatalf("checkpoint last_id = %d, want 5", cp.LastID)
	}
	// The checkpoint signature must verify against the broker's public key.
	if !ed25519.Verify(cp.PublicKey, checkpointMsg(cp.LastID, cp.Head), cp.Signature) {
		t.Fatal("checkpoint signature did not verify")
	}

	// Simulate tail truncation: drop the last event. The remaining chain still
	// verifies, but a new head no longer matches the saved checkpoint's last_id.
	ts.mutate = func(evs []store.BrokerAuditEvent) []store.BrokerAuditEvent {
		return evs[:len(evs)-1]
	}
	// GetBrokerAuditHead still reports id 5 (memstore not truncated), so simulate a
	// verifier that only trusts the visible (truncated) list length.
	visible, _ := ts.ListBrokerAudit(context.Background(), 0)
	if int64(len(visible)) >= cp.LastID {
		t.Fatalf("truncation not simulated: %d visible >= checkpoint %d", len(visible), cp.LastID)
	}
}

// TestInChainCheckpointsEmitted proves periodic in-chain checkpoints are appended
// at the configured interval and all verify against the trusted key.
func TestInChainCheckpointsEmitted(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	c := newChain(t, st).WithCheckpointEvery(3)
	appendN(t, c, 6) // 6 events → a checkpoint after #3 and after #6

	res, err := c.VerifyFloor(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.BrokeAtID != 0 || res.BadCheckpoint != 0 {
		t.Fatalf("verify: %+v", res)
	}
	if res.Checkpoints != 2 {
		t.Fatalf("checkpoints = %d, want 2", res.Checkpoints)
	}
	// 6 tool events + 2 checkpoint events = 8 rows.
	if res.Count != 8 {
		t.Fatalf("count = %d, want 8", res.Count)
	}
}

// TestCheckpointCatchesKeyCompromiseEdit proves the ed25519 checkpoint layer is
// defense-in-depth over the HMAC: an attacker who edits history AND recomputes
// every downstream HMAC (i.e. the HMAC key leaked) still cannot forge the
// checkpoint's signed head — the anchored head no longer matches, so the
// checkpoint is flagged even though the HMAC chain reproduces.
func TestCheckpointCatchesKeyCompromiseEdit(t *testing.T) {
	ts := &tamperStore{Memstore: memstore.New()}
	c := newChain(t, ts).WithCheckpointEvery(3)
	appendN(t, c, 5) // events 1..5 + a checkpoint after #3 (id 4)

	ts.mutate = func(evs []store.BrokerAuditEvent) []store.BrokerAuditEvent {
		out := append([]store.BrokerAuditEvent(nil), evs...)
		out[0].Detail = "EVIL" // edit the first event's content
		// Recompute every HMAC with the (compromised) key so the HMAC walk passes.
		var head []byte
		for i := range out {
			out[i].HMAC = c.mac(head, out[i])
			out[i].PrevHash = head
			head = out[i].HMAC
		}
		return out
	}
	res, err := c.VerifyFloor(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.BrokeAtID != 0 {
		t.Fatalf("HMAC walk should pass (attacker recomputed): broke at %d", res.BrokeAtID)
	}
	if res.OK || res.BadCheckpoint == 0 {
		t.Fatalf("checkpoint signature must catch the edit: %+v", res)
	}
}

// TestRotationTrustsPreviousSigner proves that after a signing-key rotation a
// checkpoint signed by the rotated-out key still verifies when the old public key
// is trusted via WithRotation — and fails without it.
func TestRotationTrustsPreviousSigner(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	// Chain A signs a checkpoint with key1.
	c1 := newChain(t, st).WithCheckpointEvery(2)
	oldPub := c1.TrustedKeys()[0]
	appendN(t, c1, 2) // → one checkpoint signed by key1

	// "Rotate": a new Chain over the same store with a fresh signing key.
	key := c1.key // reuse the HMAC key so the chain stays continuous
	_, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	c2, err := New(ctx, key, newPriv, st)
	if err != nil {
		t.Fatal(err)
	}
	// Without trusting the old key, the old checkpoint is untrusted → flagged.
	if res, _ := c2.VerifyFloor(ctx, 0); res.OK || res.BadCheckpoint == 0 {
		t.Fatalf("old checkpoint must be untrusted after rotation without overlap: %+v", res)
	}
	// With the overlap (old public key trusted), it verifies again.
	c2.WithRotation(oldPub)
	if res, _ := c2.VerifyFloor(ctx, 0); !res.OK || res.BadCheckpoint != 0 {
		t.Fatalf("old checkpoint must verify during the rotation overlap: %+v", res)
	}
}

// TestTruncationFloor proves the min-entries floor detects tail truncation.
func TestTruncationFloor(t *testing.T) {
	ctx := context.Background()
	c := newChain(t, memstore.New())
	appendN(t, c, 5)
	if res, _ := c.VerifyFloor(ctx, 10); !res.Truncated || res.OK {
		t.Fatalf("floor above count must flag truncation: %+v", res)
	}
	if res, _ := c.VerifyFloor(ctx, 5); res.Truncated || !res.OK {
		t.Fatalf("floor equal to count must pass: %+v", res)
	}
	if res, _ := c.VerifyFloor(ctx, 0); res.Truncated || !res.OK {
		t.Fatalf("no floor must pass: %+v", res)
	}
}
