package session

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"time"
)

// TestShareRegistryBasicRoundTrip proves a single writer's bytes reach the
// reader in order, unmodified — the mux's baseline behavior before any
// multi-writer concurrency is layered on.
func TestShareRegistryBasicRoundTrip(t *testing.T) {
	r := NewShareRegistry()
	r.Open("s1")
	defer r.Close("s1")

	w := r.Writer("s1")
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 32)
	rd := r.Reader("s1")
	n, err := rd.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != "hello" {
		t.Fatalf("got %q, want %q", got, "hello")
	}
}

// TestShareRegistryMultiParallelWriters proves multiple concurrent writers
// (the primary plus several view-control joiners) can all feed one session's
// mux without any write being lost, corrupted, or requiring exclusivity —
// the "multi-parallel view-control" requirement.
func TestShareRegistryMultiParallelWriters(t *testing.T) {
	r := NewShareRegistry()
	r.Open("s1")
	defer r.Close("s1")

	const writers = 8
	const perWriter = 50
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			w := r.Writer("s1")
			for j := 0; j < perWriter; j++ {
				if _, err := w.Write([]byte{byte(id)}); err != nil {
					t.Errorf("writer %d: %v", id, err)
					return
				}
			}
		}(i)
	}

	// Drain concurrently with the writers so the bounded mux buffer (64)
	// never deadlocks 8*50=400 total sends.
	counts := make([]int, writers)
	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		rd := r.Reader("s1")
		buf := make([]byte, 1)
		total := 0
		for total < writers*perWriter {
			n, err := rd.Read(buf)
			if err != nil {
				return
			}
			if n == 1 {
				mu.Lock()
				counts[buf[0]]++
				mu.Unlock()
				total++
			}
		}
		close(done)
	}()

	wg.Wait()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out draining the mux — a write or read is stuck")
	}
	for id, c := range counts {
		if c != perWriter {
			t.Fatalf("writer %d: got %d bytes delivered, want %d", id, c, perWriter)
		}
	}
}

// TestShareRegistryCloseUnblocksWriters proves Close wakes a writer blocked
// on a full mux (nobody reading) instead of leaking its goroutine forever —
// the property that makes session teardown safe even with an attached
// joiner mid-write.
func TestShareRegistryCloseUnblocksWriters(t *testing.T) {
	r := NewShareRegistry()
	r.Open("s1")
	w := r.Writer("s1")

	// Fill the mux buffer so the next write blocks (nobody is reading).
	for i := 0; i < muxBuf; i++ {
		if _, err := w.Write([]byte("x")); err != nil {
			t.Fatalf("fill write %d: %v", i, err)
		}
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := w.Write([]byte("blocked"))
		errCh <- err
	}()

	// Give the goroutine a moment to actually reach the blocking send.
	time.Sleep(20 * time.Millisecond)
	r.Close("s1")

	select {
	case err := <-errCh:
		if err != io.ErrClosedPipe {
			t.Fatalf("got err %v, want io.ErrClosedPipe", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock the pending writer — goroutine leak")
	}
}

// TestShareRegistryReaderBuffersOversizedChunk proves a chunk larger than the
// caller's read buffer is delivered across multiple Read calls rather than
// silently truncated — required because pump's read buffer (32KB) is finite
// while a Write can, in principle, hand it a larger []byte in one call.
func TestShareRegistryReaderBuffersOversizedChunk(t *testing.T) {
	r := NewShareRegistry()
	r.Open("s1")
	defer r.Close("s1")

	payload := bytes.Repeat([]byte("A"), 10)
	w := r.Writer("s1")
	go func() { _, _ = w.Write(payload) }()

	rd := r.Reader("s1")
	var got []byte
	small := make([]byte, 3)
	for len(got) < len(payload) {
		n, err := rd.Read(small)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		got = append(got, small[:n]...)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}
}

// TestShareRegistryUnknownSessionIsInert proves Writer/Reader for a session
// that was never Open'd (or already Closed) behave as documented — discard
// and immediate EOF — rather than panicking, since a forwarder goroutine can
// race session teardown.
func TestShareRegistryUnknownSessionIsInert(t *testing.T) {
	r := NewShareRegistry()
	w := r.Writer("nope")
	if n, err := w.Write([]byte("x")); n != 1 || err != nil {
		t.Fatalf("write to unknown session: n=%d err=%v, want discard success", n, err)
	}
	rd := r.Reader("nope")
	buf := make([]byte, 4)
	if n, err := rd.Read(buf); n != 0 || err != io.EOF {
		t.Fatalf("read from unknown session: n=%d err=%v, want (0, io.EOF)", n, err)
	}
}

// TestShareRegistryRoster proves Track/Untrack/Roster reflect exactly who is
// currently attached — what the console roster and the primary's join notice
// both read from.
func TestShareRegistryRoster(t *testing.T) {
	r := NewShareRegistry()
	r.Open("s1")
	defer r.Close("s1")

	if got := r.Roster("s1"); len(got) != 0 {
		t.Fatalf("fresh session roster = %v, want empty", got)
	}
	r.Track("s1", "j1", "alice", "view_only")
	r.Track("s1", "j2", "guest:bob@vendor.com", "view_control")
	got := r.Roster("s1")
	if len(got) != 2 {
		t.Fatalf("roster = %v, want 2 entries", got)
	}
	r.Untrack("s1", "j1")
	got = r.Roster("s1")
	if len(got) != 1 || got[0].Actor != "guest:bob@vendor.com" || got[0].Mode != "view_control" {
		t.Fatalf("roster after untrack = %+v, want one view_control guest entry", got)
	}
}

// TestShareRegistryGuestKeyRoundTrip proves a minted guest key resolves back
// to exactly the session/actor/mode it was issued for — what the web-redeemed
// external-invite SSE stream and view-control input POST both authenticate
// with, in place of the (already single-use-consumed) invite token.
func TestShareRegistryGuestKeyRoundTrip(t *testing.T) {
	r := NewShareRegistry()
	r.Open("s1")
	defer r.Close("s1")

	key, err := r.IssueGuestKey("s1", "guest:bob@vendor.com", "view_control", time.Hour)
	if err != nil {
		t.Fatalf("IssueGuestKey: %v", err)
	}
	sid, actor, mode, ok := r.ResolveGuestKey(key)
	if !ok || sid != "s1" || actor != "guest:bob@vendor.com" || mode != "view_control" {
		t.Fatalf("ResolveGuestKey = (%q,%q,%q,%v), want (s1,guest:bob@vendor.com,view_control,true)", sid, actor, mode, ok)
	}
	if _, _, _, ok := r.ResolveGuestKey("no-such-key"); ok {
		t.Fatal("resolving an unknown guest key succeeded, want ok=false")
	}
}

// TestShareRegistryGuestKeyExpires proves a guest key stops resolving once
// its TTL elapses — a leaked link must not stay valid forever.
func TestShareRegistryGuestKeyExpires(t *testing.T) {
	r := NewShareRegistry()
	r.Open("s1")
	defer r.Close("s1")

	key, err := r.IssueGuestKey("s1", "guest:bob@vendor.com", "view_only", time.Millisecond)
	if err != nil {
		t.Fatalf("IssueGuestKey: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, _, _, ok := r.ResolveGuestKey(key); ok {
		t.Fatal("an expired guest key still resolved")
	}
}

// TestShareRegistryClosePurgesGuestKeys proves ending a session invalidates
// every guest key issued for it immediately, not just once each key's own TTL
// happens to elapse — a session that ends must not leave a live back door.
func TestShareRegistryClosePurgesGuestKeys(t *testing.T) {
	r := NewShareRegistry()
	r.Open("s1")

	key, err := r.IssueGuestKey("s1", "guest:bob@vendor.com", "view_only", time.Hour)
	if err != nil {
		t.Fatalf("IssueGuestKey: %v", err)
	}
	r.Close("s1")
	if _, _, _, ok := r.ResolveGuestKey(key); ok {
		t.Fatal("a guest key for a closed session still resolved")
	}
}

// TestShareRegistryKickDisconnects proves Kick closes the channel Track
// returned (waking a join's own select loop) and removes it from the
// roster — the mechanism the console's kick action relies on to actually
// terminate a joiner's access, not just its bookkeeping entry.
func TestShareRegistryKickDisconnects(t *testing.T) {
	r := NewShareRegistry()
	r.Open("s1")
	defer r.Close("s1")

	kicked := r.Track("s1", "j1", "alice", "view_only")
	if len(r.Roster("s1")) != 1 {
		t.Fatalf("roster after Track = %v, want 1 entry", r.Roster("s1"))
	}
	if !r.Kick("s1", "j1") {
		t.Fatal("Kick on a tracked join returned false")
	}
	select {
	case <-kicked:
	default:
		t.Fatal("Kick did not close the channel Track returned")
	}
	if got := r.Roster("s1"); len(got) != 0 {
		t.Fatalf("roster after Kick = %v, want empty", got)
	}
	// A second Kick of the same (now-gone) join is a no-op, not a panic
	// (double-close of the same channel would panic if this were wrong).
	if r.Kick("s1", "j1") {
		t.Fatal("second Kick of an already-kicked join returned true")
	}
}

// TestShareRegistryKickRevokesGuestKey proves Kick also revokes a web guest's
// key (a web join is tracked under GuestJoinID, the guests map's own key —
// see streamShareGuest), so a request already in flight when Kick is called
// cannot be followed by a new one even if it raced the closed channel.
func TestShareRegistryKickRevokesGuestKey(t *testing.T) {
	r := NewShareRegistry()
	r.Open("s1")
	defer r.Close("s1")

	key, err := r.IssueGuestKey("s1", "guest:bob@vendor.com", "view_only", time.Hour)
	if err != nil {
		t.Fatalf("IssueGuestKey: %v", err)
	}
	r.Track("s1", GuestJoinID(key), "guest:bob@vendor.com", "view_only")
	if !r.Kick("s1", GuestJoinID(key)) {
		t.Fatal("Kick on the tracked guest join id returned false")
	}
	if _, _, _, ok := r.ResolveGuestKey(key); ok {
		t.Fatal("guest key still resolves after Kick")
	}
}

// TestShareRegistryKickUnknownIsInert proves Kick against an unknown
// session or join id, or a nil registry, behaves like every other
// ShareRegistry method — reports failure, never panics.
func TestShareRegistryKickUnknownIsInert(t *testing.T) {
	r := NewShareRegistry()
	r.Open("s1")
	defer r.Close("s1")
	if r.Kick("s1", "no-such-join") {
		t.Fatal("Kick on an unknown join id returned true")
	}
	if r.Kick("no-such-session", "j1") {
		t.Fatal("Kick on an unknown session returned true")
	}
	var nilReg *ShareRegistry
	if nilReg.Kick("s1", "j1") {
		t.Fatal("Kick on a nil registry returned true")
	}
}

// TestShareRegistryNilIssueGuestKey proves a nil *ShareRegistry refuses to
// mint (rather than panicking or silently minting a key nothing can ever
// resolve) — nil-safety for every OTHER method is a silent no-op, but a
// minting method needs its caller to know it did not happen.
func TestShareRegistryNilIssueGuestKey(t *testing.T) {
	var r *ShareRegistry
	if _, err := r.IssueGuestKey("s1", "guest:bob@vendor.com", "view_only", time.Hour); err == nil {
		t.Fatal("IssueGuestKey on a nil registry did not error")
	}
	if _, _, _, ok := r.ResolveGuestKey("anything"); ok {
		t.Fatal("ResolveGuestKey on a nil registry returned ok=true")
	}
}

// TestShareRegistrySuspendBlocksReader proves the core Phase 122 guarantee:
// once suspended, bytes already sitting in the mux (and any written after)
// are held back from the reader — not dropped, not delivered — until Resume,
// at which point they arrive intact and in order. This is what stands
// between an operator's keystrokes and the target while frozen.
func TestShareRegistrySuspendBlocksReader(t *testing.T) {
	r := NewShareRegistry()
	r.Open("s1")
	defer r.Close("s1")

	if !r.Suspend("s1") {
		t.Fatal("Suspend reported false for a live session")
	}
	if !r.Suspended("s1") {
		t.Fatal("Suspended reported false right after Suspend")
	}

	w := r.Writer("s1")
	if _, err := w.Write([]byte("frozen")); err != nil {
		t.Fatalf("write while suspended: %v", err)
	}

	rd := r.Reader("s1")
	buf := make([]byte, 32)
	readDone := make(chan struct{})
	var n int
	var readErr error
	go func() {
		n, readErr = rd.Read(buf)
		close(readDone)
	}()

	select {
	case <-readDone:
		t.Fatal("Read returned while suspended — suspend did not block delivery")
	case <-time.After(100 * time.Millisecond):
		// still blocked, as expected
	}

	if !r.Resume("s1") {
		t.Fatal("Resume reported false for a live session")
	}
	if r.Suspended("s1") {
		t.Fatal("Suspended reported true right after Resume")
	}

	select {
	case <-readDone:
		if readErr != nil {
			t.Fatalf("read after resume: %v", readErr)
		}
		if got := string(buf[:n]); got != "frozen" {
			t.Fatalf("got %q, want %q — a byte was dropped or reordered", got, "frozen")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Resume did not unblock the pending reader — goroutine leak")
	}
}

// TestShareRegistrySuspendResumeIdempotent proves both directions are safe to
// call repeatedly — a supervisor re-clicking "suspend" (or a retry after a
// network blip) must never error or double-toggle back to flowing.
func TestShareRegistrySuspendResumeIdempotent(t *testing.T) {
	r := NewShareRegistry()
	r.Open("s1")
	defer r.Close("s1")

	first := r.Suspend("s1")
	second := r.Suspend("s1")
	if !first || !second {
		t.Fatalf("Suspend called twice should report true both times, got %v then %v", first, second)
	}
	if !r.Suspended("s1") {
		t.Fatal("expected suspended after two Suspend calls")
	}
	first = r.Resume("s1")
	second = r.Resume("s1")
	if !first || !second {
		t.Fatalf("Resume called twice should report true both times, got %v then %v", first, second)
	}
	if r.Suspended("s1") {
		t.Fatal("expected flowing after two Resume calls")
	}
}

// TestShareRegistrySuspendUnknownSession proves every suspend-family call
// reports false/false for a session that was never opened (or already
// closed) — the same "unknown is inert, never a panic" convention every
// other ShareRegistry method already follows.
func TestShareRegistrySuspendUnknownSession(t *testing.T) {
	r := NewShareRegistry()
	if r.Suspend("ghost") {
		t.Fatal("Suspend on an unknown session returned true")
	}
	if r.Resume("ghost") {
		t.Fatal("Resume on an unknown session returned true")
	}
	if r.Suspended("ghost") {
		t.Fatal("Suspended on an unknown session returned true")
	}
}

// TestShareRegistryCloseUnblocksSuspendedReader proves a reader parked inside
// a suspend (not just an ordinary mux-empty wait) is still released when the
// session ends — Close must win over a suspend that was never explicitly
// resumed, or a session-share goroutine leaks forever once its session ends
// suspended.
func TestShareRegistryCloseUnblocksSuspendedReader(t *testing.T) {
	r := NewShareRegistry()
	r.Open("s1")
	r.Suspend("s1")

	rd := r.Reader("s1")
	errCh := make(chan error, 1)
	go func() {
		_, err := rd.Read(make([]byte, 32))
		errCh <- err
	}()

	time.Sleep(20 * time.Millisecond)
	r.Close("s1")

	select {
	case err := <-errCh:
		if err != io.EOF {
			t.Fatalf("got err %v, want io.EOF", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock a reader parked in a suspend — goroutine leak")
	}
}

// TestShareRegistryNilSuspendResume proves a nil registry is inert for the
// suspend family too, matching every other method's nil-is-a-safe-no-op
// convention.
func TestShareRegistryNilSuspendResume(t *testing.T) {
	var r *ShareRegistry
	if r.Suspend("s1") {
		t.Fatal("Suspend on a nil registry returned true")
	}
	if r.Resume("s1") {
		t.Fatal("Resume on a nil registry returned true")
	}
	if r.Suspended("s1") {
		t.Fatal("Suspended on a nil registry returned true")
	}
}

// TestShareRegistryGuestJoinIDIsNotTheKey pins the 2026-08-27 audit fix: a web
// guest is tracked on the roster under GuestJoinID, which must identify the
// join without being usable as the guest's key, and Kick by that id must
// still revoke the key. Before the fix the roster carried the raw key, so any
// CapReadAudit reader of the roster held the guest's live credential.
func TestShareRegistryGuestJoinIDIsNotTheKey(t *testing.T) {
	r := NewShareRegistry()
	r.Open("s1")
	defer r.Close("s1")

	key, err := r.IssueGuestKey("s1", "guest:bob@vendor.com", "view_control", time.Hour)
	if err != nil {
		t.Fatalf("IssueGuestKey: %v", err)
	}
	joinID := GuestJoinID(key)
	if joinID == key || joinID == "" {
		t.Fatalf("GuestJoinID(%q) = %q, want a distinct non-empty id", key, joinID)
	}
	r.Track("s1", joinID, "guest:bob@vendor.com", "view_control")
	roster := r.Roster("s1")
	if len(roster) != 1 || roster[0].JoinID != joinID {
		t.Fatalf("roster = %+v, want one entry under the join id", roster)
	}
	if roster[0].JoinID == key {
		t.Fatal("roster exposes the raw guest key")
	}
	// The id that the roster hands out resolves to nothing as a key...
	if _, _, _, ok := r.ResolveGuestKey(roster[0].JoinID); ok {
		t.Fatal("the roster's join_id resolved as a guest key")
	}
	// ...while the key itself still works until the id is kicked.
	if _, _, _, ok := r.ResolveGuestKey(key); !ok {
		t.Fatal("the real guest key stopped resolving before any kick")
	}
	if !r.Kick("s1", roster[0].JoinID) {
		t.Fatal("Kick by the roster's join_id found no join")
	}
	if _, _, _, ok := r.ResolveGuestKey(key); ok {
		t.Fatal("the guest key still resolves after a kick by join_id")
	}
	if got := r.Roster("s1"); len(got) != 0 {
		t.Fatalf("roster after kick = %+v, want empty", got)
	}
}
