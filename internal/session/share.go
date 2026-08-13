package session

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"time"
)

// errUnavailable is returned by ShareRegistry methods that mint state (rather
// than merely reading it) when called on a nil registry — nil otherwise
// behaves as a silent no-op throughout this file, but minting a guest key
// that will never resolve to anything would be a confusing success, not a
// harmless one.
var errUnavailable = errors.New("session sharing is disabled")

// muxBuf bounds how many pending input chunks a session's mux holds before a
// sender blocks — generous enough to absorb one paste burst from any single
// writer without a merely-slightly-slow pump loop stalling a typist on the
// very next keystroke.
const muxBuf = 64

// shareSession is one live SSH session's input-sharing state: the mux channel
// every writer (the primary operator, and any attached view-control joiners)
// feeds, and the roster of who is currently attached (in either mode, for the
// console and for kick).
type shareSession struct {
	mux  chan []byte
	done chan struct{} // closed by Close; wakes every blocked/future Write and Read

	mu     sync.Mutex
	joined map[string]joinedEntry
	notify func(string) // delivers a Stderr banner to the primary's own terminal
}

// JoinedParty describes one attached session-share join, for the console
// roster and the primary operator's join notice.
type JoinedParty struct {
	JoinID string `json:"join_id"` // opaque id Kick targets — the SSH join's own id, or a web guest's key
	Actor  string `json:"actor"`   // "guest:<email>" for an external/vendor redemption
	Mode   string `json:"mode"`    // view_only | view_control
}

// joinedEntry is the roster's internal bookkeeping for one attached join:
// the public-facing JoinedParty plus the channel Kick closes to force it to
// disconnect.
type joinedEntry struct {
	party  JoinedParty
	kicked chan struct{}
}

// ShareRegistry multiplexes a live SSH session's operator input across
// possibly-many writers onto the one upstream channel a session actually has
// (Phase 116). Output stays one-way through the existing Hub (session.Hub);
// this is the input-direction counterpart, needed because x/crypto/ssh
// forbids concurrent writes to one channel, so two live typists cannot each
// write the upstream channel directly. Multiple simultaneous view-control
// joiners are supported — the mux is a plain Go channel, which accepts any
// number of concurrent senders natively; there is no per-session write lock
// to contend over. A nil *ShareRegistry is a safe no-op everywhere (matching
// Hub's own convention), so a caller that has not wired one can still hold
// and call it unconditionally.
type ShareRegistry struct {
	mu sync.Mutex
	m  map[string]*shareSession

	guestMu sync.Mutex
	guests  map[string]guestBinding
}

// guestBinding is what a web-redeemed external invite's guest key resolves
// to: which session, which actor to audit as, and which mode — plus an
// expiry, since unlike the SSH join: token (checked once, at channel-open) a
// guest key is presented repeatedly (once per SSE reconnect, once per
// view-control keystroke POST) for as long as the guest's browser tab stays
// open.
type guestBinding struct {
	sessionID string
	actor     string
	mode      string
	expires   time.Time
}

// NewShareRegistry returns an empty, ready-to-use registry.
func NewShareRegistry() *ShareRegistry {
	return &ShareRegistry{m: make(map[string]*shareSession)}
}

// IssueGuestKey mints a fresh bearer key binding a web-redeemed external
// invite to its session, actor and mode for the remainder of its viewing.
// This is deliberately a SEPARATE secret from the invite's own one-time
// token (already consumed by ConsumeSessionShareInviteByTokenHash by the
// time this is called) — the guest's browser makes several follow-up
// requests (the SSE output stream, and for view_control repeated input
// POSTs), and a single-use token cannot back more than one of them. Guest
// keys are in-memory and replica-local, matching this registry's existing
// same-replica-only scope for view-control joins. A nil *ShareRegistry
// mints nothing (matching every other method's nil-safety).
func (r *ShareRegistry) IssueGuestKey(sid, actor, mode string, ttl time.Duration) (string, error) {
	if r == nil {
		return "", errUnavailable
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	key := hex.EncodeToString(b)
	r.guestMu.Lock()
	if r.guests == nil {
		r.guests = make(map[string]guestBinding)
	}
	r.guests[key] = guestBinding{sessionID: sid, actor: actor, mode: mode, expires: time.Now().Add(ttl)}
	r.guestMu.Unlock()
	return key, nil
}

// ResolveGuestKey reports the session/actor/mode a guest key was issued for.
// ok is false for an unknown, expired, or (nil-registry) unavailable key —
// callers must treat every false the same way: refuse the request.
func (r *ShareRegistry) ResolveGuestKey(key string) (sid, actor, mode string, ok bool) {
	if r == nil {
		return "", "", "", false
	}
	r.guestMu.Lock()
	defer r.guestMu.Unlock()
	b, found := r.guests[key]
	if !found || time.Now().After(b.expires) {
		return "", "", "", false
	}
	return b.sessionID, b.actor, b.mode, true
}

// Open allocates session sid's input mux and roster. Call once per
// interactive SSH session, before the primary operator's own keystrokes start
// flowing — the primary is itself the first (and, until anyone joins, only)
// writer into the mux. A nil *ShareRegistry is a no-op (matching Hub's own
// convention), so a caller that has not wired one — e.g. a test building a
// minimal Proxy — can still hold and call one unconditionally.
func (r *ShareRegistry) Open(sid string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[sid] = &shareSession{
		mux:    make(chan []byte, muxBuf),
		done:   make(chan struct{}),
		joined: make(map[string]joinedEntry),
	}
}

// Close releases session sid's mux and roster and wakes every blocked or
// future Writer/Reader for it. The mux channel itself is never closed (a
// concurrent send racing this call must never panic on a closed channel) —
// instead `done` is closed, which every Write/Read selects on alongside the
// channel op, so a sender or reader that can no longer make progress returns
// an error/EOF immediately rather than leaking. Call once when the session
// ends (deferred alongside Registry.Remove).
func (r *ShareRegistry) Close(sid string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	ss := r.m[sid]
	delete(r.m, sid)
	r.mu.Unlock()
	if ss != nil {
		close(ss.done)
	}
	// Purge any guest keys issued for this session too — a leaked key must
	// not resolve to anything once the session it pointed to is gone, even
	// though it hasn't hit its own TTL yet.
	r.guestMu.Lock()
	for key, b := range r.guests {
		if b.sessionID == sid {
			delete(r.guests, key)
		}
	}
	r.guestMu.Unlock()
}

// session resolves sid to its live shareSession, or nil if this registry is
// nil, sid was never Open'd, or it has already Close'd — every other method
// on ShareRegistry funnels through here so a nil registry or unknown session
// only needs handling once.
func (r *ShareRegistry) session(sid string) *shareSession {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.m[sid]
}

// Writer returns an io.Writer that feeds session sid's input mux — used both
// for the primary operator's own keystrokes and for every attached
// view-control joiner's, each via its own forwarding goroutine
// (io.Copy(shares.Writer(sid), someClientChan)). A write blocks until the mux
// has room (backpressure, not drop — losing input bytes would corrupt a typed
// command) or the session ends, whichever comes first. A Writer for an
// unknown/already-closed sid discards silently (io.Discard semantics) rather
// than panicking, so a forwarder goroutine racing session teardown never
// crashes the proxy.
func (r *ShareRegistry) Writer(sid string) io.Writer {
	ss := r.session(sid)
	if ss == nil {
		return io.Discard
	}
	return muxWriter{ss}
}

// Reader returns an io.Reader that drains session sid's input mux — what
// insp.pump actually reads operator input from, instead of the primary's raw
// SSH channel directly. Returns io.EOF immediately for an unknown sid.
func (r *ShareRegistry) Reader(sid string) io.Reader {
	ss := r.session(sid)
	if ss == nil {
		return eofReader{}
	}
	return &muxReader{ss: ss}
}

// Track adds joinID to session sid's roster (the primary operator's join
// notice and the console roster read this) and returns a channel that Kick
// later closes to force this join to disconnect — the caller's own I/O loop
// selects on it alongside its normal work so a kick takes effect promptly
// rather than only on the join's own natural exit. The returned channel is
// nil for an unknown sid (a nil channel is never ready in a select, so this
// composes safely with the rest of ShareRegistry's nil-is-a-no-op
// convention — the caller does not need to check for nil itself).
func (r *ShareRegistry) Track(sid, joinID, actor, mode string) <-chan struct{} {
	ss := r.session(sid)
	if ss == nil {
		return nil
	}
	kicked := make(chan struct{})
	ss.mu.Lock()
	ss.joined[joinID] = joinedEntry{party: JoinedParty{JoinID: joinID, Actor: actor, Mode: mode}, kicked: kicked}
	ss.mu.Unlock()
	return kicked
}

// Untrack removes joinID from session sid's roster (call when a joiner
// detaches on its own — leaving, or its connection simply ending — not when
// it was Kicked, which already removes it). A no-op for an unknown sid or
// joinID, so a redundant call (e.g. a deferred Untrack racing a Kick) is
// always safe.
func (r *ShareRegistry) Untrack(sid, joinID string) {
	ss := r.session(sid)
	if ss == nil {
		return
	}
	ss.mu.Lock()
	delete(ss.joined, joinID)
	ss.mu.Unlock()
}

// Kick force-disconnects an attached join: closes the channel Track returned
// for it, which wakes the join's own select loop so it returns and runs its
// own deferred cleanup (Untrack, closing notices, audit) — the same
// "close it and let the loop unwind" shape session kill already uses
// elsewhere in this codebase, rather than reaching in and tearing down its
// connection directly. joinID doubling as a web guest's key (see
// IssueGuestKey — streamShareGuest Tracks under the key itself) is also
// revoked here, so a request already in flight when Kick is called cannot be
// followed by a new one even if it raced the closed channel. Reports whether
// a matching join was found.
func (r *ShareRegistry) Kick(sid, joinID string) bool {
	if r == nil {
		return false
	}
	ss := r.session(sid)
	if ss == nil {
		return false
	}
	ss.mu.Lock()
	e, ok := ss.joined[joinID]
	delete(ss.joined, joinID)
	ss.mu.Unlock()
	r.guestMu.Lock()
	delete(r.guests, joinID)
	r.guestMu.Unlock()
	if ok {
		close(e.kicked)
	}
	return ok
}

// SetNotifier registers how to deliver a message to the PRIMARY operator's
// own terminal (a Stderr banner) for session sid. Call once, when the
// primary's own handleSession accepts its client channel — a join running in
// a separate goroutine/connection has no other way to reach that terminal. A
// no-op for an unknown sid.
func (r *ShareRegistry) SetNotifier(sid string, fn func(string)) {
	ss := r.session(sid)
	if ss == nil {
		return
	}
	ss.mu.Lock()
	ss.notify = fn
	ss.mu.Unlock()
}

// Notify delivers msg to the primary operator's terminal for session sid, via
// whatever SetNotifier registered. A no-op if the session is unknown or no
// notifier has been registered yet — a narrow startup race (a join arriving
// in the same instant as the primary's own channel accept) that only means
// that one notice is silently dropped, never a panic or a stuck send.
func (r *ShareRegistry) Notify(sid, msg string) {
	ss := r.session(sid)
	if ss == nil {
		return
	}
	ss.mu.Lock()
	fn := ss.notify
	ss.mu.Unlock()
	if fn != nil {
		fn(msg)
	}
}

// Roster returns the parties currently attached to session sid (empty, never
// nil, for an unknown sid).
func (r *ShareRegistry) Roster(sid string) []JoinedParty {
	ss := r.session(sid)
	if ss == nil {
		return []JoinedParty{}
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	out := make([]JoinedParty, 0, len(ss.joined))
	for _, e := range ss.joined {
		out = append(out, e.party)
	}
	return out
}

// muxWriter implements io.Writer over one session's mux channel.
type muxWriter struct{ ss *shareSession }

func (w muxWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	cp := append([]byte(nil), p...) // the caller (io.Copy) reuses its buffer
	select {
	case w.ss.mux <- cp:
		return len(p), nil
	case <-w.ss.done:
		return 0, io.ErrClosedPipe
	}
}

// muxReader implements io.Reader over one session's mux channel, buffering
// any tail of a chunk too large for the caller's []byte so no input byte is
// ever silently dropped (io.Reader may return fewer bytes than asked, but
// must never discard unread ones).
type muxReader struct {
	ss   *shareSession
	rest []byte
}

func (rd *muxReader) Read(p []byte) (int, error) {
	if len(rd.rest) > 0 {
		n := copy(p, rd.rest)
		rd.rest = rd.rest[n:]
		return n, nil
	}
	select {
	case b := <-rd.ss.mux:
		n := copy(p, b)
		if n < len(b) {
			rd.rest = b[n:]
		}
		return n, nil
	case <-rd.ss.done:
		return 0, io.EOF
	}
}

// eofReader is an io.Reader that always reports end-of-file, for a Reader
// call against an unknown session id.
type eofReader struct{}

func (eofReader) Read([]byte) (int, error) { return 0, io.EOF }
