package proxy

// sftpcapture.go records the CONTENT of files moved through the SSH proxy's
// SFTP subsystem (Phase 59). Phase 32 made every file *operation* auditable and
// Phase 51 made paths deniable, but the transferred bytes themselves still
// crossed the proxy unrecorded — an investigator could prove /srv/report.csv
// was uploaded, never WHAT was uploaded. With capture enabled, each remote file
// a session opens produces an artifact in the recording directory: a chunk log
// of every data movement (see internal/recording/sftpfile.go for the format and
// why it is a log, not a reassembled file). The artifact is sealed at rest when
// recording encryption is on, its SHA-256 joins the recording hash chain, and
// an sftp.file_recorded audit event binds file, path, byte counts and hash.
//
// Correlating a WRITE or READ packet with a file requires state the wire only
// reveals across both directions: OPEN (request) names the path, HANDLE
// (response) names the server's handle for it, and every later data packet
// names only the handle. So capture watches both legs — the request inspector
// (sftpguard.go) feeds it opens, reads, writes and closes; a response watcher
// (below) feeds it handles, data and statuses. All state is per-session and
// mutex-guarded, because the two legs run on different goroutines.
//
// Posture: unlike Phase 32's audit-only inspection (fail open on forwarding,
// loud on auditing), capture is a CONTAINMENT control — an admin who enabled it
// expects that bytes cannot move unobserved. So while capture is active, a
// stream that cannot be parsed, a tracking table that overflows, or (under
// PAM_REQUIRE_RECORDING) an artifact that cannot be written all fail the
// transfer CLOSED rather than letting content continue uncaptured. Every
// refusal is audited.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/morandeirachema/pamv1/internal/recording"
)

// SFTPCaptureMode selects which transfer directions have their content
// recorded: off (the pre-Phase-59 behavior), uploads (operator→target WRITE
// data), downloads (target→operator DATA responses), or all (both).
type SFTPCaptureMode string

const (
	SFTPCaptureOff       SFTPCaptureMode = "off"
	SFTPCaptureUploads   SFTPCaptureMode = "uploads"
	SFTPCaptureDownloads SFTPCaptureMode = "downloads"
	SFTPCaptureAll       SFTPCaptureMode = "all"
)

// ParseSFTPCaptureMode maps a config string to an SFTPCaptureMode, defaulting
// an empty value to off and reporting an unknown one fail-loud — a typo must
// not silently disable (or enable) content recording.
func ParseSFTPCaptureMode(s string) (SFTPCaptureMode, error) {
	switch SFTPCaptureMode(s) {
	case "", SFTPCaptureOff:
		return SFTPCaptureOff, nil
	case SFTPCaptureUploads:
		return SFTPCaptureUploads, nil
	case SFTPCaptureDownloads:
		return SFTPCaptureDownloads, nil
	case SFTPCaptureAll:
		return SFTPCaptureAll, nil
	default:
		return "", fmt.Errorf("invalid SFTP capture mode %q (want off, uploads, downloads, or all)", s)
	}
}

// Bounds on the per-session tracking state, so a hostile client cannot grow the
// proxy's memory or file descriptors without limit. A real OpenSSH client
// pipelines at most 64 requests and keeps a handful of handles open; these are
// generous multiples. Hitting one refuses the overflowing request (fail closed)
// with an audited reason, never silently untracked flow.
const (
	sftpCaptureMaxPending = 1024  // outstanding OPEN/READ requests awaiting a response
	sftpCaptureMaxOpen    = 128   // concurrently open capture artifacts (each is a file descriptor)
	sftpCaptureMaxFiles   = 10000 // artifacts per session (each is a file on disk)
)

// errSFTPCaptureAbort tears the SFTP flow down when content capture cannot
// observe it (an unframable stream): with capture on, "cannot parse" must mean
// "cannot transfer", or the control is advisory.
var errSFTPCaptureAbort = errors.New("proxy: sftp stream unparsable while content capture is enforced")

// sftpPendingOpen is an OPEN awaiting its HANDLE (or failure STATUS): the path
// and open mode that the eventual handle will inherit.
type sftpPendingOpen struct {
	path string
	mode string // read | write | readwrite
}

// sftpPendingRead is a READ awaiting its DATA (or STATUS): which handle and
// file offset the arriving bytes belong to.
type sftpPendingRead struct {
	handle string
	offset uint64
}

// sftpCaptureFile is one open capture artifact: the disk file, its sealing and
// hashing pipeline, and the counters that feed the closing audit event.
type sftpCaptureFile struct {
	name   string // artifact base name on disk
	remote string // remote path as the client named it
	mode   string // read | write | readwrite
	f      *os.File
	sink   io.Writer // sealer (when encrypting) or the file+hasher directly
	hasher hash.Hash // over the bytes as stored on disk, like session recordings
	upBytes, downBytes,
	captured int64 // captured = upBytes + downBytes, checked against the cap
	capped     bool // the per-file cap started refusing data (audited once)
	broken     bool // the artifact cannot be written; recording stopped (audited once)
	refuseData bool // always refuse this handle's data (a tracking bound overflowed)
	closing    bool // CLOSE seen with reads still in flight; finalize when they resolve
	inflight   int  // outstanding READ requests naming this handle
}

// sftpCapture is one session's content-capture state. Methods named gate* run
// on the request leg and can refuse a packet; methods named note*/bind* run on
// either leg and only observe. All of them lock, because the request inspector
// and the response watcher run on different goroutines.
type sftpCapture struct {
	mu       sync.Mutex
	ctx      context.Context
	dir      string // the recording directory
	base     string // the session recording's title; artifacts are <base>_f<N>.sftp
	kw       recording.KeyWrapper
	chain    *recordChain
	audit    func(action, detail string)
	maxBytes int64 // per-file captured-byte cap (0 = unlimited)
	up, down bool  // which directions this deployment captures
	required bool  // PAM_REQUIRE_RECORDING: an unwritable artifact refuses the transfer

	pendingOpens map[uint32]sftpPendingOpen
	pendingReads map[uint32]sftpPendingRead
	files        map[string]*sftpCaptureFile // keyed by the server-issued handle
	seq          int                         // artifacts created so far (names + the per-session bound)
	backlogged   bool                        // a tracking bound refused work (audited once)
}

// newSFTPCapture builds a session's capture state. base is the session
// recording's title, so a session's .cast and its .sftp artifacts share a
// prefix (under opaque naming both stay opaque — the path/actor mapping lives
// only in the audit trail, the Phase 48 discipline). required mirrors
// PAM_REQUIRE_RECORDING: when set, a file whose artifact cannot be created or
// written has its data refused rather than forwarded unrecorded.
func newSFTPCapture(dir, base string, kw recording.KeyWrapper, chain *recordChain, mode SFTPCaptureMode, maxBytes int64, required bool, audit func(action, detail string)) *sftpCapture {
	return &sftpCapture{
		ctx:          context.Background(),
		dir:          dir,
		base:         base,
		kw:           kw,
		chain:        chain,
		audit:        audit,
		maxBytes:     maxBytes,
		up:           mode == SFTPCaptureUploads || mode == SFTPCaptureAll,
		down:         mode == SFTPCaptureDownloads || mode == SFTPCaptureAll,
		required:     required,
		pendingOpens: make(map[uint32]sftpPendingOpen),
		pendingReads: make(map[uint32]sftpPendingRead),
		files:        make(map[string]*sftpCaptureFile),
	}
}

// refuseBacklog audits (once) that a tracking bound was hit and reports the
// refusal. Fail closed: an untracked open or read would be unrecorded flow.
func (c *sftpCapture) refuseBacklog(what string) bool {
	if !c.backlogged {
		c.backlogged = true
		c.audit("sftp.blocked", "reason:capture-backlog detail:"+what+" tracking bound reached; further requests of this kind are refused while capture is enforced")
	}
	return true
}

// trackOpen records an OPEN the inspector is about to forward, so the HANDLE
// response can be tied back to the path. It reports refuse=true when capture
// cannot track the open (a bound was hit), in which case the inspector answers
// permission-denied instead of forwarding. An open in a direction this
// deployment does not capture is simply not tracked.
func (c *sftpCapture) trackOpen(id uint32, path string, read, write bool) (refuse bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !((write && c.up) || (read && c.down)) {
		return false // direction not captured: forward untracked
	}
	if len(c.pendingOpens) >= sftpCaptureMaxPending {
		return c.refuseBacklog("pending opens")
	}
	if c.seq >= sftpCaptureMaxFiles {
		return c.refuseBacklog("artifacts this session")
	}
	mode := "readwrite"
	switch {
	case write && !read:
		mode = "write"
	case read && !write:
		mode = "read"
	}
	c.pendingOpens[id] = sftpPendingOpen{path: path, mode: mode}
	return false
}

// bindHandle (response leg) ties a HANDLE response to its pending OPEN and
// creates the capture artifact for it. A handle with no pending open — a
// directory handle, or an open in an uncaptured direction — is ignored.
func (c *sftpCapture) bindHandle(id uint32, handle string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	po, ok := c.pendingOpens[id]
	if !ok {
		return
	}
	delete(c.pendingOpens, id)
	if old := c.files[handle]; old != nil {
		// The server re-issued a handle still tracked here (its close was
		// deferred); the old artifact is finished by definition. Reads still
		// awaited against the old file must not be attributed to the new one.
		for rid, pr := range c.pendingReads {
			if pr.handle == handle {
				delete(c.pendingReads, rid)
			}
		}
		c.finalizeLocked(handle, old, "handle-reused")
	}
	cf := &sftpCaptureFile{remote: po.path, mode: po.mode}
	c.files[handle] = cf
	if c.openArtifacts() >= sftpCaptureMaxOpen {
		// No artifact can back this handle, so its data is refused outright:
		// the bound exists to contain abuse, and only a client far outside any
		// real SFTP implementation's behavior can reach it.
		cf.refuseData = true
		c.refuseBacklog("open artifacts")
		return
	}
	name := fmt.Sprintf("%s_f%d.sftp", c.base, c.seq)
	c.seq++
	if err := c.openArtifact(cf, name); err != nil {
		cf.broken = true
		cf.f = nil
		c.audit("sftp.capture_failed", fmt.Sprintf("path:%s file:%s error:%v", auditPath(po.path), name, err))
	}
}

// openArtifacts counts the files that actually hold an open descriptor.
func (c *sftpCapture) openArtifacts() int {
	n := 0
	for _, f := range c.files {
		if f.f != nil {
			n++
		}
	}
	return n
}

// openArtifact creates one artifact file and its hashing/sealing pipeline,
// then writes the header line. Mirrors newRecording: the hash is taken over
// the bytes as stored on disk, so the audited SHA-256 and the recording chain
// keep describing the artifact at rest whether or not it is sealed; a sealer
// failure removes the empty file so nothing lands in the clear by accident.
func (c *sftpCapture) openArtifact(cf *sftpCaptureFile, name string) error {
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(c.dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- name is proxy-generated (title + ordinal), never client input
	if err != nil {
		return err
	}
	hasher := sha256.New()
	var sink io.Writer = io.MultiWriter(f, hasher)
	if c.kw != nil {
		sealer, serr := recording.NewSealer(c.ctx, sink, c.kw, name)
		if serr != nil {
			f.Close()
			_ = os.Remove(path)
			return serr
		}
		sink = sealer
	}
	hdr, err := recording.EncodeSFTPHeader(recording.SFTPFileHeader{Path: cf.remote, OpenMode: cf.mode, Time: time.Now().Unix()})
	if err == nil {
		_, err = sink.Write(hdr)
	}
	if err != nil {
		f.Close()
		_ = os.Remove(path)
		return err
	}
	cf.name, cf.f, cf.sink, cf.hasher = name, f, sink, hasher
	return nil
}

// record appends one chunk to an artifact, updating the counters. A write
// failure marks the artifact broken and audits it once; whether that also
// refuses further data is the caller's required-mode decision.
func (c *sftpCapture) record(cf *sftpCaptureFile, dir string, offset uint64, data []byte) {
	if cf.broken || cf.f == nil {
		return
	}
	line, err := recording.EncodeSFTPChunk(recording.SFTPChunk{Dir: dir, Offset: offset, Data: data})
	if err == nil {
		_, err = cf.sink.Write(line)
	}
	if err != nil {
		cf.broken = true
		c.audit("sftp.capture_failed", fmt.Sprintf("path:%s file:%s error:%v", auditPath(cf.remote), cf.name, err))
		return
	}
	cf.captured += int64(len(data))
	if dir == "w" {
		cf.upBytes += int64(len(data))
	} else {
		cf.downBytes += int64(len(data))
	}
}

// overCap reports whether adding n bytes to cf would exceed the per-file cap,
// auditing the first refusal. Beyond the cap the transfer is refused, not
// merely uncaptured: a cap that let bytes keep flowing unrecorded would be the
// exact gap this control exists to close (the same reasoning as the session
// recording cap, which ends the session rather than run it unrecorded).
func (c *sftpCapture) overCap(cf *sftpCaptureFile, n int64) bool {
	if c.maxBytes <= 0 || cf.captured+n <= c.maxBytes {
		return false
	}
	if !cf.capped {
		cf.capped = true
		c.audit("sftp.blocked", fmt.Sprintf("op:transfer path:%s reason:capture-limit max_bytes:%d", auditPath(cf.remote), c.maxBytes))
	}
	return true
}

// gateWrite (request leg) decides one WRITE packet: refuse it (cap hit, or the
// artifact is unwritable under required mode), or record its data and let it
// forward. A WRITE on an untracked handle — a directory-less server quirk, or
// an uncaptured direction — forwards untouched; writes are simply not recorded
// when only downloads are captured, which is the admin's stated choice.
func (c *sftpCapture) gateWrite(handle string, offset uint64, data []byte) (refuse bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cf := c.files[handle]
	if cf == nil || !c.up {
		return false
	}
	if cf.refuseData || (cf.broken && c.required) {
		return true
	}
	if offset+uint64(len(data)) > recording.SFTPMaxOffset {
		c.audit("sftp.blocked", fmt.Sprintf("op:write path:%s reason:offset-out-of-range", auditPath(cf.remote)))
		return true
	}
	if c.overCap(cf, int64(len(data))) {
		return true
	}
	c.record(cf, "w", offset, data)
	if cf.broken && c.required {
		return true // the recording just failed; the bytes must not move unrecorded
	}
	return false
}

// gateRead (request leg) decides one READ packet: refuse it (cap already
// reached, tracking full, or the artifact is unwritable under required mode) or
// register it so the DATA response can be attributed. The response may exceed
// the cap by the requests already in flight — bounded by the client's pipeline
// window — and everything that actually arrives is recorded.
func (c *sftpCapture) gateRead(id uint32, handle string, offset uint64) (refuse bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cf := c.files[handle]
	if cf == nil || !c.down {
		return false
	}
	if cf.refuseData || (cf.broken && c.required) {
		return true
	}
	if offset > recording.SFTPMaxOffset {
		c.audit("sftp.blocked", fmt.Sprintf("op:read path:%s reason:offset-out-of-range", auditPath(cf.remote)))
		return true
	}
	if c.overCap(cf, 1) {
		return true
	}
	if len(c.pendingReads) >= sftpCaptureMaxPending {
		return c.refuseBacklog("pending reads")
	}
	c.pendingReads[id] = sftpPendingRead{handle: handle, offset: offset}
	cf.inflight++
	return false
}

// noteData (response leg) attributes a DATA response to its pending READ and
// records the bytes. Data for an id nothing waits on is ignored (a read in an
// uncaptured direction, or protocol noise).
func (c *sftpCapture) noteData(id uint32, data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	pr, ok := c.pendingReads[id]
	if !ok {
		return
	}
	delete(c.pendingReads, id)
	cf := c.files[pr.handle]
	if cf == nil {
		return
	}
	cf.inflight--
	c.record(cf, "r", pr.offset, data)
	if cf.closing && cf.inflight <= 0 {
		c.finalizeLocked(pr.handle, cf, "close")
	}
}

// noteStatus (response leg) resolves a request id that failed or finished
// without data: a refused OPEN loses its pending entry, a READ that hit EOF or
// an error stops being awaited (and may release a deferred close).
func (c *sftpCapture) noteStatus(id uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.pendingOpens, id)
	pr, ok := c.pendingReads[id]
	if !ok {
		return
	}
	delete(c.pendingReads, id)
	if cf := c.files[pr.handle]; cf != nil {
		cf.inflight--
		if cf.closing && cf.inflight <= 0 {
			c.finalizeLocked(pr.handle, cf, "close")
		}
	}
}

// noteClose (request leg) finalizes a handle's artifact — unless reads are
// still in flight, in which case finalization waits for them: a client that
// CLOSEs with a READ outstanding would otherwise receive data whose capture
// had already been sealed, which is exactly the evasion the deferral prevents.
func (c *sftpCapture) noteClose(handle string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cf := c.files[handle]
	if cf == nil {
		return
	}
	if cf.inflight > 0 {
		cf.closing = true
		return
	}
	c.finalizeLocked(handle, cf, "close")
}

// finalizeAll closes every remaining artifact at session end (handles the
// client never closed, or closes deferred behind in-flight reads that will now
// never resolve).
func (c *sftpCapture) finalizeAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for handle, cf := range c.files {
		c.finalizeLocked(handle, cf, "session-end")
	}
	c.pendingOpens = map[uint32]sftpPendingOpen{}
	c.pendingReads = map[uint32]sftpPendingRead{}
}

// finalizeLocked closes one artifact, hashes it into the recording chain and
// audits sftp.file_recorded — the event that ties remote path, artifact name,
// byte counts, SHA-256 and chain position together (and that the playback API
// uses to attribute and tamper-check the artifact). Callers hold c.mu. An
// artifact that never opened (creation failed) was already audited as
// sftp.capture_failed and leaves no file to attest.
func (c *sftpCapture) finalizeLocked(handle string, cf *sftpCaptureFile, reason string) {
	delete(c.files, handle)
	if cf.f == nil {
		return
	}
	cf.f.Close()
	sum := fmt.Sprintf("%x", cf.hasher.Sum(nil))
	chain := c.chain.append(sum)
	detail := fmt.Sprintf("path:%s file:%s open_mode:%s bytes_up:%d bytes_down:%d sha256:%s chain:%s",
		auditPath(cf.remote), cf.name, cf.mode, cf.upBytes, cf.downBytes, sum, chain)
	if cf.capped {
		detail += " capped:true"
	}
	if cf.broken {
		detail += " incomplete:true"
	}
	if reason != "close" {
		detail += " closed:" + reason
	}
	c.audit("sftp.file_recorded", detail)
}

// --- response-leg watcher ----------------------------------------------------

// sftpRespWatcher frames the target→operator SFTP stream and feeds capture the
// three response types it needs (HANDLE, DATA, STATUS). It never alters the
// stream — responses are forwarded by the caller exactly as received — but a
// stream it cannot frame fails the session closed, per the capture posture.
// Single-goroutine (the session's target-output copy loop), like the request
// inspector; shared state lives behind sftpCapture's lock.
type sftpRespWatcher struct {
	cap *sftpCapture
	buf bytes.Buffer
}

// SFTP response packet types the watcher distinguishes.
const (
	fxpHandle = 102
	fxpData   = 103
)

// observe consumes one chunk of the response stream, framing and handling any
// complete packets inside it. It returns errSFTPCaptureAbort when the stream
// cannot be parsed — the caller stops the session rather than let content flow
// unobserved.
func (w *sftpRespWatcher) observe(chunk []byte) error {
	w.buf.Write(chunk)
	for {
		b := w.buf.Bytes()
		if len(b) < 4 {
			return nil
		}
		plen := binary.BigEndian.Uint32(b[:4])
		if plen < 1 || plen > sftpMaxPacket {
			return w.abort()
		}
		if uint32(len(b)-4) < plen {
			return nil
		}
		body := make([]byte, plen)
		copy(body, b[4:4+plen])
		w.buf.Next(int(4 + plen))
		if err := w.handle(body); err != nil {
			return err
		}
	}
}

// handle inspects one framed response packet (type byte + payload).
func (w *sftpRespWatcher) handle(body []byte) error {
	if len(body) < 1 {
		return nil
	}
	switch body[0] {
	case fxpHandle:
		id, r, ok := readU32(body[1:])
		h, _, ok2 := readString(r)
		if !(ok && ok2) {
			return w.abort()
		}
		w.cap.bindHandle(id, h)
	case fxpData:
		id, r, ok := readU32(body[1:])
		data, _, ok2 := readBytesView(r)
		if !(ok && ok2) {
			return w.abort()
		}
		w.cap.noteData(id, data)
	case fxpStatus:
		id, _, ok := readU32(body[1:])
		if !ok {
			return w.abort()
		}
		w.cap.noteStatus(id)
	}
	return nil
}

// abort audits the unparsable response stream and reports the fail-closed
// error that tears the session down.
func (w *sftpRespWatcher) abort() error {
	w.cap.audit("sftp.parse_error", "detail:unframable SFTP response stream; content capture is enforced, so the session fails closed")
	return errSFTPCaptureAbort
}

// copyObserved is io.Copy with the response watcher in the path: every chunk
// read from the target is (1) parsed for capture once the SFTP subsystem is
// active, then (2) forwarded unchanged. It returns the first write or watcher
// error (nil on a clean source EOF), mirroring io.Copy's error semantics so
// the recording-limit check upstream keeps working.
func copyObserved(dst io.Writer, src io.Reader, active func() bool, w *sftpRespWatcher) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if active() {
				if perr := w.observe(buf[:n]); perr != nil {
					return perr
				}
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if err != nil {
			return nil
		}
	}
}

// readU64 reads a big-endian uint64 off the front of b (SFTP file offsets),
// returning the value, the remainder, and whether b was long enough.
func readU64(b []byte) (uint64, []byte, bool) {
	if len(b) < 8 {
		return 0, b, false
	}
	return binary.BigEndian.Uint64(b), b[8:], true
}

// readBytesView reads an SFTP string off the front of b WITHOUT copying it to a
// string — a view into b, valid only while b is. Used for data payloads, which
// are recorded (base64-encoded) before the packet buffer is reused.
func readBytesView(b []byte) ([]byte, []byte, bool) {
	n, r, ok := readU32(b)
	if !ok || uint32(len(r)) < n {
		return nil, b, false
	}
	return r[:n], r[n:], true
}
