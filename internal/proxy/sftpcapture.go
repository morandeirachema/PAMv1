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
// file offset the arriving bytes belong to, and how many bytes it reserved
// against the per-file cap (released when the response resolves it).
type sftpPendingRead struct {
	handle   string
	offset   uint64
	reserved int64
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
	reserved   int64 // bytes claimed against the cap by READs still in flight
	capped     bool  // the per-file cap started refusing data (audited once)
	broken     bool  // the artifact cannot be written; recording stopped (audited once)
	refuseData bool  // always refuse this handle's data (a tracking bound overflowed)
	closing    bool  // CLOSE seen with reads still in flight; finalize when they resolve
	inflight   int   // outstanding READ requests naming this handle
}

// sftpCapture is one session's content-capture state. Methods named gate* run
// on the request leg and can refuse a packet; methods named note*/bind* run on
// either leg and only observe. All of them lock, because the request inspector
// and the response watcher run on different goroutines.
type sftpCapture struct {
	mu           sync.Mutex
	ctx          context.Context
	dir          string // the recording directory
	base         string // sanitized session-recording title; artifacts are <base>_f<N>.sftp
	kw           recording.KeyWrapper
	chain        *recordChain
	audit        func(action, detail string) // in-session events
	auditClosing func(action, detail string) // events written as the session unwinds
	maxBytes     int64                       // per-file captured-byte cap (0 = unlimited)
	up, down     bool                        // which directions this deployment captures
	required     bool                        // PAM_REQUIRE_RECORDING: an unwritable artifact refuses the transfer

	pendingOpens map[uint32]sftpPendingOpen
	pendingReads map[uint32]sftpPendingRead
	outstanding  map[uint32]struct{}         // request ids awaiting a response
	files        map[string]*sftpCaptureFile // keyed by the server-issued handle
	seq          int                         // artifacts created so far (names + the per-session bound)
	backlogged   bool                        // a tracking bound refused work (audited once)
	pending      []sftpAuditRec              // audit events queued while the lock is held
}

// sftpAuditRec is one queued audit event. Capture never writes to the audit
// store while holding its mutex: the store is a database round trip, and the
// request and response legs both block on that mutex for every packet.
type sftpAuditRec struct {
	action, detail string
	closing        bool // emit through the session-teardown auditor
}

// artifactWrapTimeout bounds the KEK call that wraps one artifact's data key.
// Without it a blackholed KMS would hang a session forever with no error —
// this is per transferred FILE, not per session, so the exposure is wider than
// the session recording's equivalent.
const artifactWrapTimeout = 10 * time.Second

// newSFTPCapture builds a session's capture state. base is the session
// recording's title, so a session's .cast and its .sftp artifacts share a
// prefix (under opaque naming both stay opaque — the path/actor mapping lives
// only in the audit trail, the Phase 48 discipline). It is sanitized here, the
// same treatment newRecording gives the .cast name: the title embeds the
// target and actor names, so an unsanitized one could escape the recording
// directory or produce a file the playback allowlist can never serve.
// required mirrors PAM_REQUIRE_RECORDING: when set, a file whose artifact
// cannot be created or written has its data refused rather than forwarded
// unrecorded.
func newSFTPCapture(ctx context.Context, dir, base string, kw recording.KeyWrapper, chain *recordChain, mode SFTPCaptureMode, maxBytes int64, required bool, audit, auditClosing func(action, detail string)) *sftpCapture {
	if ctx == nil {
		ctx = context.Background()
	}
	return &sftpCapture{
		ctx:          ctx,
		dir:          dir,
		base:         sanitize(base),
		kw:           kw,
		chain:        chain,
		audit:        audit,
		auditClosing: auditClosing,
		maxBytes:     maxBytes,
		up:           mode == SFTPCaptureUploads || mode == SFTPCaptureAll,
		down:         mode == SFTPCaptureDownloads || mode == SFTPCaptureAll,
		required:     required,
		pendingOpens: make(map[uint32]sftpPendingOpen),
		pendingReads: make(map[uint32]sftpPendingRead),
		outstanding:  make(map[uint32]struct{}),
		files:        make(map[string]*sftpCaptureFile),
	}
}

// note queues an audit event to be written once the mutex is released.
func (c *sftpCapture) note(action, detail string) {
	c.pending = append(c.pending, sftpAuditRec{action: action, detail: detail})
}

// noteClosingAudit queues an event that must survive session teardown — the
// per-file attestation, which is written exactly when a session may be
// unwinding and whose loss would leave an artifact on disk that the trail
// never names.
func (c *sftpCapture) noteClosingAudit(action, detail string) {
	c.pending = append(c.pending, sftpAuditRec{action: action, detail: detail, closing: true})
}

// flush writes the queued audit events. Every entry point defers it BEFORE
// deferring the unlock, so it runs after the mutex is released.
func (c *sftpCapture) flush() {
	c.mu.Lock()
	queued := c.pending
	c.pending = nil
	c.mu.Unlock()
	for _, a := range queued {
		emit := c.audit
		if a.closing && c.auditClosing != nil {
			emit = c.auditClosing
		}
		if emit != nil {
			emit(a.action, a.detail)
		}
	}
}

// refuseBacklog audits (once) that a tracking bound was hit and reports the
// refusal. Fail closed: an untracked open or read would be unrecorded flow.
func (c *sftpCapture) refuseBacklog(what string) bool {
	if !c.backlogged {
		c.backlogged = true
		c.note("sftp.blocked", "reason:capture-backlog detail:"+what+" tracking bound reached; further requests of this kind are refused while capture is enforced")
	}
	return true
}

// noteRequest claims a request id on the request leg, before the packet is
// forwarded. It refuses an id that is already awaiting a response.
//
// This is what makes handle tracking sound. Correlating data with a file needs
// the OPEN's id to survive until its HANDLE arrives, and a client that reuses
// an id for two in-flight requests can make the wrong response resolve the
// pending open — [SSH_FXP_STAT id=7][SSH_FXP_OPEN id=7] has the STAT's status
// discard the open, after which every WRITE on that handle is untracked and
// moves uncaptured. The SFTP protocol has no rule against reusing an
// outstanding id (no real client does it), so capture enforces one: while
// content recording is on, an id may name one request at a time.
func (c *sftpCapture) noteRequest(id uint32) (refuse bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, busy := c.outstanding[id]; busy {
		return c.refuseBacklog("request id reused while outstanding")
	}
	if len(c.outstanding) >= sftpCaptureMaxPending {
		return c.refuseBacklog("outstanding requests")
	}
	c.outstanding[id] = struct{}{}
	return false
}

// releaseID frees a request id: called for every response the watcher frames,
// and for every refusal capture synthesizes itself (which the target will
// never answer).
func (c *sftpCapture) releaseID(id uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.outstanding, id)
}

// trackOpen records an OPEN the inspector is about to forward, so the HANDLE
// response can be tied back to the path. It reports refuse=true when capture
// cannot track the open (a bound was hit), in which case the inspector answers
// permission-denied instead of forwarding. An open in a direction this
// deployment does not capture is simply not tracked.
func (c *sftpCapture) trackOpen(id uint32, path string, read, write bool) (refuse bool) {
	defer c.flush()
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
	defer c.flush()
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
	// sanitize again on the assembled name, not only on the base: it is what
	// actually reaches filepath.Join, and the playback allowlist
	// (api.recordingNameRe) accepts exactly this alphabet — an artifact it
	// rejects is evidence no auditor can list, replay or archive, while
	// retention would still delete it on schedule.
	name := sanitize(fmt.Sprintf("%s_f%d", c.base, c.seq)) + ".sftp"
	c.seq++
	if err := c.openArtifact(cf, name); err != nil {
		cf.broken = true
		cf.f = nil
		c.note("sftp.capture_failed", fmt.Sprintf("path:%s file:%s error:%v", auditPath(po.path), name, err))
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
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- name is sanitize()d to [A-Za-z0-9._@-], so it cannot leave c.dir
	if err != nil {
		return err
	}
	hasher := sha256.New()
	var sink io.Writer = io.MultiWriter(f, hasher)
	if c.kw != nil {
		// Bounded and cancellable: this is a KMS round trip taken once per
		// transferred file, and it runs under the lock both SFTP legs need.
		ctx, cancel := context.WithTimeout(c.ctx, artifactWrapTimeout)
		sealer, serr := recording.NewSealer(ctx, sink, c.kw, name)
		cancel()
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
		c.note("sftp.capture_failed", fmt.Sprintf("path:%s file:%s error:%v", auditPath(cf.remote), cf.name, err))
		return
	}
	cf.captured += int64(len(data))
	if dir == "w" {
		cf.upBytes += int64(len(data))
	} else {
		cf.downBytes += int64(len(data))
	}
}

// overCap reports whether claiming n more bytes for cf would exceed the
// per-file cap, auditing the first refusal. Beyond the cap the transfer is
// refused, not merely uncaptured: a cap that let bytes keep flowing unrecorded
// would be the exact gap this control exists to close (the same reasoning as
// the session recording cap, which ends the session rather than run it
// unrecorded).
//
// Bytes already claimed by in-flight READs count. Without that, the cap bounded
// uploads only: a download's counter grows when DATA arrives, so a client
// pipelining its usual 64 reads of 256 KiB blows 16 MiB past a 1 MiB cap
// before the first refusal, and one widening its window goes further. The
// documented behaviour is a hard per-file limit, so the claim has to be made
// when the request is admitted, not when the answer lands.
func (c *sftpCapture) overCap(cf *sftpCaptureFile, n int64) bool {
	if c.maxBytes <= 0 || cf.captured+cf.reserved+n <= c.maxBytes {
		return false
	}
	if !cf.capped {
		cf.capped = true
		c.note("sftp.blocked", fmt.Sprintf("op:transfer path:%s reason:capture-limit max_bytes:%d", auditPath(cf.remote), c.maxBytes))
	}
	return true
}

// gateWrite (request leg) decides one WRITE packet: refuse it (cap hit, or the
// artifact is unwritable under required mode), or record its data and let it
// forward. A WRITE on an untracked handle — a directory-less server quirk, or
// an uncaptured direction — forwards untouched; writes are simply not recorded
// when only downloads are captured, which is the admin's stated choice.
func (c *sftpCapture) gateWrite(handle string, offset uint64, data []byte) (refuse bool) {
	defer c.flush()
	c.mu.Lock()
	defer c.mu.Unlock()
	cf := c.files[handle]
	if cf == nil || !c.up {
		return false
	}
	if cf.refuseData || cf.broken {
		// A broken artifact refuses in every mode, not only under
		// PAM_REQUIRE_RECORDING: `broken` is sticky, so continuing would forward
		// the whole rest of the file with the capture silently stopped — which
		// one crafted packet used to be enough to arrange.
		return true
	}
	// Written as a subtraction because the sum overflows: offset is a wire
	// uint64, and 0xFFFF…FFFF + 1 wraps to 0, which slipped past the bound and
	// then broke the artifact from inside record().
	if offset > recording.SFTPMaxOffset || uint64(len(data)) > recording.SFTPMaxOffset-offset {
		c.note("sftp.blocked", fmt.Sprintf("op:write path:%s reason:offset-out-of-range", auditPath(cf.remote)))
		return true
	}
	if c.overCap(cf, int64(len(data))) {
		return true
	}
	c.record(cf, "w", offset, data)
	return cf.broken // the recording just failed; the bytes must not move unrecorded
}

// gateRead (request leg) decides one READ packet: refuse it (the cap cannot
// cover the bytes it asks for, tracking is full, or the artifact is
// unwritable) or register it so the DATA response can be attributed. length is
// the READ's requested byte count, which is claimed against the cap now and
// released when the response resolves — see overCap.
func (c *sftpCapture) gateRead(id uint32, handle string, offset uint64, length uint32) (refuse bool) {
	defer c.flush()
	c.mu.Lock()
	defer c.mu.Unlock()
	cf := c.files[handle]
	if cf == nil || !c.down {
		return false
	}
	if cf.refuseData || cf.broken {
		return true
	}
	if offset > recording.SFTPMaxOffset {
		c.note("sftp.blocked", fmt.Sprintf("op:read path:%s reason:offset-out-of-range", auditPath(cf.remote)))
		return true
	}
	// A zero-length read still occupies a slot and must resolve, so it claims
	// one byte rather than nothing.
	want := int64(length)
	if want <= 0 {
		want = 1
	}
	if c.overCap(cf, want) {
		return true
	}
	if len(c.pendingReads) >= sftpCaptureMaxPending {
		return c.refuseBacklog("pending reads")
	}
	c.pendingReads[id] = sftpPendingRead{handle: handle, offset: offset, reserved: want}
	cf.reserved += want
	cf.inflight++
	return false
}

// releaseRead drops a resolved READ's claim on the cap and its in-flight count,
// returning the file it belonged to (nil if the handle is already gone).
// Callers hold c.mu.
func (c *sftpCapture) releaseRead(pr sftpPendingRead) *sftpCaptureFile {
	cf := c.files[pr.handle]
	if cf == nil {
		return nil
	}
	cf.inflight--
	cf.reserved -= pr.reserved
	if cf.reserved < 0 {
		cf.reserved = 0
	}
	return cf
}

// noteData (response leg) attributes a DATA response to its pending READ and
// records the bytes. Data for an id nothing waits on is ignored (a read in an
// uncaptured direction, or protocol noise).
func (c *sftpCapture) noteData(id uint32, data []byte) {
	defer c.flush()
	c.mu.Lock()
	defer c.mu.Unlock()
	pr, ok := c.pendingReads[id]
	if !ok {
		return
	}
	delete(c.pendingReads, id)
	cf := c.releaseRead(pr)
	if cf == nil {
		return
	}
	c.record(cf, "r", pr.offset, data)
	if cf.closing && cf.inflight <= 0 {
		c.finalizeLocked(pr.handle, cf, "close")
	}
}

// noteStatus (response leg) resolves a request id that failed or finished
// without data: a refused OPEN loses its pending entry, a READ that hit EOF or
// an error stops being awaited (and may release a deferred close). An id names
// one outstanding request at a time (noteRequest), so the pending open this
// clears can only be the one this status answers.
func (c *sftpCapture) noteStatus(id uint32) {
	defer c.flush()
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.pendingOpens, id)
	pr, ok := c.pendingReads[id]
	if !ok {
		return
	}
	delete(c.pendingReads, id)
	if cf := c.releaseRead(pr); cf != nil && cf.closing && cf.inflight <= 0 {
		c.finalizeLocked(pr.handle, cf, "close")
	}
}

// noteClose (request leg) finalizes a handle's artifact — unless reads are
// still in flight, in which case finalization waits for them: a client that
// CLOSEs with a READ outstanding would otherwise receive data whose capture
// had already been sealed, which is exactly the evasion the deferral prevents.
func (c *sftpCapture) noteClose(handle string) {
	defer c.flush()
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
	defer c.flush()
	c.mu.Lock()
	defer c.mu.Unlock()
	for handle, cf := range c.files {
		c.finalizeLocked(handle, cf, "session-end")
	}
	c.pendingOpens = map[uint32]sftpPendingOpen{}
	c.pendingReads = map[uint32]sftpPendingRead{}
	c.outstanding = map[uint32]struct{}{}
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
	// Through the closing auditor: this fires exactly when a session may be
	// unwinding (a drain on SIGTERM finalizes every open artifact), and the
	// chain head has already advanced on disk — an attestation dropped because
	// the session context was cancelled would leave a file whose hash appears
	// nowhere, which playback reports as indistinguishable from tampering.
	c.noteClosingAudit("sftp.file_recorded", detail)
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

// SFTP response packet types. Every response carries the request id as its
// first field, which is what lets the watcher free the id whatever the server
// answered — including the NAME/ATTRS/EXTENDED_REPLY kinds capture does not
// otherwise care about, whose ids would otherwise accumulate until the pending
// bound refused an honest session.
const (
	fxpHandle        = 102
	fxpData          = 103
	fxpName          = 104
	fxpAttrs         = 105
	fxpExtendedReply = 201
)

// observe consumes one chunk of the response stream and returns the bytes that
// form COMPLETE packets, which is what the caller forwards; a partial tail
// stays buffered until the rest of it arrives. It returns errSFTPCaptureAbort
// when the stream cannot be parsed — the caller stops the session rather than
// let content flow unobserved.
//
// Forwarding whole packets is not tidiness: the request goroutine writes
// synthesized SSH_FXP_STATUS refusals to the SAME serialized writer, and
// syncWriter serializes Write calls, not packet boundaries. Forwarding raw
// 32 KiB reads meant a refusal could land inside a half-written 32 KiB DATA
// response, after which the client reads the status bytes as file content and
// every later boundary is shifted — routine once a mid-transfer cap refusal
// exists.
func (w *sftpRespWatcher) observe(chunk []byte) ([]byte, error) {
	w.buf.Write(chunk)
	var forward []byte
	for {
		b := w.buf.Bytes()
		if len(b) < 4 {
			return forward, nil
		}
		plen := binary.BigEndian.Uint32(b[:4])
		if plen < 1 || plen > sftpMaxPacket {
			return forward, w.abort()
		}
		if uint32(len(b)-4) < plen {
			return forward, nil
		}
		packet := make([]byte, 4+plen)
		copy(packet, b[:4+plen])
		w.buf.Next(int(4 + plen))
		forward = append(forward, packet...)
		if err := w.handle(packet[4:]); err != nil {
			return forward, err
		}
	}
}

// handle inspects one framed response packet (type byte + payload).
func (w *sftpRespWatcher) handle(body []byte) error {
	if len(body) < 1 {
		return nil
	}
	id, rest, ok := readU32(body[1:])
	if !ok {
		if body[0] >= fxpStatus {
			return w.abort() // a response with no request id is not framable
		}
		return nil
	}
	switch body[0] {
	case fxpHandle:
		h, _, ok := readString(rest)
		if !ok {
			return w.abort()
		}
		w.cap.bindHandle(id, h)
	case fxpData:
		data, _, ok := readBytesView(rest)
		if !ok {
			return w.abort()
		}
		w.cap.noteData(id, data)
	case fxpStatus:
		w.cap.noteStatus(id)
	}
	switch body[0] {
	case fxpStatus, fxpHandle, fxpData, fxpName, fxpAttrs, fxpExtendedReply:
		w.cap.releaseID(id)
	}
	return nil
}

// abort audits the unparsable response stream and reports the fail-closed
// error that tears the session down.
func (w *sftpRespWatcher) abort() error {
	w.cap.audit("sftp.parse_error", "detail:unframable SFTP response stream; content capture is enforced, so the session fails closed")
	return errSFTPCaptureAbort
}

// copyObserved is io.Copy with the response watcher in the path: once the SFTP
// subsystem is active the target's bytes are framed for capture and forwarded
// one whole packet at a time; before that (a shell or exec session) they are
// forwarded unchanged. It returns the first write or watcher error (nil on a
// clean source EOF), mirroring io.Copy's error semantics so the
// recording-limit check upstream keeps working.
func copyObserved(dst io.Writer, src io.Reader, active func() bool, w *sftpRespWatcher) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			out, perr := buf[:n], error(nil)
			if active() {
				out, perr = w.observe(buf[:n])
			}
			if len(out) > 0 {
				if _, werr := dst.Write(out); werr != nil {
					return werr
				}
			}
			if perr != nil {
				return perr
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
