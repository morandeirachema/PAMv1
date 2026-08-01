package proxy

// sftpguard.go implements file-transfer control for the SSH proxy. SFTP is not a
// separate protocol on the wire: it runs as an SSH "subsystem" channel whose
// payload is the binary SFTP protocol (the version-3 dialect OpenSSH speaks —
// draft-ietf-secsh-filexfer-02,
// https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02). Without
// inspection that stream flows through the proxy opaque: an operator can upload
// or exfiltrate files with no audit trail and no policy gate, and the bytes only
// garble the session recording. This inspector sits on the operator→target leg
// of an SFTP session and, per SFTP request packet, records an audit event for
// each file operation and — in read-only mode — refuses a mutating request by
// synthesizing a permission-denied response back to the client, so the target is
// never touched. It parses the wire format directly (no third-party SFTP
// dependency) and fails open on forwarding but loud on auditing: a frame it
// cannot parse is passed through and flagged, never silently dropped.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sync/atomic"

	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/cmdguard"
)

// SFTPMode is the SSH proxy's file-transfer policy.
type SFTPMode string

const (
	// SFTPAllow forwards SFTP and audits every file operation (the default —
	// strictly more visible than the pre-Phase-32 opaque pass-through).
	SFTPAllow SFTPMode = "allow"
	// SFTPReadOnly forwards and audits read operations but refuses any mutating
	// one (upload, delete, rename, mkdir/rmdir, chmod/chown, symlink) with an SFTP
	// permission-denied status — the target is never contacted for the write.
	SFTPReadOnly SFTPMode = "readonly"
	// SFTPDeny refuses the SFTP subsystem outright: an operator gets a shell but
	// no file transfer at all.
	SFTPDeny SFTPMode = "deny"
)

// ParseSFTPMode maps a config string to an SFTPMode, defaulting an empty value to
// SFTPAllow and reporting an unknown one fail-loud.
func ParseSFTPMode(s string) (SFTPMode, error) {
	switch SFTPMode(s) {
	case "", SFTPAllow:
		return SFTPAllow, nil
	case SFTPReadOnly:
		return SFTPReadOnly, nil
	case SFTPDeny:
		return SFTPDeny, nil
	default:
		return "", fmt.Errorf("invalid SFTP mode %q (want allow, readonly, or deny)", s)
	}
}

// SFTP protocol packet types (version 3) that this inspector distinguishes. The
// read-family types not named here (CLOSE, READ, OPENDIR, READDIR, STAT, LSTAT,
// FSTAT, REALPATH, READLINK) are forwarded unmodified.
const (
	fxpInit     = 1
	fxpVersion  = 2
	fxpOpen     = 3
	fxpClose    = 4
	fxpRead     = 5
	fxpWrite    = 6
	fxpSetstat  = 9
	fxpFsetstat = 10
	fxpRemove   = 13
	fxpMkdir    = 14
	fxpRmdir    = 15
	fxpRename   = 18
	fxpSymlink  = 20
	fxpExtended = 200
	fxpStatus   = 101
)

// SSH_FXF_* file-open flags: a set bit among the write family marks write
// intent; the read bit marks download intent (content capture cares which).
const (
	fxfRead      = 0x00000001
	fxfWrite     = 0x00000002
	fxfAppend    = 0x00000004
	fxfCreat     = 0x00000008
	fxfTrunc     = 0x00000010
	fxfExcl      = 0x00000020
	fxfWriteMask = fxfWrite | fxfAppend | fxfCreat | fxfTrunc | fxfExcl
)

// SSH_FX_PERMISSION_DENIED is the SFTP status code returned for a refused op.
const fxPermissionDenied = 3

// sftpMaxPacket caps a single SFTP packet the inspector will buffer before
// giving up and passing the stream through opaquely — a malformed or hostile
// length field can't make it accumulate unbounded memory. OpenSSH's own limit is
// 256 KiB; this is generous of it.
const sftpMaxPacket = 1 << 20 // 1 MiB

// sftpInspector parses one operator→target SFTP stream. It is single-goroutine
// (driven by the session's client→upstream copy loop), so it needs no locking
// beyond the atomic activation flag that the request pump sets from another
// goroutine when it accepts the sftp subsystem.
type sftpInspector struct {
	mode    SFTPMode
	paths   *cmdguard.Guard             // path denylist; nil = no path policy
	capture *sftpCapture                // content capture (Phase 59); nil = off
	audit   func(action, detail string) // bound to this session's actor + target
	active  atomic.Bool                 // set once the sftp subsystem is accepted
	buf     bytes.Buffer                // accumulates bytes until a full packet is framed
	giveUp  bool                        // set on a parse error: forward the rest opaquely
	fatal   error                       // set when capture demands the session fail closed
}

// auditPath makes a client-supplied SFTP path safe for an audit detail. These
// paths come straight off the wire from the operator's SFTP client, so they can
// contain newlines, quotes, or text shaped like the `key:value` pairs the detail
// format uses — a filename of `x reason:allowed op:read` would read as three
// legitimate fields to a human or a SIEM parser. The same package already did
// this for commands (auditCmd); the SFTP inspector, added later, interpolated
// raw.
func auditPath(path string) string { return auditField(path, 400) }

// newSFTPInspector builds an inspector for mode, with an optional path denylist
// and optional content capture (Phase 59), auditing through audit. audit is
// invoked from the data path, so it must not block for long (it records a file
// operation, not a byte).
func newSFTPInspector(mode SFTPMode, paths *cmdguard.Guard, capture *sftpCapture, audit func(action, detail string)) *sftpInspector {
	return &sftpInspector{mode: mode, paths: paths, capture: capture, audit: audit}
}

// pathDenied reports whether path matches the denylist, and the pattern that
// matched. A nil guard denies nothing, so callers need no branch.
func (s *sftpInspector) pathDenied(path string) (string, bool) {
	return s.paths.Blocked(path)
}

// denyPath refuses one operation because its path is on the denylist, audits it
// with the matched pattern, and answers the client so it sees a permission
// error rather than hanging. It reports forward=false for the caller to return.
func (s *sftpInspector) denyPath(reply io.Writer, id uint32, op, path, pattern string) bool {
	s.audit("sftp.blocked", fmt.Sprintf("op:%s path:%s reason:path-denied pattern:%s", op, auditPath(path), auditField(pattern, 200)))
	s.deny(reply, id)
	return false
}

// activate marks the stream as SFTP (called when the subsystem request is
// accepted). Before this the operator→target bytes are an opaque shell/exec
// stream and are forwarded untouched.
func (s *sftpInspector) activate() {
	if s != nil {
		s.active.Store(true)
	}
}

// enabled reports whether SFTP parsing is live for this stream.
func (s *sftpInspector) enabled() bool { return s != nil && s.active.Load() }

// pump copies the operator's channel to the target, inspecting it as SFTP once
// activated. Forwarded packets go to dst (the upstream channel); a refusal is
// answered on reply (the operator's channel) so the client gets a proper SFTP
// status instead of hanging. It returns when src reaches EOF or errors,
// mirroring io.Copy's termination — except errSFTPCaptureAbort, which it
// returns so the caller can tear the whole session down (content capture found
// the stream unparsable and must fail closed, not merely stop copying).
//
// reply is an io.Writer rather than the channel itself, and that is the whole
// point: this runs on its own goroutine while the session's main goroutine is
// copying target output to the SAME channel. x/crypto/ssh documents that
// concurrent WriteExtended calls on one extended code share a pooled buffer and
// are unsafe, so the caller passes a writer that serializes them. Before Phase
// 51 a refusal only fired in readonly mode; path denials fire in allow mode too,
// which makes an ordinary mget over a mixed allowed/denied set a realistic
// trigger for a status packet interleaved into a split read response.
func (s *sftpInspector) pump(dst ssh.Channel, src io.Reader, reply io.Writer) error {
	rbuf := make([]byte, 32*1024)
	for {
		n, err := src.Read(rbuf)
		if n > 0 {
			if s.enabled() && !s.giveUp {
				if perr := s.process(rbuf[:n], dst, reply); perr != nil {
					return perr
				}
			} else if _, werr := dst.Write(rbuf[:n]); werr != nil {
				return werr
			}
		}
		if err != nil {
			return nil
		}
	}
}

// process frames complete SFTP packets out of the accumulated bytes, handling
// each and forwarding those that survive policy. A packet that cannot be parsed
// makes the inspector give up (flush the buffer and pass the rest through), so a
// protocol quirk degrades to today's opaque behavior rather than corrupting the
// session.
func (s *sftpInspector) process(chunk []byte, dst ssh.Channel, reply io.Writer) error {
	s.buf.Write(chunk)
	for {
		b := s.buf.Bytes()
		if len(b) < 4 {
			return nil // need the 4-byte length prefix
		}
		plen := binary.BigEndian.Uint32(b[:4])
		if plen < 1 || plen > sftpMaxPacket {
			return s.abandon(dst) // implausible framing: stop parsing, forward the rest
		}
		if uint32(len(b)-4) < plen {
			return nil // packet not fully arrived yet
		}
		// Copy the framed packet out before consuming: the following Buffer.Next
		// (and the next chunk's Write) may reuse the backing array.
		packet := make([]byte, 4+plen)
		copy(packet, b[:4+plen])
		s.buf.Next(int(4 + plen))

		if s.handlePacket(packet[4:], reply) {
			if _, err := dst.Write(packet); err != nil {
				return err
			}
		}
		if s.fatal != nil {
			return s.fatal
		}
	}
}

// abandon handles a stream the inspector cannot frame. Without content capture
// it flushes whatever is buffered to the upstream and switches to opaque
// pass-through for the remainder of the stream (fail-open on forwarding, loud
// on auditing — the Phase 32 posture for an audit-only control). With capture
// enabled that posture inverts: letting an unframable stream through would let
// any client move files uncaptured just by declining to be parseable, so the
// session fails closed instead.
func (s *sftpInspector) abandon(dst ssh.Channel) error {
	if s.capture != nil {
		s.audit("sftp.parse_error", "detail:unframable SFTP stream; content capture is enforced, so the session fails closed")
		return errSFTPCaptureAbort
	}
	s.giveUp = true
	s.audit("sftp.parse_error", "detail:unframed SFTP stream; inspection abandoned, transfer continues unaudited")
	rest := s.buf.Bytes()
	if len(rest) > 0 {
		if _, err := dst.Write(rest); err != nil {
			return err
		}
	}
	s.buf.Reset()
	return nil
}

// captureUnparsable handles a framed packet whose body capture needed but could
// not parse: with capture enforced the session fails closed (an unparseable
// WRITE would otherwise be unrecorded content), audited once. It reports false
// so the caller does not forward the packet.
func (s *sftpInspector) captureUnparsable(op string) bool {
	s.audit("sftp.parse_error", "detail:unparsable "+op+" packet; content capture is enforced, so the session fails closed")
	s.fatal = errSFTPCaptureAbort
	return false
}

// handlePacket audits and applies policy to one SFTP packet (body = type byte +
// payload). It reports whether the packet should be forwarded upstream. An
// unparseable body is forwarded (fail-open) rather than dropped.
func (s *sftpInspector) handlePacket(body []byte, reply io.Writer) (forward bool) {
	if len(body) < 1 {
		return true
	}
	switch body[0] {
	case fxpInit, fxpVersion:
		return true // the version handshake carries no request id
	case fxpOpen:
		return s.handleOpen(body[1:], reply)
	case fxpWrite:
		// Defence in depth: a read-only session should never have obtained a
		// writable handle (its OPEN was refused), but block any WRITE regardless.
		if s.mode == SFTPReadOnly {
			return !s.refuse(reply, body[1:], "write", "")
		}
		return s.handleWrite(body[1:], reply)
	case fxpRead:
		return s.handleRead(body[1:], reply)
	case fxpClose:
		return s.handleClose(body[1:])
	case fxpRemove:
		return s.handleMutating(body[1:], reply, "remove")
	case fxpRmdir:
		return s.handleMutating(body[1:], reply, "rmdir")
	case fxpMkdir:
		return s.handleMutating(body[1:], reply, "mkdir")
	case fxpSetstat:
		return s.handleMutating(body[1:], reply, "setstat")
	case fxpFsetstat:
		// FSETSTAT names a handle, not a path — block/audit without a path.
		if s.mode == SFTPReadOnly {
			return !s.refuse(reply, body[1:], "setstat", "")
		}
		s.audit("sftp.modify", "op:setstat path:<handle>")
		return true
	case fxpRename:
		return s.handleRename(body[1:], reply)
	case fxpSymlink:
		return s.handleMutating(body[1:], reply, "symlink")
	case fxpExtended:
		return s.handleExtended(body[1:], reply)
	default:
		return true // read-family op (opendir/readdir/stat/realpath/…)
	}
}

// handleWrite feeds a WRITE's data to content capture, which may refuse it
// (per-file cap reached, or an unwritable artifact under required-recording
// mode). Without capture the packet forwards untouched, as before Phase 59.
// rest: uint32 id, string handle, uint64 offset, string data.
func (s *sftpInspector) handleWrite(rest []byte, reply io.Writer) (forward bool) {
	if s.capture == nil {
		return true
	}
	id, r, ok := readU32(rest)
	handle, r2, ok2 := readString(r)
	offset, r3, ok3 := readU64(r2)
	data, _, ok4 := readBytesView(r3)
	if !(ok && ok2 && ok3 && ok4) {
		return s.captureUnparsable("write")
	}
	if s.capture.gateWrite(handle, offset, data) {
		s.deny(reply, id)
		return false
	}
	return true
}

// handleRead registers a READ with content capture so its DATA response can be
// attributed to the right file and offset — or refuses it when the per-file cap
// is already reached. rest: uint32 id, string handle, uint64 offset, uint32 len.
func (s *sftpInspector) handleRead(rest []byte, reply io.Writer) (forward bool) {
	if s.capture == nil {
		return true
	}
	id, r, ok := readU32(rest)
	handle, r2, ok2 := readString(r)
	offset, _, ok3 := readU64(r2)
	if !(ok && ok2 && ok3) {
		return s.captureUnparsable("read")
	}
	if s.capture.gateRead(id, handle, offset) {
		s.deny(reply, id)
		return false
	}
	return true
}

// handleClose tells content capture a handle is done so its artifact can be
// finalized (hashed, chained, audited). rest: uint32 id, string handle.
func (s *sftpInspector) handleClose(rest []byte) (forward bool) {
	if s.capture == nil {
		return true
	}
	_, r, ok := readU32(rest)
	handle, _, ok2 := readString(r)
	if !(ok && ok2) {
		return s.captureUnparsable("close")
	}
	s.capture.noteClose(handle)
	return true
}

// handleOpen audits a file open and, in read-only mode, refuses one that carries
// any write-intent flag. rest is the packet body after the type byte:
// uint32 id, string filename, uint32 pflags, ATTRS…
func (s *sftpInspector) handleOpen(rest []byte, reply io.Writer) (forward bool) {
	id, r, ok := readU32(rest)
	name, r2, ok2 := readString(r)
	pflags, _, ok3 := readU32(r2)
	if !(ok && ok2 && ok3) {
		if s.capture != nil {
			// An open capture cannot parse would leave its handle untracked —
			// every later WRITE/READ on it invisible — so it cannot be let through.
			return s.captureUnparsable("open")
		}
		return true // can't parse the open; forward rather than guess
	}
	// A denied path is refused in every mode and in both directions: allowing
	// the read of a path you have denied would protect nothing.
	if pattern, denied := s.pathDenied(name); denied {
		return s.denyPath(reply, id, "open", name, pattern)
	}
	write := pflags&fxfWriteMask != 0
	mode := "read"
	if write {
		mode = "write"
	}
	if write && s.mode == SFTPReadOnly {
		s.audit("sftp.blocked", fmt.Sprintf("op:open path:%s reason:readonly", auditPath(name)))
		s.deny(reply, id)
		return false
	}
	if s.capture != nil && s.capture.trackOpen(id, name, pflags&fxfRead != 0, write) {
		s.deny(reply, id)
		return false
	}
	s.audit("sftp.open", fmt.Sprintf("path:%s mode:%s", auditPath(name), mode))
	return true
}

// handleMutating handles a single-path mutating op (remove/rmdir/mkdir/setstat/
// symlink): it audits the op and, in read-only mode, refuses it. rest begins with
// uint32 id, string path.
func (s *sftpInspector) handleMutating(rest []byte, reply io.Writer, op string) (forward bool) {
	id, r, ok := readU32(rest)
	path, _, ok2 := readString(r)
	if !(ok && ok2) {
		return true
	}
	if pattern, denied := s.pathDenied(path); denied {
		return s.denyPath(reply, id, op, path, pattern)
	}
	if s.mode == SFTPReadOnly {
		s.audit("sftp.blocked", fmt.Sprintf("op:%s path:%s reason:readonly", op, auditPath(path)))
		s.deny(reply, id)
		return false
	}
	s.audit("sftp.modify", fmt.Sprintf("op:%s path:%s", op, auditPath(path)))
	return true
}

// handleRename handles SSH_FXP_RENAME (uint32 id, string oldpath, string
// newpath): it audits both paths and, in read-only mode, refuses it.
func (s *sftpInspector) handleRename(rest []byte, reply io.Writer) (forward bool) {
	id, r, ok := readU32(rest)
	oldp, r2, ok2 := readString(r)
	newp, _, ok3 := readString(r2)
	if !(ok && ok2 && ok3) {
		return true
	}
	// BOTH paths are checked: renaming a denied file to an allowed name, or an
	// allowed file onto a denied one, would each defeat the policy.
	for _, p := range []string{oldp, newp} {
		if pattern, denied := s.pathDenied(p); denied {
			return s.denyPath(reply, id, "rename", p, pattern)
		}
	}
	if s.mode == SFTPReadOnly {
		s.audit("sftp.blocked", fmt.Sprintf("op:rename path:%s reason:readonly", auditPath(oldp)))
		s.deny(reply, id)
		return false
	}
	s.audit("sftp.modify", fmt.Sprintf("op:rename path:%s to:%s", auditPath(oldp), auditPath(newp)))
	return true
}

// handleExtended applies policy to SSH_FXP_EXTENDED requests whose OpenSSH
// extensions are path-mutating. This matters because a modern OpenSSH client
// renames via `posix-rename@openssh.com` (not SSH_FXP_RENAME) whenever the
// server advertises it — so before this, an ordinary `rename` in `sftp` slid
// past both the read-only refusal and the path denylist, which only saw the
// classic packet. `hardlink@openssh.com` gets the same treatment: a hard link
// gives a denied path a second, undenied name. Other extensions (statvfs,
// fsync, limits, copy-data — whose source is a handle an already-checked OPEN
// produced) are forwarded as before. rest: uint32 id, string extended-request,
// then the extension's own payload.
func (s *sftpInspector) handleExtended(rest []byte, reply io.Writer) (forward bool) {
	id, r, ok := readU32(rest)
	extName, r2, ok2 := readString(r)
	if !(ok && ok2) {
		return true // unparsable extension header: forward, as before Phase 59
	}
	switch extName {
	case "posix-rename@openssh.com", "hardlink@openssh.com":
		op := "posix-rename"
		if extName == "hardlink@openssh.com" {
			op = "hardlink"
		}
		oldp, r3, ok3 := readString(r2)
		newp, _, ok4 := readString(r3)
		if !(ok3 && ok4) {
			return true
		}
		// Both sides are checked, exactly as handleRename: either direction can
		// launder a denied path.
		for _, p := range []string{oldp, newp} {
			if pattern, denied := s.pathDenied(p); denied {
				return s.denyPath(reply, id, op, p, pattern)
			}
		}
		if s.mode == SFTPReadOnly {
			s.audit("sftp.blocked", fmt.Sprintf("op:%s path:%s reason:readonly", op, auditPath(oldp)))
			s.deny(reply, id)
			return false
		}
		s.audit("sftp.modify", fmt.Sprintf("op:%s path:%s to:%s", op, auditPath(oldp), auditPath(newp)))
		return true
	default:
		return true
	}
}

// refuse audits a read-only block for op (reading the request id from rest, whose
// first field is the uint32 id) and sends the permission-denied status. It
// reports true so the caller can invert it into "do not forward".
func (s *sftpInspector) refuse(reply io.Writer, rest []byte, op, path string) bool {
	id, _, _ := readU32(rest)
	s.audit("sftp.blocked", fmt.Sprintf("op:%s path:%s reason:readonly", op, auditPath(path)))
	s.deny(reply, id)
	return true
}

// deny writes an SSH_FXP_STATUS(SSH_FX_PERMISSION_DENIED) for request id back to
// the operator's channel, so the client sees a clean refusal instead of hanging
// on a dropped request. A write error is ignored: the session is already ending.
func (s *sftpInspector) deny(reply io.Writer, id uint32) {
	const msg = "pamv1: read-only session — write operation denied by policy"
	body := []byte{fxpStatus}
	body = binary.BigEndian.AppendUint32(body, id)
	body = binary.BigEndian.AppendUint32(body, fxPermissionDenied)
	body = appendString(body, msg)
	body = appendString(body, "") // language tag
	pkt := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	pkt = append(pkt, body...)
	_, _ = reply.Write(pkt)
}

// readU32 reads a big-endian uint32 off the front of b, returning the value, the
// remainder, and whether b was long enough.
func readU32(b []byte) (uint32, []byte, bool) {
	if len(b) < 4 {
		return 0, b, false
	}
	return binary.BigEndian.Uint32(b), b[4:], true
}

// readString reads an SFTP string (uint32 length + bytes) off the front of b.
func readString(b []byte) (string, []byte, bool) {
	n, r, ok := readU32(b)
	if !ok || uint32(len(r)) < n {
		return "", b, false
	}
	return string(r[:n]), r[n:], true
}

// appendString appends an SFTP string (uint32 length prefix + bytes) to b.
func appendString(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}
