package guacd

// clipboard.go audits the RDP clipboard (Phase 50). Phase 33 could already
// GATE the clipboard bridge (`PAM_RDP_CLIPBOARD`: both directions, paste-in
// blocked, or off entirely) but not say what crossed it — so an allowed
// clipboard was an unobserved channel out of, or into, a privileged desktop.
//
// The tunnel already frames the Guacamole stream one instruction at a time, so
// this is an observer on that seam: a clipboard transfer is `clipboard` (open a
// stream, with a mimetype) → `blob`* (base64 payload) → `end`, and watching
// those three opcodes reconstructs the transfer's direction, type and size.
//
// **Content is not audited by default, deliberately.** A clipboard on a
// privileged desktop routinely carries a password an operator just copied out
// of a vault; writing that into an audit trail every auditor can read would
// create the exposure this system exists to prevent. The default records
// metadata plus a SHA-256 — enough to prove what moved and to match two
// transfers — and full content is a separate, documented opt-in.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/morandeirachema/pamv1/internal/auditfmt"
	"strings"
	"sync"
)

// Clipboard-audit modes for PAM_RDP_CLIPBOARD_AUDIT.
const (
	ClipAuditOff  = "off"  // no clipboard auditing (Phase 33 behavior)
	ClipAuditMeta = "meta" // direction, mimetype, byte count, SHA-256 (default when on)
	ClipAuditFull = "full" // also the content, truncated — see the warning above
)

// clipAuditPreviewMax bounds how much content a "full" audit records, so one
// pasted file cannot write megabytes into the audit trail.
const clipAuditPreviewMax = 4096

// clipStreamMax bounds how much of a single transfer is buffered for hashing,
// so a hostile or accidental multi-gigabyte clipboard cannot exhaust memory.
// Past the cap the transfer is still audited, flagged truncated.
const clipStreamMax = 1 << 20 // 1 MiB

// NormalizeClipAudit maps a configured clipboard-audit mode to a known value,
// defaulting anything unrecognized (including empty) to off — auditing content
// is opt-in and a typo must not silently enable it.
func NormalizeClipAudit(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case ClipAuditMeta, "on", "true":
		return ClipAuditMeta
	case ClipAuditFull:
		return ClipAuditFull
	default:
		return ClipAuditOff
	}
}

// clipStream accumulates one in-flight clipboard transfer.
type clipStream struct {
	mimetype  string
	data      []byte
	truncated bool
}

// ClipWatcher observes the Guacamole instruction stream of one RDP session and
// reports completed clipboard transfers. It is fed both directions of the
// tunnel; direction is supplied by the caller ("out" = target → operator, "in"
// = operator → target), since the opcodes are identical either way.
//
// It never modifies or blocks a frame: gating is Phase 33's job (guacd is told
// not to bridge the clipboard at all), and an observer that could drop a frame
// would be able to corrupt the display.
type ClipWatcher struct {
	mode string

	mu      sync.Mutex
	streams map[string]*clipStream // keyed by direction + stream index
}

// NewClipWatcher returns a watcher for the given mode, or nil when auditing is
// off so the caller's hot path is a single nil check.
func NewClipWatcher(mode string) *ClipWatcher {
	if NormalizeClipAudit(mode) == ClipAuditOff {
		return nil
	}
	return &ClipWatcher{mode: NormalizeClipAudit(mode), streams: map[string]*clipStream{}}
}

// ClipTransfer is one completed clipboard transfer, ready to audit.
type ClipTransfer struct {
	Direction string // out (target → operator) | in (operator → target)
	Mimetype  string
	Bytes     int
	SHA256    string
	Truncated bool
	Preview   string // only in "full" mode
}

// Detail renders the transfer as an audit detail string. In full mode the
// content is included with newlines flattened, so one transfer stays one audit
// line and cannot forge a second.
func (t ClipTransfer) Detail() string {
	// The mimetype is whatever the client put in the `clipboard` instruction, so
	// it is quoted and bounded like any other untrusted value. Unquoted, a
	// mimetype of `text/plain bytes:0 sha256:00…` prepended its own bytes and
	// digest to this record — and because it is the SECOND field, a first-wins
	// reader believed the forgery, making a large exfiltration read as an empty
	// transfer in the one record that exists to evidence it.
	d := fmt.Sprintf("direction:%s mimetype:%s bytes:%d sha256:%s",
		t.Direction, auditfmt.Field(t.Mimetype, 128), t.Bytes, t.SHA256)
	if t.Truncated {
		d += " truncated:true"
	}
	if t.Preview != "" {
		d += fmt.Sprintf(" content:%q", strings.NewReplacer("\r", " ", "\n", " ").Replace(t.Preview))
	}
	return d
}

// Observe feeds one raw frame to the watcher and returns EVERY transfer the
// frame completed. A nil watcher observes nothing, so the caller needs no
// branch.
//
// Returning a slice rather than a single transfer is the point: one frame can
// carry several instructions, and therefore finish several transfers. Reporting
// only the last silently dropped the others from the audit trail — a subtler
// version of the same evasion this function exists to close, since batching two
// clipboard streams into one message would have hidden the first.
//
// The frame may hold SEVERAL instructions — the Guacamole protocol is a stream
// of self-delimiting instructions and a client may batch them in one WebSocket
// message, which the bridge forwards whole. Observing only the first (which is
// what Decode returns) meant a batched `nop;clipboard;blob` was forwarded to the
// target with only the `nop` examined, so the clipboard audit could be evaded by
// a client that simply did not send one instruction per message.
func (w *ClipWatcher) Observe(direction string, raw []byte) []ClipTransfer {
	if w == nil {
		return nil
	}
	var completed []ClipTransfer
	for _, inst := range DecodeAll(raw) {
		if t := w.observeOne(direction, inst); t != nil {
			completed = append(completed, *t)
		}
	}
	return completed
}

// observeOne applies a single decoded instruction to the watcher's stream state.
func (w *ClipWatcher) observeOne(direction string, inst Instruction) *ClipTransfer {
	switch inst.Opcode {
	case "clipboard":
		// clipboard,<stream index>,<mimetype>
		if len(inst.Args) < 2 {
			return nil
		}
		w.mu.Lock()
		w.streams[direction+":"+inst.Args[0]] = &clipStream{mimetype: inst.Args[1]}
		w.mu.Unlock()
	case "blob":
		// blob,<stream index>,<base64 data>
		if len(inst.Args) < 2 {
			return nil
		}
		chunk, err := base64.StdEncoding.DecodeString(inst.Args[1])
		if err != nil {
			return nil
		}
		w.mu.Lock()
		if st := w.streams[direction+":"+inst.Args[0]]; st != nil {
			if room := clipStreamMax - len(st.data); room > 0 {
				if len(chunk) > room {
					chunk, st.truncated = chunk[:room], true
				}
				st.data = append(st.data, chunk...)
			} else {
				st.truncated = true
			}
		}
		w.mu.Unlock()
	case "end":
		// end,<stream index>
		if len(inst.Args) < 1 {
			return nil
		}
		key := direction + ":" + inst.Args[0]
		w.mu.Lock()
		st := w.streams[key]
		delete(w.streams, key)
		w.mu.Unlock()
		if st == nil {
			return nil // an "end" for a non-clipboard stream (image, file, audio)
		}
		sum := sha256.Sum256(st.data)
		t := &ClipTransfer{
			Direction: direction, Mimetype: st.mimetype, Bytes: len(st.data),
			SHA256: hex.EncodeToString(sum[:]), Truncated: st.truncated,
		}
		if w.mode == ClipAuditFull {
			preview := st.data
			if len(preview) > clipAuditPreviewMax {
				preview, t.Truncated = preview[:clipAuditPreviewMax], true
			}
			t.Preview = string(preview)
		}
		return t
	}
	return nil
}
