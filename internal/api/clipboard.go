package api

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
	"strings"
	"sync"

	"github.com/morandeirachema/pamv1/internal/guacd"
)

// Clipboard-audit modes for PAM_RDP_CLIPBOARD_AUDIT.
const (
	clipAuditOff  = "off"  // no clipboard auditing (Phase 33 behavior)
	clipAuditMeta = "meta" // direction, mimetype, byte count, SHA-256 (default when on)
	clipAuditFull = "full" // also the content, truncated — see the warning above
)

// clipAuditPreviewMax bounds how much content a "full" audit records, so one
// pasted file cannot write megabytes into the audit trail.
const clipAuditPreviewMax = 4096

// clipStreamMax bounds how much of a single transfer is buffered for hashing,
// so a hostile or accidental multi-gigabyte clipboard cannot exhaust memory.
// Past the cap the transfer is still audited, flagged truncated.
const clipStreamMax = 1 << 20 // 1 MiB

// normalizeClipAudit maps a configured clipboard-audit mode to a known value,
// defaulting anything unrecognized (including empty) to off — auditing content
// is opt-in and a typo must not silently enable it.
func normalizeClipAudit(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case clipAuditMeta, "on", "true":
		return clipAuditMeta
	case clipAuditFull:
		return clipAuditFull
	default:
		return clipAuditOff
	}
}

// clipStream accumulates one in-flight clipboard transfer.
type clipStream struct {
	mimetype  string
	data      []byte
	truncated bool
}

// clipWatcher observes the Guacamole instruction stream of one RDP session and
// reports completed clipboard transfers. It is fed both directions of the
// tunnel; direction is supplied by the caller ("out" = target → operator, "in"
// = operator → target), since the opcodes are identical either way.
//
// It never modifies or blocks a frame: gating is Phase 33's job (guacd is told
// not to bridge the clipboard at all), and an observer that could drop a frame
// would be able to corrupt the display.
type clipWatcher struct {
	mode string

	mu      sync.Mutex
	streams map[string]*clipStream // keyed by direction + stream index
}

// newClipWatcher returns a watcher for the given mode, or nil when auditing is
// off so the caller's hot path is a single nil check.
func newClipWatcher(mode string) *clipWatcher {
	if normalizeClipAudit(mode) == clipAuditOff {
		return nil
	}
	return &clipWatcher{mode: normalizeClipAudit(mode), streams: map[string]*clipStream{}}
}

// clipTransfer is one completed clipboard transfer, ready to audit.
type clipTransfer struct {
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
func (t clipTransfer) Detail() string {
	d := fmt.Sprintf("direction:%s mimetype:%s bytes:%d sha256:%s", t.Direction, t.Mimetype, t.Bytes, t.SHA256)
	if t.Truncated {
		d += " truncated:true"
	}
	if t.Preview != "" {
		d += fmt.Sprintf(" content:%q", strings.NewReplacer("\r", " ", "\n", " ").Replace(t.Preview))
	}
	return d
}

// Observe feeds one raw frame to the watcher and returns a completed transfer
// when the frame ended one. A nil watcher observes nothing, so the caller needs
// no branch.
//
// The frame may hold SEVERAL instructions — the Guacamole protocol is a stream
// of self-delimiting instructions and a client may batch them in one WebSocket
// message, which the bridge forwards whole. Observing only the first (which is
// what Decode returns) meant a batched `nop;clipboard;blob` was forwarded to the
// target with only the `nop` examined, so the clipboard audit could be evaded by
// a client that simply did not send one instruction per message.
func (w *clipWatcher) Observe(direction string, raw []byte) *clipTransfer {
	if w == nil {
		return nil
	}
	var completed *clipTransfer
	for _, inst := range guacd.DecodeAll(raw) {
		if t := w.observeOne(direction, inst); t != nil {
			completed = t // a frame can complete more than one; report the last
		}
	}
	return completed
}

// observeOne applies a single decoded instruction to the watcher's stream state.
func (w *clipWatcher) observeOne(direction string, inst guacd.Instruction) *clipTransfer {
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
		t := &clipTransfer{
			Direction: direction, Mimetype: st.mimetype, Bytes: len(st.data),
			SHA256: hex.EncodeToString(sum[:]), Truncated: st.truncated,
		}
		if w.mode == clipAuditFull {
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
