package guacd

// transfergate.go holds desktop file transfers and clipboard content until a
// scanner — an ICAP AV/DLP service — has passed them (Phase 280, Tier 10
// row 11). The SFTP path could only DETECT: by the time a whole file can be
// scanned it has already been written. A Guacamole stream is different: it
// crosses the portal as `file`/`put`/`body`/`clipboard` → `blob`* → `end`,
// so PAMv1 can keep every frame of a stream back, scan the reassembled
// bytes, and release the stream only when it is clean. A blocked stream
// never reaches the other side at all.
//
// Holding frames would stall Guacamole's flow control — a file stream's
// sender waits for an `ack` per blob — so the gate answers the sender itself
// while it holds, and swallows the receiver's own acks for the stream once
// it has released it. Clipboard streams are not flow-controlled and get no
// acks.
//
// The gate does its own framing on the frames it sees: an instruction split
// across two WebSocket messages is carried until it is whole, so a client
// cannot slip a stream past it by cutting an instruction in two.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"
	"unicode/utf8"

	"github.com/morandeirachema/pamv1/internal/auditfmt"
)

// Directions, as the viewer bridge names them.
const (
	DirIn  = "in"  // operator → target (upload, paste)
	DirOut = "out" // target → operator (download, copy)
)

// Transfer kinds.
const (
	KindFile      = "file"
	KindClipboard = "clipboard"
)

// Outcomes of a held transfer.
const (
	OutcomeClean     = "clean"
	OutcomeInfected  = "infected"
	OutcomeTooLarge  = "too-large"
	OutcomeScanError = "scan-error"
)

// streamIndexMime is the mimetype guacd uses for a directory listing sent as
// a `body` stream; listings are protocol, not content, and pass unheld.
const streamIndexMime = "application/vnd.glyptodon.guacamole.stream-index+json"

// maxCarry bounds an incomplete instruction carried between messages.
const maxCarry = 4 << 20

// maxHeld bounds the transfers one session may have held at once. With
// MaxBytes per transfer it bounds the gate's memory; a transfer opened past
// it is refused outright (review of 274-280: a client could open hundreds of
// never-ended streams, each acked by the gate, and grow the server without
// limit).
const maxHeld = 4

// OutcomeTooMany is a transfer refused because maxHeld were already held.
const OutcomeTooMany = "too-many-transfers"

// Scanner judges reassembled content. err means the verdict is unknown.
type Scanner func(ctx context.Context, data []byte) (clean bool, reason string, err error)

// GateConfig chooses what is held.
type GateConfig struct {
	Files     bool
	Clipboard bool
	// MaxBytes caps one held transfer; a larger one is blocked, because
	// content that cannot be scanned must not cross unscanned.
	MaxBytes int
	Scan     Scanner
}

// Verdict is one held transfer's outcome, ready to audit.
type Verdict struct {
	Direction string
	Kind      string
	Name      string
	Mimetype  string
	Bytes     int
	SHA256    string
	Outcome   string
	Reason    string
}

// Released reports whether the transfer was let through.
func (v Verdict) Released() bool { return v.Outcome == OutcomeClean }

// Detail renders the verdict for an audit row; the name, mimetype and
// reason are client- or scanner-supplied, so each is quoted and bounded.
func (v Verdict) Detail() string {
	d := fmt.Sprintf("kind:%s direction:%s name:%s mimetype:%s bytes:%d sha256:%s outcome:%s",
		v.Kind, v.Direction, auditfmt.Field(v.Name, 128), auditfmt.Field(v.Mimetype, 128), v.Bytes, v.SHA256, v.Outcome)
	if v.Reason != "" {
		d += " reason:" + auditfmt.Field(v.Reason, 128)
	}
	return d
}

type heldStream struct {
	kind, name, mimetype string
	acked                bool // a file stream: the sender expects acks
	frames               [][]byte
	size                 int // decoded bytes so far
	over                 bool
	refused              bool // opened past maxHeld: nothing is kept
	blobs                int
}

// Gate is one desktop session's transfer gate. Process is called from both
// directions' goroutines.
type Gate struct {
	cfg GateConfig

	mu      sync.Mutex
	held    map[string]*heldStream // "dir:index"
	swallow map[string]int         // "dir:index" → acks from that direction to drop
	carry   map[string][]byte
}

// NewGate returns a gate, or nil when nothing is held — the caller's path
// then stays byte-for-byte what it was.
func NewGate(cfg GateConfig) *Gate {
	if (!cfg.Files && !cfg.Clipboard) || cfg.Scan == nil {
		return nil
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = 25 << 20
	}
	return &Gate{cfg: cfg, held: map[string]*heldStream{}, swallow: map[string]int{}, carry: map[string][]byte{}}
}

// GateOut is what to do with one processed frame.
type GateOut struct {
	// Forward are the frames to send on, in order: the frame's own
	// instructions that are not held, and any stream released by it.
	Forward [][]byte
	// Reply are acks to send back to the frame's sender.
	Reply [][]byte
	// Done are the transfers this frame completed.
	Done []Verdict
	// Abort means the frame could not be framed as Guacamole instructions
	// and the session must end; nothing of it is forwarded. Passing such
	// bytes on would let the receiver find a stream in them that the gate
	// never saw: libguac sizes a character by its first byte and accepts a
	// zero-padded length, so a message the gate reads as malformed can carry
	// a file guacd reads as valid (review of 274-280).
	Abort bool
}

func opposite(dir string) string {
	if dir == DirIn {
		return DirOut
	}
	return DirIn
}

func ackFor(index string) []byte {
	return []byte(Instruction{Opcode: "ack", Args: []string{index, "OK", "0"}}.Encode())
}

// Process applies the gate to one frame travelling in dir. A nil gate
// forwards the frame unchanged.
func (g *Gate) Process(ctx context.Context, dir string, frame []byte) GateOut {
	if g == nil {
		return GateOut{Forward: [][]byte{frame}}
	}
	g.mu.Lock()
	data := append(g.carry[dir], frame...)
	insts, tail, bad := splitInstructions(data)
	if bad || len(tail) > maxCarry {
		// Fail closed: a message that does not frame cleanly ends the
		// session, whole — not even the instructions before the bad one are
		// forwarded, so nothing the gate could not fully read crosses.
		delete(g.carry, dir)
		g.mu.Unlock()
		return GateOut{Abort: true}
	}
	g.carry[dir] = append([]byte(nil), tail...)
	g.mu.Unlock()

	var out GateOut
	var pass []byte // consecutive unheld instructions, forwarded as one frame
	flush := func() {
		if len(pass) > 0 {
			out.Forward = append(out.Forward, pass)
			pass = nil
		}
	}
	for _, ri := range insts {
		fwd, reply, verdict := g.one(ctx, dir, ri)
		if fwd == nil && verdict == nil {
			out.Reply = append(out.Reply, reply...)
			continue
		}
		if verdict == nil { // passthrough
			pass = append(pass, fwd[0]...)
			continue
		}
		flush()
		out.Forward = append(out.Forward, fwd...)
		out.Reply = append(out.Reply, reply...)
		out.Done = append(out.Done, *verdict)
	}
	flush()
	return out
}

// one handles a single instruction: it either passes it (fwd = itself),
// holds it (fwd nil, possibly with an ack to reply), or completes a held
// stream (verdict set, fwd = the released frames or nothing).
func (g *Gate) one(ctx context.Context, dir string, ri rawInstruction) (fwd [][]byte, reply [][]byte, verdict *Verdict) {
	in := ri.inst
	passthrough := [][]byte{ri.raw}
	key := func(i int) string {
		if len(in.Args) <= i {
			return ""
		}
		return dir + ":" + in.Args[i]
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	switch in.Opcode {
	case "file", "clipboard", "put", "body":
		hs, k := g.open(dir, in)
		if hs == nil {
			return passthrough, nil, nil
		}
		if g.liveHeld() >= maxHeld {
			hs.refused, hs.over = true, true
		}
		// A new stream on an index clears any acks still owed to swallow
		// for an older stream that used it.
		delete(g.swallow, opposite(dir)+":"+streamIndex(in))
		g.held[k] = hs
		if !hs.over {
			hs.frames = append(hs.frames, ri.raw)
		}
		if hs.acked {
			return nil, [][]byte{ackFor(streamIndex(in))}, nil
		}
		return nil, nil, nil
	case "blob":
		hs := g.held[key(0)]
		if hs == nil {
			return passthrough, nil, nil
		}
		hs.blobs++
		if !hs.over {
			n := base64.StdEncoding.DecodedLen(len(argOr(in, 1)))
			if hs.size+n > g.cfg.MaxBytes+3 { // DecodedLen may overcount padding by up to 2
				hs.over, hs.frames = true, nil
			} else {
				hs.size += n
				hs.frames = append(hs.frames, ri.raw)
			}
		}
		if hs.acked {
			return nil, [][]byte{ackFor(in.Args[0])}, nil
		}
		return nil, nil, nil
	case "end":
		k := key(0)
		hs := g.held[k]
		if hs == nil {
			return passthrough, nil, nil
		}
		delete(g.held, k)
		v := Verdict{Direction: dir, Kind: hs.kind, Name: hs.name, Mimetype: hs.mimetype}
		data, derr := hs.decode()
		switch {
		case hs.refused:
			v.Outcome = OutcomeTooMany
		case hs.over || len(data) > g.cfg.MaxBytes:
			v.Outcome = OutcomeTooLarge
		case derr != nil:
			v.Outcome, v.Reason = OutcomeScanError, "undecodable blob"
		}
		if v.Outcome != "" {
			return [][]byte{}, g.endReply(dir, hs, in.Args[0]), &v
		}
		sum := sha256.Sum256(data)
		v.Bytes, v.SHA256 = len(data), hex.EncodeToString(sum[:])
		// The scan runs with the lock released: it is network I/O, and the
		// other direction must keep flowing meanwhile.
		g.mu.Unlock()
		clean, reason, err := g.cfg.Scan(ctx, data)
		g.mu.Lock()
		switch {
		case err != nil:
			v.Outcome, v.Reason = OutcomeScanError, err.Error()
		case !clean:
			v.Outcome, v.Reason = OutcomeInfected, reason
		default:
			v.Outcome = OutcomeClean
		}
		if !v.Released() {
			return [][]byte{}, g.endReply(dir, hs, in.Args[0]), &v
		}
		if hs.acked {
			// The receiver will ack the open and every blob; the sender
			// already had those from the gate. The END of a released upload
			// is not acked by the gate: guacd's own end ack reaches the
			// browser, so a write guacd refuses is reported as refused
			// rather than as uploaded (review of 274-280).
			g.swallow[opposite(dir)+":"+in.Args[0]] += 1 + hs.blobs
		}
		return append(hs.frames, ri.raw), nil, &v
	case "ack":
		k := key(0)
		// An error ack is never swallowed: it is the receiver refusing the
		// transfer, and the sender must hear it. It also ends what is owed.
		if g.swallow[k] > 0 && argOr(in, 2) != "0" {
			delete(g.swallow, k)
			return passthrough, nil, nil
		}
		if g.swallow[k] > 0 {
			g.swallow[k]--
			if g.swallow[k] == 0 {
				delete(g.swallow, k)
			}
			return nil, nil, nil
		}
	}
	return passthrough, nil, nil
}

// endReply is what the sender of a refused upload hears: a refusal (0x0303,
// CLIENT_FORBIDDEN) acking its end, so the operator's client reports the
// upload as failed rather than done. A released upload's end is acked by
// guacd itself. A download's sender (guacd) and any clipboard stream expect
// nothing.
func (g *Gate) endReply(dir string, hs *heldStream, index string) [][]byte {
	if dir != DirIn || !hs.acked {
		return nil
	}
	return [][]byte{[]byte(Instruction{Opcode: "ack", Args: []string{index, "Blocked by content scan", "771"}}.Encode())}
}

// open decides whether a stream-opening instruction is held, returning the
// stream state and its key.
// liveHeld counts the transfers currently held (refused ones keep nothing).
func (g *Gate) liveHeld() int {
	n := 0
	for _, hs := range g.held {
		if !hs.refused {
			n++
		}
	}
	return n
}

// decode reassembles a held stream's content from its blob frames.
func (hs *heldStream) decode() ([]byte, error) {
	var out []byte
	for _, f := range hs.frames {
		insts, _, _ := splitInstructions(f)
		if len(insts) != 1 || insts[0].inst.Opcode != "blob" {
			continue
		}
		chunk, err := base64.StdEncoding.DecodeString(argOr(insts[0].inst, 1))
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
	}
	return out, nil
}

func (g *Gate) open(dir string, in Instruction) (*heldStream, string) {
	switch in.Opcode {
	case "clipboard": // clipboard,<stream>,<mimetype>
		if !g.cfg.Clipboard || len(in.Args) < 2 {
			return nil, ""
		}
		return &heldStream{kind: KindClipboard, mimetype: in.Args[1]}, dir + ":" + in.Args[0]
	case "file": // file,<stream>,<mimetype>,<filename>
		if !g.cfg.Files || len(in.Args) < 3 {
			return nil, ""
		}
		return &heldStream{kind: KindFile, mimetype: in.Args[1], name: in.Args[2], acked: true}, dir + ":" + in.Args[0]
	case "put": // put,<object>,<stream>,<mimetype>,<name> — an upload into the drive
		if !g.cfg.Files || dir != DirIn || len(in.Args) < 4 {
			return nil, ""
		}
		return &heldStream{kind: KindFile, mimetype: in.Args[2], name: in.Args[3], acked: true}, dir + ":" + in.Args[1]
	case "body": // body,<object>,<stream>,<mimetype>,<name> — a download from the drive
		if !g.cfg.Files || dir != DirOut || len(in.Args) < 4 || in.Args[2] == streamIndexMime {
			return nil, ""
		}
		return &heldStream{kind: KindFile, mimetype: in.Args[2], name: in.Args[3], acked: true}, dir + ":" + in.Args[1]
	}
	return nil, ""
}

// streamIndex is the stream an opening instruction names.
func streamIndex(in Instruction) string {
	if in.Opcode == "put" || in.Opcode == "body" {
		return argOr(in, 1)
	}
	return argOr(in, 0)
}

func argOr(in Instruction, i int) string {
	if len(in.Args) > i {
		return in.Args[i]
	}
	return ""
}

type rawInstruction struct {
	raw  []byte
	inst Instruction
}

// splitInstructions cuts raw into whole instructions, returning each one's
// bytes and decoded form, the incomplete tail, and whether a malformed
// element stopped it (the tail is then everything from that instruction on).
// Lengths count Unicode code points, as the protocol defines them.
func splitInstructions(raw []byte) (out []rawInstruction, tail []byte, bad bool) {
	i := 0
	for i < len(raw) {
		start := i
		var elems []string
		for {
			j := i
			for j < len(raw) && raw[j] >= '0' && raw[j] <= '9' {
				j++
			}
			if j == len(raw) {
				return out, raw[start:], false
			}
			// A length is plain decimal: no leading zero (libguac would read
			// "0003" as 3, the gate must not read it any other way).
			if j == i || raw[j] != '.' || j-i > 9 || (raw[i] == '0' && j-i > 1) {
				return out, raw[start:], true
			}
			n, _ := strconv.Atoi(string(raw[i:j]))
			k := j + 1
			for c := 0; c < n; c++ {
				if k >= len(raw) || !utf8.FullRune(raw[k:]) {
					return out, raw[start:], false
				}
				r, size := utf8.DecodeRune(raw[k:])
				// Invalid UTF-8 is malformed, not one replacement character:
				// guacd sizes a character by its lead byte alone, and the two
				// readings must never disagree on where an element ends.
				if r == utf8.RuneError && size == 1 {
					return out, raw[start:], true
				}
				k += size
			}
			if k >= len(raw) {
				return out, raw[start:], false
			}
			elems = append(elems, string(raw[j+1:k]))
			i = k + 1
			if raw[k] == ';' {
				break
			}
			if raw[k] != ',' {
				return out, raw[start:], true
			}
		}
		out = append(out, rawInstruction{raw: raw[start:i], inst: Instruction{Opcode: elems[0], Args: elems[1:]}})
	}
	return out, nil, false
}
