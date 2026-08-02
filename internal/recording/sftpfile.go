package recording

// sftpfile.go defines the on-disk format for captured SFTP file content
// (Phase 59). When the SSH proxy's SFTP inspector has content capture enabled,
// every file moved through the subsystem produces one artifact in this format,
// stored next to the session recordings (and sealed the same way when
// PAM_RECORDING_ENCRYPT is on).
//
// # Why a chunk log and not the reassembled file
//
// SFTP moves data as (offset, bytes) packets that may arrive out of order,
// overlap, or rewrite earlier ranges. An artifact that reassembled them into a
// final file would (a) silently merge those events, losing the wire truth an
// investigator may need, and (b) require random-access writes, which cannot be
// streamed through the at-rest Sealer — plaintext would have to touch disk
// first, defeating the seal. So the artifact is an append-only log, exactly as
// asciicast is for terminal output: a JSON header line describing the file,
// then one JSON line per captured data movement, in arrival order. The final
// content is reproducible from the log (ReconstructSFTP); the log itself is the
// evidence.
//
// # Format
//
//	{"version":1,"kind":"sftp-file","path":"/remote/path","open_mode":"write","ts":1690000000}
//	["w",0,"aGVsbG8="]
//	["r",4096,"d29ybGQ="]
//	…
//
// Each chunk line is a three-element array: direction ("w" = operator→target,
// an upload; "r" = target→operator, a download), the byte offset within the
// remote file, and the data base64-encoded. Offsets are bounded by
// SFTPMaxOffset so they survive JSON's float64 numbers exactly.

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
)

// SFTPFileHeader is the first line of a captured SFTP file artifact: which
// remote file the log describes and how it was opened.
type SFTPFileHeader struct {
	Version  int    `json:"version"`
	Kind     string `json:"kind"`      // always "sftp-file"
	Path     string `json:"path"`      // the remote path exactly as the client named it
	OpenMode string `json:"open_mode"` // read | write | readwrite (from the SFTP open flags)
	Time     int64  `json:"ts"`        // unix seconds when the remote file was opened
}

// SFTPChunk is one captured data movement within a file: Dir is "w" for an
// upload chunk (operator→target) or "r" for a download chunk
// (target→operator), Offset is the position in the remote file, Data the bytes.
type SFTPChunk struct {
	Dir    string
	Offset uint64
	Data   []byte
}

// SFTPMaxOffset bounds a chunk's offset (and offset+length) so it round-trips
// through a JSON number exactly: JSON numbers are IEEE-754 doubles, which are
// integer-exact only up to 2^53. A real transfer never comes near this (it is
// eight petabytes); an offset beyond it is hostile or corrupt and is refused.
const SFTPMaxOffset = uint64(1) << 53

// sftpMaxChunkData caps one chunk's payload. The SFTP inspector already caps a
// whole packet at 1 MiB, so this is a consistency bound for the format itself,
// protecting decoders from a hand-crafted artifact.
const sftpMaxChunkData = 2 << 20 // 2 MiB

// sftpMaxScanLine sizes the decoder's line buffer: a maximal chunk's base64
// plus JSON framing fits comfortably.
const sftpMaxScanLine = 4 << 20 // 4 MiB

// EncodeSFTPHeader renders the artifact's header line (with trailing newline).
func EncodeSFTPHeader(h SFTPFileHeader) ([]byte, error) {
	h.Version = 1
	h.Kind = "sftp-file"
	b, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// EncodeSFTPChunk renders one chunk line (with trailing newline). It refuses a
// direction other than "w"/"r", an offset (or end position) beyond
// SFTPMaxOffset, and an oversized payload — the writer fails loud rather than
// produce a log a decoder cannot trust.
func EncodeSFTPChunk(c SFTPChunk) ([]byte, error) {
	if c.Dir != "w" && c.Dir != "r" {
		return nil, fmt.Errorf("recording: sftp chunk direction %q (want \"w\" or \"r\")", c.Dir)
	}
	if len(c.Data) > sftpMaxChunkData {
		return nil, fmt.Errorf("recording: sftp chunk of %d bytes exceeds the format bound", len(c.Data))
	}
	if c.Offset > SFTPMaxOffset || c.Offset+uint64(len(c.Data)) > SFTPMaxOffset {
		return nil, fmt.Errorf("recording: sftp chunk offset %d exceeds the format bound", c.Offset)
	}
	b, err := json.Marshal([]any{c.Dir, c.Offset, base64.StdEncoding.EncodeToString(c.Data)})
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// DecodeSFTPFile parses a (plaintext) captured-file artifact back into its
// header and chunks. A truncated final line — a capture cut off mid-write by a
// killed session — yields the chunks that did land plus io.ErrUnexpectedEOF,
// so a partial artifact is still usable evidence rather than lost.
func DecodeSFTPFile(r io.Reader) (SFTPFileHeader, []SFTPChunk, error) {
	var hdr SFTPFileHeader
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), sftpMaxScanLine)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return hdr, nil, err
		}
		return hdr, nil, io.ErrUnexpectedEOF
	}
	if err := json.Unmarshal(sc.Bytes(), &hdr); err != nil {
		return hdr, nil, fmt.Errorf("recording: sftp artifact header: %w", err)
	}
	if hdr.Kind != "sftp-file" || hdr.Version != 1 {
		return hdr, nil, fmt.Errorf("recording: not a v1 sftp-file artifact (kind %q, version %d)", hdr.Kind, hdr.Version)
	}
	var chunks []SFTPChunk
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		c, ok := decodeSFTPChunkLine(line)
		if !ok {
			// An undecodable line is a torn tail ONLY if it is the last one: a
			// killed session leaves a half-written final line, whereas damage in
			// the middle is corruption and must not be reported as a clean
			// truncation (which a caller renders as "partial evidence, fine").
			if sc.Scan() {
				return hdr, chunks, fmt.Errorf("recording: sftp artifact chunk %d is malformed", len(chunks))
			}
			return hdr, chunks, io.ErrUnexpectedEOF
		}
		chunks = append(chunks, c)
	}
	if err := sc.Err(); err != nil {
		return hdr, chunks, err
	}
	return hdr, chunks, nil
}

// decodeSFTPChunkLine parses one chunk line, reporting whether it decoded. It
// is deliberately total — every malformed shape reports !ok rather than
// erroring — so the caller can decide whether a bad line means a torn tail or
// corruption, which depends only on whether anything follows it.
func decodeSFTPChunkLine(line []byte) (SFTPChunk, bool) {
	var raw [3]json.RawMessage
	if err := json.Unmarshal(line, &raw); err != nil {
		return SFTPChunk{}, false
	}
	var dir, b64 string
	var off float64
	if json.Unmarshal(raw[0], &dir) != nil || json.Unmarshal(raw[1], &off) != nil || json.Unmarshal(raw[2], &b64) != nil {
		return SFTPChunk{}, false
	}
	if (dir != "w" && dir != "r") || off < 0 || off > float64(SFTPMaxOffset) || off != math.Trunc(off) {
		return SFTPChunk{}, false
	}
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return SFTPChunk{}, false
	}
	return SFTPChunk{Dir: dir, Offset: uint64(off), Data: data}, true
}

// ErrSFTPTooLarge reports a reconstruction whose result would exceed the
// caller's bound; the chunk log itself remains available.
var ErrSFTPTooLarge = errors.New("recording: reconstructed file exceeds the size bound")

// ReconstructSFTP replays the chunks of one direction ("w" or "r") in log
// order — later writes to the same range win, as they did on the real file —
// and returns the resulting content. sparse reports whether any byte of the
// result was never covered by a chunk (such holes read as zeros). max bounds
// the result's size; exceeding it returns ErrSFTPTooLarge rather than
// allocating without limit for a hostile artifact.
func ReconstructSFTP(chunks []SFTPChunk, dir string, max int64) (content []byte, sparse bool, err error) {
	var end uint64
	var spans [][2]uint64
	for _, c := range chunks {
		if c.Dir != dir || len(c.Data) == 0 {
			continue
		}
		stop := c.Offset + uint64(len(c.Data))
		if stop > SFTPMaxOffset {
			return nil, false, fmt.Errorf("recording: sftp chunk ends beyond the offset bound")
		}
		if stop > end {
			end = stop
		}
		spans = append(spans, [2]uint64{c.Offset, stop})
	}
	if max >= 0 && end > uint64(max) {
		return nil, false, ErrSFTPTooLarge
	}
	content = make([]byte, end)
	for _, c := range chunks {
		// The same two conditions as the sizing loop above, and they must stay
		// the same: a zero-length chunk contributes nothing to `end`, so slicing
		// content at its offset would panic on an artifact holding an empty
		// write past the end — which a client can produce at will.
		if c.Dir != dir || len(c.Data) == 0 || c.Offset > uint64(len(content)) {
			continue
		}
		copy(content[c.Offset:], c.Data)
	}
	// Coverage sweep: merge the written ranges and compare to the total. Any gap
	// means a hole the transfer never filled (or capture never saw).
	sort.Slice(spans, func(i, j int) bool { return spans[i][0] < spans[j][0] })
	var covered, pos uint64
	for _, s := range spans {
		if s[0] > pos {
			pos = s[0]
		}
		if s[1] > pos {
			covered += s[1] - pos
			pos = s[1]
		}
	}
	return content, covered < end, nil
}
