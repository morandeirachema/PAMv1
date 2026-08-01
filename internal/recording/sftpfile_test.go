package recording

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// TestSFTPFileRoundTrip proves the chunk-log format encodes and decodes
// losslessly: header fields survive, chunks keep their direction, offset and
// bytes, and arrival order is preserved.
func TestSFTPFileRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	hdr, err := EncodeSFTPHeader(SFTPFileHeader{Path: "/srv/report.csv", OpenMode: "write", Time: 1700000000})
	if err != nil {
		t.Fatal(err)
	}
	buf.Write(hdr)
	chunks := []SFTPChunk{
		{Dir: "w", Offset: 6, Data: []byte("world!")},
		{Dir: "w", Offset: 0, Data: []byte("hello ")},
		{Dir: "r", Offset: 0, Data: []byte{0x00, 0xff, 0x10}}, // binary survives base64
	}
	for _, c := range chunks {
		line, err := EncodeSFTPChunk(c)
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(line)
	}

	gotHdr, gotChunks, err := DecodeSFTPFile(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if gotHdr.Path != "/srv/report.csv" || gotHdr.OpenMode != "write" || gotHdr.Version != 1 || gotHdr.Kind != "sftp-file" {
		t.Fatalf("header round-trip: %+v", gotHdr)
	}
	if len(gotChunks) != len(chunks) {
		t.Fatalf("chunks = %d, want %d", len(gotChunks), len(chunks))
	}
	for i, c := range chunks {
		g := gotChunks[i]
		if g.Dir != c.Dir || g.Offset != c.Offset || !bytes.Equal(g.Data, c.Data) {
			t.Fatalf("chunk %d round-trip: got %+v want %+v", i, g, c)
		}
	}
}

// TestSFTPFileTornTail proves a truncated artifact (a session killed mid-write)
// still yields its complete chunks plus io.ErrUnexpectedEOF — partial evidence
// is preserved, not lost.
func TestSFTPFileTornTail(t *testing.T) {
	var buf bytes.Buffer
	hdr, _ := EncodeSFTPHeader(SFTPFileHeader{Path: "/f", OpenMode: "write", Time: 1})
	buf.Write(hdr)
	line, _ := EncodeSFTPChunk(SFTPChunk{Dir: "w", Offset: 0, Data: []byte("intact")})
	buf.Write(line)
	buf.WriteString(`["w",6,"aGVs`) // torn mid-line

	_, chunks, err := DecodeSFTPFile(&buf)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("torn tail: want io.ErrUnexpectedEOF, got %v", err)
	}
	if len(chunks) != 1 || string(chunks[0].Data) != "intact" {
		t.Fatalf("the intact chunk must survive a torn tail: %+v", chunks)
	}
}

// TestSFTPFileDecodeRejectsWrongKind proves the decoder refuses a header that
// is not a v1 sftp-file artifact.
func TestSFTPFileDecodeRejectsWrongKind(t *testing.T) {
	if _, _, err := DecodeSFTPFile(strings.NewReader("{\"version\":2,\"width\":80}\n")); err == nil {
		t.Fatal("an asciicast header must be rejected as an sftp artifact")
	}
}

// TestSFTPEncodeBounds proves the writer refuses what the format cannot carry:
// a bad direction, an offset past the float64-exact bound, an oversized chunk.
func TestSFTPEncodeBounds(t *testing.T) {
	if _, err := EncodeSFTPChunk(SFTPChunk{Dir: "x", Offset: 0, Data: []byte("a")}); err == nil {
		t.Fatal("direction other than w/r must be refused")
	}
	if _, err := EncodeSFTPChunk(SFTPChunk{Dir: "w", Offset: SFTPMaxOffset + 1, Data: []byte("a")}); err == nil {
		t.Fatal("an offset beyond SFTPMaxOffset must be refused")
	}
	if _, err := EncodeSFTPChunk(SFTPChunk{Dir: "w", Offset: SFTPMaxOffset - 1, Data: []byte("ab")}); err == nil {
		t.Fatal("an end position beyond SFTPMaxOffset must be refused")
	}
	if _, err := EncodeSFTPChunk(SFTPChunk{Dir: "w", Offset: 0, Data: make([]byte, sftpMaxChunkData+1)}); err == nil {
		t.Fatal("an oversized chunk must be refused")
	}
}

// TestReconstructSFTP proves reconstruction replays chunks in log order: later
// writes win on overlap, out-of-order offsets land correctly, holes are
// reported sparse, direction filtering works, and the size bound refuses a
// hostile artifact instead of allocating for it.
func TestReconstructSFTP(t *testing.T) {
	chunks := []SFTPChunk{
		{Dir: "w", Offset: 6, Data: []byte("world!")},
		{Dir: "w", Offset: 0, Data: []byte("hello ")},
		{Dir: "w", Offset: 0, Data: []byte("HELLO")}, // rewrite: last wins
		{Dir: "r", Offset: 0, Data: []byte("downloaded")},
	}
	got, sparse, err := ReconstructSFTP(chunks, "w", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "HELLO world!" {
		t.Fatalf("reconstructed = %q, want %q", got, "HELLO world!")
	}
	if sparse {
		t.Fatal("fully covered content must not report sparse")
	}

	down, _, err := ReconstructSFTP(chunks, "r", 1<<20)
	if err != nil || string(down) != "downloaded" {
		t.Fatalf("download direction: %q err=%v", down, err)
	}

	// A hole: nothing ever wrote bytes 3..9.
	holey := []SFTPChunk{
		{Dir: "w", Offset: 0, Data: []byte("abc")},
		{Dir: "w", Offset: 10, Data: []byte("z")},
	}
	got, sparse, err = ReconstructSFTP(holey, "w", 1<<20)
	if err != nil || len(got) != 11 || !sparse {
		t.Fatalf("holey reconstruct: len=%d sparse=%v err=%v (want 11, true, nil)", len(got), sparse, err)
	}

	// The size bound refuses instead of allocating.
	big := []SFTPChunk{{Dir: "w", Offset: 1 << 30, Data: []byte("x")}}
	if _, _, err := ReconstructSFTP(big, "w", 1<<20); !errors.Is(err, ErrSFTPTooLarge) {
		t.Fatalf("oversized reconstruct: want ErrSFTPTooLarge, got %v", err)
	}
}
