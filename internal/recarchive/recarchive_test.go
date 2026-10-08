package recarchive

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func entry(name, body string) Entry {
	sum := sha256.Sum256([]byte(body))
	return Entry{Name: name, Kind: "asciicast", Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:]), Modified: time.Unix(1700000000, 0).UTC()}
}

func files(m map[string]string) func(string) (io.ReadCloser, error) {
	return func(n string) (io.ReadCloser, error) {
		b, ok := m[n]
		if !ok {
			return nil, errors.New("missing")
		}
		return io.NopCloser(strings.NewReader(b)), nil
	}
}

func valid(n string) bool { return strings.HasSuffix(n, ".cast") }

func TestRoundTrip(t *testing.T) {
	bodies := map[string]string{"a.cast": "first recording", "b.cast": "second"}
	m := Manifest{Format: Format, CreatedAt: time.Unix(1700000100, 0).UTC(), CreatedBy: "auditor",
		Files: []Entry{entry("b.cast", bodies["b.cast"]), entry("a.cast", bodies["a.cast"])}}
	_, want, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := Write(&buf, m, files(bodies)); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	rm, digest, err := Read(bytes.NewReader(buf.Bytes()), valid, func(e Entry, r io.Reader) error {
		b, err := io.ReadAll(r)
		got[e.Name] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if digest != want || len(rm.Files) != 2 || rm.Files[0].Name != "a.cast" || got["a.cast"] != "first recording" || got["b.cast"] != "second" {
		t.Fatalf("round trip: digest %s want %s, files %+v, got %v", digest, want, rm.Files, got)
	}
	if _, d, err := ReadManifest(bytes.NewReader(buf.Bytes())); err != nil || d != want {
		t.Fatalf("ReadManifest: %s %v", d, err)
	}
}

func TestWriteRefusesAChangedFile(t *testing.T) {
	m := Manifest{Format: Format, Files: []Entry{entry("a.cast", "as hashed")}}
	if err := Write(io.Discard, m, files(map[string]string{"a.cast": "as edited"})); err == nil {
		t.Fatal("a file that changed after hashing was archived")
	}
}

// tarOf builds an archive by hand, to forge what Write never produces.
func tarOf(t *testing.T, manifest []byte, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if manifest != nil {
		_ = tw.WriteHeader(&tar.Header{Name: ManifestName, Mode: 0o600, Size: int64(len(manifest))})
		_, _ = tw.Write(manifest)
	}
	for n, b := range entries {
		_ = tw.WriteHeader(&tar.Header{Name: n, Mode: 0o600, Size: int64(len(b))})
		_, _ = tw.Write([]byte(b))
	}
	_ = tw.Close()
	return buf.Bytes()
}

func TestReadRefuses(t *testing.T) {
	good := Manifest{Format: Format, Files: []Entry{entry("a.cast", "body")}}
	mb, _, _ := good.Encode()
	sink := func(Entry, io.Reader) error { return nil }
	drain := func(_ Entry, r io.Reader) error { _, err := io.Copy(io.Discard, r); return err }
	for name, tc := range map[string]struct {
		data []byte
		sink func(Entry, io.Reader) error
	}{
		"no manifest":   {tarOf(t, nil, map[string]string{"recordings/a.cast": "body"}), sink},
		"tampered body": {tarOf(t, mb, map[string]string{"recordings/a.cast": "bodY"}), drain},
		"unlisted file": {tarOf(t, mb, map[string]string{"recordings/a.cast": "body", "recordings/x.cast": "x"}), drain},
		"missing file":  {tarOf(t, mb, nil), drain},
		"path escape":   {tarOf(t, mb, map[string]string{"../a.cast": "body"}), drain},
		"invalid name": {func() []byte {
			m := Manifest{Format: Format, Files: []Entry{entry("../../etc/passwd", "x")}}
			b, _, _ := m.Encode()
			return tarOf(t, b, nil)
		}(), drain},
		"wrong format": {tarOf(t, []byte(`{"format":"something/else","files":[]}`), nil), drain},
	} {
		if _, _, err := Read(bytes.NewReader(tc.data), valid, tc.sink); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
