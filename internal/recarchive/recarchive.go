// Package recarchive is the portable recording archive (Phase 283, Tier 10
// row 12): a tar stream that carries a selection of session recordings out
// of a deployment — for long-term storage, a legal hold, a hand-over — and
// back in for replay.
//
// Layout: MANIFEST.json first, then recordings/<name> for every file it
// lists, each exactly as stored. A sealed recording stays sealed (it opens
// only where its key-encryption key is), and its SHA-256 is the hash the
// audit trail attests to, so the archive is checkable against the trail of
// the deployment that wrote it. The manifest says, per file, what the trail
// said when the archive was made: the audit row that stamped it, and
// whether the stored bytes still matched that row.
//
// The manifest's own SHA-256 is the archive's identity. The exporting
// deployment audits it (recording.archive manifest_sha256:…), and the
// destructive operations that act on an archive — purging what was
// exported — require that row, so an archive cannot be forged to purge
// recordings it never contained.
package recarchive

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// Format is the manifest format string.
const Format = "pamv1-recording-archive/1"

// Names inside the tar.
const (
	ManifestName = "MANIFEST.json"
	FilePrefix   = "recordings/"
	// maxManifest bounds the manifest a reader will load.
	maxManifest = 16 << 20
)

// Entry describes one archived recording.
type Entry struct {
	Name     string    `json:"name"`
	Kind     string    `json:"kind"`
	Size     int64     `json:"size"`
	SHA256   string    `json:"sha256"`
	Modified time.Time `json:"modified"`
	Target   string    `json:"target,omitempty"`
	Actor    string    `json:"actor,omitempty"`
	Protocol string    `json:"protocol,omitempty"`
	// The audit row that stamped the recording when it was written, and
	// whether the stored bytes still matched it when archived.
	AuditAction string    `json:"audit_action,omitempty"`
	AuditID     int64     `json:"audit_id,omitempty"`
	AuditTime   time.Time `json:"audit_ts,omitempty"`
	Audited     bool      `json:"audited"`
}

// Manifest is the archive's table of contents.
type Manifest struct {
	Format    string            `json:"format"`
	CreatedAt time.Time         `json:"created_at"`
	CreatedBy string            `json:"created_by"`
	Filter    map[string]string `json:"filter,omitempty"`
	Files     []Entry           `json:"files"`
}

// Encode renders the manifest canonically (files sorted by name) and
// returns the bytes and their hex SHA-256 — the archive's identity.
func (m Manifest) Encode() ([]byte, string, error) {
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Name < m.Files[j].Name })
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(b)
	return b, hex.EncodeToString(sum[:]), nil
}

// Write emits the archive: the manifest, then each listed file read through
// open. Every file is re-hashed as it is copied; one whose bytes no longer
// match the manifest (it changed after the manifest was made) stops the
// archive with an error, so a reader never receives a file the manifest
// misdescribes.
func Write(w io.Writer, m Manifest, open func(name string) (io.ReadCloser, error)) error {
	mb, _, err := m.Encode()
	if err != nil {
		return err
	}
	tw := tar.NewWriter(w)
	if err := tw.WriteHeader(&tar.Header{Name: ManifestName, Mode: 0o600, Size: int64(len(mb)), ModTime: m.CreatedAt, Format: tar.FormatPAX}); err != nil {
		return err
	}
	if _, err := tw.Write(mb); err != nil {
		return err
	}
	for _, e := range m.Files {
		if err := writeFile(tw, e, open); err != nil {
			return fmt.Errorf("%s: %w", e.Name, err)
		}
	}
	return tw.Close()
}

func writeFile(tw *tar.Writer, e Entry, open func(string) (io.ReadCloser, error)) error {
	rc, err := open(e.Name)
	if err != nil {
		return err
	}
	defer rc.Close()
	if err := tw.WriteHeader(&tar.Header{Name: FilePrefix + e.Name, Mode: 0o600, Size: e.Size, ModTime: e.Modified, Format: tar.FormatPAX}); err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(tw, io.TeeReader(io.LimitReader(rc, e.Size), h))
	if err != nil {
		return err
	}
	if n != e.Size || hex.EncodeToString(h.Sum(nil)) != e.SHA256 {
		return errors.New("changed after the manifest was made")
	}
	return nil
}

// ErrNotArchive is a stream that does not open with a manifest.
var ErrNotArchive = errors.New("not a PAMv1 recording archive: MANIFEST.json must come first")

// ReadManifest reads only the manifest, returning it and its digest.
func ReadManifest(r io.Reader) (Manifest, string, error) {
	m, digest, _, err := readManifest(tar.NewReader(r))
	return m, digest, err
}

func readManifest(tr *tar.Reader) (Manifest, string, *tar.Reader, error) {
	h, err := tr.Next()
	if err != nil || h.Name != ManifestName || h.Size > maxManifest {
		return Manifest{}, "", nil, ErrNotArchive
	}
	raw, err := io.ReadAll(io.LimitReader(tr, maxManifest))
	if err != nil {
		return Manifest{}, "", nil, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil || m.Format != Format {
		return Manifest{}, "", nil, fmt.Errorf("%w (format %q)", ErrNotArchive, m.Format)
	}
	// The digest is of the bytes as stored, which Write produced
	// canonically; re-encoding instead would accept a manifest edited into
	// an equivalent but different document.
	sum := sha256.Sum256(raw)
	return m, hex.EncodeToString(sum[:]), tr, nil
}

// Read reads a whole archive. Each file is handed to sink as it streams;
// its size and SHA-256 are checked against the manifest as it passes, and
// sink's verified result is committed only when Read returns nil — the
// caller writes to a temporary place in sink and promotes after. A file the
// manifest does not list, a file listed twice, a name valid rejects, a
// hash or size mismatch, or a listed file missing from the stream fails the
// whole archive.
func Read(r io.Reader, valid func(name string) bool, sink func(e Entry, body io.Reader) error) (Manifest, string, error) {
	m, digest, tr, err := readManifest(tar.NewReader(r))
	if err != nil {
		return Manifest{}, "", err
	}
	listed := make(map[string]Entry, len(m.Files))
	for _, e := range m.Files {
		if !valid(e.Name) {
			return Manifest{}, "", fmt.Errorf("manifest names %q, which is not a recording name", e.Name)
		}
		if _, dup := listed[e.Name]; dup {
			return Manifest{}, "", fmt.Errorf("manifest lists %q twice", e.Name)
		}
		listed[e.Name] = e
	}
	seen := map[string]bool{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, "", err
		}
		name, ok := strings.CutPrefix(h.Name, FilePrefix)
		e, listedOK := listed[name]
		switch {
		case !ok || !listedOK:
			return Manifest{}, "", fmt.Errorf("archive carries %q, which the manifest does not list", h.Name)
		case seen[name]:
			return Manifest{}, "", fmt.Errorf("archive carries %q twice", h.Name)
		case h.Size != e.Size:
			return Manifest{}, "", fmt.Errorf("%s: %d bytes, the manifest says %d", name, h.Size, e.Size)
		}
		seen[name] = true
		hasher := sha256.New()
		if err := sink(e, io.TeeReader(tr, hasher)); err != nil {
			return Manifest{}, "", fmt.Errorf("%s: %w", name, err)
		}
		if got := hex.EncodeToString(hasher.Sum(nil)); got != e.SHA256 {
			return Manifest{}, "", fmt.Errorf("%s: sha256 %s, the manifest says %s", name, got, e.SHA256)
		}
	}
	for name := range listed {
		if !seen[name] {
			return Manifest{}, "", fmt.Errorf("%s: listed in the manifest but missing from the archive", name)
		}
	}
	return m, digest, nil
}
