package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/morandeirachema/pamv1/internal/probe"
	"github.com/morandeirachema/pamv1/internal/recording"
)

// probeArtifacts is the proxy's probe.Artifacts (Phase 271): each connected
// probe's event stream becomes a `.probe.log` beside the session recordings —
// sealed under the same key when recordings are, hashed over the bytes on
// disk, and appended to the recording hash chain at close, exactly like a
// `.cast`. The Windows session's metadata (what started, what ended, which
// window was in front, what a rule matched) is therefore evidence of the
// same standing as the desktop recording it accompanies.
type probeArtifacts struct{ p *Proxy }

// Open creates the artifact file for a probe link.
func (a *probeArtifacts) Open(l probe.Link) (probe.Artifact, error) {
	if a.p.recordingDir == "" {
		return nil, fmt.Errorf("no recording directory")
	}
	if err := os.MkdirAll(a.p.recordingDir, 0o700); err != nil {
		return nil, err
	}
	now := time.Now()
	name := recording.Title(a.p.opaqueNames, now, l.TargetName, l.Hello.User) + ".probe.log"
	path := filepath.Join(a.p.recordingDir, sanitize(name))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- the recording dir joined with a sanitized title
	if err != nil {
		return nil, err
	}
	hasher := sha256.New()
	var sink io.Writer = io.MultiWriter(f, hasher)
	if a.p.recKey != nil {
		sealer, serr := recording.NewSealer(context.Background(), sink, a.p.recKey, filepath.Base(path))
		if serr != nil {
			f.Close()
			_ = os.Remove(path)
			return nil, serr
		}
		sink = sealer
	}
	return &probeArtifact{p: a.p, path: path, f: f, w: sink, hasher: hasher}, nil
}

// probeArtifact is one open `.probe.log`.
type probeArtifact struct {
	p      *Proxy
	path   string
	f      *os.File
	w      io.Writer
	hasher hash.Hash
	mu     sync.Mutex
	n      int64
}

// WriteLine appends one JSON line.
func (a *probeArtifact) WriteLine(line []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.w.Write(append(line, '\n')); err != nil {
		return err
	}
	a.n += int64(len(line)) + 1
	return nil
}

// Close finishes the file, appends its hash to the recording chain and
// returns the audit detail naming it.
func (a *probeArtifact) Close() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	_ = a.f.Close()
	sum := hex.EncodeToString(a.hasher.Sum(nil))
	chain := a.p.chain.append(sum)
	return fmt.Sprintf("file:%s bytes:%d sha256:%s chain:%s", a.path, a.n, sum, chain)
}
