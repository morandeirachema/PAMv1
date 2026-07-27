package proxy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/recording"
)

// TestRecordingFileNameIsOpaque proves the on-disk artifact a session actually
// leaves behind honors the naming mode (Phase 48): with opaque names the file
// on the recording volume names neither the target nor the operator, while the
// descriptive default still does — and either way the file is created, replays
// through the same path, and keeps its timestamp prefix for retention pruning.
func TestRecordingFileNameIsOpaque(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()

	for _, tc := range []struct {
		name       string
		opaque     bool
		wantHidden bool
	}{
		{"descriptive", false, false},
		{"opaque", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			title := recording.Title(tc.opaque, now, "prod-db-01", "alice")
			rec, err := newRecording(context.Background(), dir, title, now, 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := rec.Write([]byte("whoami\n")); err != nil {
				t.Fatal(err)
			}
			path, _, _ := rec.Close()
			base := filepath.Base(path)

			if _, err := os.Stat(path); err != nil {
				t.Fatalf("recording not written: %v", err)
			}
			leaks := strings.Contains(base, "prod-db-01") || strings.Contains(base, "alice")
			if tc.wantHidden && leaks {
				t.Fatalf("opaque mode left target/actor in the file name: %q", base)
			}
			if !tc.wantHidden && !leaks {
				t.Fatalf("descriptive mode lost target/actor: %q", base)
			}
			// The retention sweeper and the newest-first listing key off the
			// timestamp prefix, so it must survive in both modes.
			if !strings.HasPrefix(base, "1") || !strings.Contains(base, "_") {
				t.Fatalf("file name lost its timestamp prefix: %q", base)
			}
		})
	}
}
