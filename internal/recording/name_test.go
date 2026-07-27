package recording

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestTitleOpaqueHidesMetadata proves the Phase 48 naming choice: the default
// name carries target and actor (greppable, but readable by anyone with volume
// or backup access), while the opaque name carries neither — only a timestamp
// prefix and random hex, so the mapping lives solely in the audit trail.
func TestTitleOpaqueHidesMetadata(t *testing.T) {
	now := time.Date(2026, 7, 27, 10, 0, 0, 0, time.UTC)

	plain := Title(false, now, "prod-db-01", "alice")
	if !strings.Contains(plain, "prod-db-01") || !strings.Contains(plain, "alice") {
		t.Fatalf("descriptive title lost its metadata: %q", plain)
	}

	opaque := Title(true, now, "prod-db-01", "alice")
	if strings.Contains(opaque, "prod-db-01") || strings.Contains(opaque, "alice") {
		t.Fatalf("opaque title leaked target/actor: %q", opaque)
	}
	if !regexp.MustCompile(`^\d+_[0-9a-f]{8}$`).MatchString(opaque) {
		t.Fatalf("opaque title = %q, want <unixnano>_<8 hex>", opaque)
	}
	// The timestamp prefix survives, because retention pruning and the
	// newest-first listing key off it.
	if !strings.HasPrefix(opaque, "1785") {
		t.Fatalf("opaque title lost its timestamp prefix: %q", opaque)
	}
}

// TestTitleOpaqueIsUnique proves two recordings started in the same nanosecond
// still get distinct names — a collision would overwrite evidence.
func TestTitleOpaqueIsUnique(t *testing.T) {
	now := time.Now()
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		n := Title(true, now, "t", "a")
		if seen[n] {
			t.Fatalf("duplicate opaque title %q at iteration %d", n, i)
		}
		seen[n] = true
	}
}
