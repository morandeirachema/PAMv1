package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/store"
)

// TestRecordingListingResolvesOwnersFromAudit proves the Phase 48 pairing: an
// opaquely-named recording carries no target or actor in its file name, yet the
// listing still reports both — resolved from the audited session.record /
// winrm.run event, which is behind read_audit like the replay itself. A file
// with no audit event lists with empty metadata rather than a guess.
func TestRecordingListingResolvesOwnersFromAudit(t *testing.T) {
	dir := t.TempDir()
	srv, st := newTestServerOpts(t, nil, api.Options{RecordingDir: dir})
	ctx := context.Background()

	// An opaque asciicast (timestamp + random hex) and its audit event; the SSH
	// proxy writes a full PATH into file:, so the listing must match on base name.
	opaque := "1785000000000000000_a1b2c3d4.cast"
	if err := os.WriteFile(filepath.Join(dir, opaque), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendAudit(ctx, &store.AuditEvent{
		Actor: "alice", Action: "session.record",
		Detail: "target:prod-db-01 cred_user:root file:" + filepath.Join(dir, opaque) + " bytes:3 sha256:deadbeef chain:ab",
	}); err != nil {
		t.Fatal(err)
	}
	// An opaque WinRM transcript, whose audit event carries a bare file name.
	winrmName := "1785000000000000001_9f8e7d6c.winrm.log"
	if err := os.WriteFile(filepath.Join(dir, winrmName), []byte("transcript\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendAudit(ctx, &store.AuditEvent{
		Actor: "bob", Action: "winrm.run",
		Detail: "target:win-01 cred_user:Administrator exit:0 file:" + winrmName + " sha256:cafe",
	}); err != nil {
		t.Fatal(err)
	}
	// A recording with no audit event at all (e.g. copied in by hand).
	orphan := "1785000000000000002_00112233.cast"
	if err := os.WriteFile(filepath.Join(dir, orphan), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, data := do(t, srv, http.MethodGet, "/api/recordings", testAPIKey, nil)
	if code != http.StatusOK {
		t.Fatalf("list recordings: %d %s", code, data)
	}
	var recs []struct {
		Name   string `json:"name"`
		Target string `json:"target"`
		Actor  string `json:"actor"`
	}
	if err := json.Unmarshal(data, &recs); err != nil {
		t.Fatal(err)
	}
	byName := map[string][2]string{}
	for _, r := range recs {
		byName[r.Name] = [2]string{r.Target, r.Actor}
		// The whole point: the NAME must not carry the metadata.
		if strings.Contains(r.Name, "prod-db-01") || strings.Contains(r.Name, "alice") {
			t.Fatalf("opaque recording name leaked metadata: %q", r.Name)
		}
	}
	if got := byName[opaque]; got != [2]string{"prod-db-01", "alice"} {
		t.Fatalf("asciicast owner = %v, want [prod-db-01 alice] (matched on base name)", got)
	}
	if got := byName[winrmName]; got != [2]string{"win-01", "bob"} {
		t.Fatalf("transcript owner = %v, want [win-01 bob]", got)
	}
	if got := byName[orphan]; got != [2]string{"", ""} {
		t.Fatalf("unaudited recording owner = %v, want empty (no guessing)", got)
	}

	// The listing stays behind read_audit — resolving owners must not widen it.
	userTok := seedUser(t, srv, "rec-user", "user")
	if code, _ := do(t, srv, http.MethodGet, "/api/recordings", userTok, nil); code != http.StatusForbidden {
		t.Fatalf("plain user lists recordings: want 403, got %d", code)
	}
}
