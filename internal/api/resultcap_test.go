package api_test

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/winrm"
)

// TestBrokeredResultIsCappedButTheTranscriptIsWhole proves the trade Phase 165
// makes: the agent gets a bounded slice of a huge result, and the durable
// transcript keeps every byte.
//
// That pairing is the whole design. Capping alone would lose evidence; recording
// alone would leave an agent free to pull a multi-megabyte log through the API
// and into a model's context, which is both a cost and a prompt-injection
// surface far larger than anything the agent asked for. Arguments have been
// capped since Phase 13 — results never were, which is the wrong way round when
// the caller is a language model.
func TestBrokeredResultIsCappedButTheTranscriptIsWhole(t *testing.T) {
	huge := strings.Repeat("LOGLINE-", 40_000) // ~320 KB
	fake := &fakeWinRM{result: winrm.Result{Stdout: huge, ExitCode: 0}}
	recDir := t.TempDir()
	opts := brokerOpts(t, fake, allowAnyExecRules)
	opts.RecordingDir = recDir
	opts.BrokerMaxResultBytes = 4096
	srv, _ := newTestServerOpts(t, nil, opts)
	seedWinRMTarget(t, srv, "win-cap", "vault-pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-cap", "owner": "a"})
	tok, _ := jsonMap(t, ad)["token"].(string)

	_, d := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{
		"tool": "winrm_exec", "args": map[string]any{"target": "win-cap", "command": "get-log"},
	})
	m := jsonMap(t, d)
	if m["status"] != "executed" {
		t.Fatalf("the call should still succeed — the output is large, not wrong: %s", d)
	}
	if len(d) > 8192 {
		t.Fatalf("the capped response is %d bytes; the cap is not being applied", len(d))
	}
	res, _ := m["result"].(map[string]any)
	got, _ := res["stdout"].(string)
	if !strings.HasPrefix(got, "LOGLINE-") {
		t.Fatalf("the start of the output must survive: %q", got)
	}
	if !strings.Contains(got, "truncated by pamv1") || res["truncated"] != true {
		t.Fatalf("the agent must be told its copy is partial, got %v", res)
	}

	// The transcript on disk holds all of it.
	entries, err := os.ReadDir(recDir)
	if err != nil {
		t.Fatal(err)
	}
	var transcript string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".winrm.log") {
			b, rerr := os.ReadFile(filepath.Join(recDir, e.Name()))
			if rerr != nil {
				t.Fatal(rerr)
			}
			transcript = string(b)
		}
	}
	if transcript == "" {
		t.Fatal("no transcript was written for a brokered command")
	}
	if len(transcript) < len(huge) {
		t.Fatalf("the transcript is %d bytes for %d bytes of output — the durable record must be whole, "+
			"since that is what makes truncating the agent's copy acceptable", len(transcript), len(huge))
	}
	if strings.Contains(transcript, "truncated by pamv1") {
		t.Fatal("the truncation marker leaked into the durable transcript")
	}
}

// TestBrokeredResultCapIsOffByDefaultForSmallOutput guards the ordinary case:
// output that fits is delivered exactly as before, with no marker and no extra
// fields. A cap that changes everyday results would cost more trust than it buys.
func TestBrokeredResultCapIsOffByDefaultForSmallOutput(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "contoso\\svc\r\n", ExitCode: 0}}
	opts := brokerOpts(t, fake, allowAnyExecRules)
	opts.BrokerMaxResultBytes = 4096
	srv, _ := newTestServerOpts(t, nil, opts)
	seedWinRMTarget(t, srv, "win-small", "vault-pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-small", "owner": "a"})
	tok, _ := jsonMap(t, ad)["token"].(string)

	_, d := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{
		"tool": "winrm_exec", "args": map[string]any{"target": "win-small", "command": "whoami"},
	})
	res, _ := jsonMap(t, d)["result"].(map[string]any)
	if res["stdout"] != "contoso\\svc\r\n" {
		t.Fatalf("an in-budget result must be byte-for-byte unchanged, got %q", res["stdout"])
	}
	if _, marked := res["truncated"]; marked {
		t.Fatalf("an in-budget result must not be marked truncated: %v", res)
	}
}
