package broker

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestCapResultLeavesSmallResultsAlone pins the common case: a result inside the
// cap must come back byte-for-byte, with no marker and no added fields. A cap
// that quietly rewrites ordinary results would be far more disruptive than the
// problem it solves.
func TestCapResultLeavesSmallResultsAlone(t *testing.T) {
	in := Result{Data: map[string]any{"target": "db-01", "exit_code": float64(0), "output": "ok\n"}}
	out, cut := capResult(in, 65536)
	if cut {
		t.Fatal("a small result must not be reported as truncated")
	}
	if out.Data["output"] != "ok\n" || len(out.Data) != 3 {
		t.Fatalf("a small result must be untouched, got %v", out.Data)
	}
}

// TestCapResultTruncatesAndSaysSo proves an oversized result is shortened, kept
// under the cap, and marked — visibly in the text and structurally in the data,
// so neither a human reading it nor a model consuming it can mistake a slice for
// the whole thing.
func TestCapResultTruncatesAndSaysSo(t *testing.T) {
	huge := strings.Repeat("A", 200_000)
	out, cut := capResult(Result{Data: map[string]any{"target": "db-01", "output": huge}}, 4096)
	if !cut {
		t.Fatal("an oversized result must report that it was truncated")
	}
	raw, err := json.Marshal(out.Data)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 4096 {
		t.Fatalf("the capped result is still %d bytes, over the 4096 cap", len(raw))
	}
	got, _ := out.Data["output"].(string)
	if !strings.HasPrefix(got, "AAAA") {
		t.Fatal("the beginning of the output must be preserved — that is the part worth keeping")
	}
	if !strings.Contains(got, "truncated by PAMv1") {
		t.Fatalf("the shortened text must say so in the text itself, got: %q", got[len(got)-80:])
	}
	if out.Data["truncated"] != true {
		t.Fatal("the result must be marked truncated structurally, not only in prose")
	}
	if out.Data["original_bytes"] == nil {
		t.Fatal("a reader must be able to see how much was dropped")
	}
	// The fields that were not oversized are untouched.
	if out.Data["target"] != "db-01" {
		t.Fatalf("non-string / in-budget fields must survive, got %v", out.Data["target"])
	}
}

// TestCapResultNeverTruncatesASecret is the important one. A secret cut in half
// is not a smaller secret, it is a broken one, and an agent that pastes it into
// a login gets a failure it cannot diagnose. reveal_credential results are
// bounded where they are created instead.
func TestCapResultNeverTruncatesASecret(t *testing.T) {
	secret := strings.Repeat("S", 100_000)
	out, cut := capResult(Result{Sensitive: true, Data: map[string]any{"secret": secret}}, 1024)
	if cut {
		t.Fatal("a sensitive result must never be reported as truncated")
	}
	if out.Data["secret"] != secret {
		t.Fatal("a sensitive result must be returned whole, whatever the cap")
	}
}

// TestCapResultIsDeterministic proves the same oversized result is cut the same
// way every time. Go randomises map iteration, so a naive implementation would
// shorten a different field on each call — and two identical tool calls that
// return differently are impossible to reason about in an audit trail.
func TestCapResultIsDeterministic(t *testing.T) {
	in := func() Result {
		return Result{Data: map[string]any{
			"stdout": strings.Repeat("o", 50_000),
			"stderr": strings.Repeat("e", 50_000),
			"trace":  strings.Repeat("t", 50_000),
		}}
	}
	first, _ := capResult(in(), 2048)
	firstRaw, _ := json.Marshal(first.Data)
	for i := 0; i < 30; i++ {
		got, _ := capResult(in(), 2048)
		gotRaw, _ := json.Marshal(got.Data)
		if string(gotRaw) != string(firstRaw) {
			t.Fatal("the same oversized result was cut two different ways")
		}
	}
}

// TestCapResultReplacesAResultItCannotShorten covers the case where the
// non-string parts alone blow the cap: there is nothing meaningful to shorten,
// so the result is replaced wholesale rather than shipped over the limit. The
// replacement still points at the transcript, which is where the real answer is.
func TestCapResultReplacesAResultItCannotShorten(t *testing.T) {
	rows := make([]any, 0, 2000)
	for i := 0; i < 2000; i++ {
		rows = append(rows, map[string]any{"id": float64(i), "name": "credential-row"})
	}
	out, cut := capResult(Result{Data: map[string]any{"credentials": rows}}, 1024)
	if !cut {
		t.Fatal("a result with no shortenable field must still be capped")
	}
	raw, _ := json.Marshal(out.Data)
	if len(raw) > 1024 {
		t.Fatalf("the replacement is %d bytes, over the cap", len(raw))
	}
	if out.Data["truncated"] != true || out.Data["note"] == nil {
		t.Fatalf("the replacement must explain itself, got %v", out.Data)
	}
}

// TestCapResultOffMeansOff pins that a zero cap disables the whole mechanism, so
// an operator who wants the old behaviour has it.
func TestCapResultOffMeansOff(t *testing.T) {
	huge := strings.Repeat("A", 300_000)
	out, cut := capResult(Result{Data: map[string]any{"output": huge}}, 0)
	if cut || out.Data["output"] != huge {
		t.Fatal("a zero cap must leave the result completely alone")
	}
}

// TestCapResultKeepsAToolsOwnVocabulary proves the cap does not overwrite a
// field the tool itself set. A tool that returns its own `truncated` means
// something by it, and having two layers quietly redefine the same key is how an
// audit trail ends up self-contradictory.
func TestCapResultKeepsAToolsOwnVocabulary(t *testing.T) {
	out, cut := capResult(Result{Data: map[string]any{
		"output":    strings.Repeat("A", 50_000),
		"truncated": "by the remote command itself",
	}}, 2048)
	if !cut {
		t.Fatal("the result should still have been capped")
	}
	if out.Data["truncated"] != "by the remote command itself" {
		t.Fatalf("the tool's own field was overwritten: %v", out.Data["truncated"])
	}
}
