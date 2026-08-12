package recording

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// asciicastFixture builds a minimal, valid asciicast v2 stream: the header
// line followed by one "o" event per data string, each at its own
// increasing time (event i at 0.1*(i+1) seconds) — mirroring exactly what
// proxy.Recording.Write produces (each event is one upstream Write call) and
// giving tests distinct, predictable times to assert MatchSeconds against.
func asciicastFixture(data ...string) string {
	var b strings.Builder
	b.WriteString(`{"version":2,"width":80,"height":24,"timestamp":0,"title":"t"}` + "\n")
	for i, d := range data {
		line, err := json.Marshal([]any{0.1 * float64(i+1), "o", d})
		if err != nil {
			panic(err) // fixture construction only; a bad test input is a test bug
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// TestSearchASCIICastSpansChunks proves the reconstruction-then-search shape
// this feature exists for: a query that never appears intact within any
// single event's data (because the terminal echoed it a few bytes at a time)
// is still found once the output is concatenated in order, and the reported
// match time is that of the EVENT CONTAINING the match start ("wor", the
// second of the four events), not the first or last event in the recording.
func TestSearchASCIICastSpansChunks(t *testing.T) {
	cast := asciicastFixture("hello ", "wor", "ld", " it worked")
	res, err := SearchASCIICast(strings.NewReader(cast), 1<<20, "world")
	if err != nil {
		t.Fatal(err)
	}
	if res.Matches != 1 {
		t.Fatalf("matches = %d, want 1", res.Matches)
	}
	if res.Truncated {
		t.Fatal("truncated should be false")
	}
	if !strings.Contains(res.Snippet, "hello world it worked") {
		t.Fatalf("snippet = %q, want it to contain the reconstructed text", res.Snippet)
	}
	if res.MatchSeconds != 0.2 {
		t.Fatalf("matchSeconds = %v, want 0.2 (the \"wor\" event, where \"world\" starts)", res.MatchSeconds)
	}
}

// TestSearchASCIICastCaseInsensitive proves matching ignores case in both the
// query and the stored output.
func TestSearchASCIICastCaseInsensitive(t *testing.T) {
	cast := asciicastFixture("Secret Value: AKIAABCDEF")
	res, err := SearchASCIICast(strings.NewReader(cast), 1<<20, "akiaabcdef")
	if err != nil {
		t.Fatal(err)
	}
	if res.Matches != 1 {
		t.Fatalf("matches = %d, want 1", res.Matches)
	}
}

// TestSearchASCIICastNoMatch proves a query absent from the recording reports
// zero matches and an empty snippet, not an error.
func TestSearchASCIICastNoMatch(t *testing.T) {
	cast := asciicastFixture("nothing interesting here")
	res, err := SearchASCIICast(strings.NewReader(cast), 1<<20, "needle")
	if err != nil {
		t.Fatal(err)
	}
	if res.Matches != 0 || res.Snippet != "" {
		t.Fatalf("matches=%d snippet=%q, want 0 and empty", res.Matches, res.Snippet)
	}
}

// TestSearchASCIICastCountsAllOccurrences proves repeated occurrences are all
// counted, not just the first.
func TestSearchASCIICastCountsAllOccurrences(t *testing.T) {
	cast := asciicastFixture("fail fail fail success")
	res, err := SearchASCIICast(strings.NewReader(cast), 1<<20, "fail")
	if err != nil {
		t.Fatal(err)
	}
	if res.Matches != 3 {
		t.Fatalf("matches = %d, want 3", res.Matches)
	}
}

// TestSearchASCIICastIgnoresNonOutputEvents proves an event whose type is not
// "o" does not contribute to the searched text — the recorder never writes
// one today, but a hand-edited or future file might, and such an event must
// not silently participate in a match.
func TestSearchASCIICastIgnoresNonOutputEvents(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"version":2,"width":80,"height":24,"timestamp":0,"title":"t"}` + "\n")
	b.WriteString(`[0.1,"i","needle"]` + "\n") // an input event, not output
	b.WriteString(`[0.2,"o","haystack"]` + "\n")
	res, err := SearchASCIICast(strings.NewReader(b.String()), 1<<20, "needle")
	if err != nil {
		t.Fatal(err)
	}
	if res.Matches != 0 {
		t.Fatalf("matches = %d, want 0 (the hit is in a non-output event)", res.Matches)
	}
}

// TestSearchASCIICastTruncates proves a recording longer than maxBytes is
// searched only up to the bound and reports truncated — and that a match
// sitting past the bound is honestly reported as not found, not silently
// missed with no indication why.
func TestSearchASCIICastTruncates(t *testing.T) {
	cast := asciicastFixture(strings.Repeat("x", 100), "needle-past-the-cap")
	res, err := SearchASCIICast(strings.NewReader(cast), 50, "needle")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated {
		t.Fatal("truncated should be true when the bound is hit")
	}
	if res.Matches != 0 {
		t.Fatalf("matches = %d, want 0 (the match is past the 50-byte bound)", res.Matches)
	}
}

// TestSearchASCIICastTolerantOfTornTail proves a recording cut off mid-line
// (a session killed while writing) is still searched up to what landed,
// rather than erroring the whole search.
func TestSearchASCIICastTolerantOfTornTail(t *testing.T) {
	cast := asciicastFixture("findme") + `[0.3,"o","incomple`
	res, err := SearchASCIICast(strings.NewReader(cast), 1<<20, "findme")
	if err != nil {
		t.Fatal(err)
	}
	if res.Matches != 1 {
		t.Fatalf("matches = %d, want 1", res.Matches)
	}
}

// TestSearchASCIICastSanitizesSnippet proves ANSI escape sequences and
// control bytes embedded in real terminal output are stripped from the
// returned snippet rather than passed through raw.
func TestSearchASCIICastSanitizesSnippet(t *testing.T) {
	cast := asciicastFixture("\x1b[31mneedle\x1b[0m in \x1b[1mhaystack\x1b[0m")
	res, err := SearchASCIICast(strings.NewReader(cast), 1<<20, "needle")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Snippet, "\x1b") {
		t.Fatalf("snippet still contains a raw escape byte: %q", res.Snippet)
	}
	if !strings.Contains(res.Snippet, "needle in haystack") {
		t.Fatalf("snippet = %q, want the escapes stripped but the text intact", res.Snippet)
	}
}

// TestSearchASCIICastPropagatesRealErrors proves a genuine read failure (not
// a clean or torn-tail EOF) is returned rather than silently read as "no
// matches" — the shape a tampered sealed recording's authentication failure
// takes.
func TestSearchASCIICastPropagatesRealErrors(t *testing.T) {
	r := io.MultiReader(strings.NewReader(asciicastFixture("some output")), errReader{})
	_, err := SearchASCIICast(r, 1<<20, "output")
	if err == nil {
		t.Fatal("want a propagated error, got nil")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

// TestSearchASCIICastOverSealedRecording proves the function works
// transparently over an encrypted-at-rest recording via Open — the actual
// call shape playback (and this feature) use in production, with no
// awareness in SearchASCIICast itself that the bytes were ever sealed.
func TestSearchASCIICastOverSealedRecording(t *testing.T) {
	const name = "sealed.cast"
	sealed := seal(t, name,
		`{"version":2,"width":80,"height":24,"timestamp":0,"title":"t"}`+"\n",
		`[0.1,"o","the sec"]`+"\n",
		`[0.2,"o","ret is here"]`+"\n",
	)
	pr, err := Open(context.Background(), bytes.NewReader(sealed), fakeKEK{}, name)
	if err != nil {
		t.Fatal(err)
	}
	res, err := SearchASCIICast(pr, 1<<20, "secret is here")
	if err != nil {
		t.Fatal(err)
	}
	if res.Matches != 1 {
		t.Fatalf("matches = %d, want 1; snippet=%q", res.Matches, res.Snippet)
	}
	if res.MatchSeconds != 0.1 {
		t.Fatalf("matchSeconds = %v, want 0.1 (the event where \"secret\" starts)", res.MatchSeconds)
	}
}
