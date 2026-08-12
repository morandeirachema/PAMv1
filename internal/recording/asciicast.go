package recording

// asciicast.go supports content search over stored asciicast v2 recordings
// (Phase 110). A recording holds only "o" (output) events — the SSH proxy
// records what the operator SAW, not raw keystrokes — so a match is terminal
// output, never something inferred about input alone.
//
// # Why concatenate rather than grep line by line
//
// Each event line is exactly one Write() call from the upstream connection,
// and interactive terminal output arrives in whatever chunks the network and
// the target's own echo produce — often a handful of bytes at a time for
// ordinary typing. A query spanning more than one such chunk would never
// match within a single line's "data" field, so this reconstructs the
// concatenated output stream (bounded, so one long session cannot make a
// query hold unbounded memory) and searches that — the same shape as
// ReconstructSFTP replaying a file's chunks before anything is served.
//
// A byte offset alone is not actionable for a console that wants to jump
// playback to a match, so the reconstruction also remembers, at each event
// boundary, the asciicast time of the event starting there — the same "t"
// field the player already seeks by — and reports the time of the event
// containing the first match.

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
)

// SearchASCIICastMaxSnippet bounds how much context surrounds a match in the
// returned snippet, each side.
const SearchASCIICastMaxSnippet = 80

// ansiEscape strips ANSI CSI sequences (cursor movement, color, clearing) so
// a search snippet reads as text instead of escape-code noise. This is not a
// terminal emulator — it targets the sequences a shell prompt and common
// tools actually emit, not every corner of ECMA-48.
var ansiEscape = regexp.MustCompile("\x1b\\[[0-9;?]*[A-Za-z]")

// SearchResult is the outcome of one SearchASCIICast call. Snippet and
// MatchSeconds are meaningful only when Matches > 0 (the zero value
// otherwise, not a sentinel that needs its own check).
type SearchResult struct {
	Matches      int
	Snippet      string
	MatchSeconds float64
	Truncated    bool
}

// eventMark records that the reconstructed buffer's byte offset marks the
// start of an asciicast event at time t, so a match's buffer position can be
// mapped back to when it happened.
type eventMark struct {
	offset int
	t      float64
}

// SearchASCIICast reads an asciicast v2 stream (the header line followed by
// output events) and reports whether query appears anywhere in the
// reconstructed output, case-insensitively. r must already be plaintext —
// callers decrypt a sealed recording with Open first, exactly as playback
// does; this function has no crypto dependency, so it is testable on its own
// terms.
//
// Output is reconstructed up to maxBytes; a recording longer than that is
// searched only up to the bound and reports Truncated — never silently,
// since a query that would have matched past the bound must not read as "not
// found". A read error other than a clean or torn-tail EOF (in particular, a
// sealed recording that fails authentication — tampered, corrupted, or from
// another recording) is returned rather than swallowed: an integrity failure
// must not silently present as zero matches.
func SearchASCIICast(r io.Reader, maxBytes int, query string) (SearchResult, error) {
	br := bufio.NewReaderSize(r, 64*1024)

	// The header line describes the terminal (version/size/title), not
	// output; skip it and search the rest regardless of whether the header
	// itself was readable.
	_, _ = br.ReadString('\n')

	var buf strings.Builder
	var marks []eventMark
	var truncated bool
	for buf.Len() < maxBytes {
		line, rerr := br.ReadString('\n')
		var raw [3]json.RawMessage
		var t float64
		var typ, data string
		if json.Unmarshal([]byte(line), &raw) == nil &&
			json.Unmarshal(raw[0], &t) == nil &&
			json.Unmarshal(raw[1], &typ) == nil && typ == "o" &&
			json.Unmarshal(raw[2], &data) == nil {
			marks = append(marks, eventMark{offset: buf.Len(), t: t})
			remaining := maxBytes - buf.Len()
			if len(data) > remaining {
				buf.WriteString(data[:remaining])
				truncated = true
				break
			}
			buf.WriteString(data)
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF) {
				break // clean end, or a torn final line from a killed session — search what landed
			}
			return SearchResult{}, rerr
		}
	}
	if buf.Len() >= maxBytes {
		truncated = true
	}

	q := strings.ToLower(query)
	if q == "" {
		return SearchResult{Truncated: truncated}, nil
	}
	text := buf.String()
	lower := strings.ToLower(text)
	matches := strings.Count(lower, q)
	if matches == 0 {
		return SearchResult{Truncated: truncated}, nil
	}
	idx := strings.Index(lower, q)
	start := idx - SearchASCIICastMaxSnippet
	if start < 0 {
		start = 0
	}
	end := idx + len(q) + SearchASCIICastMaxSnippet
	if end > len(text) {
		end = len(text)
	}
	var matchSeconds float64
	for _, m := range marks {
		if m.offset > idx {
			break
		}
		matchSeconds = m.t
	}
	return SearchResult{
		Matches: matches, Snippet: sanitizeSnippet(text[start:end]),
		MatchSeconds: matchSeconds, Truncated: truncated,
	}, nil
}

// sanitizeSnippet strips ANSI escapes and other control bytes from a search
// snippet before it is returned to a client, so a color code or
// cursor-movement sequence embedded in the recorded output does not garble —
// or, in a client that renders it raw, redirect the cursor over — the
// display. Whitespace (including embedded newlines and tabs) collapses to
// single spaces, since a snippet is a one-line preview, not a replay.
func sanitizeSnippet(s string) string {
	s = ansiEscape.ReplaceAllString(s, "")
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n', r == '\t', r == ' ':
			b.WriteByte(' ')
		case r < 0x20, r == 0x7f:
			// other control bytes: backspace, bell, carriage return, a raw ESC
			// the CSI regexp did not match — dropped, not spaced, so they do
			// not fragment a word across them.
		default:
			b.WriteRune(r)
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}
