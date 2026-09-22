package recording

import (
	"bufio"
	"io"
	"strings"
)

// SearchLines searches a line-oriented artifact (a probe metadata stream,
// Phase 271: one JSON object per line) for query, case-insensitively, up to
// maxBytes. It reports how many lines matched and the first matching line as
// the snippet; MatchSeconds stays zero, since a line stream has no timeline
// to seek. Like SearchASCIICast it reports Truncated rather than "not found"
// when the bound stops it, and returns a read error rather than hiding one.
func SearchLines(r io.Reader, maxBytes int, query string) (SearchResult, error) {
	q := strings.ToLower(query)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	var res SearchResult
	read := 0
	for sc.Scan() {
		line := sc.Text()
		read += len(line) + 1
		if strings.Contains(strings.ToLower(line), q) {
			res.Matches++
			if res.Snippet == "" {
				res.Snippet = sanitizeSnippet(line)
			}
		}
		if maxBytes > 0 && read >= maxBytes {
			res.Truncated = true
			break
		}
	}
	if err := sc.Err(); err != nil && err != io.ErrUnexpectedEOF {
		return res, err
	}
	return res, nil
}
