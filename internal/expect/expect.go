// Package expect runs a target's startup scenario (Phase 279, WALLIX's
// SEND/EXPECT scenarios): a short script that waits for text from the
// target and answers it, so PAMv1 can log in to a device that only offers
// an interactive prompt (telnet) or take a scripted first step in an SSH
// shell (`enable`, `sudo -i`) with the vaulted credential — which the
// operator never sees.
//
// A scenario is one step per line:
//
//	expect login:
//	send ${login}
//	expect "Password: "
//	send ${password}
//
// `expect TEXT` waits for TEXT in the target's output; `send TEXT` writes
// TEXT and a line ending. TEXT may be double-quoted (Go syntax) to keep
// leading or trailing spaces or to write \r, \t. `${login}` and
// `${password}` are the credential's username and secret; nothing else is
// substituted, and a scenario may not EXPECT the password — waiting for the
// secret to appear is never what anyone means, and it would put the secret
// into an error message on a timeout.
package expect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Bounds on a scenario.
const (
	MaxSteps = 32
	MaxText  = 256
	// DefaultStepTimeout is how long one expect waits.
	DefaultStepTimeout = 10 * time.Second
	// window is how much recent output an expect matches against.
	window = 8192
)

// Placeholders a send may use.
const (
	Login    = "${login}"
	Password = "${password}"
)

// Step is one line of a scenario.
type Step struct {
	Send bool // false: expect
	Text string
}

// Script is a parsed scenario.
type Script []Step

// Parse reads a scenario. Blank lines and lines starting with # are
// skipped. An empty scenario parses to nil.
func Parse(s string) (Script, error) {
	var out Script
	for i, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		verb, rest, _ := strings.Cut(line, " ")
		var st Step
		switch strings.ToLower(verb) {
		case "expect":
		case "send":
			st.Send = true
		default:
			return nil, fmt.Errorf("line %d: %q is not expect or send", i+1, verb)
		}
		text, err := unquote(strings.TrimSpace(rest))
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", i+1, err)
		}
		switch {
		case !st.Send && text == "":
			return nil, fmt.Errorf("line %d: expect needs the text to wait for", i+1)
		case !st.Send && strings.Contains(text, "${"):
			return nil, fmt.Errorf("line %d: expect may not use a placeholder", i+1)
		case len(text) > MaxText:
			return nil, fmt.Errorf("line %d: longer than %d characters", i+1, MaxText)
		}
		if st.Send {
			if bad := unknownPlaceholder(text); bad != "" {
				return nil, fmt.Errorf("line %d: unknown placeholder %s (use %s or %s)", i+1, bad, Login, Password)
			}
		}
		st.Text = text
		out = append(out, st)
		if len(out) > MaxSteps {
			return nil, fmt.Errorf("more than %d steps", MaxSteps)
		}
	}
	return out, nil
}

func unquote(s string) (string, error) {
	if strings.HasPrefix(s, `"`) {
		u, err := strconv.Unquote(s)
		if err != nil {
			return "", fmt.Errorf("bad quoted text %s", s)
		}
		return u, nil
	}
	return s, nil
}

func unknownPlaceholder(s string) string {
	for {
		i := strings.Index(s, "${")
		if i < 0 {
			return ""
		}
		j := strings.IndexByte(s[i:], '}')
		if j < 0 {
			return s[i:]
		}
		if p := s[i : i+j+1]; p != Login && p != Password {
			return p
		}
		s = s[i+j+1:]
	}
}

// String renders the canonical stored form: one step per line, text quoted
// when it would not survive a round trip bare.
func (sc Script) String() string {
	lines := make([]string, len(sc))
	for i, st := range sc {
		verb := "expect"
		if st.Send {
			verb = "send"
		}
		text := st.Text
		if text != strings.TrimSpace(text) || strings.ContainsAny(text, "\r\n\t\"") {
			text = strconv.Quote(text)
		}
		lines[i] = strings.TrimRight(verb+" "+text, " ")
	}
	return strings.Join(lines, "\n")
}

// Uses reports whether any send uses the placeholder.
func (sc Script) Uses(placeholder string) bool {
	for _, st := range sc {
		if st.Send && strings.Contains(st.Text, placeholder) {
			return true
		}
	}
	return false
}

// DefaultLogin is the scenario a telnet target without its own runs: the
// usual login and password prompts (matched without their first letter, so
// "Login:", "login:" and "Password:" all match).
var DefaultLogin = Script{
	{Text: "ogin:"}, {Send: true, Text: Login},
	{Text: "assword:"}, {Send: true, Text: Password},
}

// Stream reads a target's output on its own goroutine so an expect can time
// out; after a scenario the caller keeps reading the same Stream, which
// first returns whatever the scenario read past its last match.
type Stream struct {
	ch      chan []byte
	err     error // set before ch is closed
	pending []byte
}

// NewStream starts reading r.
func NewStream(r io.Reader) *Stream {
	s := &Stream{ch: make(chan []byte, 16)}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				s.ch <- append([]byte(nil), buf[:n]...)
			}
			if err != nil {
				s.err = err
				close(s.ch)
				return
			}
		}
	}()
	return s
}

// Wait blocks until the stream has output to read, reporting false when it
// ended first. It consumes nothing.
func (s *Stream) Wait() bool {
	if len(s.pending) > 0 {
		return true
	}
	b, ok := <-s.ch
	if !ok {
		return false
	}
	s.pending = b
	return true
}

// Read returns the leftover from a scenario first, then the stream.
func (s *Stream) Read(p []byte) (int, error) {
	if len(s.pending) > 0 {
		n := copy(p, s.pending)
		s.pending = s.pending[n:]
		return n, nil
	}
	b, ok := <-s.ch
	if !ok {
		return 0, s.err
	}
	n := copy(p, b)
	if n < len(b) {
		s.pending = b[n:]
	}
	return n, nil
}

// ErrTimeout and ErrClosed classify a failed expect.
var (
	ErrTimeout = errors.New("timed out")
	ErrClosed  = errors.New("connection closed")
)

// Run plays the scenario: each expect consumes s until its text appears,
// each send writes to w with eol appended. What was read past the final
// match stays in s for the caller. The transcript itself is not returned —
// it is the login dialogue, and may echo what was typed. login and secret
// fill the placeholders. The error names the failed step and what it was
// waiting for, never what was sent.
func (sc Script) Run(ctx context.Context, s *Stream, w io.Writer, login, secret, eol string, stepTimeout time.Duration) error {
	if stepTimeout <= 0 {
		stepTimeout = DefaultStepTimeout
	}
	fill := strings.NewReplacer(Login, login, Password, secret)
	acc := append([]byte(nil), s.pending...)
	s.pending = nil
	for i, st := range sc {
		if st.Send {
			if _, err := io.WriteString(w, fill.Replace(st.Text)+eol); err != nil {
				return fmt.Errorf("step %d (send): %w", i+1, err)
			}
			continue
		}
		timer := time.NewTimer(stepTimeout)
		for {
			if k := strings.Index(string(acc), st.Text); k >= 0 {
				acc = acc[k+len(st.Text):]
				break
			}
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
				return fmt.Errorf("step %d: %q not seen within %s: %w", i+1, st.Text, stepTimeout, ErrTimeout)
			case b, ok := <-s.ch:
				if !ok {
					timer.Stop()
					return fmt.Errorf("step %d: waiting for %q: %w", i+1, st.Text, ErrClosed)
				}
				acc = append(acc, b...)
				if len(acc) > window {
					acc = acc[len(acc)-window:]
				}
			}
		}
		timer.Stop()
	}
	s.pending = acc
	return nil
}
