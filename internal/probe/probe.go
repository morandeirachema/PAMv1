// Package probe is the SESSION PROBE (Phase 266): the telemetry-and-blocking
// half of cmd/pam-agent, for Windows servers operators reach over RDP.
//
// The command denylist (internal/cmdguard) governs every path where PAMv1 can
// see a discrete command — SSH exec, WinRM, SQL — and the low-level doc is
// explicit that an interactive PTY is never parsed. A brokered RDP desktop is
// the widest form of that blind spot: guacd relays pixels and keystrokes, and
// nothing on the PAMv1 side knows which programs the operator started or where
// they connected from the target. The only vantage point that does know is the
// target itself, and the only PAMv1 code that runs on a target is the endpoint
// agent (Phase 153). So this package makes the agent a probe: launched INSIDE
// the operator's logon session (a scheduled task "at log on of any user", or a
// Run key), with that user's own token and nothing more, it
//
//   - dials OUT to pam-server's SSH listener as "endpoint-agent:<name>" exactly
//     as a tunnel agent does (host key pinned, bearer key), and sends one
//     "probe@pamv1" global request carrying a Hello — who and which Windows
//     session it is running in;
//   - is handed one "pam-probe@pamv1" channel, which pam-server opens toward
//     it (the agent still opens nothing toward PAMv1), and speaks JSON lines
//     on it: Snapshots and Events up, Policy and Commands down;
//   - every Options.Interval reports the processes and network connections of
//     ITS OWN logon session — never another user's — and terminates whatever
//     the current Policy's rules match, reporting each termination as an
//     Event that pam-server writes to the audit trail against the session.
//
// "With the user's own permissions" is the design, not a limitation to
// apologise for: the probe can end only what the session user could end, it
// cannot install firewall rules (that needs an administrator, which a brokered
// operator deliberately is not), and the user can end the probe. It is the
// desktop counterpart of cmdguard — visibility plus a tripwire — and, like
// cmdguard, NOT a containment boundary. pam-server, in turn, can tell a probe
// nothing but "here are the rules" and "end this PID": the command vocabulary
// is closed, so a compromised pam-server cannot run anything on the endpoint.
//
// The wire format is deliberately small and bounded: one JSON object per
// line, MaxLine bytes at most, and a Snapshot is capped at Options.MaxProcesses
// / MaxConnections rows (Truncated says so) — a runaway session cannot flood
// the server.
//
// Platform (platform.go) is the only OS-specific seam: the Windows
// implementation shells out to PowerShell for enumeration and calls
// TerminateProcess directly; every other OS reports ErrUnsupported, and the
// protocol, the enforcement loop and the hub are proven against a fake.
package probe

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"time"
)

// Wire constants. RequestType is the SSH global request a probe sends once,
// right after authenticating, with a JSON Hello as payload; ChannelType is the
// channel pam-server then opens toward it. Both carry the "@pamv1" suffix the
// SSH extension-naming convention (RFC 4251 §4.2) asks of private names.
const (
	RequestType = "probe@pamv1"
	ChannelType = "pam-probe@pamv1"
	// MaxLine bounds one JSON line in either direction (a Snapshot at the row
	// caps fits with room to spare; anything bigger is a fault, not data).
	MaxLine = 4 << 20
	// MaxHello bounds the Hello payload of the global request.
	MaxHello = 64 << 10
	// DefaultInterval is how often a probe scans when Options.Interval is 0.
	DefaultInterval = 5 * time.Second
)

// Message types. Up (probe → server): snapshot, event, result. Down (server →
// probe): policy, command.
const (
	TypeSnapshot = "snapshot"
	TypeEvent    = "event"
	TypeResult   = "result"
	TypePolicy   = "policy"
	TypeCommand  = "command"
)

// Event kinds.
const (
	EventProcessKilled     = "process_killed"     // a process rule matched and the process was ended
	EventConnectionBlocked = "connection_blocked" // a connection rule matched and the owning process was ended
	EventKillFailed        = "kill_failed"        // a rule or command matched but the process could not be ended
	EventCommandKilled     = "command_killed"     // a server command ended the process
)

// Command operations.
const OpKill = "kill"

// Rule kinds — the same vocabulary as store.ProbeRule (spelled here so the
// agent binary needs nothing from the store package).
const (
	RuleProcess    = "process"
	RuleConnection = "connection"
)

// Hello is what a probe declares about itself in the RequestType payload:
// which host and Windows logon session it runs in, as which user. LogonTime
// is when the probe itself started in that session (the closest thing to a
// logon time a user-token process can report without privileged APIs).
type Hello struct {
	Hostname  string    `json:"hostname"`
	OS        string    `json:"os"`
	User      string    `json:"user"`
	SessionID uint32    `json:"session_id"`
	LogonTime time.Time `json:"logon_time"`
	Version   string    `json:"version,omitempty"`
}

// Process is one process of the probe's logon session.
type Process struct {
	PID         uint32    `json:"pid"`
	PPID        uint32    `json:"ppid,omitempty"`
	Name        string    `json:"name"`
	Path        string    `json:"path,omitempty"`
	CommandLine string    `json:"command_line,omitempty"`
	Started     time.Time `json:"started,omitempty"`
}

// Connection is one TCP connection or UDP endpoint owned by a process of the
// probe's logon session. A listening socket has no RemoteAddr.
type Connection struct {
	PID        uint32 `json:"pid"`
	Proto      string `json:"proto"` // tcp | udp
	LocalAddr  string `json:"local_addr"`
	LocalPort  uint16 `json:"local_port"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	RemotePort uint16 `json:"remote_port,omitempty"`
	State      string `json:"state,omitempty"`
}

// Snapshot is one scan of the session. Errors carries what the platform could
// not enumerate (a PowerShell failure, say) so an empty list is never mistaken
// for an idle session.
type Snapshot struct {
	Taken       time.Time    `json:"taken"`
	Processes   []Process    `json:"processes"`
	Connections []Connection `json:"connections"`
	Truncated   bool         `json:"truncated,omitempty"`
	Errors      []string     `json:"errors,omitempty"`
}

// Rule is one block rule as pushed to a probe (store.ProbeRule minus the
// bookkeeping). See Validate for the field contract.
type Rule struct {
	ID    int64  `json:"id"`
	Kind  string `json:"kind"`
	Match string `json:"match,omitempty"`
	Port  int    `json:"port,omitempty"`
	Proto string `json:"proto,omitempty"`
}

// Policy is the full rule set for one probe; each push replaces the last.
type Policy struct {
	Rules []Rule `json:"rules"`
}

// Command is one server → probe instruction. The vocabulary is OpKill only.
type Command struct {
	ID  int64  `json:"id"`
	Op  string `json:"op"`
	PID uint32 `json:"pid,omitempty"`
}

// Result answers a Command.
type Result struct {
	ID    int64  `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// Event is one enforcement outcome, reported as it happens.
type Event struct {
	Kind      string `json:"kind"`
	PID       uint32 `json:"pid"`
	Name      string `json:"name,omitempty"`
	Path      string `json:"path,omitempty"`
	Remote    string `json:"remote,omitempty"` // "addr:port/proto" for a connection event
	RuleID    int64  `json:"rule_id,omitempty"`
	CommandID int64  `json:"command_id,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Message is one JSON line in either direction; Type says which field is set.
type Message struct {
	Type     string    `json:"type"`
	Snapshot *Snapshot `json:"snapshot,omitempty"`
	Event    *Event    `json:"event,omitempty"`
	Policy   *Policy   `json:"policy,omitempty"`
	Command  *Command  `json:"command,omitempty"`
	Result   *Result   `json:"result,omitempty"`
}

// Validate refuses a rule that could not mean anything, or would mean
// everything: a process rule needs a glob; a connection rule needs a remote
// address (IP or CIDR) or a port — a protocol alone would block the whole
// session's traffic, which is a kill switch, not a rule.
func (r Rule) Validate() error {
	switch r.Kind {
	case RuleProcess:
		if strings.TrimSpace(r.Match) == "" {
			return errors.New("a process rule needs an image name or path glob")
		}
		if r.Port != 0 || r.Proto != "" {
			return errors.New("a process rule takes no port or protocol")
		}
	case RuleConnection:
		if r.Match == "" && r.Port == 0 {
			return errors.New("a connection rule needs a remote address/CIDR or a port")
		}
		if r.Match != "" {
			if _, err := parsePrefix(r.Match); err != nil {
				return fmt.Errorf("remote %q is not an IP address or CIDR", r.Match)
			}
		}
		if r.Port < 0 || r.Port > 65535 {
			return errors.New("port must be 0 (any) or 1–65535")
		}
		switch r.Proto {
		case "", "tcp", "udp":
		default:
			return errors.New(`proto must be "", "tcp" or "udp"`)
		}
	default:
		return fmt.Errorf(`kind must be %q or %q`, RuleProcess, RuleConnection)
	}
	return nil
}

// MatchesProcess reports whether a process rule matches p: the glob is tried
// against the image name, the full path and the path's base name, all
// case-insensitively (Windows paths are).
func (r Rule) MatchesProcess(p Process) bool {
	if r.Kind != RuleProcess {
		return false
	}
	pat := strings.ToLower(r.Match)
	if glob(pat, strings.ToLower(p.Name)) {
		return true
	}
	if p.Path == "" {
		return false
	}
	lp := strings.ToLower(p.Path)
	return glob(pat, lp) || glob(pat, strings.ToLower(winBase(lp)))
}

// MatchesConnection reports whether a connection rule matches c. A socket
// with no remote peer (listening, or UDP unconnected) never matches — the
// rule is about where the session connects TO.
func (r Rule) MatchesConnection(c Connection) bool {
	if r.Kind != RuleConnection || c.RemoteAddr == "" {
		return false
	}
	remote, err := netip.ParseAddr(c.RemoteAddr)
	if err != nil || remote.IsUnspecified() {
		return false
	}
	if r.Proto != "" && r.Proto != c.Proto {
		return false
	}
	if r.Port != 0 && r.Port != int(c.RemotePort) {
		return false
	}
	if r.Match != "" {
		pfx, err := parsePrefix(r.Match)
		if err != nil || !pfx.Contains(remote.WithZone("").Unmap()) {
			return false
		}
	}
	return true
}

// parsePrefix accepts "10.0.0.0/8" or a bare "10.0.0.5" (a /32 or /128).
func parsePrefix(s string) (netip.Prefix, error) {
	if pfx, err := netip.ParsePrefix(s); err == nil {
		return netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits()).Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	addr = addr.WithZone("").Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// winBase is filepath.Base for a path that may use either separator — the
// probe's paths come from Windows whatever OS pam-server's tests run on.
func winBase(p string) string {
	return filepath.Base(strings.ReplaceAll(p, `\`, "/"))
}

// glob matches pattern against s with '*' (any run, separators included) and
// '?' (any one character) — path.Match would treat '/' specially and '\' as
// an escape, both wrong for Windows paths. Iterative with one backtrack
// point, so a pathological pattern cannot blow the stack.
func glob(pattern, s string) bool {
	p, i := 0, 0
	starP, starI := -1, -1
	for i < len(s) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[i]):
			p++
			i++
		case p < len(pattern) && pattern[p] == '*':
			starP, starI = p, i
			p++
		case starP >= 0:
			p = starP + 1
			starI++
			i = starI
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
