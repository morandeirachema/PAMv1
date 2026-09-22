package probe

import (
	"testing"
)

func TestRuleValidate(t *testing.T) {
	bad := []Rule{
		{Kind: "shell"},
		{Kind: RuleProcess},
		{Kind: RuleProcess, Match: "x.exe", Port: 80},
		{Kind: RuleConnection},
		{Kind: RuleConnection, Proto: "tcp"},
		{Kind: RuleConnection, Match: "not-an-ip"},
		{Kind: RuleConnection, Port: 70000},
		{Kind: RuleConnection, Port: 80, Proto: "icmp"},
	}
	for _, r := range bad {
		if err := r.Validate(); err == nil {
			t.Errorf("%+v: want error", r)
		}
	}
	good := []Rule{
		{Kind: RuleProcess, Match: "powershell*"},
		{Kind: RuleConnection, Match: "10.0.0.0/8"},
		{Kind: RuleConnection, Match: "2001:db8::1"},
		{Kind: RuleConnection, Port: 445, Proto: "tcp"},
		{Kind: RuleConnection, Match: "192.168.1.5", Port: 22, Proto: "tcp"},
	}
	for _, r := range good {
		if err := r.Validate(); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
}

func TestRuleMatchesProcess(t *testing.T) {
	ps := Process{PID: 4242, Name: "PowerShell.exe", Path: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`}
	cases := []struct {
		match string
		want  bool
	}{
		{"powershell.exe", true},
		{"POWERSHELL*", true},
		{"*\\v1.0\\*", true},
		{"c:\\windows\\*", true},
		{"?owershell.exe", true},
		{"cmd.exe", false},
		{"*psexec*", false},
		{"", false},
	}
	for _, c := range cases {
		r := Rule{Kind: RuleProcess, Match: c.match}
		if got := r.MatchesProcess(ps); got != c.want {
			t.Errorf("match %q: got %v want %v", c.match, got, c.want)
		}
	}
	if (Rule{Kind: RuleConnection, Match: "*"}).MatchesProcess(ps) {
		t.Error("a connection rule must never match a process")
	}
	// A process with no path still matches on its name.
	if !(Rule{Kind: RuleProcess, Match: "mimikatz*"}).MatchesProcess(Process{Name: "mimikatz.exe"}) {
		t.Error("name-only process not matched")
	}
}

func TestRuleMatchesConnection(t *testing.T) {
	c := Connection{PID: 7, Proto: "tcp", LocalAddr: "10.1.1.9", LocalPort: 51000, RemoteAddr: "10.20.30.40", RemotePort: 445, State: "Established"}
	cases := []struct {
		r    Rule
		want bool
	}{
		{Rule{Kind: RuleConnection, Match: "10.0.0.0/8"}, true},
		{Rule{Kind: RuleConnection, Match: "10.20.30.40"}, true},
		{Rule{Kind: RuleConnection, Port: 445}, true},
		{Rule{Kind: RuleConnection, Port: 445, Proto: "tcp"}, true},
		{Rule{Kind: RuleConnection, Port: 445, Proto: "udp"}, false},
		{Rule{Kind: RuleConnection, Match: "192.168.0.0/16"}, false},
		{Rule{Kind: RuleConnection, Port: 3389}, false},
		{Rule{Kind: RuleProcess, Match: "*"}, false},
	}
	for _, tc := range cases {
		if got := tc.r.MatchesConnection(c); got != tc.want {
			t.Errorf("%+v: got %v want %v", tc.r, got, tc.want)
		}
	}
	// No peer: listening sockets and unconnected UDP never match anything.
	listen := Connection{PID: 7, Proto: "tcp", LocalAddr: "0.0.0.0", LocalPort: 445, State: "Listen"}
	if (Rule{Kind: RuleConnection, Port: 445}).MatchesConnection(listen) {
		t.Error("a listening socket matched a connection rule")
	}
	// IPv4-mapped and zoned IPv6 peers normalize before the prefix check.
	if !(Rule{Kind: RuleConnection, Match: "10.0.0.0/8"}).MatchesConnection(Connection{Proto: "tcp", RemoteAddr: "::ffff:10.9.9.9", RemotePort: 1}) {
		t.Error("v4-mapped peer not matched")
	}
	if !(Rule{Kind: RuleConnection, Match: "fe80::/10"}).MatchesConnection(Connection{Proto: "tcp", RemoteAddr: "fe80::1%12", RemotePort: 1}) {
		t.Error("zoned link-local peer not matched")
	}
}

func TestGlob(t *testing.T) {
	cases := []struct {
		p, s string
		want bool
	}{
		{"*", "", true},
		{"*", "anything", true},
		{"a*b", "ab", true},
		{"a*b", "axxb", true},
		{"a*b", "axxbx", false},
		{"*.exe", "c:\\x\\y.exe", true},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"**x**", "yyxzz", true},
		{"a*b*c", "aXbYc", true},
		{"a*b*c", "aXcYb", false},
	}
	for _, c := range cases {
		if got := glob(c.p, c.s); got != c.want {
			t.Errorf("glob(%q,%q)=%v want %v", c.p, c.s, got, c.want)
		}
	}
}

func TestSameUser(t *testing.T) {
	yes := [][2]string{{"alice", "CORP\\Alice"}, {"alice@corp.local", "alice"}, {"Bob", "bob"}}
	for _, p := range yes {
		if !SameUser(p[0], p[1]) {
			t.Errorf("%q vs %q: want same", p[0], p[1])
		}
	}
	no := [][2]string{{"alice", "alicia"}, {"", ""}, {"", "x"}, {"corp\\", "corp\\"}}
	for _, p := range no {
		if SameUser(p[0], p[1]) {
			t.Errorf("%q vs %q: want different", p[0], p[1])
		}
	}
}
