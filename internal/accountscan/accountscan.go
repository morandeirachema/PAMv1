// Package accountscan parses the output of a fixed, read-only enumeration
// command run against a target PAMv1 already holds a vaulted credential for,
// to answer "what local/service accounts exist here, and does PAMv1 manage
// them?" (Phase 128) — the authenticated counterpart to internal/discovery's
// pre-auth port probing. Every function here is pure text parsing with no I/O
// and no store dependency, so the two output shapes (a Unix /etc/passwd, a
// pair of Windows `net user`/`net localgroup Administrators` listings) are
// unit-tested directly against fixed sample text.
package accountscan

import (
	"strconv"
	"strings"
)

// Account is one login-capable account discovered on a target.
type Account struct {
	Username   string `json:"username"`
	Privileged bool   `json:"privileged"`
}

// unixNologinShells are shells that make a Unix account non-interactive: an
// account like this cannot be used to log in, so it is outside this scan's
// concern (a service account with a real secret would still show up via its
// PAMv1 credential, not this list).
var unixNologinShells = map[string]bool{
	"/usr/sbin/nologin": true,
	"/sbin/nologin":     true,
	"/bin/false":        true,
	"/usr/bin/false":    true,
}

// ParseUnixAccounts extracts login-capable accounts from the text of
// /etc/passwd (7 colon-separated fields: name:passwd:uid:gid:gecos:home:shell).
// Root (uid 0) is always kept and marked Privileged; other system accounts
// (uid 1-999, the Debian/Ubuntu convention PAMv1's own OVA and Docker images
// use) are skipped as noise, not accounts an operator could use to log in
// interactively. A line that doesn't parse (wrong field count, non-numeric
// uid) is skipped rather than treated as an error — the output of a fixed
// remote command must be handled defensively, not trusted to be well-formed.
func ParseUnixAccounts(passwdOutput string) []Account {
	var out []Account
	for _, line := range strings.Split(passwdOutput, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			continue
		}
		name, uidStr, shell := fields[0], fields[2], fields[6]
		uid, err := strconv.Atoi(uidStr)
		if err != nil || uid < 0 {
			continue
		}
		if uid != 0 && uid < 1000 {
			continue
		}
		if unixNologinShells[shell] {
			continue
		}
		out = append(out, Account{Username: name, Privileged: uid == 0})
	}
	return out
}

// isWindowsNoiseLine identifies the fixed header/footer
// noise `net user` and `net localgroup` wrap every real listing in, so it can
// be dropped without a fragile line-count assumption (localized Windows
// builds vary the exact wording, but "starts with a run of dashes" and "the
// well-known English success line" are stable enough for this scan's purpose
// — PAMv1 does not attempt to localize this parser).
func isWindowsNoiseLine(line string) bool {
	t := strings.TrimSpace(line)
	switch {
	case t == "":
		return true
	case strings.HasPrefix(t, "User accounts for"):
		return true
	case strings.HasPrefix(t, "Alias name"):
		return true
	case strings.HasPrefix(t, "Comment"):
		return true
	case t == "Members":
		return true
	case strings.HasPrefix(t, "The command completed"):
		return true
	case strings.Trim(t, "-") == "":
		return true
	}
	return false
}

// ParseWindowsAccounts extracts local accounts from `net user` output
// (usernames packed several per line in fixed-width columns) and cross-marks
// each as Privileged using a `net localgroup Administrators` listing (one
// member name per line). Either input may be empty — an admins listing that
// failed to run still yields the account list, just with Privileged always
// false, which is the honest degraded result rather than refusing the whole
// scan.
func ParseWindowsAccounts(netUserOutput, netLocalGroupAdminsOutput string) []Account {
	admins := map[string]bool{}
	for _, line := range strings.Split(netLocalGroupAdminsOutput, "\n") {
		if isWindowsNoiseLine(line) {
			continue
		}
		admins[strings.TrimSpace(strings.TrimRight(line, "\r"))] = true
	}

	seen := map[string]bool{}
	var out []Account
	for _, line := range strings.Split(netUserOutput, "\n") {
		if isWindowsNoiseLine(line) {
			continue
		}
		for _, name := range strings.Fields(line) {
			if seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, Account{Username: name, Privileged: admins[name]})
		}
	}
	return out
}
