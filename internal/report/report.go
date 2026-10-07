// Package report builds the operational reports an administrator reads about
// the deployment rather than about one session (Phase 277, Tier 10 row 8):
// which users and targets went unused over a window, how many privileged
// connections were opened and by whom, and the daily digest that mails both.
//
// Every figure is read back from the audit trail, never from a separate
// counter: the trail is already the durable, fail-closed record of every
// session start (the proxies refuse a session whose start cannot be audited),
// so a report computed from it cannot disagree with what the auditors see.
// The package is pure — it takes events and inventory and returns values — so
// the API, the digest worker and the tests all share one implementation.
package report

import (
	"sort"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

// connectActions maps each audit action that records a privileged connection
// being OPENED to the protocol it implies. These are the rows written after
// every gate passed: a denied attempt has its own action and is not a
// connection. session.start covers SSH and WinRM through the SSH gateway (its
// detail carries protocol: when not ssh); db.session.start covers PostgreSQL
// and, with via:mssql, SQL Server.
//
// Two more are access without a session (review of 274-280): a brokered
// kubectl operation (k8s.run — a kubernetes target never opens a session,
// so without it every one read as unused forever) and a REST WinRM command
// (winrm.run without via:proxy; the proxy's WinRM shell writes a winrm.run
// per command inside a session already counted by its session.start).
var connectActions = map[string]string{
	"session.start":    "ssh",
	"db.session.start": "postgres",
	"rdp.connect":      "rdp",
	"vnc.connect":      "vnc",
	"k8s.run":          "kubernetes",
	"winrm.run":        "winrm",
}

// Actions is every audit action the reports read: the connection actions,
// portal logins and critical connections — what a report asks the store
// for instead of a whole window of trail.
func Actions() []string {
	out := []string{"login", "target.critical_connect"}
	for a := range connectActions {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// IsConnect reports whether an audit row records an opened connection.
func IsConnect(e store.AuditEvent) bool {
	_, ok := connectActions[e.Action]
	if ok && e.Action == "winrm.run" && Field(e.Detail, "via") == "proxy" {
		return false
	}
	return ok
}

// isSignIn reports whether a login row is a completed sign-in. A password
// accepted while a second factor or MFA enrollment is still pending is
// written as login with scope: — that is not use of the account.
func isSignIn(e store.AuditEvent) bool {
	return e.Action == "login" && Field(e.Detail, "scope") == ""
}

// Connection is one opened privileged session, read back from the trail.
type Connection struct {
	TS       time.Time `json:"ts"`
	User     string    `json:"user"`
	Target   string    `json:"target"`
	Protocol string    `json:"protocol"`
}

// Field returns the value of the first "key:value" token in an audit detail,
// or "" when absent. Audit details are space-separated tokens and the values
// read here (target names, protocols) are validated identifiers, so a token
// split is exact for them.
func Field(detail, key string) string {
	for _, tok := range strings.Fields(detail) {
		if v, ok := strings.CutPrefix(tok, key+":"); ok {
			return v
		}
	}
	return ""
}

// Connections extracts the opened connections from events, in input order.
// A connect row with no target: field is skipped rather than counted against
// an empty name.
func Connections(events []store.AuditEvent) []Connection {
	var out []Connection
	for _, e := range events {
		if !IsConnect(e) {
			continue
		}
		proto := connectActions[e.Action]
		target := Field(e.Detail, "target")
		if target == "" {
			continue
		}
		if p := Field(e.Detail, "protocol"); p != "" {
			proto = p
		} else if Field(e.Detail, "via") == "mssql" {
			proto = "mssql"
		}
		out = append(out, Connection{TS: e.TS, User: e.Actor, Target: target, Protocol: proto})
	}
	return out
}

// Count is one row of a grouped tally.
type Count struct {
	Key string `json:"key"`
	N   int    `json:"n"`
}

// Stats is the connection-statistics report over [Since, Until).
type Stats struct {
	Since      time.Time `json:"since"`
	Until      time.Time `json:"until"`
	Total      int       `json:"total"`
	ByUser     []Count   `json:"by_user"`
	ByTarget   []Count   `json:"by_target"`
	ByProtocol []Count   `json:"by_protocol"`
	// ByDay is UTC calendar days, oldest first, every day of the window
	// present (zero included) so a chart of it has no silent gaps.
	ByDay []Count `json:"by_day"`
}

// Summarize tallies conns over the window. Connections outside [since, until)
// are ignored, so a caller may pass a wider slice.
func Summarize(conns []Connection, since, until time.Time) Stats {
	st := Stats{Since: since.UTC(), Until: until.UTC()}
	users, targets, protos := map[string]int{}, map[string]int{}, map[string]int{}
	days := map[string]int{}
	for _, c := range conns {
		if c.TS.Before(since) || !c.TS.Before(until) {
			continue
		}
		st.Total++
		users[c.User]++
		targets[c.Target]++
		protos[c.Protocol]++
		days[c.TS.UTC().Format(time.DateOnly)]++
	}
	st.ByUser, st.ByTarget, st.ByProtocol = ranked(users), ranked(targets), ranked(protos)
	st.ByDay = []Count{}
	for d := truncDay(since); d.Before(until); d = d.AddDate(0, 0, 1) {
		k := d.Format(time.DateOnly)
		st.ByDay = append(st.ByDay, Count{Key: k, N: days[k]})
	}
	return st
}

// ranked orders a tally by count descending, then key ascending, so equal
// counts come out in a stable order.
func ranked(m map[string]int) []Count {
	out := make([]Count, 0, len(m))
	for k, n := range m {
		out = append(out, Count{Key: k, N: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].N != out[j].N {
			return out[i].N > out[j].N
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func truncDay(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// UnusedUser is a stored user with no sign-in and no connection in the window.
type UnusedUser struct {
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	Active    bool      `json:"active"`
}

// UnusedTarget is a target nobody connected to in the window.
type UnusedTarget struct {
	Name      string    `json:"name"`
	Protocol  string    `json:"protocol"`
	Critical  bool      `json:"critical"`
	CreatedAt time.Time `json:"created_at"`
}

// Unused is the unused users/targets report.
type Unused struct {
	Since   time.Time      `json:"since"`
	Until   time.Time      `json:"until"`
	Users   []UnusedUser   `json:"users"`
	Targets []UnusedTarget `json:"targets"`
	// TooNew counts the users and targets created inside the window: they
	// have not had the window's length to be used, so listing them would be
	// noise, and silently dropping them would hide that they were left out.
	TooNewUsers   int `json:"too_new_users"`
	TooNewTargets int `json:"too_new_targets"`
}

// FindUnused reports the users that neither signed in to the portal (a
// `login` row) nor opened a connection, and the targets nobody connected to,
// between since and until. events must cover that window; rows outside it are
// ignored. Only stored users are judged: a directory identity that never
// signed in has no row to report.
func FindUnused(users []store.User, targets []store.Target, events []store.AuditEvent, since, until time.Time) Unused {
	seenUser, seenTarget := map[string]bool{}, map[string]bool{}
	for _, e := range events {
		if e.TS.Before(since) || !e.TS.Before(until) {
			continue
		}
		switch {
		case isSignIn(e):
			seenUser[e.Actor] = true
		case IsConnect(e):
			seenUser[e.Actor] = true
			if t := Field(e.Detail, "target"); t != "" {
				seenTarget[t] = true
			}
		}
	}
	out := Unused{Since: since.UTC(), Until: until.UTC(), Users: []UnusedUser{}, Targets: []UnusedTarget{}}
	for _, u := range users {
		switch {
		case u.CreatedAt.After(since):
			out.TooNewUsers++
		case !seenUser[u.Username]:
			out.Users = append(out.Users, UnusedUser{Username: u.Username, Role: u.Role, CreatedAt: u.CreatedAt, Active: u.Active})
		}
	}
	for _, t := range targets {
		switch {
		case t.CreatedAt.After(since):
			out.TooNewTargets++
		case !seenTarget[t.Name]:
			out.Targets = append(out.Targets, UnusedTarget{Name: t.Name, Protocol: t.Protocol, Critical: t.Critical, CreatedAt: t.CreatedAt})
		}
	}
	sort.Slice(out.Users, func(i, j int) bool { return out.Users[i].Username < out.Users[j].Username })
	sort.Slice(out.Targets, func(i, j int) bool { return out.Targets[i].Name < out.Targets[j].Name })
	return out
}
