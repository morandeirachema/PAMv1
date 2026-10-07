package report

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

var day0 = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

func at(h int) time.Time { return day0.Add(time.Duration(h) * time.Hour) }

// trail is a small audit trail with one connection on each path the report
// reads, one denial that must not count, and one portal login.
func trail() []store.AuditEvent {
	return []store.AuditEvent{
		{TS: at(1), Actor: "alice", Action: "session.start", Detail: "target:web-01 host:\"10.0.0.5\":22 cred_user:root mode:interactive"},
		{TS: at(2), Actor: "alice", Action: "session.start", Detail: "target:win-01 host:\"10.0.0.6\":5986 cred_user:Administrator mode:interactive protocol:winrm"},
		{TS: at(3), Actor: "bob", Action: "db.session.start", Detail: "target:pg-01 db:app cred_user:app"},
		{TS: at(4), Actor: "bob", Action: "db.session.start", Detail: "target:sql-01 db:master cred_user:sa via:mssql"},
		{TS: at(26), Actor: "alice", Action: "rdp.connect", Detail: "target:desk-01 cred_user:Administrator recording:x clipboard:deny"},
		{TS: at(27), Actor: "carol", Action: "session.denied", Detail: "target:web-01 reason:no-grant"},
		{TS: at(28), Actor: "dave", Action: "login", Detail: "user:dave role:auditor"},
		{TS: at(29), Actor: "erin", Action: "session.start", Detail: "mode:interactive"}, // no target: skipped
	}
}

func TestConnections(t *testing.T) {
	got := Connections(trail())
	want := []Connection{
		{at(1), "alice", "web-01", "ssh"},
		{at(2), "alice", "win-01", "winrm"},
		{at(3), "bob", "pg-01", "postgres"},
		{at(4), "bob", "sql-01", "mssql"},
		{at(26), "alice", "desk-01", "rdp"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d connections, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("connection %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestSummarize(t *testing.T) {
	st := Summarize(Connections(trail()), day0, day0.AddDate(0, 0, 3))
	if st.Total != 5 {
		t.Fatalf("total = %d, want 5", st.Total)
	}
	if st.ByUser[0] != (Count{"alice", 3}) || st.ByUser[1] != (Count{"bob", 2}) {
		t.Errorf("by_user = %+v", st.ByUser)
	}
	// Ties sort by key, so the order is stable across runs.
	if st.ByTarget[0].Key != "desk-01" || st.ByTarget[4].Key != "win-01" {
		t.Errorf("by_target = %+v", st.ByTarget)
	}
	wantDays := []Count{{"2026-10-01", 4}, {"2026-10-02", 1}, {"2026-10-03", 0}}
	if len(st.ByDay) != len(wantDays) {
		t.Fatalf("by_day = %+v", st.ByDay)
	}
	for i := range wantDays {
		if st.ByDay[i] != wantDays[i] {
			t.Errorf("day %d = %+v, want %+v", i, st.ByDay[i], wantDays[i])
		}
	}

	// The window is half-open: the second day alone holds only the RDP row.
	if st := Summarize(Connections(trail()), day0.AddDate(0, 0, 1), day0.AddDate(0, 0, 2)); st.Total != 1 || st.ByProtocol[0].Key != "rdp" {
		t.Errorf("one-day window = %+v", st)
	}
}

func TestFindUnused(t *testing.T) {
	since, until := day0, day0.AddDate(0, 0, 3)
	old := day0.AddDate(0, -1, 0)
	users := []store.User{
		{Username: "alice", Role: "user", CreatedAt: old, Active: true}, // connected
		{Username: "dave", Role: "auditor", CreatedAt: old},             // portal login only
		{Username: "zoe", Role: "user", CreatedAt: old, Active: true},   // nothing
		{Username: "new", Role: "user", CreatedAt: at(5)},               // created in window
	}
	targets := []store.Target{
		{Name: "web-01", Protocol: "ssh", CreatedAt: old},
		{Name: "idle-01", Protocol: "ssh", CreatedAt: old, Critical: true},
		{Name: "fresh-01", Protocol: "rdp", CreatedAt: at(5)},
	}
	u := FindUnused(users, targets, trail(), since, until)
	if len(u.Users) != 1 || u.Users[0].Username != "zoe" {
		t.Errorf("unused users = %+v, want only zoe", u.Users)
	}
	if len(u.Targets) != 1 || u.Targets[0].Name != "idle-01" || !u.Targets[0].Critical {
		t.Errorf("unused targets = %+v, want only idle-01 (critical)", u.Targets)
	}
	if u.TooNewUsers != 1 || u.TooNewTargets != 1 {
		t.Errorf("too new = %d users, %d targets; want 1 and 1", u.TooNewUsers, u.TooNewTargets)
	}

	// A denial is not use: web-01's only row in a later window is carol's
	// session.denied, so there it is unused.
	if u := FindUnused(nil, targets[:1], trail(), at(27), at(28)); len(u.Targets) != 1 {
		t.Errorf("a denied attempt must not count as use: %+v", u.Targets)
	}
}

func TestWriteConnectionsCSV(t *testing.T) {
	var buf bytes.Buffer
	conns := []Connection{
		{at(1), "alice", "web-01", "ssh"},
		{at(2), "=HYPERLINK(\"http://x\")", "web-01", "ssh"},
		{at(3), "guest:a,b@example.com", "web-01", "ssh"},
	}
	if err := WriteConnectionsCSV(&buf, conns); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("output is not valid CSV: %v", err)
	}
	if len(rows) != 4 || rows[0][0] != "ts" || rows[1][0] != "2026-10-01T01:00:00Z" {
		t.Fatalf("rows = %q", rows)
	}
	if rows[2][1] != "'=HYPERLINK(\"http://x\")" {
		t.Errorf("formula cell not neutralised: %q", rows[2][1])
	}
	if rows[3][1] != "guest:a,b@example.com" {
		t.Errorf("comma cell must round-trip: %q", rows[3][1])
	}
}

func TestDigest(t *testing.T) {
	events := append(trail(),
		store.AuditEvent{TS: at(5), Actor: "alice", Action: "target.critical_connect", Detail: "target:pg-01 protocol:postgres cred_user:app"},
		store.AuditEvent{TS: at(6), Actor: "evil\nCONNECTIONS: 0", Action: "target.critical_connect", Detail: "target:pg-01 protocol:postgres cred_user:app"},
	)
	st := Summarize(Connections(events), day0, day0.AddDate(0, 0, 1))
	crit := CriticalConnects(events)
	unused := Unused{Users: []UnusedUser{{Username: "zoe", Role: "user"}}, Targets: []UnusedTarget{{Name: "idle-01", Protocol: "ssh", Critical: true}}, TooNewUsers: 1}
	subject, body := Digest("2026-10-01", st, crit, unused, 30)
	if subject != "[PAMv1] Daily report 2026-10-01: 4 connections, 2 to critical targets" {
		t.Errorf("subject = %q", subject)
	}
	for _, want := range []string{
		"CONNECTIONS: 4\n",
		"2026-10-01T05:00:00Z  alice -> pg-01 (postgres)\n",
		"UNUSED IN THE LAST 30 DAYS: 1 users, 1 targets\n",
		"  user   zoe (user)\n",
		"  target idle-01 (ssh, critical)\n",
		"created inside the window: 1 users, 0 targets",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("digest lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "\nCONNECTIONS: 0") {
		t.Fatalf("an actor name forged a report line:\n%s", body)
	}
}

// TestAccessWithoutASession (review of 274-280): a brokered kubectl
// operation and a REST WinRM command are access to the target; a WinRM
// command inside a proxied shell is not counted again; a password accepted
// while MFA is still pending is not a sign-in.
func TestAccessWithoutASession(t *testing.T) {
	events := []store.AuditEvent{
		{TS: at(1), Actor: "kim", Action: "k8s.run", Detail: "target:k8s-prod cred_user:sa command:\"get pods\" status:0"},
		{TS: at(2), Actor: "wes", Action: "winrm.run", Detail: "target:win-01 cred_user:Administrator exit:0"},
		{TS: at(3), Actor: "wes", Action: "winrm.run", Detail: "target:win-02 cred_user:Administrator via:proxy exit:0 cmd:dir"},
		{TS: at(4), Actor: "pat", Action: "login", Detail: "user:pat scope:mfa_pending"},
	}
	conns := Connections(events)
	if len(conns) != 2 || conns[0].Protocol != "kubernetes" || conns[1].Target != "win-01" {
		t.Fatalf("connections = %+v", conns)
	}
	old := day0.AddDate(0, -1, 0)
	u := FindUnused([]store.User{{Username: "pat", CreatedAt: old}}, []store.Target{{Name: "k8s-prod", CreatedAt: old}, {Name: "win-02", CreatedAt: old}}, events, day0, day0.AddDate(0, 0, 1))
	if len(u.Users) != 1 || len(u.Targets) != 1 || u.Targets[0].Name != "win-02" {
		t.Fatalf("unused = %+v", u)
	}
	for _, a := range []string{"login", "k8s.run", "winrm.run", "target.critical_connect", "session.start"} {
		found := false
		for _, b := range Actions() {
			found = found || a == b
		}
		if !found {
			t.Errorf("Actions() lacks %s", a)
		}
	}
}
