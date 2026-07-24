package ocsf

import (
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

// TestFromAuditClassifies proves the OCSF mapping routes routine actions to API
// Activity (6003) and security-relevant ones to Detection Finding (2004), with
// the derived activity, severity, and status ids.
func TestFromAuditClassifies(t *testing.T) {
	ts := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		action, actor string
		detail        string
		class         int
		activity      int
		severity      int
		status        int
	}{
		{"credential.create", "alice", "", ClassAPIActivity, 1, 1, 1},
		{"credential.reveal", "alice", "", ClassAPIActivity, 2, 1, 1},
		{"credential.rotate", "alice", "", ClassAPIActivity, 3, 1, 1},
		{"user.delete", "alice", "", ClassAPIActivity, 4, 1, 1},
		{"access.denied", "bob", "target:web reason:approval-required", ClassDetectionFinding, 1, 3, 2},
		{"command.blocked", "bob", "pattern:rm", ClassDetectionFinding, 1, 3, 2},
		{"breakglass.access", "break-glass", "", ClassDetectionFinding, 1, 4, 1},
		{"analytics.risk_flagged", "system", "actor:mallory level:critical", ClassDetectionFinding, 1, 5, 1},
	}
	for _, c := range cases {
		ev := FromAudit(store.AuditEvent{ID: 1, TS: ts, Actor: c.actor, Action: c.action, Detail: c.detail})
		if ev["class_uid"] != c.class {
			t.Errorf("%s: class_uid = %v, want %d", c.action, ev["class_uid"], c.class)
		}
		if ev["activity_id"] != c.activity {
			t.Errorf("%s: activity_id = %v, want %d", c.action, ev["activity_id"], c.activity)
		}
		if ev["severity_id"] != c.severity {
			t.Errorf("%s: severity_id = %v, want %d", c.action, ev["severity_id"], c.severity)
		}
		if ev["status_id"] != c.status {
			t.Errorf("%s: status_id = %v, want %d", c.action, ev["status_id"], c.status)
		}
		if ev["type_uid"] != c.class*100+c.activity {
			t.Errorf("%s: type_uid = %v, want %d", c.action, ev["type_uid"], c.class*100+c.activity)
		}
		if ev["time"] != ts.UnixMilli() {
			t.Errorf("%s: time = %v, want %d", c.action, ev["time"], ts.UnixMilli())
		}
	}
}

// TestFromAuditShape proves the required OCSF envelope fields are present and the
// actor/metadata are populated from the event.
func TestFromAuditShape(t *testing.T) {
	ev := FromAudit(store.AuditEvent{ID: 42, TS: time.Now(), Actor: "agent-7", Action: "broker.tool_call.executed", Detail: "tool:winrm_exec"})
	for _, k := range []string{"category_uid", "class_uid", "activity_id", "type_uid", "severity_id", "status_id", "time", "message", "actor", "metadata"} {
		if _, ok := ev[k]; !ok {
			t.Fatalf("missing required field %q", k)
		}
	}
	actor := ev["actor"].(map[string]any)["user"].(map[string]any)
	if actor["name"] != "agent-7" {
		t.Fatalf("actor.user.name = %v", actor["name"])
	}
	if actor["type_id"] != 1 { // an agent is a System identity
		t.Fatalf("agent actor type_id = %v, want 1 (System)", actor["type_id"])
	}
	md := ev["metadata"].(map[string]any)
	if md["uid"] != int64(42) || md["version"] != SchemaVersion {
		t.Fatalf("metadata = %+v", md)
	}
	// A non-finding carries an api block; a finding carries finding_info.
	if _, ok := ev["api"]; !ok {
		t.Fatal("API-activity event missing api block")
	}
	if _, ok := ev["finding_info"]; ok {
		t.Fatal("API-activity event must not carry finding_info")
	}
}
