package ocsf

import (
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/broker"
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

// TestSuffixSeparatorsBothMatch pins the dot/underscore rule in isFinding so a
// later "simplification" back to a single separator fails here instead of in
// production. pamv1 writes both shapes — `proxy.auth_failed` and
// `agent.disable.failed` — and for a long while only the underscore form was
// recognised, so dotted failures were exported as routine API Activity. Each
// verb is therefore asserted with BOTH separators.
//
// The negative cases matter just as much: the separator is required, so a name
// that merely ends in the letters "denied"/"failed" must stay routine. (For a
// Python reader: `cases` below is a list of small structs, the Go equivalent of
// a list of tuples, and t.Run makes each row its own named subtest.)
func TestSuffixSeparatorsBothMatch(t *testing.T) {
	cases := []struct {
		action string
		want   bool
	}{
		{"proxy.auth_failed", true},       // underscore, real
		{"agent.disable.failed", true},    // dot, real — the case that was misclassified
		{"vault.rotate_denied", true},     // underscore, shape
		{"policy.check.denied", true},     // dot, shape
		{"broker.tool_call.failed", true}, // dot, real (internal/broker, Phase 161)
		{"broker.tool_call.denied", true}, // dot, real
		{"targetdenied", false},           // no separator: must not match
		{"jobfailed", false},              // no separator: must not match
		{"credential.create", false},
		{"session.start", false},
	}
	for _, c := range cases {
		t.Run(c.action, func(t *testing.T) {
			if got := isFinding(c.action); got != c.want {
				t.Fatalf("isFinding(%q) = %v, want %v", c.action, got, c.want)
			}
		})
	}
}

// TestBrokerToolCallOutcomesClassified checks how the broker's per-outcome audit
// names (exported by internal/broker since Phase 161, now written to the PRIMARY
// trail this exporter reads) come out of the mapping. It imports those constants
// rather than retyping the strings, so renaming one in internal/broker breaks
// this test instead of silently unclassifying the event.
//
// Denied and failed must be Detection Findings — failed via the dotted suffix
// rule alone, with no findingExact entry, which is the behaviour this test
// exists to prove. Requested, executed, pending_approval and resumed must stay
// routine API Activity: a record of intent, of success, or of a call waiting on
// a human is not a detection.
func TestBrokerToolCallOutcomesClassified(t *testing.T) {
	findings := []string{broker.ActionToolCallDenied, broker.ActionToolCallFailed}
	routine := []string{
		broker.ActionToolCallRequested, broker.ActionToolCallExecuted,
		broker.ActionToolCallPending, broker.ActionToolCallResumed,
		broker.ActionToolCallWithdrawn,
	}
	for _, a := range findings {
		if !isFinding(a) {
			t.Errorf("%s must map to a Detection Finding", a)
		}
		if got := FromAudit(store.AuditEvent{Action: a, TS: time.Now()})["class_uid"]; got != ClassDetectionFinding {
			t.Errorf("%s: class_uid = %v, want %d", a, got, ClassDetectionFinding)
		}
	}
	for _, a := range routine {
		if isFinding(a) {
			t.Errorf("%s must stay routine API Activity, not a finding", a)
		}
		if got := FromAudit(store.AuditEvent{Action: a, TS: time.Now()})["class_uid"]; got != ClassAPIActivity {
			t.Errorf("%s: class_uid = %v, want %d", a, got, ClassAPIActivity)
		}
	}
	// Pinned deliberately: broker.tool_call.failed is covered by the dotted
	// suffix rule, so an explicit findingExact entry would be redundant. If a
	// future change adds one, this assertion is the note explaining why it was
	// left out — decide consciously, do not add it by reflex.
	if findingExact[broker.ActionToolCallFailed] {
		t.Errorf("%s has a findingExact entry that duplicates the .failed suffix rule; keep one mechanism, not two", broker.ActionToolCallFailed)
	}
}
