package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/morandeirachema/pamv1/internal/posture"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

// fakePosture is an EDR/posture webhook: it records what it was asked about and
// answers healthy for the names it knows.
type fakePosture struct {
	mu      sync.Mutex
	asked   []map[string]string
	healthy map[string]bool
}

func (f *fakePosture) start(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var in map[string]string
		_ = json.Unmarshal(body, &in)
		f.mu.Lock()
		f.asked = append(f.asked, in)
		ok := f.healthy[in["user"]]
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func (f *fakePosture) questions() []map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]string(nil), f.asked...)
}

// TestAgentPostureIsEnforcedAndOptIn covers Phase 180: the posture webhook that
// every human authenticated call passes through now covers agent identities too,
// when a deployment asks for it.
//
// Until this phase `internal/posture` was wired into the session proxies'
// admission gate and the REST authz middleware but NOT into agentAuth — a
// human's laptop had to prove its health on every call while an agent container
// passed on a bearer token alone. That is the inversion this whole batch keeps
// finding: the least-trusted actor with the weakest gate.
func TestAgentPostureIsEnforcedAndOptIn(t *testing.T) {
	// The admin doing the setup is a human whose device passes — otherwise the
	// existing human gate (Phase 133) refuses the fixture before the agent path
	// is ever reached, which is itself a reminder that this webhook now answers
	// about two kinds of subject.
	fp := &fakePosture{healthy: map[string]bool{"healthy-bot": true, "bootstrap-admin": true}}
	url := fp.start(t)

	call := func(t *testing.T, required bool, agent string) (int, []map[string]string) {
		t.Helper()
		opts := brokerOpts(t, &fakeWinRM{result: winrm.Result{Stdout: "ok"}}, toolsetRules)
		opts.PostureAttestor = posture.NewAttestor(url)
		opts.BrokerPostureRequired = required
		srv, _ := newTestServerOpts(t, nil, opts)
		_, tok := mintAgent(t, srv, agent, "alice", nil)
		st, _ := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": "list_targets"})
		return st, fp.questions()
	}

	// Off by default: a deployment already attesting laptops must not start
	// refusing every brokered call the moment it upgrades, because its webhook
	// has never heard of an agent name.
	if st, _ := call(t, false, "unknown-bot"); st != http.StatusOK {
		t.Fatalf("agent posture must be off by default, got %d", st)
	}

	// Opted in: an agent the posture system does not vouch for is refused, and
	// refused the way every other agent refusal is — the same 401 a bad bearer
	// gets, so it learns nothing from the reply.
	if st, _ := call(t, true, "unknown-bot"); st != http.StatusUnauthorized {
		t.Fatalf("an unhealthy agent must be refused, got %d", st)
	}
	// And one it does vouch for still works.
	st, asked := call(t, true, "healthy-bot")
	if st != http.StatusOK {
		t.Fatalf("a healthy agent should be admitted, got %d", st)
	}

	// The webhook is told WHAT it is being asked about. A posture system that
	// cannot tell a laptop from a workload tends to answer "healthy" for both.
	var sawAgentKind bool
	for _, q := range asked {
		if q["user"] == "healthy-bot" && q["kind"] == posture.SubjectAgent {
			sawAgentKind = true
		}
	}
	if !sawAgentKind {
		t.Fatalf("the webhook should be asked about an %q subject: %+v", posture.SubjectAgent, asked)
	}
}

// TestAgentPostureRefusalIsAudited pins the trail: a refusal that leaves no
// record is indistinguishable from an agent that simply stopped calling.
func TestAgentPostureRefusalIsAudited(t *testing.T) {
	fp := &fakePosture{healthy: map[string]bool{"bootstrap-admin": true}}
	opts := brokerOpts(t, &fakeWinRM{}, toolsetRules)
	opts.PostureAttestor = posture.NewAttestor(fp.start(t))
	opts.BrokerPostureRequired = true
	srv, _ := newTestServerOpts(t, nil, opts)
	_, tok := mintAgent(t, srv, "sick-bot", "alice", nil)

	if st, _ := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok,
		map[string]any{"tool": "list_targets"}); st != http.StatusUnauthorized {
		t.Fatal("an unhealthy agent must be refused")
	}
	_, aud := do(t, srv, http.MethodGet, "/api/audit?limit=50", testAPIKey, nil)
	if !strings.Contains(string(aud), "agent.posture_denied") ||
		!strings.Contains(string(aud), "reason:posture-check-failed") {
		t.Fatalf("the refusal should name itself on the trail: %s", aud)
	}
}

// TestAgentPostureIsNotAskedAboutAStoppedAgent pins the ordering: posture is the
// only admission check that leaves the process, so the cheap local ones run
// first. A quarantined identity must never reach the deployment's webhook —
// otherwise stopping an agent turns into traffic somebody else has to absorb.
func TestAgentPostureIsNotAskedAboutAStoppedAgent(t *testing.T) {
	fp := &fakePosture{healthy: map[string]bool{"quarantined-bot": true, "bootstrap-admin": true}}
	opts := brokerOpts(t, &fakeWinRM{}, toolsetRules)
	opts.PostureAttestor = posture.NewAttestor(fp.start(t))
	opts.BrokerPostureRequired = true
	srv, _ := newTestServerOpts(t, nil, opts)
	_, tok := mintAgent(t, srv, "quarantined-bot", "alice", nil)
	if st, d := do(t, srv, http.MethodPost, "/v1/agents/quarantine", testAPIKey,
		map[string]any{"subject": "quarantined-bot", "reason": "incident"}); st != http.StatusCreated {
		t.Fatalf("quarantine: %d %s", st, d)
	}

	if st, _ := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok,
		map[string]any{"tool": "list_targets"}); st != http.StatusUnauthorized {
		t.Fatal("a quarantined agent must be refused")
	}
	// The admin's own setup calls legitimately reach the webhook as `kind:user`
	// — that is Phase 133's gate doing its job. What must not appear is a
	// question about the AGENT.
	for _, q := range fp.questions() {
		if q["kind"] == posture.SubjectAgent {
			t.Fatalf("a stopped agent must not reach the posture webhook: %+v", q)
		}
	}
}
