package session_test

// stepupbus_test.go proves cross-replica step-up decisions (Phase 56) with two
// independent StepUp coordinators sharing one memory store, exactly as
// livebus_test.go does for the relay: the store's in-process fan-out stands in
// for Postgres LISTEN/NOTIFY, so these tests drive the same code an HA
// deployment runs. A supervisor on "replica B" must be able to list and decide
// a statement paused on "replica A" — and nothing unsealed may move either the
// list or the pause.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/testutil"
)

// stepUpReplica builds one simulated replica's coordinator, bus attached under
// the given name, recording bus-applied audit events into audits (may be nil).
func stepUpReplica(t *testing.T, ctx context.Context, st *memstore.Memstore, name string, audits *[]string, mu *sync.Mutex) *session.StepUp {
	t.Helper()
	su := session.NewStepUp()
	cfg := session.StepUpBusConfig{BusKey: testBusKey(), Replica: name}
	if audits != nil {
		cfg.Audit = func(_ context.Context, action, detail string) {
			mu.Lock()
			*audits = append(*audits, action+" "+detail)
			mu.Unlock()
		}
	}
	if err := su.StartBus(ctx, st, cfg); err != nil {
		t.Fatalf("StartBus(%s): %v", name, err)
	}
	return su
}

// pendingFrom polls a coordinator's cluster listing until it holds want
// entries (or fails the test), returning the final listing.
func pendingFrom(t *testing.T, su *session.StepUp, want int) []session.PendingStepUp {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		got, err := su.PendingCluster(context.Background())
		if err != nil {
			t.Fatalf("PendingCluster: %v", err)
		}
		if len(got) == want {
			return got
		}
		select {
		case <-deadline:
			t.Fatalf("PendingCluster settled at %d entries, want %d: %+v", len(got), want, got)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestStepUpBusRemoteDecisionEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := memstore.New()
	var audits []string
	var mu sync.Mutex
	a := stepUpReplica(t, ctx, st, "rep-a", &audits, &mu)
	b := stepUpReplica(t, ctx, st, "rep-b", nil, nil)

	const sql = "DROP TABLE customers"
	verdict := make(chan bool, 1)
	go func() { verdict <- a.Await(ctx, "sess-1", "alice", sql, 30*time.Second) }()

	// The pause registered on A is visible from B, statement in the clear,
	// naming the operator and the hosting replica.
	got := pendingFrom(t, b, 1)
	p := got[0]
	if p.SessionID != "sess-1" || p.Actor != "alice" || p.Statement != sql || p.Replica != "rep-a" {
		t.Fatalf("cluster listing = %+v, want sess-1/alice/%q on rep-a", p, sql)
	}
	if p.Expires.IsZero() || !p.Expires.After(p.Requested) {
		t.Fatalf("listing expiry %v not after requested %v", p.Expires, p.Requested)
	}
	// At rest the statement is SEALED: the raw store row must not leak the SQL.
	raw, err := st.ListStepUps(ctx)
	if err != nil || len(raw) != 1 {
		t.Fatalf("raw ListStepUps = %d rows, %v; want 1", len(raw), err)
	}
	if strings.Contains(raw[0].Statement, "DROP") || strings.Contains(raw[0].Statement, "customers") {
		t.Fatalf("shared inventory stores the statement in the clear: %q", raw[0].Statement)
	}

	// B does not hold the pause — DecideBy is a miss, DecideRemote dispatches.
	if ok, self := b.DecideBy("sess-1", true, "boss"); ok || self {
		t.Fatalf("DecideBy on the non-hosting replica = (%v,%v), want a miss", ok, self)
	}
	outcome, err := b.DecideRemote(ctx, "sess-1", true, "boss")
	if err != nil || outcome != session.StepUpDispatched {
		t.Fatalf("DecideRemote = (%v, %v), want StepUpDispatched", outcome, err)
	}
	select {
	case ok := <-verdict:
		if !ok {
			t.Fatal("the paused statement was refused; the remote approval never reached it")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Await still blocked after the remote approval")
	}
	// The claim removed the shared row, and A audited the bus-applied decision.
	// The audit is appended by the bus-apply goroutine on the hosting replica,
	// which is not synchronized with the verdict channel above — so poll for it
	// with a bound rather than reading once and racing the append.
	pendingFrom(t, b, 0)
	const want = "session.stepup_decided session:sess-1 approve:true decider:boss via:bus"
	if !testutil.WaitFor(t, 2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return strings.Contains(strings.Join(audits, "\n"), want)
	}) {
		mu.Lock()
		joined := strings.Join(audits, "\n")
		mu.Unlock()
		t.Fatalf("hosting replica did not audit the bus-applied decision within the deadline; got:\n%s", joined)
	}
}

func TestStepUpBusRemoteDeny(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := memstore.New()
	a := stepUpReplica(t, ctx, st, "rep-a", nil, nil)
	b := stepUpReplica(t, ctx, st, "rep-b", nil, nil)

	verdict := make(chan bool, 1)
	go func() { verdict <- a.Await(ctx, "sess-2", "alice", "DELETE FROM ledger", 30*time.Second) }()
	pendingFrom(t, b, 1)
	if outcome, err := b.DecideRemote(ctx, "sess-2", false, "boss"); err != nil || outcome != session.StepUpDispatched {
		t.Fatalf("DecideRemote(deny) = (%v, %v), want StepUpDispatched", outcome, err)
	}
	select {
	case ok := <-verdict:
		if ok {
			t.Fatal("a remote denial released the statement")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Await still blocked after the remote denial")
	}
}

func TestStepUpBusSelfApprovalRefused(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := memstore.New()
	a := stepUpReplica(t, ctx, st, "rep-a", nil, nil)
	b := stepUpReplica(t, ctx, st, "rep-b", nil, nil)

	verdict := make(chan bool, 1)
	go func() { verdict <- a.Await(ctx, "sess-3", "alice", "TRUNCATE audit", 30*time.Second) }()
	pendingFrom(t, b, 1)
	// The operator hops to another replica and tries to approve their own pause:
	// refused before anything is dispatched, and the pause stays pending.
	if outcome, err := b.DecideRemote(ctx, "sess-3", true, "alice"); err != nil || outcome != session.StepUpSelfApproval {
		t.Fatalf("DecideRemote(self) = (%v, %v), want StepUpSelfApproval", outcome, err)
	}
	if got := pendingFrom(t, b, 1); got[0].SessionID != "sess-3" {
		t.Fatalf("self-approval consumed the pause: %+v", got)
	}
	// A second person can still decide it.
	if outcome, err := b.DecideRemote(ctx, "sess-3", true, "boss"); err != nil || outcome != session.StepUpDispatched {
		t.Fatalf("DecideRemote(boss) = (%v, %v), want StepUpDispatched", outcome, err)
	}
	select {
	case ok := <-verdict:
		if !ok {
			t.Fatal("the second person's approval did not release the statement")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Await still blocked after the second person's approval")
	}
}

func TestStepUpBusRejectsForgeries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := memstore.New()
	a := stepUpReplica(t, ctx, st, "rep-a", nil, nil)
	b := stepUpReplica(t, ctx, st, "rep-b", nil, nil)

	verdict := make(chan bool, 1)
	go func() { verdict <- a.Await(ctx, "sess-4", "alice", "DROP TABLE t", 30*time.Second) }()
	pendingFrom(t, b, 1)

	// A database observer publishes an unsealed approval: it must not move the
	// pause. (Anything able to NOTIFY the channel can do this on PostgreSQL.)
	if err := st.PublishStepUpDecision(ctx, session.StepUpDecision{SessionID: "sess-4", Approve: true, Decider: "mallory"}); err != nil {
		t.Fatalf("PublishStepUpDecision(forged): %v", err)
	}
	select {
	case ok := <-verdict:
		t.Fatalf("an UNSEALED decision released the pause (approve=%v)", ok)
	case <-time.After(300 * time.Millisecond):
	}

	// A fabricated inventory row (statement not sealed under the cluster key)
	// must neither appear in a supervisor's listing nor be decidable.
	forged := session.PendingStepUp{SessionID: "sess-fake", Actor: "mallory", Statement: "GRANT ALL TO mallory", Requested: time.Now(), Replica: "rep-x"}
	if err := st.PutStepUp(ctx, forged, time.Minute); err != nil {
		t.Fatalf("PutStepUp(forged): %v", err)
	}
	if got := pendingFrom(t, b, 1); got[0].SessionID != "sess-4" {
		t.Fatalf("a fabricated row reached the supervisor listing: %+v", got)
	}
	if outcome, err := b.DecideRemote(ctx, "sess-fake", true, "boss"); err != nil || outcome != session.StepUpNotFound {
		t.Fatalf("DecideRemote(fabricated row) = (%v, %v), want StepUpNotFound", outcome, err)
	}

	// The genuine path still works.
	if outcome, err := b.DecideRemote(ctx, "sess-4", true, "boss"); err != nil || outcome != session.StepUpDispatched {
		t.Fatalf("DecideRemote(genuine) = (%v, %v), want StepUpDispatched", outcome, err)
	}
	select {
	case ok := <-verdict:
		if !ok {
			t.Fatal("the genuine approval did not release the statement")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Await still blocked after the genuine approval")
	}
}

// TestStepUpBusDecisionCannotBeReplayedOntoTheNextPause is the regression test
// for the replay the pause binding closes. It plays the attacker the seal was
// written for: something holding a database session, which on PostgreSQL can
// both READ and WRITE the NOTIFY channel without any privilege at all.
//
// The shape that matters is that a session pauses REPEATEDLY — once per flagged
// statement — while `pending` is keyed by session id. So a sealed decision that
// named only the session stayed applicable to whatever was pending when it
// arrived, and its freshness window (±interestSkew) is minutes wide, which for a
// database session under a step-up policy is several statements. Capturing one
// genuine approval therefore bought a second, unsupervised release — audited
// under the name of the supervisor who approved the first.
//
// Verified to fail against the pre-fix code, where the replayed decision
// released the second statement.
func TestStepUpBusDecisionCannotBeReplayedOntoTheNextPause(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := memstore.New()
	var audits []string
	var mu sync.Mutex
	a := stepUpReplica(t, ctx, st, "rep-a", &audits, &mu)
	b := stepUpReplica(t, ctx, st, "rep-b", nil, nil)

	// The observer taps the decision channel, exactly as a database session can.
	tapped, err := st.SubscribeStepUpDecisions(ctx)
	if err != nil {
		t.Fatalf("SubscribeStepUpDecisions: %v", err)
	}

	// First flagged statement: paused on A, approved by a supervisor on B.
	first := make(chan bool, 1)
	go func() { first <- a.Await(ctx, "sess-r", "alice", "DELETE FROM ledger WHERE id = 1", 30*time.Second) }()
	pendingFrom(t, b, 1)
	if outcome, derr := b.DecideRemote(ctx, "sess-r", true, "boss"); derr != nil || outcome != session.StepUpDispatched {
		t.Fatalf("DecideRemote(first) = (%v, %v), want StepUpDispatched", outcome, derr)
	}
	select {
	case ok := <-first:
		if !ok {
			t.Fatal("the supervisor's genuine approval did not release the first statement")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Await still blocked after the genuine approval")
	}

	// The observer now holds a VALID, freshly sealed approval for this session.
	var captured session.StepUpDecision
	select {
	case captured = <-tapped:
	case <-time.After(5 * time.Second):
		t.Fatal("nothing was published on the decision channel")
	}
	if captured.Seal == "" || captured.SessionID != "sess-r" || !captured.Approve {
		t.Fatalf("captured decision is not the supervisor's approval: %+v", captured)
	}

	// Second flagged statement, same session — the ordinary case, not a contrived
	// one: this is what a step-up policy does on every flagged statement.
	second := make(chan bool, 1)
	go func() { second <- a.Await(ctx, "sess-r", "alice", "DROP TABLE ledger", 30*time.Second) }()
	pendingFrom(t, b, 1)

	// Replay the captured approval verbatim, well inside its freshness window.
	if perr := st.PublishStepUpDecision(ctx, captured); perr != nil {
		t.Fatalf("PublishStepUpDecision(replay): %v", perr)
	}
	select {
	case ok := <-second:
		t.Fatalf("a REPLAYED approval released the next flagged statement (approve=%v)", ok)
	case <-time.After(500 * time.Millisecond):
	}
	// It is still pending, so a supervisor can still decide it — a refused replay
	// must not consume the gate either.
	if got := pendingFrom(t, b, 1); got[0].SessionID != "sess-r" {
		t.Fatalf("the replay consumed the pause: %+v", got)
	}
	// And no audit claims the supervisor decided a statement they never saw.
	mu.Lock()
	joined := strings.Join(audits, "\n")
	mu.Unlock()
	if strings.Count(joined, "session.stepup_decided") != 1 {
		t.Fatalf("the replay was recorded as a decision; audits:\n%s", joined)
	}

	// The genuine path still works for the second statement: a fresh decision
	// names the CURRENT pause and releases it.
	if outcome, derr := b.DecideRemote(ctx, "sess-r", false, "boss"); derr != nil || outcome != session.StepUpDispatched {
		t.Fatalf("DecideRemote(second) = (%v, %v), want StepUpDispatched", outcome, derr)
	}
	select {
	case ok := <-second:
		if ok {
			t.Fatal("the supervisor denied the second statement; it was released anyway")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Await still blocked after the second genuine decision")
	}
}

func TestStepUpBusTimeoutCleansSharedRow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := memstore.New()
	a := stepUpReplica(t, ctx, st, "rep-a", nil, nil)
	b := stepUpReplica(t, ctx, st, "rep-b", nil, nil)

	if a.Await(ctx, "sess-5", "alice", "DROP TABLE t", 50*time.Millisecond) {
		t.Fatal("an undecided pause must time out to a refusal")
	}
	// The timeout claim deletes the mirror row, so no replica keeps listing a
	// pause that no longer exists.
	pendingFrom(t, b, 0)
}
