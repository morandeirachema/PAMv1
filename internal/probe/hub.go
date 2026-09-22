package probe

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/morandeirachema/pamv1/internal/auditfmt"
)

// ErrProbeGone is returned by Hub.Kill when the probe is not connected to
// THIS replica (any more).
var ErrProbeGone = errors.New("probe is not connected")

// PolicySource returns the rules a probe of targetID must enforce: the
// target's own plus the global ones. main wires it to the store.
type PolicySource func(ctx context.Context, targetID int64) ([]Rule, error)

// Link identifies one connected probe: the agent row it authenticated as,
// the target that row is bound to, and what the probe said about itself.
type Link struct {
	AgentID    int64  `json:"agent_id"`
	AgentName  string `json:"agent_name"`
	TargetID   int64  `json:"target_id"`
	TargetName string `json:"target_name"`
	Remote     string `json:"remote"`
	Hello      Hello  `json:"hello"`
}

// Status is the API's view of one connected probe: its Link plus what the
// latest Snapshot amounted to.
type Status struct {
	Key int64 `json:"key"`
	Link
	Connected   time.Time `json:"connected"`
	Taken       time.Time `json:"taken,omitempty"`
	Processes   int       `json:"processes"`
	Connections int       `json:"connections"`
	Rules       int       `json:"rules"`
	Events      int       `json:"events"`
}

// Artifact is one probe session's metadata record (Phase 271): a JSON line
// per event, opened when the probe connects and closed when it disconnects.
// The proxy provides the implementation (a sealed, hashed file in the
// recording directory, chained like every recording); Close returns the
// audit detail describing the stored file.
type Artifact interface {
	WriteLine(line []byte) error
	Close() (detail string)
}

// Artifacts opens an Artifact for a probe link.
type Artifacts interface {
	Open(l Link) (Artifact, error)
}

// Hub is the per-replica registry of connected probes, the server side of
// the protocol: it pushes policy, keeps each probe's latest Snapshot, turns
// Events into audit rows, and relays kill commands. Like session.EndpointAgents
// a nil *Hub is a safe no-op (the feature is off).
type Hub struct {
	mu     sync.Mutex
	seq    int64
	links  map[int64]*link
	policy PolicySource
	log    *slog.Logger
	// CommandTimeout bounds Kill's wait for the probe's Result (default 15s).
	CommandTimeout time.Duration
	// Artifacts, when set, records each probe session's events (Phase 271).
	Artifacts Artifacts
}

// link is one connected probe's server-side state.
type link struct {
	Status
	rw       io.ReadWriteCloser
	wmu      sync.Mutex
	snapshot *Snapshot
	cmdSeq   int64
	waiters  map[int64]chan Result
}

// NewHub returns an empty hub reading rules from policy.
func NewHub(policy PolicySource, log *slog.Logger) *Hub {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Hub{links: make(map[int64]*link), policy: policy, log: log, CommandTimeout: 15 * time.Second}
}

// Serve runs one probe's connection until rw ends: it registers the link,
// pushes the policy (a policy that cannot be read refuses the probe — fail
// closed, the agent reconnects with backoff), then consumes Snapshots,
// Events (each audited through audit, with the detail prefix the caller
// chose) and Results. It returns when the probe's channel closes.
func (h *Hub) Serve(ctx context.Context, l Link, rw io.ReadWriteCloser, audit func(action, detail string)) error {
	if h == nil {
		_ = rw.Close()
		return errors.New("probes are disabled")
	}
	rules, err := h.policy(ctx, l.TargetID)
	if err != nil {
		_ = rw.Close()
		return fmt.Errorf("read probe policy: %w", err)
	}
	lk := &link{Status: Status{Link: l, Connected: time.Now().UTC(), Rules: len(rules)}, rw: rw, waiters: map[int64]chan Result{}}
	h.mu.Lock()
	h.seq++
	lk.Key = h.seq
	h.links[lk.Key] = lk
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.links, lk.Key)
		h.mu.Unlock()
		_ = rw.Close()
		lk.wmu.Lock()
		for id, ch := range lk.waiters {
			close(ch)
			delete(lk.waiters, id)
		}
		lk.wmu.Unlock()
	}()
	if err := lk.send(Message{Type: TypePolicy, Policy: &Policy{Rules: rules}}); err != nil {
		return fmt.Errorf("push probe policy: %w", err)
	}
	// The user is what the endpoint SAID it is — quoted and colon-escaped
	// like every other value that comes off a wire into an audit detail.
	prefix := fmt.Sprintf("agent:%d target:%s user:%s session:%d ", l.AgentID, l.TargetName, auditfmt.Value(l.Hello.User, 128), l.Hello.SessionID)
	// The session's metadata artifact (Phase 271): every event, enforcement
	// and metadata alike, as one JSON line; opened now, closed and audited
	// when the probe leaves. An artifact that cannot be opened refuses the
	// probe — telemetry that leaves no record is exactly what this exists to
	// prevent.
	var art Artifact
	if h.Artifacts != nil {
		var err error
		art, err = h.Artifacts.Open(l)
		if err != nil {
			return fmt.Errorf("open probe artifact: %w", err)
		}
		head, _ := json.Marshal(map[string]any{"probe": l, "connected": lk.Connected})
		if err := art.WriteLine(head); err != nil {
			art.Close()
			return fmt.Errorf("write probe artifact: %w", err)
		}
		defer func() { audit("probe.record", prefix+art.Close()) }()
	}
	r := bufio.NewReaderSize(rw, 64<<10)
	for {
		line, err := readLine(r, MaxLine)
		if err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return nil
			}
			return err
		}
		var m Message
		if err := json.Unmarshal(line, &m); err != nil {
			h.log.Warn("probe: malformed message", "agent", l.AgentName, "err", err)
			continue
		}
		switch {
		case m.Type == TypeSnapshot && m.Snapshot != nil:
			h.mu.Lock()
			lk.snapshot = m.Snapshot
			lk.Taken = m.Snapshot.Taken
			lk.Processes, lk.Connections = len(m.Snapshot.Processes), len(m.Snapshot.Connections)
			h.mu.Unlock()
		case m.Type == TypeEvent && m.Event != nil:
			h.mu.Lock()
			lk.Events++
			h.mu.Unlock()
			if art != nil {
				if m.Event.At.IsZero() {
					m.Event.At = time.Now().UTC()
				}
				if b, err := json.Marshal(m.Event); err == nil {
					if err := art.WriteLine(b); err != nil {
						h.log.Warn("probe: artifact write failed; dropping probe", "agent", l.AgentName, "err", err)
						return fmt.Errorf("write probe artifact: %w", err)
					}
				}
			}
			// Metadata is the artifact's; only an enforcement or a rule
			// match is an audit row.
			if m.Event.IsMetadata() {
				continue
			}
			audit(eventAction(m.Event.Kind), prefix+eventDetail(*m.Event))
		case m.Type == TypeResult && m.Result != nil:
			lk.wmu.Lock()
			ch, ok := lk.waiters[m.Result.ID]
			if ok {
				delete(lk.waiters, m.Result.ID)
			}
			lk.wmu.Unlock()
			if ok {
				ch <- *m.Result
				close(ch)
			}
		default:
			h.log.Warn("probe: unexpected message", "agent", l.AgentName, "type", m.Type)
		}
	}
}

// eventAction maps an Event kind to its audit action. Spelled out as
// literals rather than "probe."+kind so the audit vocabulary is greppable —
// the OCSF export's coverage test reads the names from source, and a name it
// cannot see is a detection rule that can never fire. An unknown kind (a
// newer probe than this server) is reported, not dropped.
func eventAction(kind string) string {
	switch kind {
	case EventProcessKilled:
		return "probe.process_killed"
	case EventConnectionBlocked:
		return "probe.connection_blocked"
	case EventCommandKilled:
		return "probe.command_killed"
	case EventKillFailed:
		return "probe.kill_failed"
	case EventRuleNotified:
		return "probe.rule_notified"
	}
	return "probe.event"
}

// eventDetail renders an Event for the audit trail. Every free-text field
// came from the endpoint (a process name is whatever the image was called),
// so each goes through auditfmt.Value: bounded, quoted and colon-escaped,
// the same treatment an SFTP path or a database name gets.
func eventDetail(e Event) string {
	var b strings.Builder
	fmt.Fprintf(&b, "pid:%d", e.PID)
	if e.Name != "" {
		fmt.Fprintf(&b, " name:%s", auditfmt.Value(e.Name, 64))
	}
	if e.Path != "" {
		fmt.Fprintf(&b, " path:%s", auditfmt.Value(e.Path, 255))
	}
	if e.Title != "" {
		fmt.Fprintf(&b, " title:%s", auditfmt.Value(e.Title, 128))
	}
	if e.Remote != "" {
		fmt.Fprintf(&b, " remote:%s", auditfmt.Value(e.Remote, 64))
	}
	if e.RuleID != 0 {
		fmt.Fprintf(&b, " rule:%d", e.RuleID)
	}
	if e.CommandID != 0 {
		fmt.Fprintf(&b, " command:%d", e.CommandID)
	}
	if e.Error != "" {
		fmt.Fprintf(&b, " error:%s", auditfmt.Value(e.Error, 128))
	}
	return b.String()
}

// Clean bounds a string the endpoint declared about itself (a hostname, an
// account name) for storage and display WITHOUT quoting it — the API shows
// it and SameUser matches on it, so it must stay the literal value. Control
// characters are dropped; the length is capped in bytes.
func Clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// send writes one JSON line to the probe.
func (l *link) send(m Message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	l.wmu.Lock()
	defer l.wmu.Unlock()
	_, err = l.rw.Write(append(b, '\n'))
	return err
}

// List returns every connected probe, newest connection first.
func (h *Hub) List() []Status {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	out := make([]Status, 0, len(h.links))
	for _, l := range h.links {
		out = append(out, l.Status)
	}
	h.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Key > out[j].Key })
	return out
}

// Get returns one probe's status and latest Snapshot (nil before the first).
func (h *Hub) Get(key int64) (Status, *Snapshot, bool) {
	if h == nil {
		return Status{}, nil, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	l, ok := h.links[key]
	if !ok {
		return Status{}, nil, false
	}
	return l.Status, l.snapshot, true
}

// ForSession returns the probes that belong to a brokered session: those on
// the session's target running as the credential's user, newest first. Two
// simultaneous sessions of the same account on the same server cannot be
// told apart from here (the desktop knows only the account), which is why
// this returns a list rather than one.
func (h *Hub) ForSession(targetName, credUser string) []Status {
	if h == nil {
		return nil
	}
	var out []Status
	for _, s := range h.List() {
		if s.TargetName == targetName && SameUser(s.Hello.User, credUser) {
			out = append(out, s)
		}
	}
	return out
}

// SameUser compares two account names the way a Windows logon does:
// case-insensitively, ignoring a "DOMAIN\" prefix or "@domain" suffix on
// either side — the credential is vaulted as "alice", the session reports
// "CORP\alice".
func SameUser(a, b string) bool {
	return bareUser(a) != "" && bareUser(a) == bareUser(b)
}

// bareUser strips domain qualifiers and case.
func bareUser(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.LastIndex(s, `\`); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[:i]
	}
	return s
}

// Kill asks the probe key to end pid and waits for its answer (bounded by
// CommandTimeout and ctx). The probe's refusal (access denied: not the
// session user's process) comes back as an error carrying its text.
func (h *Hub) Kill(ctx context.Context, key int64, pid uint32) error {
	if h == nil {
		return ErrProbeGone
	}
	h.mu.Lock()
	l, ok := h.links[key]
	h.mu.Unlock()
	if !ok {
		return ErrProbeGone
	}
	ch := make(chan Result, 1)
	l.wmu.Lock()
	l.cmdSeq++
	id := l.cmdSeq
	l.waiters[id] = ch
	l.wmu.Unlock()
	if err := l.send(Message{Type: TypeCommand, Command: &Command{ID: id, Op: OpKill, PID: pid}}); err != nil {
		l.wmu.Lock()
		delete(l.waiters, id)
		l.wmu.Unlock()
		return fmt.Errorf("send to probe: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, h.CommandTimeout)
	defer cancel()
	select {
	case res, ok := <-ch:
		if !ok {
			return ErrProbeGone
		}
		if !res.OK {
			return fmt.Errorf("probe refused: %s", res.Error)
		}
		return nil
	case <-ctx.Done():
		l.wmu.Lock()
		delete(l.waiters, id)
		l.wmu.Unlock()
		return fmt.Errorf("probe did not answer: %w", ctx.Err())
	}
}

// RefreshPolicy re-reads and re-pushes the rule set to every connected probe
// (after a rule is created or deleted). A probe whose push fails is dropped:
// its connection is evidently dead and the agent will reconnect.
func (h *Hub) RefreshPolicy(ctx context.Context) {
	if h == nil {
		return
	}
	h.mu.Lock()
	links := make([]*link, 0, len(h.links))
	for _, l := range h.links {
		links = append(links, l)
	}
	h.mu.Unlock()
	for _, l := range links {
		rules, err := h.policy(ctx, l.TargetID)
		if err != nil {
			h.log.Error("probe: policy refresh failed", "agent", l.AgentName, "err", err)
			continue
		}
		if err := l.send(Message{Type: TypePolicy, Policy: &Policy{Rules: rules}}); err != nil {
			h.log.Warn("probe: policy push failed; dropping", "agent", l.AgentName, "err", err)
			_ = l.rw.Close()
			continue
		}
		h.mu.Lock()
		l.Rules = len(rules)
		h.mu.Unlock()
	}
}

// Kick closes every connected probe of agentID (on revocation) and reports
// how many it closed.
func (h *Hub) Kick(agentID int64) int {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	var victims []*link
	for _, l := range h.links {
		if l.AgentID == agentID {
			victims = append(victims, l)
		}
	}
	h.mu.Unlock()
	for _, l := range victims {
		_ = l.rw.Close()
	}
	return len(victims)
}
