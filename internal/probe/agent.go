package probe

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"
)

// Options tunes Serve.
type Options struct {
	// Interval between scans (default DefaultInterval).
	Interval time.Duration
	// MaxProcesses / MaxConnections cap a Snapshot's rows (defaults 5000 /
	// 20000); a capped Snapshot says Truncated.
	MaxProcesses, MaxConnections int
	// Logger receives operational logs; nil discards them.
	Logger *slog.Logger
}

// Serve runs the probe's side of the protocol on rw until the server closes
// it or ctx ends: it scans the session every Interval (and immediately when a
// policy arrives), sends each Snapshot, enforces the current rules, reports
// each enforcement as an Event, and answers Commands. It returns nil when the
// server closed the channel, or the read/write error that ended it.
func Serve(ctx context.Context, rw io.ReadWriter, pl Platform, o Options) error {
	if o.Interval <= 0 {
		o.Interval = DefaultInterval
	}
	if o.MaxProcesses <= 0 {
		o.MaxProcesses = 5000
	}
	if o.MaxConnections <= 0 {
		o.MaxConnections = 20000
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	a := &agent{rw: rw, pl: pl, o: o, kick: make(chan struct{}, 1), done: make(chan error, 1)}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go a.readLoop(ctx)

	t := time.NewTicker(o.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-a.done:
			return err
		case <-a.kick:
		case <-t.C:
		}
		if err := a.scan(ctx); err != nil {
			return err
		}
	}
}

// agent is Serve's state.
type agent struct {
	rw   io.ReadWriter
	pl   Platform
	o    Options
	wmu  sync.Mutex // serializes writes: the read loop answers commands while scan sends
	rmu  sync.Mutex
	rule []Rule
	kick chan struct{} // "scan now" (a policy arrived)
	done chan error    // the read loop ended
}

// send writes one JSON line.
func (a *agent) send(m Message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	a.wmu.Lock()
	defer a.wmu.Unlock()
	_, err = a.rw.Write(append(b, '\n'))
	return err
}

// rules returns the current policy.
func (a *agent) rules() []Rule {
	a.rmu.Lock()
	defer a.rmu.Unlock()
	return a.rule
}

// readLoop consumes server messages until EOF or an error, which it reports
// on done exactly once.
func (a *agent) readLoop(ctx context.Context) {
	r := bufio.NewReaderSize(a.rw, 64<<10)
	for {
		line, err := readLine(r, MaxLine)
		if err != nil {
			if errors.Is(err, io.EOF) {
				a.done <- nil
			} else {
				a.done <- err
			}
			return
		}
		var m Message
		if err := json.Unmarshal(line, &m); err != nil {
			a.o.Logger.Warn("probe: malformed server message", "err", err)
			continue
		}
		switch {
		case m.Type == TypePolicy && m.Policy != nil:
			a.rmu.Lock()
			a.rule = m.Policy.Rules
			a.rmu.Unlock()
			a.o.Logger.Info("probe: policy received", "rules", len(m.Policy.Rules))
			select {
			case a.kick <- struct{}{}:
			default:
			}
		case m.Type == TypeCommand && m.Command != nil:
			a.command(ctx, *m.Command)
		default:
			a.o.Logger.Warn("probe: unexpected server message", "type", m.Type)
		}
	}
}

// command executes one server command and answers it. The vocabulary is
// closed: anything but a kill is refused, never interpreted.
func (a *agent) command(ctx context.Context, c Command) {
	res := Result{ID: c.ID}
	switch c.Op {
	case OpKill:
		if c.PID == 0 {
			res.Error = "pid required"
			break
		}
		if err := a.pl.Kill(ctx, c.PID); err != nil {
			res.Error = err.Error()
			_ = a.send(Message{Type: TypeEvent, Event: &Event{Kind: EventKillFailed, PID: c.PID, CommandID: c.ID, Error: err.Error()}})
		} else {
			res.OK = true
			_ = a.send(Message{Type: TypeEvent, Event: &Event{Kind: EventCommandKilled, PID: c.PID, CommandID: c.ID}})
		}
	default:
		res.Error = fmt.Sprintf("unknown op %q", c.Op)
	}
	if err := a.send(Message{Type: TypeResult, Result: &res}); err != nil {
		a.o.Logger.Warn("probe: result not sent", "err", err)
	}
}

// scan enumerates, reports, then enforces. The Snapshot goes first so the
// server sees what was there before anything was ended; the Events that
// follow say what the probe did about it. Enumeration errors ride along in
// the Snapshot rather than ending the probe: a PowerShell hiccup should not
// cost the session its telemetry.
func (a *agent) scan(ctx context.Context) error {
	snap := Snapshot{Taken: time.Now().UTC()}
	procs, err := a.pl.Processes(ctx)
	if err != nil {
		snap.Errors = append(snap.Errors, "processes: "+err.Error())
	}
	conns, err := a.pl.Connections(ctx)
	if err != nil {
		snap.Errors = append(snap.Errors, "connections: "+err.Error())
	}
	if len(procs) > a.o.MaxProcesses {
		procs, snap.Truncated = procs[:a.o.MaxProcesses], true
	}
	if len(conns) > a.o.MaxConnections {
		conns, snap.Truncated = conns[:a.o.MaxConnections], true
	}
	snap.Processes, snap.Connections = procs, conns
	if err := a.send(Message{Type: TypeSnapshot, Snapshot: &snap}); err != nil {
		return err
	}
	rules := a.rules()
	if len(rules) == 0 {
		return nil
	}
	byPID := make(map[uint32]Process, len(procs))
	for _, p := range procs {
		byPID[p.PID] = p
	}
	killed := map[uint32]bool{}
	for _, p := range procs {
		for _, r := range rules {
			if !r.MatchesProcess(p) {
				continue
			}
			if err := a.enforce(ctx, p, Event{Kind: EventProcessKilled, RuleID: r.ID}, killed); err != nil {
				return err
			}
			break
		}
	}
	for _, c := range conns {
		for _, r := range rules {
			if !r.MatchesConnection(c) {
				continue
			}
			p := byPID[c.PID]
			if p.PID == 0 {
				p = Process{PID: c.PID}
			}
			ev := Event{Kind: EventConnectionBlocked, RuleID: r.ID, Remote: fmt.Sprintf("%s:%d/%s", c.RemoteAddr, c.RemotePort, c.Proto)}
			if err := a.enforce(ctx, p, ev, killed); err != nil {
				return err
			}
			break
		}
	}
	return nil
}

// enforce ends p once per scan (a process matching several rules, or holding
// several blocked connections, is killed and reported once) and sends the
// outcome as ev with the process filled in.
func (a *agent) enforce(ctx context.Context, p Process, ev Event, killed map[uint32]bool) error {
	if killed[p.PID] {
		return nil
	}
	killed[p.PID] = true
	ev.PID, ev.Name, ev.Path = p.PID, p.Name, p.Path
	if err := a.pl.Kill(ctx, p.PID); err != nil {
		ev.Kind, ev.Error = EventKillFailed, err.Error()
		a.o.Logger.Warn("probe: kill failed", "pid", p.PID, "name", p.Name, "err", err)
	} else {
		a.o.Logger.Info("probe: process ended", "pid", p.PID, "name", p.Name, "kind", ev.Kind, "rule", ev.RuleID)
	}
	return a.send(Message{Type: TypeEvent, Event: &ev})
}

// readLine reads one '\n'-terminated line of at most max bytes. A longer
// line is an error, not silently split: a peer that sends one is broken or
// hostile either way.
func readLine(r *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		part, isPrefix, err := r.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) && len(line) > 0 {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		line = append(line, part...)
		if len(line) > max {
			return nil, fmt.Errorf("line exceeds %d bytes", max)
		}
		if !isPrefix {
			return line, nil
		}
	}
}
