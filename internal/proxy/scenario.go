package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/expect"
	"github.com/morandeirachema/pamv1/internal/store"
)

// sshScenarioFor resolves an SSH target's startup scenario (Phase 279) and
// the one thing it may need from the vault. The decrypted secret normally
// lives only from admit() to dialUpstream; a scenario that types
// ${password} (an `enable` or `sudo -i` prompt) keeps it for the life of
// the connection, because each shell opened on it runs the scenario, and no
// other scenario receives it at all. Only a principal with the reveal
// capability may set such a scenario (api.mayTypePassword). The third
// result is an audit reason when the scenario cannot run.
func sshScenarioFor(target *store.Target, cred *store.Credential, secret string) (expect.Script, string, string) {
	if target.Scenario == "" {
		return nil, "", ""
	}
	sc, err := expect.Parse(target.Scenario)
	if err != nil {
		return nil, "", "bad-scenario"
	}
	if !sc.Uses(expect.Password) {
		return sc, "", ""
	}
	if cred.SecretType != store.SecretTypePassword || secret == "" {
		return nil, "", "scenario-needs-password"
	}
	return sc, secret, ""
}

// runSSHScenario plays the scenario in a freshly opened shell, before the
// operator's first keystroke reaches it. As on telnet, the dialogue stays
// out of the operator's stream and the recording; the operator starts at
// whatever the target printed after the last expected prompt.
func (p *Proxy) runSSHScenario(ctx context.Context, stream *expect.Stream, upChan io.Writer, clientChan ssh.Channel, rec io.Writer, target *store.Target, cred *store.Credential, actor string, sc expect.Script, secret string) bool {
	err := sc.Run(ctx, stream, upChan, cred.Username, secret, "\n", p.scenarioStep)
	outcome := "ok"
	switch {
	case err == nil:
	case errors.Is(err, expect.ErrTimeout):
		outcome = "timeout"
	case errors.Is(err, expect.ErrClosed):
		outcome = "closed"
	default:
		outcome = "failed"
	}
	p.audit(ctx, actor, "session.scenario", fmt.Sprintf("target:%s cred_user:%s protocol:ssh steps:%d outcome:%s", target.Name, cred.Username, len(sc), outcome))
	if err != nil {
		fmt.Fprintf(clientChan.Stderr(), "PAMv1: the target's startup scenario did not complete: %v\r\n", err)
		return false
	}
	if rec != nil {
		_, _ = fmt.Fprintf(rec, "pamv1: startup scenario ran in the shell (%d steps)\r\n", len(sc))
	}
	return true
}

// inputGate holds the operator's keystrokes until the startup scenario has
// run (or is not going to). wait reports false when the scenario failed and
// the session is ending, so nothing typed meanwhile is sent.
type inputGate struct {
	ch   chan struct{}
	once sync.Once
	bad  atomic.Bool
}

func newInputGate(open bool) *inputGate {
	g := &inputGate{ch: make(chan struct{})}
	if open {
		g.open()
	}
	return g
}

func (g *inputGate) open() { g.once.Do(func() { close(g.ch) }) }

func (g *inputGate) fail() {
	g.bad.Store(true)
	g.open()
}

func (g *inputGate) wait() bool {
	<-g.ch
	return !g.bad.Load()
}

func (g *inputGate) isOpen() bool {
	select {
	case <-g.ch:
		return true
	default:
		return false
	}
}
