package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/banner"
	"github.com/morandeirachema/pamv1/internal/expect"
	"github.com/morandeirachema/pamv1/internal/recording"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/telnet"
)

// serveTelnet brokers a telnet target (Phase 279). The operator's SSH
// session is bridged to a TELNET connection PAMv1 opens to the target; the
// target's startup scenario — its own, or the default login/password
// dialogue — logs in with the vaulted credential before the operator sees a
// byte, so the operator never learns the secret. The login dialogue is kept
// out of the operator's stream and the recording (a device may echo what
// was typed); what the target prints after the last expected prompt, and
// the whole session after it, is recorded and watchable like an SSH shell.
//
// Telnet itself is cleartext between PAMv1 and the target. The operator's
// leg is SSH; the target leg is only brokered when PAM_TELNET_ENABLED says
// the deployment accepts that.
//
// A telnet session is a shell, so it is held to what an SSH shell is (review
// of 274-280): the ssh_shell right of the session's sub-protocol set, and
// mandatory live supervision.
func (p *Proxy) serveTelnet(ctx context.Context, sconn *ssh.ServerConn, chans <-chan ssh.NewChannel, target *store.Target, cred *store.Credential, secret, actor, remote string, observe, breakGlass bool, bounds sessionBounds, rights string) {
	if !p.telnet {
		p.audit(ctx, actor, "session.denied", "target:"+target.Name+" reason:telnet-disabled")
		rejectAll(chans, ssh.Prohibited, "PAMv1: telnet targets are disabled on this server")
		return
	}
	if cred.SecretType != store.SecretTypePassword {
		p.audit(ctx, actor, "session.error", fmt.Sprintf("target:%s cred_user:%s reason:telnet-needs-password", target.Name, cred.Username))
		rejectAll(chans, ssh.ConnectionFailed, "PAMv1: a telnet target logs in with a password credential")
		return
	}
	sc, err := expect.Parse(target.Scenario)
	if err != nil { // stored canonical, so only a hand-edited row lands here
		p.audit(ctx, actor, "session.error", fmt.Sprintf("target:%s reason:bad-scenario", target.Name))
		rejectAll(chans, ssh.ConnectionFailed, "PAMv1: the target's login scenario is invalid")
		return
	}
	if len(sc) == 0 {
		sc = expect.DefaultLogin
	}

	var sid string
	if p.sessions != nil {
		sid = p.sessions.Register(session.Info{
			Actor: actor, Target: target.Name, Protocol: "telnet", Remote: remote, Started: time.Now(),
			Deadline: bounds.deadline, DeadlineReason: bounds.reason,
		}, func() { sconn.Close() })
		defer p.sessions.Remove(sid)
	}
	defer func() {
		p.auditClosing(ctx, actor, "session.end", "target:"+target.Name+" protocol:telnet")
		p.fireSessionEnd(cred.ID)
	}()

	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "PAMv1: only session channels are proxied")
			continue
		}
		p.handleTelnetSession(ctx, nc, target, cred, secret, actor, observe, breakGlass, sid, sc, rights)
		// One telnet connection per SSH connection: the target has one
		// login, and a second channel would need a second one.
		sconn.Close()
	}
}

// ptyReq is the RFC 4254 §6.2 pty-req payload; windowChange is §6.7.
type ptyReq struct {
	Term                 string
	Cols, Rows, PxW, PxH uint32
	Modes                string
}

func (p *Proxy) handleTelnetSession(ctx context.Context, nc ssh.NewChannel, target *store.Target, cred *store.Credential, secret, actor string, observe, breakGlass bool, sid string, sc expect.Script, rights string) {
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	defer ch.Close()

	// Wait for the shell request: telnet has no exec, and the window size
	// arrives with pty-req before it.
	term, cols, rows := "xterm", uint16(80), uint16(24)
	var winCh = make(chan [2]uint16, 4)
	started := false
	for !started {
		req, ok := <-reqs
		if !ok {
			return
		}
		switch req.Type {
		case "pty-req":
			var m ptyReq
			if ssh.Unmarshal(req.Payload, &m) == nil {
				if m.Term != "" {
					term = m.Term
				}
				if c, r := clampDim(m.Cols), clampDim(m.Rows); c != 0 && r != 0 {
					cols, rows = c, r
				}
			}
			reply(req, true)
		case "env":
			reply(req, true)
		case "shell":
			if !store.RightsAllow(rights, store.RightSSHShell) {
				p.audit(ctx, actor, "session.right_denied", fmt.Sprintf("target:%s cred_user:%s right:%s", target.Name, cred.Username, store.RightSSHShell))
				reply(req, false)
				return
			}
			reply(req, true)
			started = true
		default: // exec, subsystem, x11-req: not something telnet can carry
			reply(req, false)
		}
	}
	go func() {
		for req := range reqs {
			if req.Type == "window-change" && len(req.Payload) >= 8 {
				select {
				case winCh <- [2]uint16{clampDim(binary.BigEndian.Uint32(req.Payload[0:])), clampDim(binary.BigEndian.Uint32(req.Payload[4:]))}:
				default:
				}
			}
			reply(req, req.Type == "window-change")
		}
		close(winCh)
	}()

	if p.requireSup && !observe && !breakGlass && !p.awaitSupervision(ctx, sid) {
		p.audit(ctx, actor, "session.unsupervised", fmt.Sprintf("target:%s cred_user:%s timeout:%s", target.Name, cred.Username, p.supTimeout))
		fmt.Fprintln(ch.Stderr(), "PAMv1: no supervisor attached to watch this session; refused")
		exitStatus(ch, 1)
		return
	}

	addr := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	nconn, err := net.DialTimeout("tcp", addr, p.dialTimeout)
	if err != nil {
		p.log.Error("telnet dial failed", "actor", actor, "target", target.Name, "err", err)
		p.audit(ctx, actor, "session.error", fmt.Sprintf("target:%s protocol:telnet reason:dial-failed", target.Name))
		fmt.Fprintln(ch.Stderr(), "PAMv1: could not reach the target")
		exitStatus(ch, 1)
		return
	}
	tc := telnet.New(nconn, term, cols, rows)
	defer tc.Close()
	// A kill (registry, idle, lifetime) closes the SSH connection, which
	// ends ch; the operator-side copy below then closes the telnet
	// connection, which ends the target-side copy. The listener's context
	// only matters at shutdown; this goroutine ends with the session either
	// way (review of 274-280: it used to wait on that context alone and
	// leaked one per session).
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			tc.Close()
		case <-done:
		}
	}()

	now := time.Now()
	rec, err := newRecording(context.Background(), p.recordingDir, recording.Title(p.opaqueNames, now, target.Name, actor), now, p.maxRecBytes, p.recKey)
	if err != nil {
		p.log.Error("recording setup failed", "actor", actor, "target", target.Name, "err", err)
		p.audit(ctx, actor, "session.record_failed", fmt.Sprintf("target:%s cred_user:%s protocol:telnet error:%v", target.Name, cred.Username, err))
		if p.requireRec {
			fmt.Fprintln(p.teeLive(ch.Stderr(), sid), "PAMv1: session recording is unavailable; session refused")
			exitStatus(ch, 1)
			return
		}
	}
	defer func() {
		if rec != nil {
			path, sum, n := rec.Close()
			chain := p.chain.append(sum)
			p.auditClosing(ctx, actor, "session.record",
				fmt.Sprintf("target:%s cred_user:%s file:%s bytes:%d sha256:%s chain:%s", target.Name, cred.Username, path, n, sum, chain))
		}
	}()

	// The login. Nothing the target prints during it reaches the operator.
	stream := expect.NewStream(tc)
	defer stream.Close()
	runErr := sc.Run(ctx, stream, tc, cred.Username, secret, "\r\n", p.scenarioStep)
	if runErr != nil {
		reason := "failed"
		switch {
		case errors.Is(runErr, expect.ErrTimeout):
			reason = "timeout"
		case errors.Is(runErr, expect.ErrClosed):
			reason = "closed"
		}
		p.audit(ctx, actor, "session.scenario", fmt.Sprintf("target:%s cred_user:%s protocol:telnet steps:%d outcome:%s", target.Name, cred.Username, len(sc), reason))
		// The error names the step and the text it waited for, never what
		// was sent, so it is safe to show.
		fmt.Fprintf(ch.Stderr(), "PAMv1: the target's login scenario did not complete: %v\r\n", runErr)
		exitStatus(ch, 1)
		return
	}
	p.audit(ctx, actor, "session.scenario", fmt.Sprintf("target:%s cred_user:%s protocol:telnet steps:%d outcome:ok", target.Name, cred.Username, len(sc)))

	cw := &capWriter{w: recWriter(ch, rec)}
	out := p.teeLive(cw, sid)
	if rec != nil {
		_, _ = io.WriteString(rec, fmt.Sprintf("pamv1: logged in to %s by its startup scenario (%d steps)\r\n", target.Name, len(sc)))
	}
	if notice := p.banners.Get(banner.Session, ""); notice != "" {
		_, _ = io.WriteString(out, notice+"\r\n")
		p.audit(ctx, actor, "session.consent", fmt.Sprintf("target:%s cred_user:%s mode:printed banner_sha256:%s", target.Name, cred.Username, banner.Digest(notice)))
	}

	go func() {
		for wc := range winCh {
			_ = tc.SetWindowSize(wc[0], wc[1])
		}
	}()
	if observe {
		go func() {
			_, _ = io.Copy(io.Discard, ch)
			tc.Close() // the watcher left or was killed: hang up, as below
		}()
	} else {
		go func() {
			_, _ = io.Copy(tc, activityReader{r: ch, touch: p.sessions.Activity(sid)})
			tc.Close() // the operator left: hang up on the target
		}()
	}
	_, cerr := io.Copy(out, stream)
	if errors.Is(cerr, errRecordingLimit) || cw.capped {
		p.audit(ctx, actor, "session.record_limit", "target:"+target.Name+" cred_user:"+cred.Username+" reason:recording-size-cap")
	}
	exitStatus(ch, 0)
}

func reply(req *ssh.Request, ok bool) {
	if req.WantReply {
		_ = req.Reply(ok, nil)
	}
}

func exitStatus(ch ssh.Channel, code uint32) {
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{code}))
}

// clampDim fits a terminal dimension into telnet's 16 bits; 0 (unknown)
// stays 0 for the caller to default.
func clampDim(v uint32) uint16 {
	if v > 0xffff {
		return 0xffff
	}
	return uint16(v)
}
