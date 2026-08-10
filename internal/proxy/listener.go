package proxy

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

// listener is the shared connection-accept lifecycle for the three session
// proxies (SSH, PostgreSQL and SQL Server). Each proxy embeds one, so the
// accept loop, the capped transient-accept backoff, the bounded shutdown drain
// and the audit helpers live in exactly one place instead of being copied
// three times (where they would silently drift). The embedding proxy keeps its
// own protocol-specific handleConn and its own "listening" startup log line;
// everything the three had verbatim in common lives here.
//
// mu guards ONLY {ln, conns, closing}. bg tracks background tasks (post-session
// credential rotation) so a graceful shutdown drains them rather than killing
// the process mid-rotation. component is the default audit actor used when an
// event has no resolved principal ("proxy" / "dbproxy" / "mssqlproxy").
type listener struct {
	log          *slog.Logger
	store        store.Store
	component    string // default audit actor when an event has no resolved actor
	onSessionEnd func(int64)

	bg sync.WaitGroup // background tasks (post-session rotation) to drain on shutdown

	mu      sync.Mutex
	ln      net.Listener
	conns   map[net.Conn]struct{} // accepted client connections, for shutdown force-close
	closing bool                  // set once shutdown has begun force-closing connections
}

// serve accepts connections on ln until ctx is cancelled. On cancellation it
// closes the listener and force-closes every active client connection, then
// waits for the in-flight handlers to return — so the drain is bounded (it does
// not wait for operators to voluntarily disconnect) and no handler goroutine
// outlives serve. A fatal Accept error (not caused by cancellation) is returned
// promptly without waiting on active handlers. Each accepted connection is
// dispatched to handle in its own goroutine, guarded by recoverPanicLog so one
// malformed session cannot crash the whole proxy.
//
// acceptErrMsg is the per-proxy warning logged on a retried transient accept
// error; panicLabel is the per-proxy label a handler panic is logged under.
func (l *listener) serve(ctx context.Context, ln net.Listener, handle func(context.Context, net.Conn), acceptErrMsg, panicLabel string) error {
	l.mu.Lock()
	l.ln = ln
	l.closing = false // reset in case this proxy is served again
	l.mu.Unlock()

	go func() {
		<-ctx.Done()
		ln.Close()
		l.closeActiveConns() // unblock in-flight handlers so the drain is bounded
	}()

	var wg sync.WaitGroup
	var tempDelay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait() // graceful shutdown: active conns already force-closed
				l.bg.Wait()
				return nil
			}
			// Retry a transient accept error (e.g. fd exhaustion, EMFILE) with
			// capped exponential backoff instead of tearing the listener down —
			// the same policy net/http's Server uses.
			//lint:ignore SA1019 Temporary() is the only portable transient-accept signal; matches net/http's Serve backoff
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if tempDelay > time.Second {
					tempDelay = time.Second
				}
				l.log.Warn(acceptErrMsg, "err", err, "retry_in", tempDelay)
				select {
				case <-time.After(tempDelay):
				case <-ctx.Done():
					wg.Wait()
					l.bg.Wait()
					return nil
				}
				continue
			}
			return err // fatal listener error: report it without blocking on sessions
		}
		tempDelay = 0
		l.trackConn(conn)
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer l.untrackConn(c)
			defer recoverPanicLog(l.log, panicLabel)
			handle(ctx, c)
		}(conn)
	}
}

// trackConn records an accepted client connection so shutdown can force-close it.
func (l *listener) trackConn(c net.Conn) {
	l.mu.Lock()
	if l.closing {
		// Shutdown already force-closed the tracked set; close this straggler too
		// so it cannot slip past the drain and block serve's wg.Wait.
		l.mu.Unlock()
		c.Close()
		return
	}
	l.conns[c] = struct{}{}
	l.mu.Unlock()
}

// untrackConn drops a client connection once its handler has returned.
func (l *listener) untrackConn(c net.Conn) {
	l.mu.Lock()
	delete(l.conns, c)
	l.mu.Unlock()
}

// closeActiveConns force-closes every tracked client connection. Closing the
// client transport tears down its session mux, which ends the handler's loop and
// unblocks the session copies — bounding serve's shutdown drain.
func (l *listener) closeActiveConns() {
	l.mu.Lock()
	l.closing = true // any connection tracked after this point closes itself
	conns := make([]net.Conn, 0, len(l.conns))
	for c := range l.conns {
		conns = append(conns, c)
	}
	l.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

// fireSessionEnd runs the post-session credential-rotation callback (if any) as
// a tracked background task, so a graceful shutdown drains in-flight rotations
// instead of killing the process mid-rotation (which could leave a target's
// password changed but the vault stale). It must not block the caller.
func (l *listener) fireSessionEnd(credID int64) {
	if l.onSessionEnd == nil {
		return
	}
	l.bg.Add(1)
	go func() {
		defer l.bg.Done()
		l.onSessionEnd(credID)
	}()
}

// Addr returns the bound address (useful once serve is running).
func (l *listener) Addr() net.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ln.Addr()
}

// audit appends an audit event, defaulting an empty actor to the proxy's
// component name and logging (rather than returning) any append failure.
func (l *listener) audit(ctx context.Context, actor, action, detail string) {
	if actor == "" {
		actor = l.component
	}
	appendAudit(ctx, l.store, l.log, actor, action, detail)
}

// auditClosing writes a session-teardown audit event that must survive graceful
// shutdown. It detaches from ctx so a shutdown-cancelled context does not drop
// the event, and bounds the write so a hung store cannot stall the drain.
func (l *listener) auditClosing(ctx context.Context, actor, action, detail string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	l.audit(ctx, actor, action, detail)
}
