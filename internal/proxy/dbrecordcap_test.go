package proxy_test

// PAM_MAX_RECORDING_MB was a silent no-op on both database proxies: they wrote
// each statement with `_, _ = rec.Write(line)`, and Recording.Write LATCHES
// errRecordingLimit — so past the cap every statement was dropped and the session
// carried on UNRECORDED, indefinitely, with no session.record_limit audit, while
// the SSH path tore the session down. SECURITY-GAPS finding 23 claims the flag
// "terminates a session that exceeds the recording cap … rather than run it
// unrecorded"; that was true only of SSH.

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// TestDBProxyRecordingCapEndsSession proves a PostgreSQL session that exceeds the
// recording cap is TERMINATED and audited, rather than continuing unrecorded.
func TestDBProxyRecordingCapEndsSession(t *testing.T) {
	st := memstore.New()
	v := mustVault(t)
	fake := startFakePostgres(t, upstreamSecret)
	seedPGTarget(t, st, v, fake.addr)

	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	// A one-byte cap: the first recorded statement exceeds it.
	dbx, err := proxy.NewDB(st, v, resolver, proxy.DBConfig{
		RecordingDir:      t.TempDir(),
		DialTimeout:       5 * time.Second,
		MaxRecordingBytes: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveDBProxy(t, dbx)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fe := pgproto3.NewFrontend(conn, conn)
	fe.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": "dbuser@pg-01", "database": "appdb"},
	})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := fe.Receive(); err != nil { // cleartext password request
		t.Fatal(err)
	}
	fe.Send(&pgproto3.PasswordMessage{Password: proxyAPIKey})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}
	waitReady(t, fe)

	// Recording.Write records the frame that EXCEEDS the cap and only latches the
	// limit; the error surfaces on the next write. So the first statement is
	// recorded and the second is the one that must end the session.
	fe.Send(&pgproto3.Query{String: "SELECT 1"})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}
	waitReady(t, fe)

	fe.Send(&pgproto3.Query{String: "SELECT 2"})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}

	// The session must END — not merely stop recording. A read timeout is NOT
	// success: before the fix the relay kept forwarding and the connection stayed
	// open, so treating a timeout as "ended" would let the old behaviour pass.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	closed := false
	for {
		_, rerr := fe.Receive()
		if rerr == nil {
			continue
		}
		var nerr net.Error
		if errors.As(rerr, &nerr) && nerr.Timeout() {
			t.Fatal("the session was still open 5s after the recording cap — it is running unrecorded")
		}
		closed = true
		break
	}
	if !closed {
		t.Fatal("the session survived the recording cap")
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		events, aerr := st.ListAudit(context.Background(), 100)
		if aerr != nil {
			t.Fatal(aerr)
		}
		found := false
		for _, e := range events {
			if e.Action == "session.record_limit" && strings.Contains(e.Detail, "via:postgres") {
				found = true
			}
		}
		if found {
			return
		}
		if time.Now().After(deadline) {
			for _, e := range events {
				t.Logf("audit: %s | %s", e.Action, e.Detail)
			}
			t.Fatal("no session.record_limit audit event for a capped database session")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
