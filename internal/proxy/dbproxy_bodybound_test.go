package proxy_test

import (
	"encoding/binary"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// TestDBProxyRefusesOversizedPreAuthMessage is the regression test for the
// 2026-08-26 audit's one CRITICAL finding: an UNAUTHENTICATED peer could complete
// the bounded startup exchange and then, in the password message, declare a ~2 GiB
// body. pgproto3 allocated it and blocked on the read for the whole handshake
// timeout, and the auth rate limiter — which runs after that read — never saw
// the connection. A handful of these OOM-killed the process.
//
// The test sends exactly that five-byte payload and asserts two things: the
// proxy closes the connection promptly (it did not block for the timeout), and
// the process's heap did not grow by anything like the declared length. The
// second assertion is what distinguishes "refused" from "allocated and then
// errored", and it is the one that failed before the fix.
func TestDBProxyRefusesOversizedPreAuthMessage(t *testing.T) {
	st := memstore.New()
	v := mustVault(t)
	fake := startFakePostgres(t, upstreamSecret)
	seedPGTarget(t, st, v, fake.addr)
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	dbx, err := proxy.NewDB(st, v, resolver, proxy.DBConfig{RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second})
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
	// The proxy answers with AuthenticationCleartextPassword; consume it so the
	// next thing on the wire is our forged password frame.
	if _, err := fe.Receive(); err != nil {
		t.Fatalf("expected an auth request before the password: %v", err)
	}

	var before runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	// A PasswordMessage header: type 'p', then a big-endian int32 length that
	// INCLUDES the 4 length bytes. 0x7FFFFFFF is the largest positive length —
	// "a body of ~2 GiB follows", and nothing follows.
	frame := []byte{'p', 0, 0, 0, 0}
	binary.BigEndian.PutUint32(frame[1:], 0x7FFFFFFF)
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}

	// The proxy must hang up on its own, well inside the handshake timeout. A
	// read that returns quickly with EOF/RST is the pass; a read that sits until
	// the deadline is the pre-fix behaviour (blocked holding a 2 GiB buffer).
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	start := time.Now()
	_, rerr := conn.Read(buf)
	elapsed := time.Since(start)
	if rerr == nil {
		t.Fatal("the proxy answered an oversized pre-auth message instead of refusing it")
	}
	if nerr, ok := rerr.(net.Error); ok && nerr.Timeout() {
		t.Fatalf("the proxy did not hang up within 5s (elapsed %v): it is blocked on the oversized read", elapsed)
	}

	var after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&after)
	// The declared body was ~2 GiB. Allow a generous 64 MiB of unrelated churn
	// and still catch any attempt to honour the length.
	const slack = 64 << 20
	if grew := int64(after.HeapAlloc) - int64(before.HeapAlloc); grew > slack {
		t.Fatalf("heap grew by %d MiB on an unauthenticated 2 GiB length claim; the body bound is not in effect", grew>>20)
	}
}
