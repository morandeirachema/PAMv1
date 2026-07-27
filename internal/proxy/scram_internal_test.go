package proxy

import (
	"crypto/sha256"
	"encoding/base64"
	"net"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
	"golang.org/x/crypto/pbkdf2"
)

// runSCRAMServer speaks the server side of one SCRAM-SHA-256 exchange over be,
// deriving the correct ServerSignature from the shared password — or, when
// tamper is set, a corrupted one, so the test proves the client actually
// verifies mutual authentication instead of trusting any v= value.
func runSCRAMServer(t *testing.T, be *pgproto3.Backend, password string, tamper bool) {
	t.Helper()
	if err := be.SetAuthType(pgproto3.AuthTypeSASL); err != nil {
		t.Errorf("SetAuthType(SASL): %v", err)
		return
	}
	msg, err := be.Receive()
	if err != nil {
		t.Errorf("receive client-first: %v", err)
		return
	}
	init, ok := msg.(*pgproto3.SASLInitialResponse)
	if !ok || init.AuthMechanism != "SCRAM-SHA-256" {
		t.Errorf("want SASLInitialResponse(SCRAM-SHA-256), got %T %+v", msg, msg)
		return
	}
	// GS2 header "n,," then the bare client-first message.
	clientFirstBare := strings.TrimPrefix(string(init.Data), "n,,")
	clientNonce := parseSCRAM(clientFirstBare)["r"]

	salt := []byte("0123456789abcdef")
	const iters = 4096
	serverNonce := clientNonce + "srvext"
	serverFirst := "r=" + serverNonce + ",s=" + base64.StdEncoding.EncodeToString(salt) + ",i=4096"
	be.Send(&pgproto3.AuthenticationSASLContinue{Data: []byte(serverFirst)})
	if err := be.Flush(); err != nil {
		t.Errorf("send server-first: %v", err)
		return
	}

	if err := be.SetAuthType(pgproto3.AuthTypeSASLContinue); err != nil {
		t.Errorf("SetAuthType(SASLContinue): %v", err)
		return
	}
	msg, err = be.Receive()
	if err != nil {
		t.Errorf("receive client-final: %v", err)
		return
	}
	final, ok := msg.(*pgproto3.SASLResponse)
	if !ok {
		t.Errorf("want SASLResponse, got %T", msg)
		return
	}
	clientFinal := string(final.Data)
	clientFinalBare := clientFinal[:strings.Index(clientFinal, ",p=")]

	// Recompute the ServerSignature exactly as RFC 5802 defines it.
	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalBare
	salted := pbkdf2.Key([]byte(password), salt, iters, sha256.Size, sha256.New)
	serverKey := hmacSHA256(salted, []byte("Server Key"))
	sig := hmacSHA256(serverKey, []byte(authMessage))
	if tamper {
		sig[0] ^= 0xff // an impostor upstream that never knew the password
	}
	be.Send(&pgproto3.AuthenticationSASLFinal{Data: []byte("v=" + base64.StdEncoding.EncodeToString(sig))})
	_ = be.Flush()
}

// scramPipe runs scramAuth against an in-process SCRAM server over a pipe.
func scramPipe(t *testing.T, password string, tamper bool) error {
	t.Helper()
	cli, srv := net.Pipe()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		runSCRAMServer(t, pgproto3.NewBackend(srv, srv), password, tamper)
	}()
	err := scramAuth(pgproto3.NewFrontend(cli, cli), password, []string{"SCRAM-SHA-256"})
	<-done
	return err
}

// TestSCRAMMutualAuthVerified proves the upstream-PostgreSQL SCRAM handshake
// end-to-end: a server that derives the correct ServerSignature from the
// vaulted password is accepted, and one that cannot (an impostor/MITM that
// never knew the password) is refused — the mutual-authentication check
// SECURITY-GAPS #11 added must actually run.
func TestSCRAMMutualAuthVerified(t *testing.T) {
	if err := scramPipe(t, "s3cret-pw", false); err != nil {
		t.Fatalf("honest server refused: %v", err)
	}
	err := scramPipe(t, "s3cret-pw", true)
	if err == nil || !strings.Contains(err.Error(), "server signature mismatch") {
		t.Fatalf("tampered server signature: want mismatch error, got %v", err)
	}
}

// TestSCRAMRefusesUnsupportedMechanisms proves the client never downgrades to a
// mechanism it does not implement.
func TestSCRAMRefusesUnsupportedMechanisms(t *testing.T) {
	cli, _ := net.Pipe()
	t.Cleanup(func() { cli.Close() })
	err := scramAuth(pgproto3.NewFrontend(cli, cli), "pw", []string{"SCRAM-SHA-1", "PLAIN"})
	if err == nil || !strings.Contains(err.Error(), "no supported SASL mechanism") {
		t.Fatalf("want unsupported-mechanism error, got %v", err)
	}
}

// TestSCRAMRefusesForeignNonce proves a server nonce that does not extend the
// client's nonce (a replayed or spliced exchange) is rejected before any proof
// is sent.
func TestSCRAMRefusesForeignNonce(t *testing.T) {
	cli, srv := net.Pipe()
	t.Cleanup(func() { cli.Close(); srv.Close() })
	go func() {
		be := pgproto3.NewBackend(srv, srv)
		if err := be.SetAuthType(pgproto3.AuthTypeSASL); err != nil {
			return
		}
		if _, err := be.Receive(); err != nil {
			return
		}
		be.Send(&pgproto3.AuthenticationSASLContinue{Data: []byte("r=totally-unrelated,s=" + base64.StdEncoding.EncodeToString([]byte("salt0123")) + ",i=4096")})
		_ = be.Flush()
	}()
	err := scramAuth(pgproto3.NewFrontend(cli, cli), "pw", []string{"SCRAM-SHA-256"})
	if err == nil || !strings.Contains(err.Error(), "does not extend") {
		t.Fatalf("want nonce-extension error, got %v", err)
	}
}
