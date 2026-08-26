package auditfwd_test

// auditfwd_tls_test.go proves the Phase 47 additions against real sockets: the
// LEEF 2.0 format (with delimiter-injection resistance), and the TLS transport
// — a collector presenting a certificate the pinned CA signed is accepted with
// RFC 5425 octet-counted framing for syslog, while an untrusted collector is
// refused fail-closed and the cursor does not advance (spool-and-retry).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/auditfwd"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// selfSigned mints a throwaway server certificate for 127.0.0.1 and returns its
// PEM (the "CA" a client pins) plus the parsed keypair for the listener.
func selfSigned(t *testing.T) ([]byte, tls.Certificate) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "collector"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, pair
}

// tlsSink runs a TLS collector on loopback; each accepted connection's full
// byte stream is delivered on the channel at EOF.
func tlsSink(t *testing.T, pair tls.Certificate) (string, <-chan string) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	msgs := make(chan string, 16)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				b, _ := io.ReadAll(c)
				if len(b) > 0 {
					msgs <- string(b)
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), msgs
}

// writeCA writes a PEM bundle to a temp file and returns its path.
func writeCA(t *testing.T, pem []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "collector-ca.pem")
	if err := os.WriteFile(p, pem, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestForwardLEEF proves the QRadar LEEF 2.0 format, including that an
// attacker-controlled detail carrying the tab delimiter or newlines cannot
// forge extra attributes or records.
func TestForwardLEEF(t *testing.T) {
	addr, sink := udpSink(t)
	st := memstore.New()
	fwd, err := auditfwd.New(st, auditfwd.Config{Network: "udp", Addr: addr, Format: auditfwd.FormatLEEF})
	if err != nil {
		t.Fatal(err)
	}
	fwd.Flush(context.Background()) // cursor to "now"
	if err := st.AppendAudit(context.Background(), &store.AuditEvent{
		Actor: "alice", Action: "session.kill", Detail: "target:web-01\tusrName=forged\nLEEF:2.0|evil",
	}); err != nil {
		t.Fatal(err)
	}
	if err := fwd.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	m := collect(t, sink, 1)[0]
	for _, want := range []string{"LEEF:2.0|PAMv1|PAMv1|1|session.kill|", "usrName=alice", "devTime="} {
		if !strings.Contains(m, want) {
			t.Fatalf("LEEF record missing %q: %q", want, m)
		}
	}
	if strings.Contains(m, "\tusrName=forged") || strings.Contains(strings.TrimSuffix(m, "\n"), "\n") {
		t.Fatalf("delimiter/record injection survived sanitization: %q", m)
	}
}

// TestForwardTLSOctetCounted proves the tls transport end to end against a
// pinned collector: the handshake verifies against the CA bundle, and the
// syslog format is framed per RFC 5425 ("MSG-LEN SP MSG", no newline).
func TestForwardTLSOctetCounted(t *testing.T) {
	caPEM, pair := selfSigned(t)
	addr, sink := tlsSink(t, pair)
	st := memstore.New()
	fwd, err := auditfwd.New(st, auditfwd.Config{
		Network: "tls", Addr: addr, Format: auditfwd.FormatRFC5424, TLSCAFile: writeCA(t, caPEM),
	})
	if err != nil {
		t.Fatal(err)
	}
	fwd.Flush(context.Background())
	seedAudit(t, st, "credential.reveal")
	if err := fwd.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	stream := collect(t, sink, 1)[0]
	if !regexp.MustCompile(`^\d+ <110>1 `).MatchString(stream) {
		t.Fatalf("syslog over TLS is not octet-counted: %q", stream)
	}
	if strings.HasSuffix(stream, "\n") {
		t.Fatalf("octet-counted framing must not add a newline: %q", stream)
	}
	if !strings.Contains(stream, "credential.reveal") {
		t.Fatalf("event missing from TLS stream: %q", stream)
	}
}

// TestForwardTLSRefusesUntrustedCollector proves fail-closed verification: a
// collector whose certificate does not chain to the pinned CA is refused, the
// flush errors, and the cursor stays put — the event is delivered on the next
// flush through a trusted collector (spool-and-retry).
func TestForwardTLSRefusesUntrustedCollector(t *testing.T) {
	trustedPEM, trustedPair := selfSigned(t) // the CA the client pins…
	_, roguePair := selfSigned(t)            // …and a collector with a DIFFERENT key/cert
	addr, sink := tlsSink(t, roguePair)
	st := memstore.New()
	caFile := writeCA(t, trustedPEM)

	fwd, err := auditfwd.New(st, auditfwd.Config{Network: "tls", Addr: addr, Format: auditfwd.FormatRFC5424, TLSCAFile: caFile})
	if err != nil {
		t.Fatal(err)
	}
	fwd.Flush(context.Background())
	seedAudit(t, st, "breakglass.unseal")
	if err := fwd.Flush(context.Background()); err == nil {
		t.Fatal("flush to an untrusted collector must fail, not silently stream the audit trail")
	}
	select {
	case m := <-sink:
		t.Fatalf("audit bytes reached an unverified collector: %q", m)
	case <-time.After(200 * time.Millisecond):
	}

	// The cursor did not advance: a trusted collector receives the event.
	trustedAddr, trustedSink := tlsSink(t, trustedPair)
	fwd2, err := auditfwd.New(st, auditfwd.Config{Network: "tls", Addr: trustedAddr, Format: auditfwd.FormatRFC5424, TLSCAFile: caFile})
	if err != nil {
		t.Fatal(err)
	}
	if err := fwd2.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m := collect(t, trustedSink, 1)[0]; !strings.Contains(m, "breakglass.unseal") {
		t.Fatalf("spooled event not delivered after recovery: %q", m)
	}
}

// TestForwardTLSConfigValidation covers the CA-bundle loading errors.
func TestForwardTLSConfigValidation(t *testing.T) {
	st := memstore.New()
	if _, err := auditfwd.New(st, auditfwd.Config{Network: "tls", Addr: "x:1", TLSCAFile: "/nonexistent/ca.pem"}); err == nil {
		t.Fatal("unreadable CA bundle must be rejected at startup")
	}
	garbage := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(garbage, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := auditfwd.New(st, auditfwd.Config{Network: "tls", Addr: "x:1", TLSCAFile: garbage}); err == nil {
		t.Fatal("a CA bundle with no certificates must be rejected at startup")
	}
}
