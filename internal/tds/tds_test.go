package tds

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// The tests in this file assert against byte literals derived from MS-TDS, not
// against the encoder's own output. That distinction is the point: the proxy's
// end-to-end tests drive a fake upstream that uses THIS package on both sides,
// so a symmetric codec bug would round-trip happily through all of them. Only
// spec-pinned literals can catch one.

// TestPasswordObfuscationVector pins the password transform to a hand-computed
// vector: "abc" as UTF-16LE is 61 00 62 00 63 00; swapping each byte's nibbles
// gives 16 00 26 00 36 00; XOR 0xA5 gives b3 a5 83 a5 93 a5.
func TestPasswordObfuscationVector(t *testing.T) {
	want := []byte{0xb3, 0xa5, 0x83, 0xa5, 0x93, 0xa5}
	got := ObfuscatePassword(stringToUCS2("abc"))
	if !bytes.Equal(got, want) {
		t.Fatalf("ObfuscatePassword = % x, want % x", got, want)
	}
	if back := ucs2ToString(DeobfuscatePassword(want)); back != "abc" {
		t.Fatalf("DeobfuscatePassword round-trip = %q, want %q", back, "abc")
	}
}

// TestPreLoginDecodeGoldenBytes decodes a hand-built PRELOGIN with real offsets
// and checks the encoder produces a table whose offsets point at the right data.
func TestPreLoginDecodeGoldenBytes(t *testing.T) {
	// Two options (VERSION at 11 len 6, ENCRYPTION at 17 len 1) + terminator.
	// The table is 2*5+1 = 11 bytes, so the data starts at offset 11.
	golden := []byte{
		PreLoginVersion, 0x00, 0x0b, 0x00, 0x06,
		PreLoginEncryption, 0x00, 0x11, 0x00, 0x01,
		PreLoginTerminator,
		0x10, 0x00, 0x00, 0x00, 0x00, 0x00, // VERSION data
		EncryptOn, // ENCRYPTION data
	}
	pl, err := ParsePreLogin(golden)
	if err != nil {
		t.Fatalf("ParsePreLogin: %v", err)
	}
	if pl.Encryption() != EncryptOn {
		t.Fatalf("Encryption = %#x, want %#x", pl.Encryption(), EncryptOn)
	}
	if v := pl.Options[PreLoginVersion]; len(v) != 6 || v[0] != 0x10 {
		t.Fatalf("VERSION option = % x", v)
	}

	// Re-encoding must produce a self-consistent table: each entry's offset must
	// address its own data.
	out := pl.Encode()
	re, err := ParsePreLogin(out)
	if err != nil {
		t.Fatalf("re-parse of encoded prelogin: %v", err)
	}
	if re.Encryption() != EncryptOn || len(re.Options[PreLoginVersion]) != 6 {
		t.Fatalf("encoded prelogin lost data: % x", out)
	}
	if out[len(pl.Order)*5] != PreLoginTerminator {
		t.Fatalf("terminator not at the end of the table: % x", out)
	}
}

// TestPreLoginRejectsOutOfRangeOffset proves a malformed option table is an
// error rather than a panic or a silent read past the payload.
func TestPreLoginRejectsOutOfRangeOffset(t *testing.T) {
	bad := []byte{PreLoginEncryption, 0xff, 0xff, 0x00, 0x01, PreLoginTerminator}
	if _, err := ParsePreLogin(bad); err == nil {
		t.Fatal("an option pointing outside the payload was accepted")
	}
	if _, err := ParsePreLogin([]byte{PreLoginVersion, 0, 0, 0, 0}); err == nil {
		t.Fatal("an unterminated option table was accepted")
	}
}

// buildLogin7 assembles a LOGIN7 by hand, writing the blobs in an order that
// does NOT match the descriptor order — proving the parser reads by offset
// rather than assuming each blob follows the previous one.
func buildLogin7(t *testing.T, user, pass, host, db string) []byte {
	t.Helper()
	fixed := make([]byte, l7FixedSize)
	binary.LittleEndian.PutUint32(fixed[l7TDSVersion:], VersionTDS74)
	binary.LittleEndian.PutUint32(fixed[l7PacketSize:], 4096)
	binary.LittleEndian.PutUint32(fixed[l7ClientPID:], 4242)
	fixed[l7OptionFlags1] = 0xE0
	copy(fixed[l7ClientID:], []byte{1, 2, 3, 4, 5, 6})

	// Deliberate layout: database, then password, then user, then host.
	var body []byte
	put := func(entry int, b []byte) {
		off := l7FixedSize + len(body)
		binary.LittleEndian.PutUint16(fixed[entry:], uint16(off))
		binary.LittleEndian.PutUint16(fixed[entry+2:], uint16(len(b)/2))
		body = append(body, b...)
	}
	put(l7Database, stringToUCS2(db))
	put(l7Password, ObfuscatePassword(stringToUCS2(pass)))
	put(l7UserName, stringToUCS2(user))
	put(l7HostName, stringToUCS2(host))

	out := append(fixed, body...)
	binary.LittleEndian.PutUint32(out[l7Length:], uint32(len(out)))
	return out
}

// TestLogin7ParseGoldenBytes proves the parser reads every field through its own
// offset, including a password blob laid out before the username.
func TestLogin7ParseGoldenBytes(t *testing.T) {
	raw := buildLogin7(t, "dbuser@appdb-01", "PAM-key-123", "workstation", "orders")
	l, err := ParseLogin7(raw)
	if err != nil {
		t.Fatalf("ParseLogin7: %v", err)
	}
	if l.UserName != "dbuser@appdb-01" {
		t.Fatalf("UserName = %q", l.UserName)
	}
	if l.Password != "PAM-key-123" {
		t.Fatalf("Password = %q (de-obfuscation is wrong)", l.Password)
	}
	if l.HostName != "workstation" || l.Database != "orders" {
		t.Fatalf("HostName = %q Database = %q", l.HostName, l.Database)
	}
	if l.TDSVersion != VersionTDS74 || l.PacketSize != 4096 || l.ClientPID != 4242 {
		t.Fatalf("fixed fields wrong: %+v", l)
	}
	if l.ClientID != [6]byte{1, 2, 3, 4, 5, 6} {
		t.Fatalf("ClientID = % x", l.ClientID)
	}
	if l.IntegratedSecurity() {
		t.Fatal("a SQL-auth login reported integrated security")
	}
}

// TestLogin7RewritePreservesEverythingButCredentials is the load-bearing test
// for JIT injection: swapping the username and password must change those two
// fields and NOTHING else — every other blob, flag and the client's negotiated
// version/packet size survive, and the length plus every offset are recomputed
// (which is why the rewrite re-encodes rather than patching in place).
func TestLogin7RewritePreservesEverythingButCredentials(t *testing.T) {
	raw := buildLogin7(t, "dbuser@appdb-01", "PAM-key-123", "workstation", "orders")
	l, err := ParseLogin7(raw)
	if err != nil {
		t.Fatal(err)
	}
	l.AppName, l.Language, l.CltIntName = "sqlcmd", "us_english", "ODBC"
	l.OptionFlags2 |= 0x80 // pretend the client asked for integrated security
	l.FeatureExt = []byte{0x0A, 0x01, 0x00, 0x00, 0x00, 0x01, 0xFF}
	l.OptionFlags3 |= 0x10

	// The injection itself.
	l.UserName, l.Password = "sql_svc", "vaulted-secret-with-a-different-length"
	l.OptionFlags2 &^= 0x80 // the proxy authenticates with SQL auth

	out := l.Encode()
	if got := binary.LittleEndian.Uint32(out[l7Length:]); int(got) != len(out) {
		t.Fatalf("encoded Length = %d, want %d", got, len(out))
	}
	back, err := ParseLogin7(out)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if back.UserName != "sql_svc" || back.Password != "vaulted-secret-with-a-different-length" {
		t.Fatalf("credentials not injected: user=%q pass=%q", back.UserName, back.Password)
	}
	if back.HostName != "workstation" || back.Database != "orders" ||
		back.AppName != "sqlcmd" || back.Language != "us_english" || back.CltIntName != "ODBC" {
		t.Fatalf("client fields lost: %+v", back)
	}
	if back.TDSVersion != VersionTDS74 || back.PacketSize != 4096 {
		t.Fatalf("negotiated version/packet size lost: %#x %d", back.TDSVersion, back.PacketSize)
	}
	if back.ClientID != [6]byte{1, 2, 3, 4, 5, 6} {
		t.Fatalf("ClientID lost: % x", back.ClientID)
	}
	if back.IntegratedSecurity() {
		t.Fatal("fIntSecurity was not cleared for the upstream login")
	}
	if !bytes.Equal(back.FeatureExt, l.FeatureExt) {
		t.Fatalf("feature extension not preserved: % x want % x", back.FeatureExt, l.FeatureExt)
	}
	// The password must never appear in clear on the wire.
	if bytes.Contains(out, stringToUCS2("vaulted-secret-with-a-different-length")) {
		t.Fatal("the injected password appears unobfuscated in the encoded login")
	}
}

// TestLogin7EncodeClearsExtensionFlagWithoutBlock proves the documented
// fallback: the extension flag and the block are dropped together, never one
// without the other (a server told to expect an extension that is not there
// rejects the login).
func TestLogin7EncodeClearsExtensionFlagWithoutBlock(t *testing.T) {
	l := &Login7{TDSVersion: VersionTDS74, OptionFlags3: 0x10}
	out := l.Encode()
	if out[l7OptionFlags3]&0x10 != 0 {
		t.Fatal("fExtension stayed set with no feature block")
	}
}

// TestLogin7RejectsTruncated proves a short or lying LOGIN7 is an error rather
// than a panic — it is the first attacker-controlled structure on the wire.
func TestLogin7RejectsTruncated(t *testing.T) {
	if _, err := ParseLogin7(make([]byte, 20)); err == nil {
		t.Fatal("a LOGIN7 shorter than the fixed portion was accepted")
	}
	raw := buildLogin7(t, "u", "p", "h", "d")
	binary.LittleEndian.PutUint16(raw[l7UserName:], 0xfff0) // offset past the end
	if _, err := ParseLogin7(raw); err == nil {
		t.Fatal("a blob pointing outside the message was accepted")
	}
}

// TestPacketFramingSplitsAndReassembles proves a message larger than the packet
// size is split with EOM only on the last packet and reassembles identically,
// and that the first packet's RESETCONNECTION bit survives re-framing (it is
// how every pooled client issues sp_reset_connection).
func TestPacketFramingSplitsAndReassembles(t *testing.T) {
	var buf bytes.Buffer
	w := NewConn(&buf)
	w.SetPacketSize(512)
	payload := bytes.Repeat([]byte{0xAB}, 1500)
	if err := w.WriteMessage(PacketSQLBatch, StatusResetConnection, payload); err != nil {
		t.Fatal(err)
	}

	// Walk the raw bytes: expect 4 packets (504+504+492 body) with EOM last.
	raw := buf.Bytes()
	var packets, eom int
	for i := 0; i < len(raw); {
		length := int(binary.BigEndian.Uint16(raw[i+2 : i+4]))
		if packets == 0 && raw[i+1]&StatusResetConnection == 0 {
			t.Fatal("RESETCONNECTION was dropped from the first packet")
		}
		if raw[i+1]&StatusEOM != 0 {
			eom++
		}
		packets++
		i += length
	}
	if packets < 3 || eom != 1 {
		t.Fatalf("framing produced %d packets with %d EOM flags", packets, eom)
	}

	typ, status, data, err := NewConn(fakeConn{r: bytes.NewReader(raw), w: io.Discard}).ReadMessage(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	if typ != PacketSQLBatch || status&StatusResetConnection == 0 || !bytes.Equal(data, payload) {
		t.Fatalf("reassembly lost data: typ=%#x status=%#x len=%d", typ, status, len(data))
	}
}

// TestReadMessageBounded proves a peer that streams packets without ever
// setting EOM is cut off at the cap instead of growing the heap without limit.
func TestReadMessageBounded(t *testing.T) {
	var buf bytes.Buffer
	for i := 0; i < 8; i++ {
		var hb [HeaderSize]byte
		hb[0] = PacketSQLBatch
		hb[1] = StatusNormal // never EOM
		binary.BigEndian.PutUint16(hb[2:4], HeaderSize+256)
		buf.Write(hb[:])
		buf.Write(make([]byte, 256))
	}
	if _, _, _, err := NewConn(fakeConn{r: bytes.NewReader(buf.Bytes()), w: io.Discard}).ReadMessage(512); !errors.Is(err, ErrOversize) {
		t.Fatalf("want ErrOversize, got %v", err)
	}
}

// allHeaders builds the 22-byte ALL_HEADERS block clients prefix to a request.
func allHeaders() []byte {
	b := make([]byte, 22)
	binary.LittleEndian.PutUint32(b[0:], 22) // total length
	binary.LittleEndian.PutUint32(b[4:], 18) // header length
	binary.LittleEndian.PutUint16(b[8:], 2)  // type: transaction descriptor
	binary.LittleEndian.PutUint32(b[18:], 1) // outstanding requests
	return b
}

// TestParseSQLBatchWithAndWithoutAllHeaders proves the statement text is
// recovered both with the ALL_HEADERS block and without it (TDS 7.1 and some
// clients omit it), and that non-ASCII text survives the UTF-16 decode.
func TestParseSQLBatchWithAndWithoutAllHeaders(t *testing.T) {
	sql := "SELECT * FROM Ördérs WHERE id = 1 -- ✓"
	withHeaders := append(allHeaders(), stringToUCS2(sql)...)
	req, err := ParseSQLBatch(withHeaders)
	if err != nil || req.SQL != sql {
		t.Fatalf("with ALL_HEADERS: %q err %v", req.SQL, err)
	}
	if req.AuditText != sql {
		t.Fatalf("AuditText = %q", req.AuditText)
	}

	// No ALL_HEADERS: the first DWORD is part of the text, so the implausible
	// total length must be treated as "no headers" rather than an error.
	bare := stringToUCS2("SELECT 1")
	req, err = ParseSQLBatch(bare)
	if err != nil || req.SQL != "SELECT 1" {
		t.Fatalf("without ALL_HEADERS: %q err %v", req.SQL, err)
	}
}

// nvarcharParam builds one RPC parameter carrying NVARCHAR text.
func nvarcharParam(name, value string) []byte {
	b := []byte{byte(len(name))}
	b = append(b, stringToUCS2(name)...)
	b = append(b, 0x00) // StatusFlags
	b = append(b, 0xE7) // NVARCHARTYPE
	var u16 [2]byte
	binary.LittleEndian.PutUint16(u16[:], 8000) // MaxLength
	b = append(b, u16[:]...)
	b = append(b, 0x09, 0x04, 0xd0, 0x00, 0x34) // collation
	v := stringToUCS2(value)
	binary.LittleEndian.PutUint16(u16[:], uint16(len(v)))
	b = append(b, u16[:]...)
	return append(b, v...)
}

// plpParam builds one NVARCHAR(MAX) parameter, the form a long generated
// statement arrives in.
func plpParam(name, value string) []byte {
	b := []byte{byte(len(name))}
	b = append(b, stringToUCS2(name)...)
	b = append(b, 0x00, 0xE7)
	b = append(b, 0xff, 0xff)                   // MaxLength = 0xFFFF: PLP
	b = append(b, 0x09, 0x04, 0xd0, 0x00, 0x34) // collation
	v := stringToUCS2(value)
	var u64 [8]byte
	binary.LittleEndian.PutUint64(u64[:], uint64(len(v)))
	b = append(b, u64[:]...)
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], uint32(len(v)))
	b = append(b, u32[:]...)
	b = append(b, v...)
	return append(b, 0x00, 0x00, 0x00, 0x00) // PLP terminator
}

// TestParseRPCExecuteSQL proves the guard can see the SQL a parameterised
// client actually sends: sp_executesql by ProcID and by name, in both the
// plain and PLP encodings. A proc-name-only implementation would pass the
// first assertion and fail every one that matters.
func TestParseRPCExecuteSQL(t *testing.T) {
	sql := "UPDATE accounts SET balance = @p1 WHERE id = @p2"

	byID := append(allHeaders(), 0xff, 0xff)
	byID = append(byID, byte(ProcExecuteSQL), 0x00, 0x00, 0x00) // ProcID + OptionFlags
	byID = append(byID, nvarcharParam("@stmt", sql)...)
	req, err := ParseRPC(byID)
	if err != nil {
		t.Fatal(err)
	}
	if req.SQL != sql {
		t.Fatalf("by ProcID: SQL = %q, want %q", req.SQL, sql)
	}

	byName := append(allHeaders(), 0x0d, 0x00) // name length in characters
	byName = append(byName, stringToUCS2("sp_executesql")...)
	byName = append(byName, 0x00, 0x00) // OptionFlags
	byName = append(byName, plpParam("@stmt", sql)...)
	req, err = ParseRPC(byName)
	if err != nil {
		t.Fatal(err)
	}
	if req.SQL != sql {
		t.Fatalf("by name (PLP): SQL = %q, want %q", req.SQL, sql)
	}

	// An unknown proc yields a name and no SQL — audited, forwarded, not an error.
	other := append(allHeaders(), 0x07, 0x00)
	other = append(other, stringToUCS2("sp_who2")...)
	other = append(other, 0x00, 0x00)
	req, err = ParseRPC(other)
	if err != nil {
		t.Fatal(err)
	}
	if req.SQL != "" || req.Proc != "sp_who2" || req.AuditText != "[rpc sp_who2]" {
		t.Fatalf("unknown proc: %+v", req)
	}
}

// TestRefusalTokenBytes pins the synthesized refusal to hand-computed bytes for
// both token layouts: TDS 7.2+ (4-byte LineNumber, 8-byte RowCount) and 7.1.
func TestRefusalTokenBytes(t *testing.T) {
	out := Refusal(50000, 16, "no", PacketSQLBatch, true)
	// ERROR: token, length, number(4), state, class, msglen(2), msg, srvlen,
	// srv, proclen, linenumber(4).
	msg, srv := stringToUCS2("no"), stringToUCS2("pamv1")
	bodyLen := 4 + 1 + 1 + 2 + len(msg) + 1 + len(srv) + 1 + 4
	want := []byte{TokenError, byte(bodyLen), 0x00, 0x50, 0xc3, 0x00, 0x00, 0x01, 0x10, 0x02, 0x00}
	want = append(want, msg...)
	want = append(want, byte(len(srv)/2))
	want = append(want, srv...)
	want = append(want, 0x00, 0x00, 0x00, 0x00, 0x00)
	// DONE: token, status(2), curcmd(2), rowcount(8).
	want = append(want, TokenDone, 0x02, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0)
	if !bytes.Equal(out, want) {
		t.Fatalf("refusal bytes\n got % x\nwant % x", out, want)
	}

	// 7.1 narrows LineNumber to 2 bytes and RowCount to 4, and an RPC refusal
	// answers DONEPROC.
	old := Refusal(18456, 14, "no", PacketRPC, false)
	if old[len(old)-13] != TokenDoneProc && old[len(old)-9] != TokenDoneProc {
		t.Fatalf("an RPC refusal did not use DONEPROC: % x", old)
	}
	if len(old) >= len(out) {
		t.Fatalf("the 7.1 layout should be shorter: %d vs %d", len(old), len(out))
	}
}

// TestWalkLoginResponse proves the login-response walk tells success from
// failure, surfaces the server's message, picks up a packet-size ENVCHANGE, and
// stops safely on an unknown token.
func TestWalkLoginResponse(t *testing.T) {
	// LOGINACK (contents irrelevant to the walk) + DONE.
	ack := []byte{TokenLoginAck, 0x04, 0x00, 1, 2, 3, 4}
	ack = append(ack, TokenDone, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	if res := WalkLoginResponse(ack, true); !res.OK {
		t.Fatalf("LOGINACK not recognized: %+v", res)
	}

	// ERROR first: failure, with the message recovered.
	fail := ErrorToken{Number: 18456, State: 1, Class: 14, Message: "Login failed for user 'x'.", ServerName: "sql01"}.Encode(true)
	res := WalkLoginResponse(fail, true)
	if res.OK || res.ServerError != "Login failed for user 'x'." {
		t.Fatalf("login failure not surfaced: %+v", res)
	}

	// ENVCHANGE type 4 (packet size): new value "8192", old value "4096".
	newV, oldV := stringToUCS2("8192"), stringToUCS2("4096")
	body := []byte{envChangePacketSize, byte(len(newV) / 2)}
	body = append(body, newV...)
	body = append(body, byte(len(oldV)/2))
	body = append(body, oldV...)
	env := []byte{TokenEnvChange, byte(len(body)), 0x00}
	env = append(env, body...)
	env = append(env, ack...)
	if res := WalkLoginResponse(env, true); !res.OK || res.PacketSize != 8192 {
		t.Fatalf("packet-size ENVCHANGE missed: %+v", res)
	}

	// An unknown token stops the walk without panicking.
	if res := WalkLoginResponse([]byte{0x42, 0x00, 0x00}, true); res.OK {
		t.Fatal("an unknown token was treated as a successful login")
	}
}

// TestTLSOverTDSHandshake proves the shim: a real TLS handshake completes with
// every record framed inside TDS packets, and application data flows once it
// does. This is the piece with no second chance in an end-to-end test — a
// handshake that hangs looks like a network problem.
func TestTLSOverTDSHandshake(t *testing.T) {
	cert := selfSigned(t)
	cli, srv := net.Pipe()
	t.Cleanup(func() { cli.Close(); srv.Close() })

	type result struct {
		conn net.Conn
		err  error
	}
	serverDone := make(chan result, 1)
	go func() {
		c, err := ServerHandshake(srv, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		serverDone <- result{c, err}
	}()

	clientConn, err := ClientHandshake(cli, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) // #nosec G402 -- a throwaway self-signed cert in a unit test
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	sr := <-serverDone
	if sr.err != nil {
		t.Fatalf("server handshake: %v", sr.err)
	}

	// Application data must cross the now-plain TLS connection.
	go func() {
		_, _ = clientConn.Write([]byte("LOGIN7-would-go-here"))
	}()
	buf := make([]byte, 32)
	_ = sr.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := sr.conn.Read(buf)
	if err != nil {
		t.Fatalf("reading application data: %v", err)
	}
	if string(buf[:n]) != "LOGIN7-would-go-here" {
		t.Fatalf("application data = %q", buf[:n])
	}
}

// TestHandshakeConnRejectsNonPreLoginFraming proves the shim refuses a peer
// that sends TLS records outside PRELOGIN packets rather than mis-parsing them.
func TestHandshakeConnRejectsNonPreLoginFraming(t *testing.T) {
	var hb [HeaderSize]byte
	hb[0] = PacketSQLBatch
	binary.BigEndian.PutUint16(hb[2:4], HeaderSize+1)
	h := newHandshakeConn(fakeConn{r: bytes.NewReader(append(hb[:], 0x00)), w: io.Discard})
	if _, err := h.Read(make([]byte, 8)); err == nil {
		t.Fatal("a non-prelogin packet was accepted during the handshake")
	}
}

// fakeConn adapts a reader/writer pair to net.Conn for the framing tests.
type fakeConn struct {
	r io.Reader
	w io.Writer
}

func (f fakeConn) Read(b []byte) (int, error)         { return f.r.Read(b) }
func (f fakeConn) Write(b []byte) (int, error)        { return f.w.Write(b) }
func (f fakeConn) Close() error                       { return nil }
func (f fakeConn) LocalAddr() net.Addr                { return nil }
func (f fakeConn) RemoteAddr() net.Addr               { return nil }
func (f fakeConn) SetDeadline(t time.Time) error      { return nil }
func (f fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (f fakeConn) SetWriteDeadline(t time.Time) error { return nil }

// selfSigned mints a throwaway certificate for the TLS shim test.
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pamv1-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
