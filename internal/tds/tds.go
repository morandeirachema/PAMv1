// Package tds implements the slice of the Tabular Data Stream protocol —
// Microsoft SQL Server's wire protocol — that a session broker needs.
//
// It is a codec, not a client: it frames packets, parses the handshake
// (PRELOGIN, LOGIN7), extracts the SQL text of a request (SQLBatch and the RPC
// forms every parameterised driver actually uses), and synthesizes the error
// tokens a refusal needs. The PAM semantics — who may connect, which credential
// is injected, what is audited — live in internal/proxy, exactly as they do for
// the PostgreSQL proxy over pgproto3.
//
// Why hand-rolled: the repo takes no new runtime dependencies, and the pieces
// needed here are small and stable (they have not changed since TDS 7.4). The
// risk that buys is a codec that could be self-consistently wrong, so the tests
// assert against byte literals derived from the specification rather than
// round-tripping the encoder against its own parser.
//
// Reference: MS-TDS, https://learn.microsoft.com/openspecs/windows_protocols/ms-tds/
package tds

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf16"
)

// Packet types (the first header byte).
const (
	PacketSQLBatch      byte = 0x01
	PacketRPC           byte = 0x03
	PacketTabularResult byte = 0x04
	PacketAttention     byte = 0x06
	PacketBulkLoad      byte = 0x07
	PacketFedAuthToken  byte = 0x08
	PacketTransMgr      byte = 0x0E
	PacketLogin7        byte = 0x10
	PacketSSPI          byte = 0x11
	PacketPreLogin      byte = 0x12
)

// Packet status bits (the second header byte).
const (
	StatusNormal                  byte = 0x00
	StatusEOM                     byte = 0x01
	StatusIgnore                  byte = 0x02
	StatusResetConnection         byte = 0x08
	StatusResetConnectionSkipTran byte = 0x10
)

// PRELOGIN option tokens.
const (
	PreLoginVersion         byte = 0x00
	PreLoginEncryption      byte = 0x01
	PreLoginInstOpt         byte = 0x02
	PreLoginThreadID        byte = 0x03
	PreLoginMARS            byte = 0x04
	PreLoginTraceID         byte = 0x05
	PreLoginFedAuthRequired byte = 0x06
	PreLoginNonceOpt        byte = 0x07
	PreLoginTerminator      byte = 0xFF
)

// PRELOGIN encryption negotiation values.
const (
	EncryptOff    byte = 0x00 // encrypt the login packet only, then revert to plaintext
	EncryptOn     byte = 0x01 // encrypt the whole session
	EncryptNotSup byte = 0x02 // encryption not supported
	EncryptReq    byte = 0x03 // encryption required
)

// Response token types.
const (
	TokenReturnStatus  byte = 0x79
	TokenError         byte = 0xAA
	TokenInfo          byte = 0xAB
	TokenLoginAck      byte = 0xAD
	TokenFeatureExtAck byte = 0xAE
	TokenEnvChange     byte = 0xE3
	TokenSSPI          byte = 0xED
	TokenDone          byte = 0xFD
	TokenDoneProc      byte = 0xFE
	TokenDoneInProc    byte = 0xFF
)

// DONE status bits.
const (
	DoneFinal byte = 0x00
	DoneMore  byte = 0x01
	DoneError byte = 0x02
)

// ENVCHANGE types this package cares about.
const envChangePacketSize byte = 4

// TDS version numbers. 7.4 is what every currently supported SQL Server speaks;
// the proxy relays the client's own version upstream, so this is only used to
// decide token layouts (LineNumber and RowCount widths changed at 7.2).
const (
	VersionTDS71 uint32 = 0x71000001
	VersionTDS72 uint32 = 0x72090002
	VersionTDS74 uint32 = 0x74000004
)

// HeaderSize is the fixed TDS packet header length.
const HeaderSize = 8

// DefaultPacketSize is the TDS default; a client may negotiate another in
// LOGIN7 and a server may shrink it via ENVCHANGE.
const DefaultPacketSize = 4096

// Well-known stored procedure ids (RPC by ProcID rather than by name). These
// are the ones that carry SQL text as their first parameter — the path every
// parameterised driver takes, and therefore the path per-statement auditing and
// command control must be able to see through.
const (
	ProcCursorOpen     uint16 = 2
	ProcCursorExecute  uint16 = 4
	ProcCursorPrepExec uint16 = 5
	ProcExecuteSQL     uint16 = 10
	ProcPrepare        uint16 = 11
	ProcExecute        uint16 = 12
	ProcPrepExec       uint16 = 13
)

// sqlBearingProcs maps a procedure name (upper case) to whether its first
// NVARCHAR parameter is SQL text.
var sqlBearingProcs = map[string]bool{
	"SP_EXECUTESQL":     true,
	"SP_PREPARE":        true,
	"SP_PREPEXEC":       true,
	"SP_CURSOROPEN":     true,
	"SP_CURSOREXECUTE":  true,
	"SP_CURSORPREPEXEC": true,
}

// sqlBearingProcIDs is the ProcID form of sqlBearingProcs.
var sqlBearingProcIDs = map[uint16]bool{
	ProcCursorOpen: true, ProcCursorExecute: true, ProcCursorPrepExec: true,
	ProcExecuteSQL: true, ProcPrepare: true, ProcPrepExec: true,
}

// ErrOversize reports a message that exceeded the caller's cap before its
// end-of-message packet arrived. Returned rather than grown into, so a peer
// that never sets EOM cannot exhaust memory.
var ErrOversize = errors.New("tds: message exceeds the maximum size")

// Header is one TDS packet header.
type Header struct {
	Type     byte
	Status   byte
	Length   uint16 // total packet length INCLUDING the 8-byte header
	SPID     uint16
	PacketID byte
	Window   byte
}

// EOM reports whether this packet ends its message.
func (h Header) EOM() bool { return h.Status&StatusEOM != 0 }

// Conn frames TDS packets over a byte stream. It is not safe for concurrent
// use by multiple writers; the proxy serializes client-facing writes exactly as
// the PostgreSQL relay does.
type Conn struct {
	rw         io.ReadWriter
	packetSize int
	outID      byte
}

// NewConn wraps rw with the default packet size.
func NewConn(rw io.ReadWriter) *Conn {
	return &Conn{rw: rw, packetSize: DefaultPacketSize}
}

// SetPacketSize adopts a negotiated packet size (LOGIN7's PacketSize, or an
// ENVCHANGE from the server). Values outside the protocol's range are ignored,
// so a malformed negotiation cannot produce packets a peer will reject.
func (c *Conn) SetPacketSize(n int) {
	if n >= 512 && n <= 32767 {
		c.packetSize = n
	}
}

// PacketSize returns the framer's current packet size.
func (c *Conn) PacketSize() int { return c.packetSize }

// ReadPacket reads exactly one packet: its header and payload.
func (c *Conn) ReadPacket() (Header, []byte, error) {
	var hb [HeaderSize]byte
	if _, err := io.ReadFull(c.rw, hb[:]); err != nil {
		return Header{}, nil, err
	}
	h := Header{
		Type:     hb[0],
		Status:   hb[1],
		Length:   binary.BigEndian.Uint16(hb[2:4]),
		SPID:     binary.BigEndian.Uint16(hb[4:6]),
		PacketID: hb[6],
		Window:   hb[7],
	}
	if h.Length < HeaderSize {
		return h, nil, fmt.Errorf("tds: packet length %d is shorter than the header", h.Length)
	}
	payload := make([]byte, int(h.Length)-HeaderSize)
	if _, err := io.ReadFull(c.rw, payload); err != nil {
		return h, nil, err
	}
	return h, payload, nil
}

// ReadMessage reassembles packets until one carries the end-of-message flag,
// returning the message type, the first packet's status (so a caller can
// preserve RESETCONNECTION when re-framing) and the concatenated payload.
// Growth is bounded by max: a peer that never sets EOM is cut off rather than
// allowed to exhaust memory.
func (c *Conn) ReadMessage(max int) (typ byte, status byte, data []byte, err error) {
	first := true
	for {
		h, payload, rerr := c.ReadPacket()
		if rerr != nil {
			return typ, status, nil, rerr
		}
		if first {
			typ, status, first = h.Type, h.Status, false
		}
		if max > 0 && len(data)+len(payload) > max {
			return typ, status, nil, ErrOversize
		}
		data = append(data, payload...)
		if h.EOM() {
			return typ, status, data, nil
		}
	}
}

// WriteMessage writes data as one TDS message of the given type, split across
// as many packets as the negotiated packet size requires. extraStatus carries
// non-EOM status bits (notably RESETCONNECTION, which is how every pooled
// client issues sp_reset_connection — dropping it breaks connection pooling
// silently) and is applied to the first packet.
func (c *Conn) WriteMessage(typ byte, extraStatus byte, data []byte) error {
	body := c.packetSize - HeaderSize
	if body <= 0 {
		body = DefaultPacketSize - HeaderSize
	}
	extraStatus &^= StatusEOM // EOM is decided per packet, never by the caller
	for first := true; first || len(data) > 0; first = false {
		n := len(data)
		if n > body {
			n = body
		}
		chunk := data[:n]
		data = data[n:]
		status := byte(0)
		if first {
			status |= extraStatus
		}
		if len(data) == 0 {
			status |= StatusEOM
		}
		var hb [HeaderSize]byte
		hb[0] = typ
		hb[1] = status
		binary.BigEndian.PutUint16(hb[2:4], uint16(HeaderSize+n))
		binary.BigEndian.PutUint16(hb[4:6], 0)
		hb[6] = c.outID
		hb[7] = 0
		c.outID++
		if _, err := c.rw.Write(append(hb[:], chunk...)); err != nil {
			return err
		}
	}
	return nil
}

// PreLogin is a PRELOGIN option table, preserving the order options appeared in
// so a re-encode looks like what the peer sent.
type PreLogin struct {
	Order   []byte
	Options map[byte][]byte
}

// NewPreLogin returns an empty option table.
func NewPreLogin() *PreLogin {
	return &PreLogin{Options: make(map[byte][]byte)}
}

// Set adds or replaces one option, keeping first-set order.
func (p *PreLogin) Set(token byte, data []byte) {
	if _, seen := p.Options[token]; !seen {
		p.Order = append(p.Order, token)
	}
	p.Options[token] = data
}

// Encryption returns the peer's advertised encryption option, or EncryptNotSup
// when it offered none.
func (p *PreLogin) Encryption() byte {
	if v, ok := p.Options[PreLoginEncryption]; ok && len(v) > 0 {
		return v[0]
	}
	return EncryptNotSup
}

// ParsePreLogin decodes a PRELOGIN payload's option table.
func ParsePreLogin(data []byte) (*PreLogin, error) {
	pl := NewPreLogin()
	for i := 0; ; i += 5 {
		if i >= len(data) {
			return nil, errors.New("tds: prelogin option table is not terminated")
		}
		token := data[i]
		if token == PreLoginTerminator {
			return pl, nil
		}
		if i+5 > len(data) {
			return nil, errors.New("tds: truncated prelogin option entry")
		}
		off := int(binary.BigEndian.Uint16(data[i+1 : i+3]))
		length := int(binary.BigEndian.Uint16(data[i+3 : i+5]))
		if off < 0 || length < 0 || off+length > len(data) {
			return nil, fmt.Errorf("tds: prelogin option %#x points outside the payload", token)
		}
		pl.Set(token, append([]byte(nil), data[off:off+length]...))
	}
}

// Encode renders the option table: every entry, then the terminator, then the
// option data each entry points at.
func (p *PreLogin) Encode() []byte {
	head := len(p.Order)*5 + 1
	out := make([]byte, 0, head+32)
	off := head
	for _, token := range p.Order {
		v := p.Options[token]
		var e [5]byte
		e[0] = token
		binary.BigEndian.PutUint16(e[1:3], uint16(off))
		binary.BigEndian.PutUint16(e[3:5], uint16(len(v)))
		out = append(out, e[:]...)
		off += len(v)
	}
	out = append(out, PreLoginTerminator)
	for _, token := range p.Order {
		out = append(out, p.Options[token]...)
	}
	return out
}

// Login7 is a parsed LOGIN7 message. Strings are decoded from UCS-2; the
// password arrives obfuscated and is stored here in clear so the proxy can
// authenticate the operator with it and substitute the vaulted one.
type Login7 struct {
	TDSVersion     uint32
	PacketSize     uint32
	ClientProgVer  uint32
	ClientPID      uint32
	ConnectionID   uint32
	OptionFlags1   byte
	OptionFlags2   byte
	TypeFlags      byte
	OptionFlags3   byte
	ClientTimeZone int32
	ClientLCID     uint32
	ClientID       [6]byte

	HostName       string
	UserName       string
	Password       string
	AppName        string
	ServerName     string
	CltIntName     string
	Language       string
	Database       string
	AtchDBFile     string
	ChangePassword string

	// SSPI is the integrated-authentication blob. The proxy refuses a login
	// carrying one: brokering means swapping the operator's PAM key for a
	// vaulted SQL login, which Windows authentication cannot express.
	SSPI []byte
	// FeatureExt is the raw feature-extension block (UTF-8 support, column
	// encryption, session recovery...), preserved verbatim so a client's
	// negotiated features still reach the server.
	FeatureExt []byte
}

// IntegratedSecurity reports whether the client asked for Windows/SSPI
// authentication.
func (l *Login7) IntegratedSecurity() bool {
	return l.OptionFlags2&0x80 != 0 || len(l.SSPI) > 0
}

// TDS72OrLater reports whether the client speaks TDS 7.2+, which widens DONE's
// RowCount to 8 bytes and ERROR's LineNumber to 4.
func (l *Login7) TDS72OrLater() bool { return l.TDSVersion >= VersionTDS72 }

// login7 fixed-portion field offsets, from the start of the LOGIN7 structure.
const (
	l7Length         = 0
	l7TDSVersion     = 4
	l7PacketSize     = 8
	l7ClientProgVer  = 12
	l7ClientPID      = 16
	l7ConnectionID   = 20
	l7OptionFlags1   = 24
	l7OptionFlags2   = 25
	l7TypeFlags      = 26
	l7OptionFlags3   = 27
	l7ClientTimeZone = 28
	l7ClientLCID     = 32
	l7HostName       = 36
	l7UserName       = 40
	l7Password       = 44
	l7AppName        = 48
	l7ServerName     = 52
	l7Extension      = 56
	l7CltIntName     = 60
	l7Language       = 64
	l7Database       = 68
	l7ClientID       = 72
	l7SSPI           = 78
	l7AtchDBFile     = 82
	l7ChangePassword = 86
	l7FixedSize      = 94
)

// ParseLogin7 decodes a LOGIN7 payload. Every variable field is read through
// its own offset/length pair rather than assumed to follow the previous one:
// drivers do not agree on the order they lay the blobs out.
func ParseLogin7(data []byte) (*Login7, error) {
	if len(data) < l7FixedSize {
		return nil, fmt.Errorf("tds: login7 is %d bytes, shorter than the %d-byte fixed portion", len(data), l7FixedSize)
	}
	l := &Login7{
		TDSVersion:     binary.LittleEndian.Uint32(data[l7TDSVersion:]),
		PacketSize:     binary.LittleEndian.Uint32(data[l7PacketSize:]),
		ClientProgVer:  binary.LittleEndian.Uint32(data[l7ClientProgVer:]),
		ClientPID:      binary.LittleEndian.Uint32(data[l7ClientPID:]),
		ConnectionID:   binary.LittleEndian.Uint32(data[l7ConnectionID:]),
		OptionFlags1:   data[l7OptionFlags1],
		OptionFlags2:   data[l7OptionFlags2],
		TypeFlags:      data[l7TypeFlags],
		OptionFlags3:   data[l7OptionFlags3],
		ClientTimeZone: int32(binary.LittleEndian.Uint32(data[l7ClientTimeZone:])),
		ClientLCID:     binary.LittleEndian.Uint32(data[l7ClientLCID:]),
	}
	copy(l.ClientID[:], data[l7ClientID:l7ClientID+6])

	str := func(at int) (string, error) {
		b, err := varBytes(data, at, 2)
		if err != nil {
			return "", err
		}
		return ucs2ToString(b), nil
	}
	var err error
	if l.HostName, err = str(l7HostName); err != nil {
		return nil, err
	}
	if l.UserName, err = str(l7UserName); err != nil {
		return nil, err
	}
	pw, err := varBytes(data, l7Password, 2)
	if err != nil {
		return nil, err
	}
	l.Password = ucs2ToString(DeobfuscatePassword(pw))
	if l.AppName, err = str(l7AppName); err != nil {
		return nil, err
	}
	if l.ServerName, err = str(l7ServerName); err != nil {
		return nil, err
	}
	if l.CltIntName, err = str(l7CltIntName); err != nil {
		return nil, err
	}
	if l.Language, err = str(l7Language); err != nil {
		return nil, err
	}
	if l.Database, err = str(l7Database); err != nil {
		return nil, err
	}
	if l.AtchDBFile, err = str(l7AtchDBFile); err != nil {
		return nil, err
	}
	if l.ChangePassword, err = str(l7ChangePassword); err != nil {
		return nil, err
	}
	// SSPI's length field counts BYTES, not characters.
	if l.SSPI, err = varBytes(data, l7SSPI, 1); err != nil {
		return nil, err
	}
	if l.OptionFlags3&0x10 != 0 {
		ext, eerr := parseFeatureExt(data)
		if eerr != nil {
			return nil, eerr
		}
		l.FeatureExt = ext
	}
	return l, nil
}

// varBytes reads one variable-portion blob: its offset/length pair sits at
// entry, and unit is the byte width of one length unit (2 for character counts,
// 1 for byte counts).
func varBytes(data []byte, entry, unit int) ([]byte, error) {
	if entry+4 > len(data) {
		return nil, errors.New("tds: login7 variable entry is out of range")
	}
	off := int(binary.LittleEndian.Uint16(data[entry:]))
	n := int(binary.LittleEndian.Uint16(data[entry+2:])) * unit
	if n == 0 {
		return nil, nil
	}
	if off < 0 || off+n > len(data) {
		return nil, fmt.Errorf("tds: login7 blob at %d points outside the message", entry)
	}
	return append([]byte(nil), data[off:off+n]...), nil
}

// parseFeatureExt follows ibExtension to the DWORD that locates the feature
// block, then reads the block's {FeatureId, DataLen, Data}* entries to its
// 0xFF terminator, returning the raw bytes for verbatim re-emission.
func parseFeatureExt(data []byte) ([]byte, error) {
	ptr, err := varBytes(data, l7Extension, 1)
	if err != nil {
		return nil, err
	}
	if len(ptr) < 4 {
		return nil, nil // flag set with no usable pointer: nothing to preserve
	}
	off := int(binary.LittleEndian.Uint32(ptr))
	if off <= 0 || off > len(data) {
		return nil, nil
	}
	i := off
	for {
		if i >= len(data) {
			return nil, errors.New("tds: feature extension is not terminated")
		}
		if data[i] == 0xFF {
			i++
			return append([]byte(nil), data[off:i]...), nil
		}
		if i+5 > len(data) {
			return nil, errors.New("tds: truncated feature extension entry")
		}
		n := int(binary.LittleEndian.Uint32(data[i+1:]))
		if n < 0 || i+5+n > len(data) {
			return nil, errors.New("tds: feature extension entry runs past the message")
		}
		i += 5 + n
	}
}

// Encode renders the LOGIN7 message. It always re-encodes from the parsed
// struct rather than patching bytes in place: replacing the username and
// password shifts every following blob, and an in-place patch is how you get a
// login that works for one credential length and corrupts for another.
func (l *Login7) Encode() []byte {
	fixed := make([]byte, l7FixedSize)
	binary.LittleEndian.PutUint32(fixed[l7TDSVersion:], l.TDSVersion)
	binary.LittleEndian.PutUint32(fixed[l7PacketSize:], l.PacketSize)
	binary.LittleEndian.PutUint32(fixed[l7ClientProgVer:], l.ClientProgVer)
	binary.LittleEndian.PutUint32(fixed[l7ClientPID:], l.ClientPID)
	binary.LittleEndian.PutUint32(fixed[l7ConnectionID:], l.ConnectionID)
	fixed[l7OptionFlags1] = l.OptionFlags1
	fixed[l7OptionFlags2] = l.OptionFlags2
	fixed[l7TypeFlags] = l.TypeFlags
	fixed[l7OptionFlags3] = l.OptionFlags3
	binary.LittleEndian.PutUint32(fixed[l7ClientTimeZone:], uint32(l.ClientTimeZone))
	binary.LittleEndian.PutUint32(fixed[l7ClientLCID:], l.ClientLCID)
	copy(fixed[l7ClientID:], l.ClientID[:])

	var body []byte
	// put writes one blob and its offset/length entry. chars reports whether the
	// length field counts UCS-2 characters (all the strings) or bytes (SSPI).
	put := func(entry int, b []byte, chars bool) {
		off := l7FixedSize + len(body)
		n := len(b)
		if chars {
			n /= 2
		}
		if len(b) == 0 {
			// A zero-length blob still needs a plausible offset: point it at the
			// current end of the message, which is what drivers do.
			binary.LittleEndian.PutUint16(fixed[entry:], uint16(off))
			binary.LittleEndian.PutUint16(fixed[entry+2:], 0)
			return
		}
		binary.LittleEndian.PutUint16(fixed[entry:], uint16(off))
		binary.LittleEndian.PutUint16(fixed[entry+2:], uint16(n))
		body = append(body, b...)
	}

	put(l7HostName, stringToUCS2(l.HostName), true)
	put(l7UserName, stringToUCS2(l.UserName), true)
	put(l7Password, ObfuscatePassword(stringToUCS2(l.Password)), true)
	put(l7AppName, stringToUCS2(l.AppName), true)
	put(l7ServerName, stringToUCS2(l.ServerName), true)
	put(l7CltIntName, stringToUCS2(l.CltIntName), true)
	put(l7Language, stringToUCS2(l.Language), true)
	put(l7Database, stringToUCS2(l.Database), true)
	put(l7AtchDBFile, stringToUCS2(l.AtchDBFile), true)
	put(l7ChangePassword, stringToUCS2(l.ChangePassword), true)
	put(l7SSPI, l.SSPI, false)

	if len(l.FeatureExt) > 0 && l.OptionFlags3&0x10 != 0 {
		// The extension entry points at a 4-byte value holding the offset of the
		// feature block itself, so the pointer is written first and patched once
		// the block's position is known.
		ptrOff := l7FixedSize + len(body)
		binary.LittleEndian.PutUint16(fixed[l7Extension:], uint16(ptrOff))
		binary.LittleEndian.PutUint16(fixed[l7Extension+2:], 4)
		body = append(body, 0, 0, 0, 0)
		blockOff := l7FixedSize + len(body)
		binary.LittleEndian.PutUint32(body[len(body)-4:], uint32(blockOff))
		body = append(body, l.FeatureExt...)
	} else {
		// No preserved block: clear the flag as well, so a server is never told
		// to expect an extension that is not there.
		fixed[l7OptionFlags3] &^= 0x10
		binary.LittleEndian.PutUint16(fixed[l7Extension:], 0)
		binary.LittleEndian.PutUint16(fixed[l7Extension+2:], 0)
	}

	out := append(fixed, body...)
	binary.LittleEndian.PutUint32(out[l7Length:], uint32(len(out)))
	return out
}

// ObfuscatePassword applies TDS's password transform to UCS-2 bytes: swap the
// nibbles of each byte, then XOR with 0xA5. This is obfuscation, not
// encryption — there is no key — which is exactly why the proxy insists on TLS
// on the leg that carries the vaulted credential.
func ObfuscatePassword(ucs2 []byte) []byte {
	out := make([]byte, len(ucs2))
	for i, b := range ucs2 {
		out[i] = ((b >> 4) | (b << 4)) ^ 0xA5
	}
	return out
}

// DeobfuscatePassword reverses ObfuscatePassword (XOR first, then swap — the
// nibble swap is its own inverse).
func DeobfuscatePassword(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		x := c ^ 0xA5
		out[i] = (x >> 4) | (x << 4)
	}
	return out
}

// ucs2ToString decodes UTF-16LE bytes. An odd trailing byte is ignored rather
// than treated as an error: it can only come from a malformed peer, and the
// caller's authorization gates are a better place to refuse one.
func ucs2ToString(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, binary.LittleEndian.Uint16(b[i:]))
	}
	return string(utf16.Decode(u))
}

// stringToUCS2 encodes s as UTF-16LE.
func stringToUCS2(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, r := range u {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}

// Request is a client request the proxy inspects: its SQL text where one is
// recoverable, plus enough context for the audit trail.
type Request struct {
	// SQL is the statement text, empty when it could not be recovered.
	SQL string
	// Proc names the stored procedure for an RPC (or "#<id>" for a ProcID call).
	Proc string
	// AuditText is what the audit trail should record — the SQL when there is
	// one, else a bracketed description, so an unparseable call still leaves a
	// per-statement trail instead of silently escaping it.
	AuditText string
}

// ParseSQLBatch extracts the statement text from a SQLBatch payload: an
// ALL_HEADERS block followed by UCS-2 text running to the end of the message.
func ParseSQLBatch(data []byte) (Request, error) {
	body, err := skipAllHeaders(data)
	if err != nil {
		return Request{}, err
	}
	sql := ucs2ToString(body)
	return Request{SQL: sql, AuditText: sql}, nil
}

// ParseRPC extracts what an RPC request is asking for: the procedure name (or
// id) and, for the procedures that carry SQL as their first NVARCHAR parameter,
// that statement text — the path every parameterised driver takes, so command
// control and per-statement auditing must be able to see through it.
//
// A call whose text cannot be recovered is NOT an error: it is reported with an
// AuditText description and forwarded, mirroring how the PostgreSQL proxy
// audits a fast-path function call it cannot filter. Failing closed on every
// unrecognised RPC would break ordinary clients.
func ParseRPC(data []byte) (Request, error) {
	body, err := skipAllHeaders(data)
	if err != nil {
		return Request{}, err
	}
	if len(body) < 2 {
		return Request{}, errors.New("tds: truncated rpc request")
	}
	nameLen := binary.LittleEndian.Uint16(body)
	var (
		proc     string
		procID   uint16
		byProcID bool
		i        int
	)
	if nameLen == 0xFFFF {
		if len(body) < 4 {
			return Request{}, errors.New("tds: truncated rpc procid")
		}
		procID = binary.LittleEndian.Uint16(body[2:])
		byProcID = true
		proc = fmt.Sprintf("#%d", procID)
		i = 4
	} else {
		n := int(nameLen) * 2
		if 2+n > len(body) {
			return Request{}, errors.New("tds: rpc name runs past the message")
		}
		proc = ucs2ToString(body[2 : 2+n])
		i = 2 + n
	}
	req := Request{Proc: proc, AuditText: "[rpc " + proc + "]"}
	if i+2 > len(body) {
		return req, nil // no option flags: nothing more to read, still auditable
	}
	i += 2 // OptionFlags

	carriesSQL := (byProcID && sqlBearingProcIDs[procID]) || (!byProcID && sqlBearingProcs[upper(proc)])
	if !carriesSQL {
		return req, nil
	}
	if sql, ok := firstNVarCharParam(body[i:]); ok && sql != "" {
		req.SQL = sql
		req.AuditText = sql
	}
	return req, nil
}

// firstNVarCharParam decodes the FIRST parameter of an RPC call and returns its
// text when it is an NVARCHAR — which is where every SQL-bearing procedure
// (sp_executesql and friends) carries its statement. Only that one type is
// decoded; anything else reports "not recovered", which degrades the call to
// proc-name-only auditing rather than breaking the session.
//
// Deliberately not a loop over parameters: the statement is always the first
// one, and scanning further would mean decoding arbitrary TYPE_INFO shapes to
// find parameter boundaries — much more surface for no more coverage.
func firstNVarCharParam(b []byte) (string, bool) {
	i := 0
	if i >= len(b) {
		return "", false
	}
	nameLen := int(b[i])
	i++
	i += nameLen * 2 // parameter name (UCS-2)
	if i+1 >= len(b) {
		return "", false
	}
	i++ // StatusFlags
	typeID := b[i]
	i++
	if typeID != 0xE7 { // NVARCHARTYPE — the only type we decode
		return "", false
	}
	if i+7 > len(b) {
		return "", false
	}
	maxLen := binary.LittleEndian.Uint16(b[i:])
	i += 2
	i += 5 // collation
	if maxLen == 0xFFFF {
		return plpString(b[i:])
	}
	if i+2 > len(b) {
		return "", false
	}
	n := int(binary.LittleEndian.Uint16(b[i:]))
	i += 2
	if n == 0xFFFF { // NULL
		return "", false
	}
	if i+n > len(b) {
		return "", false
	}
	return ucs2ToString(b[i : i+n]), true
}

// plpString decodes a partially-length-prefixed value: an 8-byte total length
// (or the "unknown" sentinel), then 4-byte-prefixed chunks to a zero-length
// terminator. This is how a statement longer than 8000 bytes — a big generated
// query, exactly the kind worth auditing — arrives.
func plpString(b []byte) (string, bool) {
	if len(b) < 8 {
		return "", false
	}
	i := 8 // total length (or 0xFFFFFFFFFFFFFFFE = unknown); chunks are authoritative
	var out []byte
	for {
		if i+4 > len(b) {
			return "", false
		}
		n := int(binary.LittleEndian.Uint32(b[i:]))
		i += 4
		if n == 0 {
			return ucs2ToString(out), true
		}
		if i+n > len(b) {
			return "", false
		}
		out = append(out, b[i:i+n]...)
		i += n
	}
}

// skipAllHeaders steps over the ALL_HEADERS block that precedes a SQLBatch or
// RPC body. The block is absent on TDS 7.1 and from some clients, so an
// implausible total length is treated as "no headers" rather than an error.
func skipAllHeaders(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, errors.New("tds: request payload is too short")
	}
	total := int(binary.LittleEndian.Uint32(data))
	if total >= 4 && total <= len(data) {
		return data[total:], nil
	}
	return data, nil
}

// upper upper-cases an ASCII procedure name without allocating through
// strings.ToUpper's Unicode path.
func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}

// ErrorToken is a server ERROR (0xAA) token.
type ErrorToken struct {
	Number     uint32
	State      byte
	Class      byte // severity; >= 11 makes a client raise an error
	Message    string
	ServerName string
	ProcName   string
	LineNumber uint32
}

// Encode renders the ERROR token. tds72 selects the 4-byte LineNumber of TDS
// 7.2+ over 7.1's 2-byte field.
func (e ErrorToken) Encode(tds72 bool) []byte {
	msg := stringToUCS2(e.Message)
	srv := stringToUCS2(e.ServerName)
	proc := stringToUCS2(e.ProcName)

	body := make([]byte, 0, 16+len(msg)+len(srv)+len(proc))
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], e.Number)
	body = append(body, u32[:]...)
	body = append(body, e.State, e.Class)
	var u16 [2]byte
	binary.LittleEndian.PutUint16(u16[:], uint16(len(msg)/2))
	body = append(body, u16[:]...)
	body = append(body, msg...)
	body = append(body, byte(len(srv)/2))
	body = append(body, srv...)
	body = append(body, byte(len(proc)/2))
	body = append(body, proc...)
	if tds72 {
		binary.LittleEndian.PutUint32(u32[:], e.LineNumber)
		body = append(body, u32[:]...)
	} else {
		binary.LittleEndian.PutUint16(u16[:], uint16(e.LineNumber))
		body = append(body, u16[:]...)
	}

	out := make([]byte, 0, 3+len(body))
	out = append(out, TokenError)
	binary.LittleEndian.PutUint16(u16[:], uint16(len(body)))
	out = append(out, u16[:]...)
	return append(out, body...)
}

// DoneToken is a DONE/DONEPROC/DONEINPROC token.
type DoneToken struct {
	Token    byte
	Status   uint16
	CurCmd   uint16
	RowCount uint64
}

// Encode renders the DONE token; tds72 selects the 8-byte RowCount of TDS 7.2+.
func (d DoneToken) Encode(tds72 bool) []byte {
	token := d.Token
	if token == 0 {
		token = TokenDone
	}
	out := make([]byte, 0, 13)
	out = append(out, token)
	var u16 [2]byte
	binary.LittleEndian.PutUint16(u16[:], d.Status)
	out = append(out, u16[:]...)
	binary.LittleEndian.PutUint16(u16[:], d.CurCmd)
	out = append(out, u16[:]...)
	if tds72 {
		var u64 [8]byte
		binary.LittleEndian.PutUint64(u64[:], d.RowCount)
		return append(out, u64[:]...)
	}
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], uint32(d.RowCount))
	return append(out, u32[:]...)
}

// Refusal builds the response body for a request the proxy refuses: an ERROR
// token followed by a DONE with the error bit set and MORE clear, so the client
// reports the message and stops waiting for results. reqType selects DONEPROC
// for a refused RPC and DONE for a refused batch.
//
// The refused request is never forwarded, so the upstream connection cannot
// desync — and with MARS disabled there is no pipelining either, which is why
// a refusal always leaves the session usable (there is no TDS analogue of the
// PostgreSQL extended-protocol fail-closed branch).
func Refusal(number uint32, class byte, message string, reqType byte, tds72 bool) []byte {
	e := ErrorToken{Number: number, State: 1, Class: class, Message: message, ServerName: "pamv1"}
	done := DoneToken{Token: TokenDone, Status: uint16(DoneError)}
	if reqType == PacketRPC {
		done.Token = TokenDoneProc
	}
	return append(e.Encode(tds72), done.Encode(tds72)...)
}

// LoginResult summarizes the upstream's response to a LOGIN7.
type LoginResult struct {
	OK bool
	// ServerError is the upstream's own message when the login failed. It is
	// logged and audited but never relayed to the operator verbatim, matching
	// how the PostgreSQL proxy treats upstream dial errors.
	ServerError string
	// PacketSize is a server-imposed packet size from ENVCHANGE type 4, or 0.
	PacketSize int
}

// WalkLoginResponse inspects a login response token stream far enough to tell
// success from failure and to notice a packet-size change. It deliberately does
// not parse everything: the message is relayed to the client verbatim, so
// LOGINACK, collation and database ENVCHANGEs all arrive intact.
func WalkLoginResponse(data []byte, tds72 bool) LoginResult {
	res := LoginResult{}
	i := 0
	for i < len(data) {
		token := data[i]
		i++
		switch token {
		case TokenError, TokenInfo, TokenLoginAck, TokenEnvChange, TokenSSPI, TokenFeatureExtAck:
			if token == TokenFeatureExtAck {
				// Feature acks are a feature list terminated by 0xFF, not a
				// length-prefixed block.
				for i < len(data) && data[i] != 0xFF {
					if i+5 > len(data) {
						return res
					}
					n := int(binary.LittleEndian.Uint32(data[i+1:]))
					if n < 0 || i+5+n > len(data) {
						return res
					}
					i += 5 + n
				}
				i++ // the 0xFF terminator
				continue
			}
			if i+2 > len(data) {
				return res
			}
			n := int(binary.LittleEndian.Uint16(data[i:]))
			i += 2
			if i+n > len(data) {
				return res
			}
			body := data[i : i+n]
			i += n
			switch token {
			case TokenError:
				if !res.OK && res.ServerError == "" {
					res.ServerError = errorTokenMessage(body)
				}
			case TokenLoginAck:
				res.OK = true
			case TokenEnvChange:
				if len(body) > 0 && body[0] == envChangePacketSize {
					if n, ok := envChangeNewValue(body); ok {
						res.PacketSize = n
					}
				}
			}
		case TokenReturnStatus:
			i += 4
		case TokenDone, TokenDoneProc, TokenDoneInProc:
			if tds72 {
				i += 12
			} else {
				i += 8
			}
		default:
			// An unknown token means the walk can no longer be trusted; stop and
			// let the caller fall back to "the first token was not an error".
			return res
		}
	}
	return res
}

// errorTokenMessage pulls the human-readable text out of an ERROR token body.
func errorTokenMessage(body []byte) string {
	// Number(4) State(1) Class(1) then a US_VARCHAR message.
	if len(body) < 8 {
		return ""
	}
	n := int(binary.LittleEndian.Uint16(body[6:])) * 2
	if 8+n > len(body) {
		return ""
	}
	return ucs2ToString(body[8 : 8+n])
}

// envChangeNewValue reads the new value of an ENVCHANGE whose payload is
// B_VARCHAR new-value followed by B_VARCHAR old-value, as an integer.
func envChangeNewValue(body []byte) (int, bool) {
	if len(body) < 2 {
		return 0, false
	}
	n := int(body[1]) * 2
	if 2+n > len(body) {
		return 0, false
	}
	s := ucs2ToString(body[2 : 2+n])
	v := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v*10 + int(c-'0')
	}
	if v == 0 {
		return 0, false
	}
	return v, true
}
