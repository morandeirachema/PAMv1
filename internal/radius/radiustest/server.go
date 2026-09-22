// Package radiustest is an in-process RADIUS server for tests: it verifies an
// Access-Request the way a real server does (recovers the PAP password under
// the shared secret), applies a scripted Policy, and signs its answer with the
// Response Authenticator. The client and the login paths built on it are
// proven against the protocol rather than against a mock of themselves.
package radiustest

import (
	"crypto/md5" // #nosec G501 -- the protocol's own primitive (RFC 2865)
	"encoding/binary"
	"net"
	"strings"
	"sync/atomic"
	"testing"
)

// Packet codes and attribute types (RFC 2865).
const (
	CodeAccessRequest   = 1
	CodeAccessAccept    = 2
	CodeAccessReject    = 3
	CodeAccessChallenge = 11

	AttrUserName     = 1
	AttrUserPassword = 2
	AttrReplyMessage = 18
	AttrState        = 24
	AttrClass        = 25
)

// Attr is one attribute of a scripted answer.
type Attr struct {
	Type  byte
	Value string
}

// Policy decides the answer from the recovered username, password and State.
type Policy func(user, pass string, state []byte) (code byte, attrs []Attr)

// Server is the fake.
type Server struct {
	conn     *net.UDPConn
	secret   []byte
	policy   Policy
	Requests atomic.Int32
	// Drop silently ignores that many requests first (retransmission tests).
	Drop atomic.Int32
	// BadSecret signs answers with the wrong secret (verification tests).
	BadSecret atomic.Bool
}

// New binds a loopback UDP port; Start begins serving. Two steps so a test can
// set Drop/BadSecret before the goroutine reads them.
func New(t testing.TB, secret string, policy Policy) *Server {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{conn: pc, secret: []byte(secret), policy: policy}
	t.Cleanup(func() { pc.Close() })
	return s
}

// Start begins serving and returns the server for chaining.
func (s *Server) Start() *Server { go s.serve(); return s }

// Addr is the host:port to point a client at.
func (s *Server) Addr() string { return s.conn.LocalAddr().String() }

func (s *Server) serve() {
	buf := make([]byte, 4096)
	for {
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		s.Requests.Add(1)
		if s.Drop.Load() > 0 {
			s.Drop.Add(-1)
			continue
		}
		req := append([]byte(nil), buf[:n]...)
		if len(req) < 20 || req[0] != CodeAccessRequest {
			continue
		}
		var reqAuth [16]byte
		copy(reqAuth[:], req[4:20])
		var user, hidden string
		var state []byte
		attrs := req[20:]
		for len(attrs) >= 2 {
			l := int(attrs[1])
			if l < 2 || l > len(attrs) {
				break
			}
			switch attrs[0] {
			case AttrUserName:
				user = string(attrs[2:l])
			case AttrUserPassword:
				hidden = string(attrs[2:l])
			case AttrState:
				state = append(state, attrs[2:l]...)
			}
			attrs = attrs[l:]
		}
		pass := strings.TrimRight(string(Unhide([]byte(hidden), s.secret, reqAuth)), "\x00")
		code, out := s.policy(user, pass, state)
		resp := make([]byte, 20)
		resp[0], resp[1] = code, req[1]
		for _, a := range out {
			resp = append(resp, a.Type, byte(2+len(a.Value)))
			resp = append(resp, a.Value...)
		}
		binary.BigEndian.PutUint16(resp[2:4], uint16(len(resp))) // #nosec G115 -- test answers are small
		secret := s.secret
		if s.BadSecret.Load() {
			secret = []byte("wrong")
		}
		h := md5.New() // #nosec G401 -- RFC 2865 §3 Response Authenticator
		h.Write(resp[:4])
		h.Write(reqAuth[:])
		h.Write(resp[20:])
		h.Write(secret)
		copy(resp[4:20], h.Sum(nil))
		_, _ = s.conn.WriteToUDP(resp, from)
	}
}

// Unhide inverts RFC 2865 §5.2 password hiding: each 16-byte block is XORed
// with MD5(secret + previous HIDDEN block), the first "previous" being the
// Request Authenticator.
func Unhide(hidden, secret []byte, auth [16]byte) []byte {
	out := make([]byte, len(hidden))
	prev := auth[:]
	for i := 0; i+16 <= len(hidden); i += 16 {
		h := md5.New() // #nosec G401
		h.Write(secret)
		h.Write(prev)
		block := h.Sum(nil)
		for j := 0; j < 16; j++ {
			out[i+j] = hidden[i+j] ^ block[j]
		}
		prev = hidden[i : i+16]
	}
	return out
}
