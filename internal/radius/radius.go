// Package radius is a minimal RADIUS authentication client (RFC 2865) for the
// portal login: PAMv1 as the NAS asking a RADIUS server whether a username and
// password (or a one-time code) are good. It speaks PAP only — the User-Password
// attribute hidden the way the RFC prescribes — and understands the three
// answers a server gives: Access-Accept, Access-Reject and Access-Challenge
// (the server wants a second value, typically an OTP, and hands back a State
// the client must echo). It is the sixth hand-rolled protocol client in this
// codebase, kept to the parts an authenticator needs; there is no accounting,
// no EAP and no vendor attribute parsing beyond Class and Reply-Message.
//
// What the client verifies: every response carries a Response Authenticator,
// MD5 over the response with the request's own random authenticator and the
// shared secret mixed in; a response whose authenticator does not match is
// discarded as if it never arrived. That is what stops a party on the path
// from answering "accept" for a server it is not. Transport is UDP with a
// bounded number of retransmissions of the SAME identifier, as RFC 2865 §2.4
// asks, so a server that de-duplicates sees one request.
package radius

import (
	"context"
	"crypto/md5" // #nosec G501 -- RFC 2865 mandates MD5 for the authenticator and password hiding; there is no alternative in the protocol
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// Packet codes (RFC 2865 §3).
const (
	codeAccessRequest   = 1
	codeAccessAccept    = 2
	codeAccessReject    = 3
	codeAccessChallenge = 11
)

// Attribute types used here (RFC 2865 §5).
const (
	attrUserName      = 1
	attrUserPassword  = 2
	attrReplyMessage  = 18
	attrState         = 24
	attrClass         = 25
	attrNASIdentifier = 32
)

// Outcome is the server's answer.
type Outcome int

const (
	// Reject: the credentials were refused.
	Reject Outcome = iota
	// Accept: authenticated.
	Accept
	// Challenge: the server wants a further value (an OTP); resend with the
	// returned State and the user's answer as the password.
	Challenge
)

// Result is a decoded server answer.
type Result struct {
	Outcome Outcome
	// State is the opaque value to echo on the next request after a Challenge.
	State []byte
	// ReplyMessage is the human-readable text the server attached, if any
	// (the prompt for a challenge, a reason for a reject).
	ReplyMessage string
	// Class holds every Class attribute value on an Accept — what a server
	// uses to hand back a group or role name.
	Class []string
}

// ErrTimeout is returned when no valid response arrived within the retries.
var ErrTimeout = errors.New("radius: no response from server")

// Client talks to one RADIUS server.
type Client struct {
	// Addr is the server's host:port (1812 is the standard authentication port).
	Addr string
	// Secret is the shared secret both sides hold.
	Secret []byte
	// NASIdentifier is sent as NAS-Identifier so the server can tell PAMv1's
	// requests apart in its own logs and policy.
	NASIdentifier string
	// Timeout bounds one attempt (default 5s); Retries is how many further
	// attempts follow a silent one (default 2).
	Timeout time.Duration
	Retries int
	// dial is overridable for tests.
	dial func(ctx context.Context, addr string) (net.Conn, error)
}

// Authenticate sends one Access-Request for username with password (or an OTP
// answering a Challenge, in which case state is the State the server returned).
// It returns the decoded answer, or an error for a transport failure or a
// response that failed verification.
func (c *Client) Authenticate(ctx context.Context, username, password string, state []byte) (Result, error) {
	if c.Addr == "" || len(c.Secret) == 0 {
		return Result{}, errors.New("radius: server address and shared secret are required")
	}
	if len(username) == 0 || len(username) > 253 || len(password) == 0 || len(password) > 128 {
		return Result{}, errors.New("radius: username must be 1–253 bytes and password 1–128 bytes")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	retries := c.Retries
	if retries < 0 {
		retries = 0
	}
	if c.Retries == 0 {
		retries = 2
	}
	dial := c.dial
	if dial == nil {
		dial = func(ctx context.Context, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", addr)
		}
	}

	var id [1]byte
	var auth [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return Result{}, err
	}
	if _, err := rand.Read(auth[:]); err != nil {
		return Result{}, err
	}
	req := c.encodeRequest(id[0], auth, username, password, state)

	conn, err := dial(ctx, c.Addr)
	if err != nil {
		return Result{}, fmt.Errorf("radius: dial %s: %w", c.Addr, err)
	}
	defer conn.Close()

	buf := make([]byte, 4096)
	for attempt := 0; attempt <= retries; attempt++ {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		if _, err := conn.Write(req); err != nil {
			return Result{}, fmt.Errorf("radius: send: %w", err)
		}
		deadline := time.Now().Add(timeout)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		for time.Now().Before(deadline) {
			_ = conn.SetReadDeadline(deadline)
			n, err := conn.Read(buf)
			if err != nil {
				break // timed out or transport error: retransmit
			}
			res, ok := c.decodeResponse(buf[:n], id[0], auth)
			if ok {
				return res, nil
			}
			// A response that is not ours or fails verification is ignored,
			// not fatal: the real answer may still be on its way.
		}
	}
	return Result{}, ErrTimeout
}

// encodeRequest builds an Access-Request: header, User-Name, the hidden
// User-Password, NAS-Identifier and, when continuing a challenge, State.
func (c *Client) encodeRequest(id byte, auth [16]byte, username, password string, state []byte) []byte {
	pkt := make([]byte, 20, 20+len(username)+130+len(state)+len(c.NASIdentifier)+8)
	pkt[0] = codeAccessRequest
	pkt[1] = id
	copy(pkt[4:20], auth[:])
	pkt = appendAttr(pkt, attrUserName, []byte(username))
	pkt = appendAttr(pkt, attrUserPassword, hidePassword([]byte(password), c.Secret, auth))
	if c.NASIdentifier != "" {
		pkt = appendAttr(pkt, attrNASIdentifier, []byte(c.NASIdentifier))
	}
	if len(state) > 0 {
		pkt = appendAttr(pkt, attrState, state)
	}
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt))) // #nosec G115 -- bounded by the attribute limits above, far below 65535
	return pkt
}

// appendAttr appends one type-length-value attribute; a value longer than the
// 253-byte attribute limit is split across several, as RFC 2865 §5 allows.
func appendAttr(pkt []byte, typ byte, value []byte) []byte {
	for len(value) > 253 {
		pkt = append(pkt, typ, 255)
		pkt = append(pkt, value[:253]...)
		value = value[253:]
	}
	pkt = append(pkt, typ, byte(2+len(value)))
	return append(pkt, value...)
}

// hidePassword applies RFC 2865 §5.2: the password, padded to a multiple of
// 16, is XORed block by block with MD5(secret + previous block), the first
// "previous block" being the Request Authenticator.
func hidePassword(password, secret []byte, auth [16]byte) []byte {
	padded := make([]byte, (len(password)+15)/16*16)
	copy(padded, password)
	out := make([]byte, len(padded))
	prev := auth[:]
	for i := 0; i < len(padded); i += 16 {
		h := md5.New() // #nosec G401 -- see package doc: the RFC's scheme
		h.Write(secret)
		h.Write(prev)
		block := h.Sum(nil)
		for j := 0; j < 16; j++ {
			out[i+j] = padded[i+j] ^ block[j]
		}
		prev = out[i : i+16]
	}
	return out
}

// decodeResponse checks a datagram is the reply to our request (same
// identifier, valid Response Authenticator under the shared secret) and
// decodes its outcome and attributes. ok is false for anything else.
func (c *Client) decodeResponse(pkt []byte, id byte, reqAuth [16]byte) (Result, bool) {
	if len(pkt) < 20 || pkt[1] != id {
		return Result{}, false
	}
	length := int(binary.BigEndian.Uint16(pkt[2:4]))
	if length < 20 || length > len(pkt) {
		return Result{}, false
	}
	pkt = pkt[:length]
	// Response Authenticator = MD5(Code+ID+Length+RequestAuth+Attributes+Secret).
	h := md5.New() // #nosec G401 -- RFC 2865 §3
	h.Write(pkt[:4])
	h.Write(reqAuth[:])
	h.Write(pkt[20:])
	h.Write(c.Secret)
	if subtle.ConstantTimeCompare(h.Sum(nil), pkt[4:20]) != 1 {
		return Result{}, false
	}
	var res Result
	switch pkt[0] {
	case codeAccessAccept:
		res.Outcome = Accept
	case codeAccessReject:
		res.Outcome = Reject
	case codeAccessChallenge:
		res.Outcome = Challenge
	default:
		return Result{}, false
	}
	attrs := pkt[20:]
	for len(attrs) >= 2 {
		typ, l := attrs[0], int(attrs[1])
		if l < 2 || l > len(attrs) {
			return Result{}, false
		}
		val := attrs[2:l]
		switch typ {
		case attrState:
			res.State = append(res.State, val...)
		case attrReplyMessage:
			res.ReplyMessage += string(val)
		case attrClass:
			res.Class = append(res.Class, string(val))
		}
		attrs = attrs[l:]
	}
	return res, true
}
