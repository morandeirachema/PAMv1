package radius

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/radius/radiustest"
)

func TestHidePasswordRoundTrip(t *testing.T) {
	var auth [16]byte
	copy(auth[:], "0123456789abcdef")
	for _, pw := range []string{"a", "sixteen-bytes!!!", "a rather longer password that spans three blocks"} {
		h := hidePassword([]byte(pw), []byte("s3cret"), auth)
		if len(h)%16 != 0 {
			t.Fatalf("hidden length %d not a multiple of 16", len(h))
		}
		got := strings.TrimRight(string(radiustest.Unhide(h, []byte("s3cret"), auth)), "\x00")
		if got != pw {
			t.Fatalf("round trip: %q → %q", pw, got)
		}
	}
}

func policyFor(t *testing.T) radiustest.Policy {
	return func(user, pass string, state []byte) (byte, []radiustest.Attr) {
		switch {
		case user == "alice" && pass == "correct horse":
			return radiustest.CodeAccessAccept, []radiustest.Attr{{Type: radiustest.AttrClass, Value: "pam-admins"}, {Type: radiustest.AttrClass, Value: "vpn-users"}}
		case user == "bob" && pass == "pw" && len(state) == 0:
			return radiustest.CodeAccessChallenge, []radiustest.Attr{{Type: radiustest.AttrState, Value: "chal-42"}, {Type: radiustest.AttrReplyMessage, Value: "Enter your token"}}
		case user == "bob" && pass == "123456" && string(state) == "chal-42":
			return radiustest.CodeAccessAccept, nil
		}
		return radiustest.CodeAccessReject, []radiustest.Attr{{Type: radiustest.AttrReplyMessage, Value: "denied"}}
	}
}

func TestAuthenticateAcceptRejectChallenge(t *testing.T) {
	// The fake recovers the password with the real inverse, so the test's
	// policy sees plaintext only if the client hid it correctly.
	srv := radiustest.New(t, "s3cret", policyFor(t)).Start()
	c := &Client{Addr: srv.Addr(), Secret: []byte("s3cret"), NASIdentifier: "pamv1", Timeout: time.Second}
	ctx := context.Background()

	res, err := c.Authenticate(ctx, "alice", "correct horse", nil)
	if err != nil || res.Outcome != Accept || len(res.Class) != 2 || res.Class[0] != "pam-admins" {
		t.Fatalf("accept: %+v err %v", res, err)
	}
	res, err = c.Authenticate(ctx, "alice", "wrong", nil)
	if err != nil || res.Outcome != Reject || res.ReplyMessage != "denied" {
		t.Fatalf("reject: %+v err %v", res, err)
	}
	// Challenge round trip: the State comes back and the OTP completes it.
	res, err = c.Authenticate(ctx, "bob", "pw", nil)
	if err != nil || res.Outcome != Challenge || string(res.State) != "chal-42" || res.ReplyMessage != "Enter your token" {
		t.Fatalf("challenge: %+v err %v", res, err)
	}
	res, err = c.Authenticate(ctx, "bob", "123456", res.State)
	if err != nil || res.Outcome != Accept {
		t.Fatalf("challenge answer: %+v err %v", res, err)
	}
	res, err = c.Authenticate(ctx, "bob", "123456", []byte("forged"))
	if err != nil || res.Outcome != Reject {
		t.Fatalf("wrong state: %+v err %v", res, err)
	}
}

func TestResponseFromWrongSecretIsIgnored(t *testing.T) {
	srv := radiustest.New(t, "s3cret", policyFor(t))
	srv.BadSecret.Store(true)
	srv.Start()
	c := &Client{Addr: srv.Addr(), Secret: []byte("s3cret"), Timeout: 150 * time.Millisecond, Retries: 1}
	_, err := c.Authenticate(context.Background(), "alice", "correct horse", nil)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("an accept signed with the wrong secret must be ignored: %v", err)
	}
	if n := srv.Requests.Load(); n != 2 {
		t.Fatalf("expected the request and one retransmission, got %d", n)
	}
}

func TestRetransmitThenAnswer(t *testing.T) {
	srv := radiustest.New(t, "s3cret", policyFor(t))
	srv.Drop.Store(1)
	srv.Start()
	c := &Client{Addr: srv.Addr(), Secret: []byte("s3cret"), Timeout: 150 * time.Millisecond, Retries: 2}
	res, err := c.Authenticate(context.Background(), "alice", "correct horse", nil)
	if err != nil || res.Outcome != Accept {
		t.Fatalf("after one dropped request: %+v err %v", res, err)
	}
}

func TestClientRefusesUnusableInput(t *testing.T) {
	c := &Client{Addr: "127.0.0.1:1", Secret: []byte("x")}
	if _, err := c.Authenticate(context.Background(), "", "pw", nil); err == nil {
		t.Fatal("empty username accepted")
	}
	if _, err := c.Authenticate(context.Background(), "u", strings.Repeat("p", 129), nil); err == nil {
		t.Fatal("overlong password accepted")
	}
	if _, err := (&Client{}).Authenticate(context.Background(), "u", "p", nil); err == nil {
		t.Fatal("unconfigured client accepted")
	}
}
