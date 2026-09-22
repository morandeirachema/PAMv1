package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/radius"
	"github.com/morandeirachema/pamv1/internal/radius/radiustest"
)

func radiusPolicy(user, pass string, state []byte) (byte, []radiustest.Attr) {
	switch {
	case user == "alice" && pass == "pw":
		return radiustest.CodeAccessAccept, []radiustest.Attr{{Type: radiustest.AttrClass, Value: "PAM-Auditors"}, {Type: radiustest.AttrClass, Value: "pam-approvers"}}
	case user == "carol" && pass == "pw":
		return radiustest.CodeAccessAccept, []radiustest.Attr{{Type: radiustest.AttrClass, Value: "unrelated"}}
	case user == "bob" && pass == "pw" && len(state) == 0:
		return radiustest.CodeAccessChallenge, []radiustest.Attr{{Type: radiustest.AttrState, Value: "s1"}, {Type: radiustest.AttrReplyMessage, Value: "Token:"}}
	case user == "bob" && pass == "000111" && string(state) == "s1":
		return radiustest.CodeAccessAccept, nil
	case user == "dave" && pass == "424242":
		return radiustest.CodeAccessAccept, nil
	}
	return radiustest.CodeAccessReject, nil
}

func newRADIUS(t *testing.T, srv *radiustest.Server) *RADIUSAuthenticator {
	t.Helper()
	a, err := NewRADIUSAuthenticator(RADIUSConfig{
		Addr: srv.Addr(), Secret: "s3cret", NASIdentifier: "pamv1",
		ClassRoleMap: map[string]Role{"pam-auditors": RoleAuditor, "pam-approvers": RoleApprover},
		client:       &radius.Client{Addr: srv.Addr(), Secret: []byte("s3cret"), Timeout: 200 * time.Millisecond, Retries: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestRADIUSAuthenticator proves the adapter against the real client and the
// in-process server: an accept with mapped Class values yields the union of
// roles, an accept with none yields the default role, a reject is
// ErrUnauthorized, a challenge is a ChallengeError that Continue completes,
// and a chain falls through a directory refusal into RADIUS.
func TestRADIUSAuthenticator(t *testing.T) {
	srv := radiustest.New(t, "s3cret", radiusPolicy).Start()
	a := newRADIUS(t, srv)
	ctx := context.Background()

	p, err := a.Authenticate(ctx, "alice", "pw")
	if err != nil || p.Name != "alice" || p.Role != RoleApprover || len(p.Roles) != 2 || !p.Can(CapApprove) || !p.Can(CapReadAudit) {
		t.Fatalf("alice: %+v err %v", p, err)
	}
	p, err = a.Authenticate(ctx, "carol", "pw")
	if err != nil || p.Role != RoleUser || p.Roles != nil {
		t.Fatalf("carol (no mapped class): %+v err %v", p, err)
	}
	if _, err := a.Authenticate(ctx, "alice", "wrong"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("reject: %v", err)
	}
	if _, err := a.Authenticate(ctx, "", "pw"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("empty user: %v", err)
	}

	_, err = a.Authenticate(ctx, "bob", "pw")
	var ch *ChallengeError
	if !errors.As(err, &ch) || string(ch.State) != "s1" || ch.Message != "Token:" {
		t.Fatalf("challenge: %v", err)
	}
	if p, err := a.Continue(ctx, "bob", "000111", ch.State); err != nil || p.Name != "bob" {
		t.Fatalf("continue: %+v err %v", p, err)
	}
	if _, err := a.Continue(ctx, "bob", "000111", nil); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("continue without state: %v", err)
	}
	if _, err := a.Continue(ctx, "bob", "999999", ch.State); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("continue wrong code: %v", err)
	}

	// Second factor: accept is the only yes.
	if ok, err := a.SecondFactor(ctx, "dave", "424242"); err != nil || !ok {
		t.Fatalf("second factor accept: %v %v", ok, err)
	}
	if ok, err := a.SecondFactor(ctx, "dave", "111111"); err != nil || ok {
		t.Fatalf("second factor reject: %v %v", ok, err)
	}
	// A challenge answered to SecondFactor is not a yes either.
	if ok, err := a.SecondFactor(ctx, "bob", "pw"); err != nil || ok {
		t.Fatalf("second factor challenge must not pass: %v %v", ok, err)
	}

	// In a chain after a refusing directory, RADIUS gets its turn and its
	// challenge propagates instead of being swallowed as "unauthorized".
	chain := NewChain(refusingAuthenticator{}, a)
	if p, err := chain.Authenticate(ctx, "alice", "pw"); err != nil || p.Name != "alice" {
		t.Fatalf("chain accept: %+v err %v", p, err)
	}
	if _, err := chain.Authenticate(ctx, "bob", "pw"); !errors.As(err, &ch) {
		t.Fatalf("chain challenge: %v", err)
	}
}

// TestRADIUSServerDownFailsClosed: no server → an error, never an accept, and
// SecondFactor reports the error rather than false-and-nil.
func TestRADIUSServerDownFailsClosed(t *testing.T) {
	a, err := NewRADIUSAuthenticator(RADIUSConfig{Addr: "127.0.0.1:1", Secret: "x",
		client: &radius.Client{Addr: "127.0.0.1:1", Secret: []byte("x"), Timeout: 100 * time.Millisecond, Retries: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Authenticate(context.Background(), "alice", "pw"); err == nil || errors.Is(err, ErrUnauthorized) {
		t.Fatalf("server down must be an error, not a refusal: %v", err)
	}
	if ok, err := a.SecondFactor(context.Background(), "alice", "1"); ok || err == nil {
		t.Fatalf("second factor with server down: %v %v", ok, err)
	}
	if _, err := NewRADIUSAuthenticator(RADIUSConfig{Addr: "h:1812"}); err == nil {
		t.Fatal("missing secret accepted")
	}
	if _, err := NewRADIUSAuthenticator(RADIUSConfig{Addr: "h:1812", Secret: "s", DefaultRole: "root"}); err == nil {
		t.Fatal("bad default role accepted")
	}
}

type refusingAuthenticator struct{}

func (refusingAuthenticator) Authenticate(context.Context, string, string) (*Principal, error) {
	return nil, ErrUnauthorized
}
