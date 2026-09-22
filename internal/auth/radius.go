package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/morandeirachema/pamv1/internal/radius"
)

// RADIUSConfig configures RADIUS (RFC 2865) as an identity source (Phase 269).
type RADIUSConfig struct {
	// Addr is the server's host:port; Secret the shared secret.
	Addr   string
	Secret string
	// NASIdentifier is what PAMv1 calls itself to the server.
	NASIdentifier string
	// DefaultRole is the role an Access-Accept confers when no Class attribute
	// matches ClassRoleMap (empty = RoleUser).
	DefaultRole Role
	// ClassRoleMap maps a Class attribute value (lower-cased) the server
	// returns on Accept to a role — the RADIUS counterpart of a group mapping.
	ClassRoleMap map[string]Role
	// client is overridable for tests.
	client *radius.Client
}

// ChallengeError is returned by Authenticate when the server answered
// Access-Challenge: the credentials were not refused, but the server wants a
// further value (a one-time code) before it decides. The login handler turns
// it into a "code required" reply carrying State, and Continue finishes it.
type ChallengeError struct {
	State   []byte
	Message string
}

func (e *ChallengeError) Error() string {
	return "radius: server requires a further factor: " + e.Message
}

// RADIUSAuthenticator is an Authenticator over one RADIUS server. It serves
// two deployments: as a LOGIN source (username + password, optionally with a
// challenge for an OTP) it sits in the same chain as LDAP and Entra; as a
// SECOND FACTOR (SecondFactor) it verifies the code a directory-authenticated
// user typed — the server does the OTP, PAMv1 asks it.
type RADIUSAuthenticator struct {
	cfg    RADIUSConfig
	client *radius.Client
}

// NewRADIUSAuthenticator validates cfg and returns the authenticator.
func NewRADIUSAuthenticator(cfg RADIUSConfig) (*RADIUSAuthenticator, error) {
	if cfg.Addr == "" || cfg.Secret == "" {
		return nil, errors.New("radius: address and shared secret are required")
	}
	if cfg.DefaultRole == "" {
		cfg.DefaultRole = RoleUser
	}
	if _, err := ParseRole(string(cfg.DefaultRole)); err != nil {
		return nil, fmt.Errorf("radius: default role: %w", err)
	}
	c := cfg.client
	if c == nil {
		c = &radius.Client{Addr: cfg.Addr, Secret: []byte(cfg.Secret), NASIdentifier: cfg.NASIdentifier}
	}
	return &RADIUSAuthenticator{cfg: cfg, client: c}, nil
}

// Authenticate asks the server about username/password. Accept → a Principal
// whose roles come from the Class attributes (union of every mapped value,
// like a directory user in several mapped groups) or the default role;
// Reject → ErrUnauthorized; Challenge → *ChallengeError.
func (a *RADIUSAuthenticator) Authenticate(ctx context.Context, username, password string) (*Principal, error) {
	return a.round(ctx, username, password, nil)
}

// Continue answers a Challenge: otp is the user's reply, state the State the
// server handed back.
func (a *RADIUSAuthenticator) Continue(ctx context.Context, username, otp string, state []byte) (*Principal, error) {
	if len(state) == 0 {
		return nil, ErrUnauthorized
	}
	return a.round(ctx, username, otp, state)
}

// SecondFactor verifies a one-time code for a user another source already
// authenticated: an Access-Accept is the only yes. A challenge here is a
// refusal (there is no further prompt to show), as is any transport failure —
// a second factor fails closed.
func (a *RADIUSAuthenticator) SecondFactor(ctx context.Context, username, code string) (bool, error) {
	res, err := a.client.Authenticate(ctx, username, code, nil)
	if err != nil {
		return false, err
	}
	return res.Outcome == radius.Accept, nil
}

func (a *RADIUSAuthenticator) round(ctx context.Context, username, password string, state []byte) (*Principal, error) {
	if username == "" || password == "" {
		return nil, ErrUnauthorized
	}
	res, err := a.client.Authenticate(ctx, username, password, state)
	if err != nil {
		return nil, fmt.Errorf("radius: %w", err)
	}
	switch res.Outcome {
	case radius.Accept:
		return a.principal(username, res.Class), nil
	case radius.Challenge:
		return nil, &ChallengeError{State: res.State, Message: res.ReplyMessage}
	default:
		return nil, ErrUnauthorized
	}
}

// principal builds the Principal for an accepted user.
func (a *RADIUSAuthenticator) principal(username string, classes []string) *Principal {
	var roles []Role
	seen := map[Role]bool{}
	for _, c := range classes {
		if r, ok := a.cfg.ClassRoleMap[strings.ToLower(strings.TrimSpace(c))]; ok && !seen[r] {
			roles = append(roles, r)
			seen[r] = true
		}
	}
	if len(roles) == 0 {
		return &Principal{Name: username, Role: a.cfg.DefaultRole}
	}
	return &Principal{Name: username, Role: highestRole(roles), Roles: roles}
}

// highestRole picks the display/primary role from a set: admin over the rest,
// then approver, auditor, user — the order the directory sources use.
func highestRole(roles []Role) Role {
	for _, want := range []Role{RoleAdmin, RoleApprover, RoleAuditor, RoleUser} {
		for _, r := range roles {
			if r == want {
				return r
			}
		}
	}
	return roles[0]
}
