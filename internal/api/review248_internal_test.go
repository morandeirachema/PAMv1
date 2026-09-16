package api

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
)

// TestOperatorInputIgnoresTunnelKeepalives proves the RDP/VNC idle clock
// counts what the OPERATOR did, not what the tunnel does on its own (Phase
// 248). guacamole-common-js answers every server `sync` with one of its own
// and sends `nop` pings unprompted, so treating every inbound frame as
// activity meant PAM_SESSION_IDLE_MIN could never fire on a graphical
// session — the one kind where an unattended desktop is the whole risk.
func TestOperatorInputIgnoresTunnelKeepalives(t *testing.T) {
	// Guacamole wire format: LENGTH.VALUE, comma-separated, ';'-terminated.
	instr := func(opcode string, args ...string) []byte {
		out := ""
		for i, e := range append([]string{opcode}, args...) {
			if i > 0 {
				out += ","
			}
			out += strconv.Itoa(len([]rune(e))) + "." + e
		}
		return []byte(out + ";")
	}
	for _, tc := range []struct {
		name  string
		frame []byte
		want  bool
	}{
		{"sync keepalive", instr("sync", "31415926"), false},
		{"nop ping", instr("nop"), false},
		{"file-transfer ack", instr("ack", "1", "ok", "0"), false},
		{"keystroke", instr("key", "65", "1"), true},
		{"mouse", instr("mouse", "100", "200", "1"), true},
		{"clipboard paste", instr("clipboard", "0", "text/plain"), true},
		{"window resize", instr("size", "1024", "768"), true},
		{"unparsable frame counts as input", []byte("not-an-instruction"), true},
		{"a batch containing one keystroke", append(instr("sync", "1"), instr("key", "66", "1")...), true},
	} {
		if got := operatorInput(tc.frame); got != tc.want {
			t.Errorf("%s: operatorInput(%q) = %v, want %v", tc.name, tc.frame, got, tc.want)
		}
	}
}

// failingRecoveryStore answers the TOTP replay guard normally and fails the
// recovery-code lookup, which is the branch that used to swallow its error.
type failingRecoveryStore struct{ err error }

func (f failingRecoveryStore) ConsumeTOTPStep(context.Context, string, int64) (bool, error) {
	return true, nil
}
func (f failingRecoveryStore) ConsumeMFARecoveryCode(context.Context, string, string) (bool, error) {
	return false, f.err
}

// brokenDecrypter stands in for a vault that cannot read the TOTP seed, so
// VerifySecondFactor falls through to the recovery-code branch.
type brokenDecrypter struct{}

func (brokenDecrypter) Decrypt(context.Context, string, string) (string, error) {
	return "", errors.New("no seed")
}

// TestVerifySecondFactorReportsStoreFailure proves a store failure on the
// recovery-code check is REPORTED, not reported as a wrong code (Phase 248).
// The function's contract already said so, and the TOTP branch did it; the
// recovery branch dropped the error, so an operator locked out by an
// unreachable database looked exactly like one who mistyped.
func TestVerifySecondFactorReportsStoreFailure(t *testing.T) {
	boom := errors.New("database is down")
	factor, err := auth.VerifySecondFactor(t.Context(), failingRecoveryStore{err: boom}, brokenDecrypter{},
		&store.MFAEnrollment{Confirmed: true}, "alice", "some-recovery-code", time.Now())
	if factor != "" {
		t.Errorf("factor = %q, want none", factor)
	}
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want the store's own error", err)
	}
}
