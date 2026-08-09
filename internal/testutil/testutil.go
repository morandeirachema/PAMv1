// Package testutil holds small helpers shared across pamv1's test suites. It is
// imported only by _test.go files, so its dependency on the testing package
// never reaches a production binary.
package testutil

import (
	"testing"
	"time"
)

// WaitFor polls cond about every 5ms until it returns true or timeout elapses,
// and reports whether it became true. It replaces the hand-rolled
// deadline-plus-sleep loops that recur across the suites, so a poll can no longer
// be written without a bound. The caller supplies its own failure message:
//
//	if !testutil.WaitFor(t, 3*time.Second, func() bool { return done() }) {
//		t.Fatal("thing never happened")
//	}
func WaitFor(t testing.TB, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
}
