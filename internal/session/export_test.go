package session

import "time"

// ShrinkClusterTimersForTest lowers the cluster timing knobs so tests can
// exercise heartbeat repair, interest expiry and the crash backstop in
// milliseconds instead of tens of seconds. Call BEFORE StartCluster (the loops
// read the values when they start) and defer the returned restore.
func ShrinkClusterTimersForTest() (restore func()) {
	oh, oa, oe, ot := inventoryHeartbeat, inventoryMaxAge, interestEvery, interestTTL
	inventoryHeartbeat = 30 * time.Millisecond
	inventoryMaxAge = 90 * time.Millisecond
	interestEvery = 20 * time.Millisecond
	interestTTL = 60 * time.Millisecond
	return func() {
		inventoryHeartbeat, inventoryMaxAge, interestEvery, interestTTL = oh, oa, oe, ot
	}
}

// TestingWants exposes the relay gate so a test can observe when interest in a
// session has propagated to (or expired on) the hosting replica.
func (c *Cluster) TestingWants(id string) bool { return c.wants(id) }
