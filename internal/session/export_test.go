package session

import (
	"context"
	"time"
)

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

// TestingHeartbeatOnce runs exactly one inventory-refresh pass, so a test can
// drive the heartbeat deterministically instead of waiting on its ticker.
func (c *Cluster) TestingHeartbeatOnce(ctx context.Context) { c.heartbeatOnce(ctx) }

// TestingSessionRemoved runs the session-teardown bookkeeping (tombstone, row
// delete, end marker) WITHOUT touching the registry, which is what lets a test
// reproduce the heartbeat/removal race: the id is gone from the inventory while
// still present in the registry snapshot a heartbeat would use.
func (c *Cluster) TestingSessionRemoved(id string) { c.sessionRemoved(id) }
