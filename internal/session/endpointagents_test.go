package session_test

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/morandeirachema/pamv1/internal/session"
)

// fakeOpener counts opens and closes.
type fakeOpener struct {
	opens, closes atomic.Int32
}

func (f *fakeOpener) OpenTunnel() (net.Conn, error) {
	f.opens.Add(1)
	a, b := net.Pipe()
	b.Close()
	return a, nil
}
func (f *fakeOpener) Close() error { f.closes.Add(1); return nil }

// TestEndpointAgentsRegistry pins the registry's contract: dial through a
// registered link, offline when none, a newer registration for the same
// target closes and supersedes the older one (whose release then does NOT
// remove the newer), List order, and Kick closes by agent ID.
func TestEndpointAgentsRegistry(t *testing.T) {
	r := session.NewEndpointAgents()
	if _, err := r.Dial(7); !errors.Is(err, session.ErrEndpointAgentOffline) {
		t.Fatalf("dial with no link: %v", err)
	}
	o1, o2 := &fakeOpener{}, &fakeOpener{}
	rel1 := r.Register(session.EndpointAgentLink{AgentID: 1, Name: "a", TargetID: 7}, o1)
	c, err := r.Dial(7)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if o1.opens.Load() != 1 {
		t.Fatalf("o1 opens = %d", o1.opens.Load())
	}
	// Reconnect for the same target: o1 is closed and replaced.
	rel2 := r.Register(session.EndpointAgentLink{AgentID: 1, Name: "a", TargetID: 7}, o2)
	if o1.closes.Load() != 1 {
		t.Fatal("superseded link should be closed")
	}
	rel1() // stale release must not remove the newer registration
	if _, ok := r.Lookup(7); !ok {
		t.Fatal("stale release removed the newer link")
	}
	if _, err := r.Dial(7); err != nil || o2.opens.Load() != 1 {
		t.Fatalf("dial after supersede: %v opens=%d", err, o2.opens.Load())
	}
	o3 := &fakeOpener{}
	r.Register(session.EndpointAgentLink{AgentID: 2, Name: "b", TargetID: 9}, o3)
	list := r.List()
	if len(list) != 2 || list[0].AgentID != 1 || list[1].AgentID != 2 {
		t.Fatalf("list = %+v", list)
	}
	if !r.Kick(2) || o3.closes.Load() != 1 || r.Kick(2) {
		t.Fatal("kick should close and remove exactly once")
	}
	rel2()
	if _, ok := r.Lookup(7); ok {
		t.Fatal("release should remove the link")
	}
	// nil registry is a safe no-op.
	var nilReg *session.EndpointAgents
	if _, err := nilReg.Dial(1); !errors.Is(err, session.ErrEndpointAgentOffline) {
		t.Fatal("nil registry should report offline")
	}
	o4 := &fakeOpener{}
	nilReg.Register(session.EndpointAgentLink{AgentID: 3, TargetID: 1}, o4)()
	if o4.closes.Load() != 1 || nilReg.List() != nil || nilReg.Kick(3) {
		t.Fatal("nil registry should close what it is handed and hold nothing")
	}
}
