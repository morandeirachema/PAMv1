package proxy

import (
	"net"

	"github.com/morandeirachema/pamv1/internal/ratelimit"
)

// remoteHost extracts the host portion of a net.Addr, for keying the shared auth
// rate limiter (internal/ratelimit) by source IP. It delegates to ratelimit.Host
// — the one definition shared with the API middleware — adding only the nil
// guard a net.Addr needs.
func remoteHost(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return ratelimit.Host(addr.String())
}
