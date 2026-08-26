package proxy

import (
	"fmt"
	"time"
)

// watermarkBanner returns the static identity banner published once, right
// after a text session (SSH/PostgreSQL/SQL Server) registers, so anyone
// watching it live — from the very first byte a late-joining supervisor
// would otherwise never see — knows who is connected and to what, the same
// deterrent/forensic purpose the RDP/VNC viewer's DOM overlay serves for
// graphical sessions (Phase 137). Static text, not a dynamic tracking
// pattern, matching the DOM overlay's own v1 scope.
func watermarkBanner(actor, targetName string) []byte {
	return []byte(fmt.Sprintf("PAMv1: session watermark — operator:%s target:%s started:%s\r\n",
		actor, targetName, time.Now().Format(time.RFC3339)))
}
