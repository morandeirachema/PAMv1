package probe

import (
	"context"
	"errors"
)

// ErrUnsupported is what NewPlatform returns where the probe cannot run: the
// session model it reports on (a Windows logon session) does not exist there.
var ErrUnsupported = errors.New("the session probe runs on Windows only")

// Platform is the one OS-specific seam of the probe: what a process running
// with the session user's own token can learn about, and do to, ITS OWN
// logon session. Nothing here reaches another user's session, by API rather
// than by policy — a user token cannot enumerate or end what it does not own.
type Platform interface {
	// Identity reports who and where the probe is running.
	Identity() (Hello, error)
	// Processes lists the processes of the probe's own logon session.
	Processes(ctx context.Context) ([]Process, error)
	// Connections lists the TCP connections and UDP endpoints owned by those
	// processes.
	Connections(ctx context.Context) ([]Connection, error)
	// Kill ends one process. An error means it is still running (access
	// denied for a process the session user does not own, or already gone).
	Kill(ctx context.Context, pid uint32) error
}

// ForegroundReporter is implemented by a Platform that can name the session's
// foreground window (Phase 271); the agent reports a change as an event.
type ForegroundReporter interface {
	Foreground() (Window, bool)
}
