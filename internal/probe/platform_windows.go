//go:build windows

package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// windowsPlatform is the real Platform: PowerShell (present on every
// supported Windows Server, no module to install) enumerates the session's
// processes and sockets as JSON, and TerminateProcess ends one — under the
// probe's own token, so a process another user owns is "access denied", which
// is exactly the permission model the probe is meant to have.
type windowsPlatform struct {
	sessionID uint32
	started   time.Time
}

// NewPlatform resolves the probe's own logon session once (a process never
// changes session) and returns the Windows Platform.
func NewPlatform() (Platform, error) {
	var sid uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sid); err != nil {
		return nil, fmt.Errorf("resolve logon session: %w", err)
	}
	return &windowsPlatform{sessionID: sid, started: time.Now()}, nil
}

// Identity reports host, user and session.
func (w *windowsPlatform) Identity() (Hello, error) {
	host, _ := os.Hostname()
	name := ""
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	return Hello{Hostname: host, OS: "windows", User: name, SessionID: w.sessionID, LogonTime: w.started}, nil
}

// psProcess mirrors the properties the enumeration script selects.
type psProcess struct {
	ProcessId       uint32
	ParentProcessId uint32
	Name            string
	ExecutablePath  string
	CommandLine     string
	Created         string
}

// psConnection mirrors the properties the socket script selects.
type psConnection struct {
	Proto         string
	LocalAddress  string
	LocalPort     uint16
	RemoteAddress string
	RemotePort    uint16
	State         string
	OwningProcess uint32
}

// Processes lists the session's processes via Win32_Process filtered by
// SessionId — the session id is a number the probe resolved itself, never
// text from anywhere, so nothing is interpolated that could be shell.
func (w *windowsPlatform) Processes(ctx context.Context) ([]Process, error) {
	script := "ConvertTo-Json -Compress -InputObject @(Get-CimInstance Win32_Process -Filter 'SessionId=" + strconv.FormatUint(uint64(w.sessionID), 10) + "' | " +
		"Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine," +
		"@{n='Created';e={ if ($_.CreationDate) { $_.CreationDate.ToUniversalTime().ToString('o') } else { '' } }})"
	var rows []psProcess
	if err := runPS(ctx, script, &rows); err != nil {
		return nil, err
	}
	out := make([]Process, 0, len(rows))
	for _, r := range rows {
		p := Process{PID: r.ProcessId, PPID: r.ParentProcessId, Name: r.Name, Path: r.ExecutablePath, CommandLine: r.CommandLine}
		if t, err := time.Parse(time.RFC3339Nano, r.Created); err == nil {
			p.Started = t
		}
		out = append(out, p)
	}
	return out, nil
}

// Connections lists TCP connections and UDP endpoints whose owning process is
// in the session (Get-NetTCPConnection / Get-NetUDPEndpoint, Windows 8 /
// Server 2012 and later).
func (w *windowsPlatform) Connections(ctx context.Context) ([]Connection, error) {
	sid := strconv.FormatUint(uint64(w.sessionID), 10)
	script := "$pids = @(Get-CimInstance Win32_Process -Filter 'SessionId=" + sid + "' | ForEach-Object { $_.ProcessId }); " +
		"$t = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $pids -contains $_.OwningProcess } | " +
		"Select-Object @{n='Proto';e={'tcp'}},LocalAddress,LocalPort,RemoteAddress,RemotePort,@{n='State';e={$_.State.ToString()}},OwningProcess); " +
		"$u = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object { $pids -contains $_.OwningProcess } | " +
		"Select-Object @{n='Proto';e={'udp'}},LocalAddress,LocalPort,@{n='RemoteAddress';e={''}},@{n='RemotePort';e={0}},@{n='State';e={''}},OwningProcess); " +
		"ConvertTo-Json -Compress -InputObject @($t + $u)"
	var rows []psConnection
	if err := runPS(ctx, script, &rows); err != nil {
		return nil, err
	}
	out := make([]Connection, 0, len(rows))
	for _, r := range rows {
		c := Connection{PID: r.OwningProcess, Proto: r.Proto, LocalAddr: r.LocalAddress, LocalPort: r.LocalPort, State: r.State}
		// An unconnected socket reports 0.0.0.0/:: as its peer; that is "no
		// peer", not an address a rule could sensibly name.
		if r.RemoteAddress != "" && r.RemoteAddress != "0.0.0.0" && r.RemoteAddress != "::" {
			c.RemoteAddr, c.RemotePort = r.RemoteAddress, r.RemotePort
		}
		out = append(out, c)
	}
	return out, nil
}

var (
	user32          = windows.NewLazySystemDLL("user32.dll")
	procGetWindowTW = user32.NewProc("GetWindowTextW")
)

// Foreground names the session's foreground window: its owning PID (via
// GetWindowThreadProcessId) and title (GetWindowTextW). A desktop with no
// foreground window, or a title that cannot be read, reports false.
func (w *windowsPlatform) Foreground() (Window, bool) {
	h := windows.GetForegroundWindow()
	if h == 0 {
		return Window{}, false
	}
	var pid uint32
	windows.GetWindowThreadProcessId(h, &pid)
	buf := make([]uint16, 512)
	n, _, _ := procGetWindowTW.Call(uintptr(h), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	title := windows.UTF16ToString(buf[:n])
	return Window{PID: pid, Title: Clean(title, 256)}, true
}

// Kill ends pid with the probe's own token.
func (w *windowsPlatform) Kill(_ context.Context, pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return fmt.Errorf("open process %d: %w", pid, err)
	}
	defer windows.CloseHandle(h)
	if err := windows.TerminateProcess(h, 1); err != nil {
		return fmt.Errorf("terminate process %d: %w", pid, err)
	}
	return nil
}

// runPS runs one PowerShell command line and decodes its JSON output into v.
// -NoProfile keeps the user's profile scripts out of the probe's process,
// -NonInteractive refuses prompts, and the output is bounded by MaxLine.
func runPS(ctx context.Context, script string, v any) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script) // #nosec G204 -- fixed script text; the only variable is a numeric session id
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("powershell: %w: %s", err, strings.TrimSpace(errb.String()))
	}
	if out.Len() > MaxLine {
		return fmt.Errorf("powershell: output exceeds %d bytes", MaxLine)
	}
	data := bytes.TrimSpace(out.Bytes())
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, v)
}
