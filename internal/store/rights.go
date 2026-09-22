package store

import (
	"fmt"
	"sort"
	"strings"
)

// Sub-protocol rights (Phase 270) — what a session may do inside the protocol
// it was admitted to, the way WALLIX Bastion's per-service proxy options and
// per-authorization sub-protocol lists work. A Target and a TargetGrant each
// carry a canonical set ("ssh_exec,ssh_sftp,ssh_shell"); empty means "no
// narrowing here". The effective set for a session is the intersection of the
// deployment ceilings (PAM_SSH_SFTP_MODE, PAM_SSH_PORT_FORWARD, PAM_RDP_*),
// the target's set and the union of the sets on the grants that admitted the
// caller (auth.EffectiveRights) — a target can only narrow the deployment, a
// grant can only narrow the target, and nothing can widen a deployment switch.
const (
	RightSSHShell   = "ssh_shell"    // an interactive shell
	RightSSHExec    = "ssh_exec"     // a remote command (covers SCP, which rides exec)
	RightSSHSFTP    = "ssh_sftp"     // the sftp subsystem
	RightSSHForward = "ssh_forward"  // client-initiated port forwarding (ssh -L)
	RightSSHX11     = "ssh_x11"      // X11 forwarding
	RightRDPDrive   = "rdp_drive"    // drive redirection (file transfer through the desktop)
	RightRDPPrinter = "rdp_printer"  // printer redirection
	RightRDPAudio   = "rdp_audio"    // audio output
	RightRDPAudioIn = "rdp_audio_in" // audio input (microphone)
)

// AllRights lists every right, in canonical order.
var AllRights = []string{RightSSHShell, RightSSHExec, RightSSHSFTP, RightSSHForward, RightSSHX11,
	RightRDPDrive, RightRDPPrinter, RightRDPAudio, RightRDPAudioIn}

var rightSet = func() map[string]bool {
	m := make(map[string]bool, len(AllRights))
	for _, r := range AllRights {
		m[r] = true
	}
	return m
}()

// NormalizeRights parses a comma-separated list of rights into canonical
// stored form: trimmed, lower-cased, de-duplicated, sorted. "" (or "*") is
// the empty set, which means no narrowing. An unknown name is an error — a
// typo must not silently become "nothing allowed".
func NormalizeRights(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "*" {
		return "", nil
	}
	seen := map[string]bool{}
	var out []string
	for _, part := range strings.Split(s, ",") {
		r := strings.ToLower(strings.TrimSpace(part))
		if r == "" {
			continue
		}
		if !rightSet[r] {
			return "", fmt.Errorf("unknown right %q (known: %s)", r, strings.Join(AllRights, ", "))
		}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ","), nil
}

// ParseRights turns a canonical set into a lookup; nil for the empty set.
func ParseRights(s string) map[string]bool {
	if s == "" {
		return nil
	}
	m := map[string]bool{}
	for _, r := range strings.Split(s, ",") {
		if r != "" {
			m[r] = true
		}
	}
	return m
}

// RightsAllow reports whether a canonical set admits right: an empty set
// (no narrowing) admits everything.
func RightsAllow(set string, right string) bool {
	if set == "" {
		return true
	}
	return ParseRights(set)[right]
}
