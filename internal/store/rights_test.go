package store

import "testing"

func TestNormalizeRights(t *testing.T) {
	good := map[string]string{
		"":                                       "",
		"*":                                      "",
		" ssh_sftp , SSH_SHELL,ssh_sftp":         "ssh_sftp,ssh_shell",
		"rdp_audio_in,rdp_drive":                 "rdp_audio_in,rdp_drive",
		"ssh_exec,ssh_forward,ssh_x11,ssh_shell": "ssh_exec,ssh_forward,ssh_shell,ssh_x11",
	}
	for in, want := range good {
		got, err := NormalizeRights(in)
		if err != nil || got != want {
			t.Errorf("NormalizeRights(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"ssh_telnet", "rdp_clipboard", "shell", "ssh_shell;ssh_exec"} {
		if _, err := NormalizeRights(bad); err == nil {
			t.Errorf("NormalizeRights(%q): want error", bad)
		}
	}
	if !RightsAllow("", RightSSHX11) || !RightsAllow("ssh_shell,ssh_sftp", RightSSHSFTP) || RightsAllow("ssh_shell", RightSSHExec) || RightsAllow("none", RightSSHShell) {
		t.Error("RightsAllow semantics")
	}
	if ParseRights("") != nil || len(ParseRights("a,b")) != 2 {
		t.Error("ParseRights")
	}
}
