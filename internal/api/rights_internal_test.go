package api

import "testing"

// TestRDPRedirectionParams: a redirection is on only when the deployment
// ceiling allows it AND the session's rights include it; every switch is
// always sent explicitly.
func TestRDPRedirectionParams(t *testing.T) {
	all := rdpRedirections{drive: true, printer: true, audio: true, audioIn: true}
	none := rdpRedirections{}
	cases := []struct {
		c      rdpRedirections
		rights string
		want   map[string]string
	}{
		{all, "", map[string]string{"enable-drive": "true", "enable-printing": "true", "enable-audio-input": "true", "disable-audio": "false"}},
		{none, "", map[string]string{"enable-drive": "false", "enable-printing": "false", "enable-audio-input": "false", "disable-audio": "true"}},
		{all, "rdp_audio,ssh_shell", map[string]string{"enable-drive": "false", "enable-printing": "false", "enable-audio-input": "false", "disable-audio": "false"}},
		{all, "rdp_drive", map[string]string{"enable-drive": "true", "enable-printing": "false", "enable-audio-input": "false", "disable-audio": "true"}},
		{rdpRedirections{audio: true}, "rdp_drive,rdp_audio", map[string]string{"enable-drive": "false", "enable-printing": "false", "enable-audio-input": "false", "disable-audio": "false"}},
		{all, "none", map[string]string{"enable-drive": "false", "enable-printing": "false", "enable-audio-input": "false", "disable-audio": "true"}},
	}
	for _, tc := range cases {
		got := rdpRedirectionParams(tc.c, tc.rights)
		for k, v := range tc.want {
			if got[k] != v {
				t.Errorf("ceilings %+v rights %q: %s=%q want %q", tc.c, tc.rights, k, got[k], v)
			}
		}
	}
	// The defaults (drive/printer/mic off, audio on) through rdpExtra.
	ex := rdpExtra("", false, "allow", rdpRedirections{audio: true}, "")
	if ex["enable-drive"] != "false" || ex["disable-audio"] != "false" || ex["enable-printing"] != "false" {
		t.Fatalf("rdpExtra defaults: %v", ex)
	}
}
