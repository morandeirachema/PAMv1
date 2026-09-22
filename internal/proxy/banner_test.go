package proxy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/banner"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// TestBannersOnTheProxy (Phase 276): the login banner reaches the SSH client
// before authentication; the session notice is printed into the session and
// its recording and audited with the notice's digest.
func TestBannersOnTheProxy(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	b := banner.New(map[string]string{"login": "AUTHORIZED USE ONLY", "session": "This session is recorded."})
	recDir := t.TempDir()
	px, err := proxy.New(st, v, resolver, proxy.Config{HostKey: mustSigner(t), RecordingDir: recDir, DialTimeout: 5 * time.Second, Banners: b})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)

	var got string
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: "web-01", Auth: []ssh.AuthMethod{ssh.Password(proxyAPIKey)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106 -- test
		BannerCallback:  func(msg string) error { got = msg; return nil },
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if !strings.Contains(got, "AUTHORIZED USE ONLY") {
		t.Fatalf("login banner not delivered before auth: %q", got)
	}
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sess.CombinedOutput("whoami")
	sess.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "This session is recorded.") || !strings.Contains(string(out), targetOutput) {
		t.Fatalf("session notice missing from the session output: %q", out)
	}
	client.Close()
	waitForAuditDetail(t, st, "session.consent", "target:web-01 cred_user:"+upstreamUser+" mode:printed banner_sha256:"+banner.Digest("This session is recorded."))
	// And it is in the recording.
	entries, _ := os.ReadDir(recDir)
	found := false
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".cast") {
			data, _ := os.ReadFile(filepath.Join(recDir, e.Name()))
			if strings.Contains(string(data), "This session is recorded.") {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("session notice not in the recording")
	}
}
