package winrm

import (
	"testing"

	"context"
	mw "github.com/masterzen/winrm"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TestNewClientAuthSelection checks that both auth modes construct a client
// without error (the NTLM path must not mutate shared library defaults).
func TestNewClientAuthSelection(t *testing.T) {
	for _, ntlm := range []bool{false, true} {
		c := Client{HTTPS: true, NTLM: ntlm}
		endpoint := mw.NewEndpoint("host", 5986, true, false, nil, nil, nil, 0)
		if _, err := c.newClient(endpoint, "CONTOSO\\svc", "pw"); err != nil {
			t.Fatalf("newClient(ntlm=%v): %v", ntlm, err)
		}
	}
	// NTLM construction must not have mutated the library's shared defaults.
	if mw.DefaultParameters.TransportDecorator != nil {
		t.Fatal("NTLM path mutated masterzen/winrm DefaultParameters")
	}
}

// TestRunErrorDoesNotLeakPassword proves that when the upstream WinRM endpoint
// fails, the returned error does not carry the injected credential.
//
// This is the one part of Client.Run worth testing without a real WS-Management
// server. Everything that decides *whether* a command runs — command control,
// session supervision, the just-in-time decrypt, the audit entry — happens
// upstream behind the Runner interface and is tested there. But this function is
// the one place the plaintext password is in scope alongside an error value that
// travels back to a caller and into logs, so a future change that wrapped the
// endpoint or the client config into the error message would leak a vaulted
// secret into the log stream. That regression should break a test, not a
// deployment.
func TestRunErrorDoesNotLeakPassword(t *testing.T) {
	// An endpoint that accepts the connection and fails the WS-Management
	// exchange, so Run reaches its error return without needing a real host.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream is unwell", http.StatusInternalServerError)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}

	const password = "S3cret-P@ssw0rd-do-not-leak"
	c := Client{Timeout: 5 * time.Second}
	res, err := c.Run(context.Background(), u.Hostname(), port, "Administrator", password, "whoami")
	if err == nil {
		t.Fatal("expected a transport error from a failing endpoint")
	}
	if res.ExitCode != 0 || res.Stdout != "" || res.Stderr != "" {
		t.Fatalf("a failed run returned a populated result: %+v", res)
	}
	if strings.Contains(err.Error(), password) {
		t.Fatalf("the error message contains the vaulted password: %v", err)
	}
}
