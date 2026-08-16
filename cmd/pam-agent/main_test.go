package main

import (
	"strings"
	"testing"
)

// TestConfigFromEnv pins the fail-loud rules: no host key (and no explicit
// insecure switch) refuses to run; a bad host key refuses; missing servers,
// name or key refuse; a valid set parses with the local-address default.
func TestConfigFromEnv(t *testing.T) {
	const goodKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGwvBv2h6NcJoZ7VXW1kUeE9dqm4YQ5Q6zNlD9c8L2Kk"
	set := func(kv map[string]string) {
		for _, k := range []string{"PAM_AGENT_SERVERS", "PAM_AGENT_NAME", "PAM_AGENT_KEY", "PAM_AGENT_LOCAL_ADDR",
			"PAM_AGENT_SERVER_HOST_KEY", "PAM_AGENT_INSECURE_SKIP_HOST_KEY"} {
			t.Setenv(k, kv[k])
		}
	}
	base := map[string]string{"PAM_AGENT_SERVERS": "pam.example:2222, pam2.example:2222", "PAM_AGENT_NAME": "branch-1",
		"PAM_AGENT_KEY": "k", "PAM_AGENT_SERVER_HOST_KEY": goodKey}
	set(base)
	cfg, err := configFromEnv()
	if err != nil || len(cfg.Servers) != 2 || cfg.LocalAddr != "127.0.0.1:22" || cfg.HostKey == nil {
		t.Fatalf("valid config: %+v err %v", cfg, err)
	}
	for name, mut := range map[string]func(m map[string]string){
		"no host key":  func(m map[string]string) { m["PAM_AGENT_SERVER_HOST_KEY"] = "" },
		"bad host key": func(m map[string]string) { m["PAM_AGENT_SERVER_HOST_KEY"] = "not a key" },
		"no servers":   func(m map[string]string) { m["PAM_AGENT_SERVERS"] = "" },
		"no name":      func(m map[string]string) { m["PAM_AGENT_NAME"] = "" },
		"no key":       func(m map[string]string) { m["PAM_AGENT_KEY"] = "" },
	} {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		mut(m)
		set(m)
		if _, err := configFromEnv(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	// The explicit insecure switch is the only way to run without a pinned key.
	m := map[string]string{}
	for k, v := range base {
		m[k] = v
	}
	m["PAM_AGENT_SERVER_HOST_KEY"], m["PAM_AGENT_INSECURE_SKIP_HOST_KEY"] = "", "true"
	set(m)
	if cfg, err := configFromEnv(); err != nil || cfg.HostKey == nil {
		t.Fatalf("insecure opt-in should parse: %v", err)
	}
	// And a bad host key is refused even when the insecure switch is also set.
	m["PAM_AGENT_SERVER_HOST_KEY"] = "garbage"
	set(m)
	if _, err := configFromEnv(); err == nil || !strings.Contains(err.Error(), "HOST_KEY") {
		t.Fatalf("garbage host key should be refused: %v", err)
	}
}
