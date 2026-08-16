// Command pam-agent is pamv1's outbound-only endpoint agent (Phase 153): a
// small binary installed on a target that pam-server cannot dial into (a NAT'd
// branch box, a CGNAT'd contractor laptop, an unattended host with no inbound
// firewall rule). It dials OUT to pam-server's SSH listener with its own bearer
// key, holds a reverse tunnel open, and pipes every stream pam-server opens
// through it to ONE local address — normally the endpoint's own sshd. Nothing
// inbound is ever needed at the endpoint; see internal/endpointagent for the
// mechanism and its security posture.
//
// Configuration is environment-only (12-factor, like pam-server):
//
//	PAM_AGENT_SERVERS         pam-server SSH listener(s), comma-separated host:port — one tunnel each (HA: list every replica)
//	PAM_AGENT_NAME            the agent's registered name (POST /api/endpoint-agents)
//	PAM_AGENT_KEY             the bearer key returned once at registration
//	PAM_AGENT_LOCAL_ADDR      the one local address to expose (default 127.0.0.1:22)
//	PAM_AGENT_SERVER_HOST_KEY pam-server's SSH host public key, authorized_keys format (`ssh-keyscan -p 2222 pam-host`) — required
//	PAM_AGENT_INSECURE_SKIP_HOST_KEY=true  demos only: accept any server host key (a network attacker could then harvest PAM_AGENT_KEY)
//	PAM_AGENT_LOG_LEVEL / PAM_AGENT_LOG_FORMAT  debug|info|warn|error / json|text (default info / json)
//
// Flags: -version prints the build version and commit.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/endpointagent"
	"github.com/morandeirachema/pamv1/internal/logging"
)

// version and commit are stamped at build time (see deploy/docker/Dockerfile).
var (
	version = "dev"
	commit  = "none"
)

// main parses -version and otherwise runs the agent until SIGINT/SIGTERM.
func main() {
	showVersion := flag.Bool("version", false, "print the build version and commit, then exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("pam-agent", version+" ("+commit+")")
		return
	}
	log := logging.Setup(os.Getenv("PAM_AGENT_LOG_LEVEL"), os.Getenv("PAM_AGENT_LOG_FORMAT")).With("service", "pam-agent")
	cfg, err := configFromEnv()
	if err != nil {
		log.Error("configuration error", "err", err)
		os.Exit(2)
	}
	cfg.Logger = log
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Info("pam-agent starting", "version", version, "commit", commit,
		"servers", cfg.Servers, "agent", cfg.Name, "local", cfg.LocalAddr)
	if err := endpointagent.Run(ctx, cfg); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("agent stopped", "err", err)
		os.Exit(1)
	}
	log.Info("pam-agent stopped")
}

// configFromEnv builds the agent configuration from PAM_AGENT_* variables,
// refusing to run without server host-key verification unless the insecure
// switch is set explicitly.
func configFromEnv() (endpointagent.Config, error) {
	cfg := endpointagent.Config{
		Name:      os.Getenv("PAM_AGENT_NAME"),
		Key:       os.Getenv("PAM_AGENT_KEY"),
		LocalAddr: os.Getenv("PAM_AGENT_LOCAL_ADDR"),
	}
	for _, s := range strings.Split(os.Getenv("PAM_AGENT_SERVERS"), ",") {
		if s = strings.TrimSpace(s); s != "" {
			cfg.Servers = append(cfg.Servers, s)
		}
	}
	if cfg.LocalAddr == "" {
		cfg.LocalAddr = "127.0.0.1:22"
	}
	switch hk, insecure := os.Getenv("PAM_AGENT_SERVER_HOST_KEY"), os.Getenv("PAM_AGENT_INSECURE_SKIP_HOST_KEY"); {
	case hk != "":
		cb, err := endpointagent.FixedHostKey(hk)
		if err != nil {
			return cfg, fmt.Errorf("PAM_AGENT_SERVER_HOST_KEY: %w", err)
		}
		cfg.HostKey = cb
	case strings.EqualFold(insecure, "true"):
		cfg.HostKey = ssh.InsecureIgnoreHostKey() // #nosec G106 -- explicit opt-in for demos only, documented as such
	default:
		return cfg, errors.New("PAM_AGENT_SERVER_HOST_KEY is required (run `ssh-keyscan -p 2222 <pam-host>` and paste the key), or set PAM_AGENT_INSECURE_SKIP_HOST_KEY=true for a demo")
	}
	if len(cfg.Servers) == 0 {
		return cfg, errors.New("PAM_AGENT_SERVERS is required (comma-separated host:port)")
	}
	if cfg.Name == "" || cfg.Key == "" {
		return cfg, errors.New("PAM_AGENT_NAME and PAM_AGENT_KEY are required")
	}
	return cfg, nil
}
