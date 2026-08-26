# Contributing to PAMv1

PAMv1 is an **educational, beta** PAM — built to be read, run and learned from.
Contributions are welcome under that framing: clarity beats cleverness, and a
change that makes the system easier to understand is as valuable as a feature.

## Ground rules

1. **Every change leaves the system functional end to end.** The project is
   built phase by phase with one rule: it runs, passes tests, and deploys as
   code after every merge. Do not land half of something.
2. **Docs move in the same change as the code.** The architecture docs, guides
   and READMEs are living documents (see [docs/README.md](docs/README.md)):
   if you change structure, packages, schema, wire formats, env vars or the
   audit vocabulary, update the relevant doc — and its change-log table — in
   the same PR.
3. **Security invariants are non-negotiable.** They are listed in
   [docs/ARCHITECTURE-LOW-LEVEL.md](docs/ARCHITECTURE-LOW-LEVEL.md) §6 —
   constant-time comparisons, secrets never serialized or logged, every secret
   use audited, AAD built only via the `store.*AAD` helpers. Treat them as
   tests written in prose.
4. **Tests exercise real behavior.** The house style avoids mocks on
   security-critical paths: the proxy tests dial a real in-process sshd that
   accepts only the vaulted password; `cmd/pam-server` tests boot the real
   server and shut it down with a real SIGTERM. Prefer that style.
5. **Report vulnerabilities privately** per [SECURITY.md](SECURITY.md), not in
   public issues.

## Building and testing

Go ≥ 1.26 and no Makefile — raw Go tooling:

```bash
go build ./...                # build everything
go test -race ./...           # what CI runs
gofmt -l .                    # must print nothing
go vet ./...
staticcheck ./...             # go install honnef.co/go/tools/cmd/staticcheck@latest
govulncheck ./...             # go install golang.org/x/vuln/cmd/govulncheck@latest
gosec -confidence high -exclude=G104,G115,G304,G306,G101 ./...
go run ./cmd/archgen          # regenerates docs/ARCHITECTURE-DIAGRAMS.md; CI diffs it
```

Run it locally with no database:

```bash
go build ./cmd/pam-server
export PAM_MASTER_KEY=$(./pam-server -genkey)
export PAM_API_KEY=$(openssl rand -hex 24)
export PAM_DATABASE_URL=memory
./pam-server                  # portal on :8080, SSH proxy on :2222
```

## Style

- Every Go function carries a doc comment. Write it for a developer who knows
  programming but not Go — say what the function is *for*, not what each line
  does.
- Code comments state constraints the code cannot show; they do not narrate.
- Diagrams in docs are Mermaid, not ASCII art.
- The portal is deliberately an AS/400 / IBM 5250 green-screen and
  keyboard-first. Do not modernize it.

## Pull requests

- Branch from `main`; keep one topic per PR.
- CI must be green: gofmt, vet, staticcheck, govulncheck, gosec, build, the
  architecture-diagram drift gate, `go test -race` (with live-Postgres, SoftHSM
  and manifest-validation jobs alongside).
- PRs are squash-merged; write the PR title as the commit subject you want in
  history.
- Never include a real credential, hostname or key in code, tests, issues or
  fixtures — including "temporarily".
