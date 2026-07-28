<!-- PRs are squash-merged: the PR title becomes the commit subject. -->

## What

<!-- What changes, and why. Link the ROADMAP phase or SECURITY-GAPS finding if one applies. -->

## Checklist

- [ ] `go test -race ./...` passes; new behavior is exercised by a real test
      (no mocks on security-critical paths)
- [ ] `gofmt -l .` prints nothing; `go vet`, `staticcheck`, `govulncheck`,
      `gosec` are clean
- [ ] `go run ./cmd/archgen` produces no diff (required after route/store/schema
      changes)
- [ ] Living docs updated **in this PR** (architecture docs + change-log,
      guides, READMEs) if structure, env vars, schema, wire formats or the
      audit vocabulary changed
- [ ] Sensitive actions append an audit event with an actor; no secret is
      logged, serialized or committed
