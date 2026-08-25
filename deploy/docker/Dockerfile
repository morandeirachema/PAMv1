# Base images are pinned BY DIGEST, not only by tag. A tag is a moving pointer:
# `golang:1.26-alpine` is a different image next week, so two builds of the same
# commit produce different binaries and neither the SBOM nor the SLSA provenance
# describes what the other shipped. Dependabot watches this directory weekly and
# raises the digest, so the pin is maintained rather than merely frozen — which is
# the same bargain the deployment manifests make with the pamv1 image tag itself.
FROM golang:1.27-alpine@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build
# VERSION and COMMIT are stamped into the binary so a running container can say
# what it is (`pam-server -version`, the startup log, and the pam_build_info
# metric). They default to a local-build marker; the release workflow passes the
# real values.
ARG VERSION=dev
ARG COMMIT=none
WORKDIR /src
COPY go.mod go.sum ./
# Cache the module downloads and the Go build cache across builds. Without the
# second mount every build compiles the standard library and every dependency
# from scratch, which is most of the wall clock: the layer cache only helps when
# nothing above it changed, and the whole point of the layer below is that the
# source DID change. `sharing=locked` because two concurrent builds writing one
# module cache corrupt it.
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o /out/pam-server ./cmd/pam-server

# Distroless, static, non-root: minimal attack surface for a credential vault.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:1b7b9f0f0e0a1d2155f531db587cc48ec26aaf97ab64364225f5bf18a054e66a
COPY --from=build /out/pam-server /pam-server
# Every listener the server can open, at its default address: the portal/API,
# the SSH session proxy, the PostgreSQL proxy and the SQL Server proxy. EXPOSE is
# documentation rather than enforcement, so an incomplete list is a reader
# quietly concluding a proxy does not exist. The database proxies default to
# `off`; they listen here only when PAM_DB_ADDR / PAM_MSSQL_ADDR are set.
EXPOSE 8080 2222 5433 1433
# Numeric UID (distroless nonroot = 65532) so Kubernetes runAsNonRoot can verify
# the container is non-root without resolving a username.
USER 65532:65532
# Distroless has no shell/curl, so probe via the binary's own -healthcheck flag.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
	CMD ["/pam-server", "-healthcheck"]
ENTRYPOINT ["/pam-server"]
