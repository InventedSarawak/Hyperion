# syntax=docker/dockerfile:1.7
#
# One Dockerfile for every Go service: they are built the same way, and three
# copies of the same file would drift. The service is chosen at build time:
#
#   docker build -f deploy/docker/go-service.Dockerfile \
#     --build-arg APP=cortex --build-arg CMD=server -t hyperion/cortex .
#
# The context is the repository root (see .dockerignore, an allowlist).

ARG GO_VERSION=1.26

# --- build -------------------------------------------------------------------
FROM golang:${GO_VERSION}-alpine AS build

ARG APP
ARG CMD

# Static, so the runtime image needs no libc. GOWORK=off builds the service as
# its own module: each go.mod points at the shared packages with a replace
# directive, so the workspace — which names every app in the repo — is not
# needed, and would fail on the apps this context leaves out.
ENV CGO_ENABLED=0 GOWORK=off GOFLAGS=-trimpath

WORKDIR /src

# Module files first, on their own layer: dependencies change far less often
# than code, and this layer is then reused across nearly every rebuild.
COPY packages/common/go.mod packages/common/go.sum packages/common/
COPY packages/contracts/go.mod packages/contracts/go.sum packages/contracts/
COPY apps/${APP}/go.mod apps/${APP}/go.sum apps/${APP}/
RUN --mount=type=cache,target=/go/pkg/mod \
    cd apps/${APP} && go mod download && \
    cd /src/packages/common && go mod download

COPY packages/common packages/common
COPY packages/contracts packages/contracts
COPY apps/${APP} apps/${APP}

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    cd apps/${APP} && go build -ldflags="-s -w" -o /out/service ./cmd/${CMD} && \
    cd /src/packages/common && go build -ldflags="-s -w" -o /out/probe ./health/cmd/probe

# --- run ---------------------------------------------------------------------
# Distroless: the binary, CA certificates, tzdata and a nonroot user, and
# nothing else — no shell, no package manager. Every tool in an image is one an
# intruder can use. The healthcheck runs /probe, the one tool it carries.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/service /service
COPY --from=build /out/probe /probe

USER nonroot:nonroot
ENTRYPOINT ["/service"]
