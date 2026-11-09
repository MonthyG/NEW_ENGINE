# Build context is the repository root:
#   docker build --target engine  -t hiwaf-engine .
#   docker build --target manager -t hiwaf-manager .
#
# Both run on the host network (see compose.yaml). All config lives on the /data volume
# (manager.json, the database, Caddy's certificates), so one image works everywhere.

FROM debian:trixie-20261104-slim AS base
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tzdata curl \
 && rm -rf /var/lib/apt/lists/*
# Caddy keeps certificates, its CA and the autosaved config (for --resume) under the data volume.
ENV XDG_DATA_HOME=/data/caddy XDG_CONFIG_HOME=/data/caddy-config
VOLUME /data
WORKDIR /data

# ============================================
# Console (React), embedded into the manager
# ============================================

# package.json without its version, so a version bump doesn't invalidate the install layer.
FROM node:26.13.0-slim AS console-manifest
WORKDIR /src/console
COPY console/package.json ./
RUN sed -i '/^  "version":/d' package.json

FROM node:26.13.0-slim AS build-console
WORKDIR /src/console
COPY --from=console-manifest /src/console/package.json ./
COPY console/package-lock.json ./
RUN --mount=type=cache,id=npm,target=/root/.npm \
    npm ci --no-audit --no-fund
COPY console/ ./
# tsc --noEmit, then the production build into /src/manager/console/dist.
RUN npm run build

# ============================================
# Go
# ============================================
FROM golang:1.27.3-trixie AS go-deps
ENV CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,id=gomod,target=/go/pkg/mod \
    go mod download
COPY . .

FROM go-deps AS build-engine
RUN --mount=type=cache,id=gomod,target=/go/pkg/mod \
    --mount=type=cache,id=gobuild,target=/root/.cache/go-build \
    go build -trimpath -ldflags="-s -w" -o /out/hi-waf ./cmd/hi-waf

FROM go-deps AS build-manager
COPY --from=build-console /src/manager/console/dist/ ./manager/console/dist/
RUN --mount=type=cache,id=gomod,target=/go/pkg/mod \
    --mount=type=cache,id=gobuild,target=/root/.cache/go-build \
    go build -trimpath -ldflags="-s -w" -o /out/manager ./cmd/manager

# ============================================
# Manager (API + console on :9443): docker build --target manager -t hiwaf-manager .
# ============================================
# Both images run as root: the engine binds 80/443 on the host network, and the two
# share the root-owned /data volume.
FROM base AS manager
COPY --from=build-manager /out/manager /usr/local/bin/
CMD ["manager", "-config", "/data/manager.json"]

# ============================================
# Engine (Caddy + Coraza, serves the sites): docker build --target engine -t hiwaf-engine .
# ============================================
FROM base AS engine
COPY --from=build-engine /out/hi-waf /usr/local/bin/
CMD ["hi-waf", "run", "--resume"]
