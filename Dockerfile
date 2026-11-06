# Build context is the repository root:
#   docker build --target runner -t hiwaf-dashboard .
#   docker build --target demo   -t hiwaf-dashboard-demo .
#
# All app config is read from the environment at runtime, so one image works everywhere:
#   docker run -p 8080:8080 -e WAF_IP=223.26.0.228 hiwaf-dashboard

FROM node:26.13.0-slim AS base
WORKDIR /app

# ============================================
# Manifest
# ============================================

# package.json without its version, so a version bump doesn't invalidate the install layer.
FROM base AS manifest
COPY package.json ./
RUN sed -i '/^  "version":/d' package.json

# ----------------------------
# Install dependencies
# ----------------------------
FROM base AS build-deps
COPY --from=manifest /app/package.json ./
COPY package-lock.json ./
RUN --mount=type=cache,id=npm,target=/root/.npm \
    npm ci --no-audit --no-fund
COPY . .

# ----------------------------
# Build (tsc --noEmit runs first, so a type error fails the image)
# ----------------------------
FROM build-deps AS build-runner
RUN npm run build

FROM build-deps AS build-demo
RUN npm run build:demo

# ============================================
# Serve: nginx as a non-root user, on 8080
# ============================================
FROM nginxinc/nginx-unprivileged:1.31.7-alpine AS serve
# Defaults for the runtime settings in nginx.conf (written into /env.js at start).
ENV WAF_IP=""
COPY nginx.conf /etc/nginx/templates/default.conf.template
EXPOSE 8080

# ============================================
# Demo (sample data, no API): docker build --target demo -t hiwaf-dashboard-demo .
# ============================================
FROM serve AS demo
COPY --from=build-demo --chown=nginx:nginx /app/dist-demo /usr/share/nginx/html

# ============================================
# Runner: the real dashboard, calls the manager API
# ============================================
FROM serve AS runner
COPY --from=build-runner --chown=nginx:nginx /app/dist /usr/share/nginx/html
