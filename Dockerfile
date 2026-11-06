# HI WAF dashboard: build the SPA, then serve the static files with nginx.

FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
# Serves the built SPA. By default it only serves the UI; to proxy /api straight to a
# WAF manager for standalone testing, set WAF_API and uncomment the block in nginx.conf.
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/templates/default.conf.template
EXPOSE 80
