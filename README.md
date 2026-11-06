# HI WAF Dashboard

The web dashboard (UI) for HostingInside's WAF service. React + Vite + TypeScript.

This is **only the UI**. It has no logic of its own: it talks over HTTP to the
WAF **manager API**, which runs next to the Coraza engine on the WAF VM. Keeping
the UI here lets the web team work on it in GitLab without touching the engine.

```
Browser → this dashboard → manager API (on the WAF VM) → Coraza engine
```

## Run it locally

```bash
npm install
npm run dev
```

`npm run dev` serves the UI and proxies `/api` to a manager at
`https://localhost:9443`. To point it at another manager:

```bash
cp .env.example .env   # then set HIWAF_API=https://<manager-host>:9443
```

## Build

```bash
npm run build        # → dist/   (the real UI, calls the live API)
npm run build:demo   # → dist-demo/   (sample data, no API; for review/screenshots)
```

## Docker

```bash
docker build --target runner -t hiwaf-dashboard .
docker run -p 8080:8080 -e WAF_IP=223.26.0.228 hiwaf-dashboard
```

Settings come from the environment at runtime (served to the page as `/env.js`), so one
image works in every environment. `--target demo` builds the sample-data copy. nginx runs as
a non-root user on port 8080.

## CI

`.gitlab-ci.yml` runs on the `build` branch and on tags, like the portal's: it builds the
`runner` and `demo` images with buildx and pushes them to Harbor as `:<short sha>`; a tag
also retags them `:<tag>` and `:latest`. It needs the CI variables `HARBOR_HOST`,
`HARBOR_PROJECT`, `HARBOR_USERNAME` and `HARBOR_PASSWORD`, and a runner tagged `docker`.

## How it reaches the WAF

The UI authenticates to the manager API with a console login (session cookie) or
an API token (`Authorization: Bearer hiw_...`). The manager API and the engine
stay on the VM; nothing here connects to the engine directly.

## Customer view (what moves into the portal)

When the API caller is a customer's project token (`/auth/me` returns `kind: "token"`
with a `project`), the dashboard shows only that customer's sites and hides the
operator pages (Allow & Deny, Settings, engine status). A customer with no site
yet lands on `/welcome`:

1. **Protect your website?** Yes, or Not now (nothing is set up).
2. **Your website**: domain (+ www) and the server's IP and port.
3. **Point your domain at the WAF**: the A records to set, with a DNS check.
4. Then the normal dashboard. The site saved in the manager is the record that
   setup is done, so the next sign-in goes straight to the dashboard.

The IP shown in step 3 is `WAF_IP` in the container (`VITE_WAF_IP` in `.env` for `npm run dev`). Try the flow in the demo:
`npm run dev -- --mode demo`, then open `/#/welcome?as=customer`.
