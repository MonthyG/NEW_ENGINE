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
HIWAF_API=https://<manager-host>:9443 npm run dev
```

## Build

```bash
npm run build        # → dist/   (the real UI, calls the live API)
npm run build:demo   # → dist-demo/   (sample data, no API; for review/screenshots)
```

## How it reaches the WAF

The UI authenticates to the manager API with a console login (session cookie) or
an API token (`Authorization: Bearer hiw_...`). The manager API and the engine
stay on the VM; nothing here connects to the engine directly.
