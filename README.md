# HostingInside WAF

A web application firewall for HostingInside customer sites, built on
[Caddy](https://caddyserver.com), [Coraza](https://coraza.io) and the OWASP
Core Rule Set.

| Folder | What it is |
|---|---|
| [`hiwaf-engine/`](hiwaf-engine/) | The engine (`hi-waf`: Caddy + Coraza + our modules) and the control plane (`manager`: REST API, console, SQLite), in Go. |

The customer-facing dashboard (React + Vite) lives in its own repository,
[`cloudinside-dashboard`](https://github.com/MonthyG/cloudinside-dashboard). It's only a UI and talks to the manager API.

```
Browser ──► Dashboard ──► manager API (:9443) ──► hi-waf engine ──► customer origin
                                                     ▲
                                internet :80/:443 ───┘
```

## Two ways to deploy

- **CNAME mode** (today): one WAF VM. Customers point their DNS at its
  floating IP. See [Deploy on an OpenStack VM](hiwaf-engine/README.md#deploy-on-an-openstack-vm).
- **Transparent mode** (preview): an engine on every compute host, with web
  traffic for protected floating IPs steered to it, so customers change nothing.
  The manager drives all engines; see
  [Many engines](hiwaf-engine/README.md#many-engines-transparent-mode).

## Quick start

```sh
cd hiwaf-engine && sudo ./scripts/install.sh --acme-internal   # engine + manager on one host
```

## Tests

```sh
cd hiwaf-engine && gofmt -l cmd engine manager integration && go vet ./... && go test -race ./...
```

The engine's README has the details: configuration, the API, operations and
known limits.
