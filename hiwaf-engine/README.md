# HostingInside WAF

A web application firewall for HostingInside customer sites, built on
[Caddy](https://caddyserver.com) and [Coraza](https://coraza.io) with the
OWASP Core Rule Set (CRS). It has two programs:

- **`hi-waf`**: the engine. This is Caddy with coraza-caddy and our own
  modules compiled in:
  - `hi_access`: IP, country and custom rules
  - `hi_ratelimit`: access, attack and error limits, plus bans
  - `hi_auth`: a password gate
  - `hi_waitroom`: a waiting room
  - `hi_challenge`: a JS proof-of-work bot challenge
  - admin endpoints for bans and waiting-room counts
- **`manager`**: the control plane. It serves the web console and the REST
  API on one HTTPS port (9443), and keeps sites, certificates, IP groups,
  custom rules, console users and API tokens in SQLite. It compiles everything
  into one Caddy JSON config, pushes it to the engine's admin API, and reads
  the engine's security events and access log for the statistics and logs.

## How it fits together

```
internet ──► :80 / :443 ──► hi-waf engine ──► customer origin (upstream)
                               ▲      │
               config (JSON)   │      │ events.log, access.log
          /data/caddy-admin.sock│     ▼
                             manager ──► SQLite (/data/waf.db)
                               ▲
          console + REST API   │ :9443 (HTTPS)
          operators, website ──┘
```

**The engine and the manager must run on the same host.** The manager pushes
config to the engine's admin API, which has no login, and it reads the
engine's log files from local disk. `install.sh` puts the admin API on a unix
socket in the data volume (`/data/caddy-admin.sock`, owner-only), so nothing
else on the host network can reach it. A fresh engine starts on Caddy's default
`localhost:2019`; the manager's first push moves it to the socket.
`compose.yaml` runs both containers on the host network for
this reason.

## The console

- **Overview**: the request pipeline and what each stage stopped
- **Threats**: WAF detections, with a **false alarm** button that adds a
  per-rule exception to the site
- **Activity**: access, rate-limit, challenge and password-gate events
- **Sites**: each site's protections, in engine order (access rules, rate
  limits, password gate, queue, bot check, threat inspection)
- **Access**: allow and deny rules, IP groups and bans
- **Settings**: certificates, account with TOTP two-step sign-in, API tokens,
  rule sets, backups, alerts and system information

Detection is the OWASP CRS, not SafeLine's closed-source semantic engine. See
[Known limits](#known-limits).

## Install with Docker (recommended)

On a Linux host with Docker and the Compose plugin, from a checkout of this
repository:

```sh
sudo ./scripts/install.sh --open-firewall              # Let's Encrypt for site certificates
sudo ./scripts/install.sh --acme-internal --open-firewall   # lab: the WAF's own CA
```

- `--acme-internal` issues site certificates from the WAF's own CA instead of
  Let's Encrypt. Use it for labs and private domains; browsers will warn.
- `--open-firewall` opens 80/tcp, 443/tcp, 443/udp and the console port in
  firewalld. It does nothing on hosts without firewalld; open the ports in
  your cloud's security group instead.
- Environment: `HIWAF_DATA` (default `/data/hiwaf`), `HIWAF_CONSOLE_PORT`
  (default `9443`).

The script:

- checks that ports 80, 443 and 9443 are free
- writes `/data/hiwaf/manager.json`
- downloads the DB-IP Country Lite database for geo features
- builds the images `hiwaf-engine` and `hiwaf-manager` (two targets of one
  Dockerfile) and starts their containers, both on the host network
- prints the console URL `https://<server>:9443` and the generated `admin`
  password

Change the `admin` password and turn on two-step sign-in right after the first
login. Run the script again to upgrade; data in `/data/hiwaf` is kept.

To reset the console password:

```sh
docker exec hiwaf-manager manager -config /data/manager.json -resetadmin
```

Logs: `docker compose logs -f manager` and `docker compose logs -f engine`.

### Images and CI

```sh
docker build --target engine  -t hiwaf-engine .
docker build --target manager -t hiwaf-manager .
```

`.gitlab-ci.yml` runs on the `build` branch and on tags: gofmt, vet and the tests,
then both images are built with buildx and pushed to Harbor as
`<project>-engine:<short sha>` and `<project>-manager:<short sha>`; a tag also retags
them `:<tag>` and `:latest`. It needs the CI variables `HARBOR_HOST`,
`HARBOR_PROJECT`, `HARBOR_USERNAME` and `HARBOR_PASSWORD`, and a runner tagged `docker`.

## Deploy on an OpenStack VM

The WAF runs in an ordinary VM in the operator's own project, not on the
cloud's controller, compute or storage hosts.

1. **Network.** A private network with a router to the external network. Pick
   a subnet that doesn't overlap your internal ranges or Docker's
   `172.17.0.0/16`-`172.31.0.0/16`, and set its DNS servers (for example
   `1.1.1.1` and `8.8.8.8`); without them the VM can't resolve names and the
   install fails.
2. **Security group.**

   | Port | Protocol | Source | Why |
   |---|---|---|---|
   | 80 | TCP | `0.0.0.0/0` | Sites, and Let's Encrypt HTTP challenges |
   | 443 | TCP | `0.0.0.0/0` | Sites (HTTPS) |
   | 443 | UDP | `0.0.0.0/0` | HTTP/3 |
   | 9443 | TCP | Your office or VPN, as `/32` | Console and API |
   | 22 | TCP | Your office or VPN, as `/32` | SSH |

   Never open 9443 to the world: right after install the console is live
   with the first password and no two-step sign-in.
3. **Instance.** Ubuntu 24.04, 2 vCPU and 4 GB RAM is plenty for a pilot
   (see [memory per site](#known-limits)). Boot from a volume on shared
   storage (Ceph), not local disk, and keep the volume when the instance is
   deleted: `/data/hiwaf` holds every site's certificate private keys.
4. **Floating IP.** Attach one from the external network. Customers point
   their DNS at it.
5. **Install.** Install Docker from Docker's apt repository, clone this
   repository to `/opt/hiwaf`, and run `scripts/install.sh`.

Customer origins should accept 80/443 only from the WAF's floating IP, so the
WAF can't be bypassed.

## Many engines (transparent mode)

For an engine on every compute host, list the engines in `manager.json`.
The manager reaches each one over an SSH tunnel, never over TCP, because
the engine's admin API has no login:

```json
{
  "caddy_admin": "unix:///data/caddy-admin.sock",
  "event_log_net": "unix//data/events.sock",
  "engines": [
    {"name": "hk1-cmpt4", "admin": "unix:///run/hiwaf/hk1-cmpt4.sock", "event_listen": "127.0.0.1:7101"}
  ]
}
```

- `caddy_admin` and `event_log_net` are paths as the engines see them; the
  engine also keeps `event_log` as a local file, a backup for a dropped stream.
- One tunnel per engine forwards its admin socket here and its log socket
  back to `event_listen` (add `access_log_net` and `access_listen` for the
  access log):

  ```sh
  ssh -N -o ExitOnForwardFailure=yes -o StreamLocalBindUnlink=yes \
    -L /run/hiwaf/hk1-cmpt4.sock:/data/hiwaf/caddy-admin.sock \
    -R /data/hiwaf/events.sock:127.0.0.1:7101 hiwaf@hk1-cmpt4
  ```

  The compute host's sshd needs `StreamLocalBindUnlink yes` and
  `AllowStreamLocalForwarding all` for that user.
- A change is saved once one engine accepts it. Engines that missed it are
  retried every 10 seconds and raise the engine alert until they catch up.
- Start a fresh engine with a config that already moves its admin API to the
  socket: the manager can't reach Caddy's default `localhost:2019` on
  another host.
- Lines an engine logs while its tunnel is down are dropped.
- With `engines` set, the manager compiles for transparent mode:
  - HTTP/3 is off. Only TCP 80/443 is steered to the WAF, so a browser on
    HTTP/3 (UDP) would go around it. An origin's `Alt-Svc` header never
    reaches the browser either: Caddy drops it as a hop-by-hop header.
  - Sites need `tls.mode` `uploaded` or `off`. Every engine gets every site,
    and only the host that owns the floating IP could pass an ACME challenge.
  - Every host name served on a protected floating IP must be a site: the
    WAF answers unknown names with `404 unknown site` on HTTP and fails the
    TLS handshake on HTTPS.

## Steering on the compute hosts (`waf-steer`)

In transparent mode, `scripts/waf-steer.sh` runs on every compute host and
sends TCP 80/443 of protected floating IPs to that host's engine. Other
ports, and floating IPs not on the list, keep the normal Neutron path.

- Inside Neutron's `fip-*` namespace, packets arriving on `fg-*` for a
  listed IP get mark `0x1455`, routing table 1455 sends them over the veth
  `hiwaf-h`/`hiwaf-e` (`100.64.255.1`/`.2`) into the engine's network
  namespace, and ports 80/443 there are redirected to the engine.
- The engine sees the client's real address and proxies to the customer's
  floating IP. That connection takes the normal path to the VM, so the VM
  sees `100.64.255.2` as the source and the client in `X-Forwarded-For`. A
  security group that allows web traffic only from some addresses must
  also allow `100.64.255.2`.
- UDP 443 to a protected IP is dropped, so HTTP/3 can't go around the WAF.
- The engine runs as a container with `--network none`; `waf-steer`
  connects it, and reconnects it after a restart.
- `FAIL_MODE=open` (the default): if the engine is down, traffic goes
  straight to the VMs, unprotected. `FAIL_MODE=closed`: their web ports are
  unreachable until it is back.
- The service re-applies everything every 5 seconds, because Neutron can
  rebuild the namespace's iptables tables. Between a rebuild and the next
  pass, traffic takes the normal path.

The list is `/etc/hiwaf/waf-fips`, one IP per line, the same file on every
host: only IPs living on a host ever arrive there. It is built from the
sites' `floating_ip`. Lines that aren't plain IPv4 addresses are ignored.

```sh
install -m 755 scripts/waf-steer.sh /usr/local/sbin/
install -m 644 scripts/waf-steer.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now waf-steer
waf-steer.sh status
```

Stopping the service rolls everything back: `systemctl stop waf-steer`.
Settings go in `/etc/hiwaf/waf-steer.env`; see the top of the script.

`scripts/waf-steer-lab.sh` tests it on any Linux host with Docker, without
OpenStack: it rebuilds the floating-IP path in network namespaces and
checks steering, the WAF, fail-open and fail-closed, recovery and rollback.

## Manager configuration (`manager.json`)

`install.sh` writes this file. Unknown keys are rejected at start.

| Key | Default | Meaning |
|---|---|---|
| `listen` | `:9000` (`install.sh`: `:9443`) | Console and API address |
| `db_path` | `waf.db` | SQLite database |
| `data_dir` | the directory of `db_path` | Base for the defaults below |
| `skip_domain_check` | `false` | `true` lets projects add domains without the `_hiwaf` TXT proof (test servers only) |
| `caddy_admin` | `http://localhost:2019` (`install.sh`: `unix:///data/caddy-admin.sock`) | Engine admin API: a unix socket, or a localhost URL |
| `event_log`, `access_log` | `events.log`, none | Engine logs the manager reads |
| `api_keys` | none | Operator keys for `Authorization: Bearer <key>` |
| `http_port`, `https_port` | `80`, `443` | Default ports for sites |
| `acme_internal` | `false` | `true`: certificates from the WAF's own CA |
| `trusted_proxies` | none | CIDRs of load balancers in front of the engine |
| `geoip_db` | none | Country database (`.mmdb`); needed for country rules |
| `feeds_dir` | none | Directory of IP blocklist files |
| `static_dir` | none | Directory for static sites |
| `tls_cert`, `tls_key`, `self_signed_tls` | none | Console certificate; `self_signed_tls` generates one |
| `retention_days`, `event_retention_days` | `7`, `30` | How long access-log rows and events are kept |
| `backup_dir`, `backup_hours`, `backup_keep` | `<data_dir>/backups`, `24`, `7` | Scheduled backups; `backup_hours: -1` turns them off |
| `rulesets_dir`, `plugins_dir` | `<data_dir>/rulesets`, `<data_dir>/crs-plugins` | Extra CRS releases and app-profile plugins |
| `engines`, `event_log_net`, `access_log_net` | none | Several remote engines; see [Many engines](#many-engines-transparent-mode) |

The manager refuses to start if the example key `change-me-dev-key` is
configured while `listen` is not a loopback address (`127.0.0.1`, `::1` or
`localhost`).

For production:

- Set `http_port` to `80`, `https_port` to `443` and `acme_internal` to
  `false`.
- Set `trusted_proxies` if the engine sits behind a load balancer. The
  compiled config also sets Caddy's `trusted_proxies_strict`, so the client
  IP is read from `X-Forwarded-For` right to left, skipping trusted hops,
  and a client can't spoof an `allow_ips` address in that header.

## Site document

A site is one JSON document. Only `domains` and `upstreams` are required
(`upstreams` only for proxy sites). For every other field:

- If you leave it out, it gets its default.
- If you set it to `null`, that feature is off. This applies to the rate
  limits.

See `examples/site-shop.json` for a full example.

| Field | Meaning |
|---|---|
| `name`, `description` | Labels for the console |
| `project` | Owning project; see [Projects and API tokens](#projects-and-api-tokens) |
| `floating_ip` | Transparent mode: the customer's floating IP whose ports 80/443 the compute hosts steer to the WAF. Public IPv4 only. Only the operator sets it; a project's edits keep the stored value |
| `type` | `proxy` (default), `static` or `redirect` |
| `domains` | Host names; `*.example.com` wildcards are allowed |
| `ports` | `[{port, https}]`; omitted = the global HTTP and HTTPS ports |
| `upstreams` | Origins such as `10.0.0.5:8080` |
| `lb_policy` | `round_robin` (default), `ip_hash` or `least_conn` across upstreams |
| `redirect` | For redirect sites: `{url, code, preserve_path}`; code `301`, `302` (default), `307` or `308` |
| `advanced` | `{hsts, gzip, http_redirect, keep_host}`; the last two default to `true` |
| `tls` | `{mode, cert_id}`; mode `auto` (default), `uploaded` or `off` |
| `waf` | Detection settings, below |
| `rate_limit` | `{access, attack, error}`, below |
| `access` | IP, country and custom rules, below |
| `bot_challenge` | `{enabled, difficulty}`; difficulty 1-6, default 4 |
| `auth` | Password gate: `{enabled, users: [{username, password}], session_ttl_sec}`. Passwords are hashed before they are stored |
| `waiting_room` | `{enabled, max_active, session_ttl_sec}` |
| `block_page` | `{title, message}` for the 403 page |
| `exclusions` | Per-rule exceptions, below |

Static sites serve files uploaded with `POST /sites/{id}/static`; they need
`static_dir`.

### WAF (`waf`)

- `mode`: `block` (the default), `detect` (log only) or `off`.
- `paranoia`: 1-4, default 1.
- `anomaly_threshold`: default 5.
- `protections`: checkboxes, below.
- `apps`: app profiles, below.

### Protection checkboxes (`waf.protections`)

The keys you set are merged over the defaults, so a key you leave out keeps
its default.

| Key | Protection | CRS rule IDs | Default |
|---|---|---|---|
| `sqli` | SQL injection | 942000-942999 | on |
| `xss` | Cross-site scripting | 941000-941999 | on |
| `rce` | Command injection | 932000-932999 | on |
| `lfi` | Path traversal / local file | 930000-930999 | on |
| `rfi` | Remote file inclusion | 931000-931999 | on |
| `php` | PHP injection | 933000-933999 | on |
| `nodejs` | Node.js injection | 934000-934999 | on |
| `java` | Java / deserialization | 944000-944999 | on |
| `session_fixation` | Session fixation | 943000-943999 | on |
| `scanner` | Scanner / bad-bot detection | 913000-913999 | on |
| `protocol` | Protocol attacks + enforcement | 920000-922999 | on |
| `data_leak` | Response data leakage (needs response body inspection) | 950000-956999 | **off** |

### App profiles (`waf.apps`)

An app profile loads the official CRS exclusion plugin for that application,
so its normal admin work isn't blocked. `GET /api/v1/apps` lists them:
`wordpress`, `drupal`, `nextcloud`, `phpmyadmin`, `dokuwiki`, `phpbb` and
`xenforo`. The plugins ship inside the manager, with their licenses, under
`manager/crsplugins/files/`.

### Per-rule exceptions (`exclusions`)

An exception turns one CRS rule off where it raised a false alarm: on the
whole site, on one path, for one field, or for one field on one path.

```json
{"rule_id": 942100, "path_prefix": "/search", "field": "ARGS:q", "note": "search box"}
```

- `rule_id` must be an attack or protocol rule, not a CRS set-up or scoring
  rule.
- `path_exact` or `path_prefix` limits it to a path.
- `field` is a Coraza variable such as `ARGS:q` or `REQUEST_COOKIES:consent`.
- A site holds at most 200 exceptions.

The console's **false alarm** button calls
`POST /api/v1/sites/{id}/exclusions` with one exception.

### Rate limits (`rate_limit`)

Each limit is `{requests, window_sec, ban_sec}`.

- `attack` counts WAF blocks. Default `{10, 60, 1800}`.
- `error` counts 4xx and 5xx responses, except the WAF's own 403s. Default
  `{50, 60, 600}`.
- `access` counts every request. It is **off** unless you set it.

### Access (`access`)

- `allow_ips` and `block_ips` take IPs or CIDRs.
- `allow_countries` and `block_countries` take ISO codes and need `geoip_db`.
- `allow_groups` and `block_groups` take shared IP group IDs.
- `block_ips_file` is described in the next section.
- `rules` are custom rules, evaluated in order. The first match wins.
  - A `block` rule returns 403.
  - An `allow` rule skips the rate limits, the challenge and the WAF. For
    that reason it must include an `ip`, `path_exact` or `path_prefix`
    condition, and every request it lets through is logged as
    `allowed_by_rule`. An `allow` rule never matches a request path that
    contains `;` or a `..` segment, because backends disagree about what
    such paths mean.

Global custom rules (`/api/v1/rules`) run before a site's own rules, on every
site or on the sites they list.

### IP blocklist feeds (`feeds_dir` + `block_ips_file`)

To block a large or frequently updated IP list, set `feeds_dir` in the
manager config to a directory, for example `"feeds_dir": "feeds"`. Put plain
text files in it with one IP or CIDR per line.

In the site, set `"access": {"block_ips_file": "bad-ips.txt"}`:

- It must be a bare file name. The engine reads `<feeds_dir>/bad-ips.txt`.
- A site that sets `block_ips_file` is rejected while `feeds_dir` is empty.

The engine reads the file only when it loads a config. Caddy ignores a load
whose config hasn't changed, so re-PUTting an unchanged site doesn't pick up
a new file. An updated file takes effect at the next real config change or
the next engine restart.

### The JS challenge blocks non-browser clients

With `bot_challenge.enabled`, a GET or HEAD request that accepts `text/html`
and has no clearance cookie gets a proof-of-work page. Every other request
without the cookie gets **403**. This includes API clients, webhooks, mobile
apps and `curl`.

The challenge is off by default. Turn it on only for sites that browsers
use. You can exempt machine paths with an `allow` rule such as
`{"action":"allow","match":{"path_prefix":"/api/"}}`, but remember that an
`allow` rule also skips the WAF.

## Projects and API tokens

Sites can belong to a **project** (for example an OpenStack project ID), so
one WAF can serve many customers without them seeing each other.

- **Operator callers** (an `api_keys` key, an operator token or a console
  session) see everything. They can act for one project by sending the header
  `X-Project-Id: <project>`.
- **Project tokens** are created with a project:
  `POST /api/v1/tokens {"name": "...", "project": "...", "expires_days": 90}`.
  The token is shown once. It only ever acts for that project.
  `expires_days` (1-3650) makes a token stop working after that many days;
  0 or absent means it never expires. Any token can be revoked at any time.
- A project caller sees and changes only its own sites. Other projects' sites
  answer 404, as if they didn't exist.
- A project's site is checked more strictly, because tenants share the
  engine:
  - no `*` domain, and a wildcard needs two labels after `*.`
  - at most 100 sites per project (403 after that)
  - no custom `ports`
  - `upstreams` must be public IP addresses: not host names, and not
    loopback, private (10/8, 172.16/12, 192.168/16, fc00::/7), CGNAT
    (100.64/10), link-local (cloud metadata) or multicast
  - no shared certificates (`tls.cert_id`) or shared IP groups
- Shared objects (certificates, IP groups, global rules), backups, rule sets,
  alerts, tokens and the system page are operator-only.

The intended flow for a hosting website: your backend checks the customer's
login, then calls the manager with its own operator key and
`X-Project-Id` set to the customer's project.

## API reference

All routes are under `/api/v1` and need `Authorization: Bearer <key or
token>`, except `POST /auth/login`. "Project" means a project caller may use
the route for its own sites; every other route is operator-only.

| Route | Project | What it does |
|---|---|---|
| `GET /sites`, `POST /sites` | yes | List or create sites |
| `GET/PUT/PATCH/DELETE /sites/{id}` | yes | Read, replace, change or delete a site |
| `POST /sites/{id}/exclusions` | yes | Add a per-rule exception |
| `POST /sites/{id}/certificate` | yes | Upload a site's certificate and key (PEM) |
| `POST /sites/{id}/static` | yes | Upload files for a static site |
| `GET /events`, `/stats`, `/stats/overview` | yes, `?site=` | Events and statistics |
| `GET /attacks`, `/attacks/groups` | yes, `?site=` | WAF detections |
| `GET /attacks/{tx}` | yes | One detection's detail |
| `GET /logs`, `/logs/groups` | yes, `?site=` | Access log |
| `GET /bans`, `DELETE /bans` | yes, `?site=` | List or lift bans |
| `GET /protections`, `GET /apps` | yes | Protection checkboxes and app profiles |
| `GET /auth/me` | yes | Who the caller is |
| `GET /site-counts` | | Site counts |
| `/certificates`, `/ip-groups`, `/rules` (+ `/{id}`) | | Shared certificates, IP groups and global rules |
| `GET /waitroom` | | Waiting-room counts |
| `GET /system` | | System information |
| `GET /rulesets`, `PUT /rulesets/active` | | CRS releases and the active one |
| `GET/POST /backups`, `GET /backups/{name}` | | List, create or download backups |
| `GET/PUT /alerts`, `POST /alerts/test` | | Alert settings and a test alert |
| `POST /auth/login`, `/auth/logout`, `/auth/password` | | Console sign-in and password |
| `POST /auth/totp/setup`, `/enable`, `/disable` | | Two-step sign-in |
| `GET/POST /tokens`, `DELETE /tokens/{id}` | | API tokens |

## Walkthrough with curl

This uses the development setup from [Development](#development), with the
API on `localhost:9000`. In PowerShell, use `curl.exe` and adjust the quoting.

```sh
API=http://localhost:9000/api/v1
AUTH="Authorization: Bearer change-me-dev-key"

# 1. Create a site from the example document. The response includes the
#    site's "id" (s_ + 12 hex) and the fully resolved settings.
curl -s -H "$AUTH" -H "Content-Type: application/json" \
     --data @examples/site-shop.json $API/sites
SITE=s_xxxxxxxxxxxx   # paste the id from the response

# 2. Send an SQL injection. The WAF answers 403 with the site's block page.
#    -k: the certificate is from Caddy's internal CA. --resolve points the
#    domain at the local engine.
curl -sk -o /dev/null -w '%{http_code}\n' \
     --resolve shop.example.com:8443:127.0.0.1 \
     "https://shop.example.com:8443/?id=1%27%20OR%20%271%27=%271"
#    -> 403. (A clean request gets 502 here, because the example upstream
#    10.0.0.5:8080 doesn't exist. The WAF blocks before the proxy is tried.)

# 3. List the events. You should see "waf_block" with rule_id 942xxx.
curl -s -H "$AUTH" "$API/events?site=$SITE"
curl -s -H "$AUTH" "$API/events?site=$SITE&type=waf_block"
curl -s -H "$AUTH" "$API/stats?site=$SITE&window=1h"

# 4. Get banned. The default attack limit is 10 WAF blocks in 60 s, which
#    bans the IP for 1800 s. Banned requests get 429 with Retry-After.
for i in $(seq 1 11); do
  curl -sk -o /dev/null -w '%{http_code} ' --resolve shop.example.com:8443:127.0.0.1 \
       "https://shop.example.com:8443/?id=1%27%20OR%20%271%27=%271"
done; echo

# 5. List the bans, then lift one.
curl -s -H "$AUTH" "$API/bans?site=$SITE"
curl -s -o /dev/null -w '%{http_code}\n' -X DELETE -H "$AUTH" \
     "$API/bans?site=$SITE&ip=127.0.0.1"
#    -> 204, or 404 if the IP isn't banned.
```

### Uploaded certificates

A site with `tls.mode` set to `uploaded` can't be saved until its
certificate exists. Use this order:

```sh
# 1. Create the site with TLS off. It uses a new domain, because
#    shop.example.com exists from the walkthrough above and a duplicate
#    domain gets 400.
curl -s -H "$AUTH" -H "Content-Type: application/json" $API/sites \
     -d '{"domains":["secure.example.com"],"upstreams":["10.0.0.5:8080"],"tls":{"mode":"off"}}'
SITE=s_xxxxxxxxxxxx   # paste the id from the response

# 2. Upload the certificate and key (PEM) for that site.
jq -n --rawfile c cert.pem --rawfile k key.pem '{cert_pem:$c, key_pem:$k}' |
  curl -s -H "$AUTH" -H "Content-Type: application/json" --data @- \
       $API/sites/$SITE/certificate

# 3. Switch the site to the uploaded certificate. PUT replaces the whole
#    document.
curl -s -X PUT -H "$AUTH" -H "Content-Type: application/json" $API/sites/$SITE \
     -d '{"domains":["secure.example.com"],"upstreams":["10.0.0.5:8080"],"tls":{"mode":"uploaded"}}'
```

## Operating it

Everything below is also in the console under **Settings > System**.

**Rule set updates.** The engine has CRS 4.25.0 built in. To run a newer
release, install it on the server; the script only installs a release that
the CRS project's signing key (fingerprint pinned in the script) signed:

```bash
bash scripts/crs-install.sh 4.30.0      # unpacks into /data/hiwaf/rulesets/4.30.0
```

Then pick it in the console, or `PUT /api/v1/rulesets/active` with
`{"version":"4.30.0"}` (`""` = built-in). The switch is a config reload, so
no connection is dropped. If the engine can't load the rules, the switch is
refused and the current rules keep running. It needs at least one site with
the WAF on, because only then does the engine parse the rules. Upgrading the
engine binary itself still needs a container restart (a second or two of
downtime on a single node).

**Backups.** The manager copies its database to `/data/hiwaf/backups` a
minute after it starts, then every `backup_hours` (default 24; -1 turns the
schedule off), and keeps the newest `backup_keep` (default 7). A backup holds
the sites, rules, certificates with their keys, users and security events,
but not the access log. The files are mode 0600; treat downloaded copies as
secrets, and copy them off the WAF host. To restore one:

```bash
docker compose -f /opt/hiwaf/compose.yaml stop manager
docker compose -f /opt/hiwaf/compose.yaml run --rm manager manager -config /data/manager.json -restore /data/backups/waf-20261027-030000.db
docker compose -f /opt/hiwaf/compose.yaml start manager
```

The current database is kept beside the restored one as
`waf.db.before-restore-<time>`.

**Alerts.** Set a webhook (Slack, Discord or any JSON endpoint) to hear when
the engine stops answering for a minute, when it is back, and when a
scheduled backup fails. The manager runs on the same host, so it can't report
that the whole host is down: for that, set a heartbeat URL from an outside
monitor (Healthchecks.io, Uptime Kuma). The manager pings it every 30 s while
the engine is healthy, and the monitor alerts when the pings stop.

**Console exposure.** The console listens on `:9443` on every interface.
Sign-in is limited to 5 failures per address (per /64 for IPv6) and 50 per
account in 15 minutes. Turn on two-step sign-in, and allow `9443` only from
your office or VPN in the firewall.

**Engine restarts.** `hi-waf run --resume` starts from the last config it was
given, so sites keep working if the manager is down. If the manager can't
reach the engine, the API still starts, but any change returns `503` and is
rolled back.

## Development

- **Go 1.27 or later** (our `go.mod` says 1.27.0). You don't
  need xcaddy, because `cmd/hi-waf` is our own Caddy main.
- **Node 26** (LTS) for the console.

```sh
(cd console && npm ci && npm run build)   # builds into manager/console/dist
go build -o bin/hi-waf ./cmd/hi-waf
go build -o bin/manager ./cmd/manager

bin/hi-waf run --resume                       # engine first
bin/manager -config examples/manager.json     # then the manager
```

Without the console build, the manager shows a "Console not built" page.

In `examples/manager.json`:

- The API listens on `127.0.0.1:9000` only, and the key
  `change-me-dev-key` authenticates as
  `Authorization: Bearer change-me-dev-key`.
- The engine admin API is `http://127.0.0.1:2019`.
- Sites are served on HTTP port `8080` and HTTPS port `8443`.
- `acme_internal` is `true`, so certificates come from Caddy's local CA
  instead of Let's Encrypt.

Console work:

- `npm run dev` serves the console with live reload and proxies `/api` to a
  manager on `https://localhost:9443` (override with `HIWAF_API`).
- `npm run build:demo` builds a self-contained copy with sample data and no
  API into `console/dist-demo`, for design review and screenshots.

Tests:

```sh
go vet ./...
go test ./...          # includes end-to-end tests that start Caddy on ports 9080 and 2999
go test -short ./...   # skips them
```

CI (`.github/workflows/ci.yml`) runs gofmt, `go vet`, `go test -race`, the
console build and the Docker build on every push to `main` and on pull
requests.

If `go mod download` fails with TLS or certificate errors, a network filter is
probably intercepting `proxy.golang.org`. Point Go at another module proxy,
for example:

```sh
export GOPROXY=https://goproxy.io,direct GOSUMDB="sum.golang.org https://sum.golang.google.cn"
```

`GOSUMDB` points at Google's official mirror of the checksum database, so
every module is still verified.

## Known limits

- **Detection is the OWASP CRS at paranoia 1 by default.** It misses some
  attacks SafeLine's semantic engine catches (for example `;cat /etc/passwd`
  in a query parameter) and has more false positives. Raise the detection
  level per application, use app profiles and exceptions for false alarms,
  and measure false positives in `detect` mode before production.
- **Memory per site.** Each site gets its own Coraza instance with the CRS
  loaded. Measured with CRS 4.30.0 on one engine with no traffic: about 55 MB
  idle, about 40 MB for the first site, then about 1 MB per site when sites
  share the same WAF settings and about 4 MB per site when every site's
  settings differ. So 100 distinct sites need about 0.5 GB. A config reload
  rebuilds every site (0.2 s at 100 sites, growing with the site count), so
  keep the number of sites per engine bounded.
- **Many engines are a preview.** With `engines` set, the manager pushes to
  several engines and receives their logs over the network (see
  [Many engines](#many-engines-transparent-mode)). Every engine gets every
  site, so with `tls.mode: auto` each engine tries to get every site's
  certificate; only the one holding the site's address can pass the
  challenge. Use uploaded certificates until that is solved.
- **Single node, in-memory state.** Rate-limit counters and bans live in the
  engine process. They survive config reloads but not a restart, and they
  aren't shared between engines.
- **IPv6 limits apply per /64.** Rate limits and bans count an IPv6 client
  by its /64, because one client usually holds a whole /64 and could
  otherwise use a fresh address per request. An IPv6 ban is listed as its
  /64 and can be lifted with that prefix or any address in it. Clients that
  share a /64 share their limits.
- **Counters are capped per site.** At 100,000 tracked sources a site drops
  idle counters, then an arbitrary tenth of the rest. Bans are kept.
- **coraza-caddy error-string coupling.** `hi_ratelimit` recognises a WAF
  block by parsing the error text coraza-caddy returns. A test pins this
  format, but a coraza-caddy upgrade can break it.
- **`data_leak` buffers response bodies.** This costs memory and latency,
  which is why it is off by default.
- **The JS challenge blocks non-browser clients** (see above).
- **No Caddyfile support.** The engine is configured only through JSON from
  the manager.
- **Statistics come from the access log.** Rows are kept 7 days
  (`retention_days`) and events 30 days (`event_retention_days`) in SQLite,
  which suits one node and modest traffic.
- **No OpenStack integration yet.** The manager doesn't check Keystone tokens
  or change security groups; the hosting website's backend does that and
  calls the manager with `X-Project-Id`.

## Layout

```
cmd/hi-waf/     engine main (Caddy + coraza-caddy + hi_* modules)
cmd/manager/    manager main
engine/         Caddy modules: access, auth, challenge, ratelimit, waitroom, events, clientip
manager/        api, store (SQLite), compile (site -> Caddy JSON), caddyclient, ingest,
                site (document, defaults, validation), crsplugins (app profiles),
                backup, alert, console (embedded UI)
console/        web console source (React + Vite; npm run build -> manager/console/dist)
scripts/        install.sh (Docker install), crs-install.sh (signed CRS releases)
integration/    end-to-end engine tests (in-process Caddy)
examples/       manager.json, site-shop.json (development only)
```
