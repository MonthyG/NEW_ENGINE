# Deploy the WAF on a compute host, from GitHub

This guide takes you from nothing to a working WAF in front of one floating
IP, in transparent mode: the customer keeps their IP and DNS, nothing is
installed in their VM, and only their TCP 80/443 goes through the WAF.

You only need three things: **a laptop**, **the GitHub repo**, and **a
compute host**. No build server, no Docker on the laptop, nothing on the
controller or storage. GitHub builds the engine image; the laptop downloads
it and sends it to the compute host over SSH.

```
GitHub (code + built image) ──gh──► laptop ──ssh──► compute host (engine + waf-steer)
```

Every command says **where** it runs and **why**. It's the procedure first
run on `hk1-cmpt4` on 13 Nov 2026; the example values are from that run.

- [What you end up with](#what-you-end-up-with)
- [Before you start](#before-you-start)
- [Part 0: a VM to protect](#part-0-a-vm-to-protect)
- [Part 1: get the code](#part-1-get-the-code)
- [Part 2: get the engine image from GitHub](#part-2-get-the-engine-image-from-github)
- [Part 3: copy the image to the compute host](#part-3-copy-the-image-to-the-compute-host)
- [Part 4: install on the compute host](#part-4-install-on-the-compute-host)
- [Part 5: protect a floating IP](#part-5-protect-a-floating-ip)
- [Part 6: test it](#part-6-test-it)
- [Part 7: keep it running](#part-7-keep-it-running)
- [Undo everything](#undo-everything)
- [Troubleshooting](#troubleshooting)

---

## What you end up with

```
internet ──► br-ex ──► fip namespace (Neutron) ──┬─ TCP 80/443 to a listed IP ──► veth ──► engine (cloudinside-waf)
                                                 │                                              │ clean request
                                                 │                                              ▼
                                                 └─ everything else ──────────────► qrouter ──► customer VM
```

On the compute host there are three pieces:

| Piece | What it is | Where |
|---|---|---|
| Engine | Docker container `cloudinside-waf` (Caddy + Coraza + OWASP CRS), started with no network of its own | `docker ps` |
| Engine config | Which sites it serves and where it forwards them | `/etc/hiwaf/engine.json` |
| `waf-steer` | systemd service that connects the engine to Neutron's fip namespace and steers listed IPs to it, re-checking every 5 s | `/usr/local/sbin/waf-steer.sh`, `/etc/systemd/system/waf-steer.service` |
| The list | Floating IPs to protect, one per line | `/etc/hiwaf/waf-fips` |

Nothing goes on the controller, storage, or any customer VM.

## Before you start

You need:

- **A laptop** with macOS or Linux (on Windows, use WSL), with `git`, `ssh`
  and `curl`. They're already there on a Mac.
- **The GitHub CLI** `gh`, to download the image GitHub builds:
  `brew install gh` on a Mac, then `gh auth login` once (pick GitHub.com,
  SSH, and log in with the browser). *Why:* the repo `MonthyG/NEW_ENGINE` is
  private, and `gh` uses your login for both the code and the image. No Docker
  is needed on the laptop.
- **Root SSH to the compute host** (ours: port 11911). Test it:
  `ssh -p 11911 root@<compute> hostname`.
- **A floating IP to protect**, on a VM that runs on that compute host. If
  you have none, [Part 0](#part-0-a-vm-to-protect) creates a test one.

### Set your values once

Every command below uses these shell variables, so you only type addresses
here. Run this **on your laptop**, in every new terminal you open:

```sh
COMPUTE=root@223.26.0.20     # the compute host (hk1-cmpt4)
PORT=11911                   # its SSH port
FIP=223.26.0.228             # the floating IP to protect
```

*Why:* the commands then work for any host or IP. The variables only exist
in the terminal you set them in. If a command says `ssh: Could not resolve
hostname` or `-p: option requires an argument`, you're in a new terminal:
set them again.

### Know which machine you're on

This is the most common mistake. Look at the prompt:

| Prompt | You are on |
|---|---|
| `you@MacBook ~ %` | your laptop (macOS has no `systemctl`, `journalctl`, `ip`) |
| `root@hk1-cmpt4:~#` | the compute host |
| `ubuntu@waf-test:~$` | the test customer VM |

Most steps here run **from the laptop** and reach the server with
`ssh ... '<command>'`. That way you never have to guess where you are.

---

## Part 0: a VM to protect

Skip this if you're protecting an existing VM: just put its floating IP in
`FIP`.

Otherwise create a test "customer" in the dashboard (Skyline/Horizon):

1. **Image:** any Ubuntu cloud image. **Flavor:** the smallest.
2. **Key pair:** yours, so you can read the VM's log later.
3. **Security group:** allow TCP 22, 80 and 443 from `0.0.0.0/0`.
4. **User data** (Configuration / Customization script), paste:

   ```yaml
   #cloud-config
   write_files:
     - path: /srv/www/index.html
       content: "<h1>WAF test page</h1>"
   runcmd:
     - [systemd-run, --unit=testsite, --working-directory=/srv/www, python3, -u, -m, http.server, "80"]
   ```

   *Why:* at first boot it writes a page and serves it on port 80 with
   Python, which Ubuntu already has. Nothing is downloaded into the VM, like
   a real customer we must not touch.
5. **Associate a floating IP** and set `FIP` to it.

Check that it works and that it runs on **your** compute host:

```sh
# laptop
curl -s http://$FIP/
ssh -p $PORT $COMPUTE "ip netns exec \$(ip netns list | awk '/^fip-/{print \$1; exit}') ip route | grep $FIP"
```

✅ The page, and a line `<FIP> via 169.254... dev fpr-...`. *Why:* with DVR,
a floating IP's route only exists in the fip namespace of the host running
its VM. No line means the VM is on another compute host: install the WAF
there (change `COMPUTE`), or migrate the VM.

The VM's access log, which shows who called it:

```sh
ssh ubuntu@$FIP 'sudo journalctl -u testsite -n 3 -o cat'
```

---

## Part 1: get the code

```sh
# laptop
git clone git@github.com:MonthyG/NEW_ENGINE.git ~/NEW_ENGINE
cd ~/NEW_ENGINE
git log --oneline -1
```

*Why:* `git clone` downloads the repo, including the scripts this guide uses.
`git@github.com:` uses your SSH key; with the GitHub CLI use
`gh repo clone MonthyG/NEW_ENGINE ~/NEW_ENGINE` instead. `git log -1` shows
the commit you're deploying: write it down, it becomes the image tag.

If you already have it, update it instead:

```sh
cd ~/NEW_ENGINE && git switch main && git pull
```

All later laptop commands assume you're in `~/NEW_ENGINE`. If one says
`no such file or directory: hiwaf-engine/...`, run `cd ~/NEW_ENGINE` first.

### Take a snapshot of the compute host

```sh
# laptop
mkdir -p snapshots
ssh -p $PORT $COMPUTE 'bash -s' < hiwaf-engine/scripts/waf-snapshot.sh > snapshots/compute-before-waf.txt
```

*Why:* `waf-snapshot.sh` prints the compute host's network and Docker state
(Neutron's namespaces, routes, rules, iptables) and changes nothing. `bash -s`
runs a script read from standard input, so the script travels over SSH and
is never copied to the server. Keeping this "before" picture lets you prove
later that the rollback left nothing behind. `snapshots/` is in `.gitignore`:
it holds internal IPs and firewall rules and must not be committed.

---

## Part 2: get the engine image from GitHub

GitHub Actions builds the image on every push to `main` that touches
`hiwaf-engine/` (workflow [`Engine image`](../../.github/workflows/engine-image.yml)),
checks that it starts, and keeps it for 30 days as an artifact called
`cloudinside-waf`. You never build on the laptop or on the compute host.

*Why GitHub:* the build downloads about 2 GB (Go, Debian) and compiles for
minutes. On the compute host it would compete with customer VMs for CPU; on
a laptop it needs Docker, and an Apple Silicon Mac would have to emulate
Intel. GitHub's machines are x86_64 like the compute host.

```sh
# laptop
RUN=$(gh run list --repo MonthyG/NEW_ENGINE --workflow engine-image.yml --branch main --status success -L 1 --json databaseId --jq '.[0].databaseId')
gh run view $RUN --repo MonthyG/NEW_ENGINE
```

*Why:* finds the latest successful build of `main`. `gh run view` shows which
commit it built: it should match `git log --oneline -1` from Part 1. If there's
no run yet, or it's older than 30 days, start one:
`gh workflow run engine-image.yml --repo MonthyG/NEW_ENGINE --ref main`, wait
with `gh run watch`, then run the line above again.

```sh
# laptop
rm -rf /tmp/waf-image && gh run download $RUN --repo MonthyG/NEW_ENGINE -n cloudinside-waf -D /tmp/waf-image
ls -lh /tmp/waf-image
```

*Why:* downloads the image archive (`cloudinside-waf.tar.gz`, about 70 MB)
from GitHub. The repo is private, so this uses your `gh` login.

## Part 3: copy the image to the compute host

```sh
# laptop
ssh -p $PORT $COMPUTE 'gunzip | docker load' < /tmp/waf-image/cloudinside-waf.tar.gz
```

*Why:* `<` feeds the file into SSH, and on the compute host `gunzip` unpacks
it and `docker load` adds the image to Docker. Nothing is started. The compute
host needs no internet, no registry and no GitHub access.

✅ Ends with `Loaded image: cloudinside-waf:latest`.

---

## Part 4: install on the compute host

### 4.1 Copy the scripts

```sh
# laptop
scp -P $PORT hiwaf-engine/scripts/waf-steer.sh hiwaf-engine/scripts/waf-steer.service $COMPUTE:/tmp/
```

*Why:* `scp` copies files over SSH. Note it takes `-P` (capital) for the
port, while `ssh` takes `-p`.

### 4.2 Install them, and an empty list

```sh
# laptop
ssh -p $PORT $COMPUTE '
  install -m 755 /tmp/waf-steer.sh /usr/local/sbin/ &&
  install -m 644 /tmp/waf-steer.service /etc/systemd/system/ &&
  rm /tmp/waf-steer.sh /tmp/waf-steer.service &&
  mkdir -p /etc/hiwaf &&
  echo ENGINE_CONTAINER=cloudinside-waf > /etc/hiwaf/waf-steer.env &&
  : > /etc/hiwaf/waf-fips &&
  ls -la /etc/hiwaf'
```

*Why, line by line:*

- `install -m 755` copies and sets permissions in one step: the script is
  executable, the service file isn't.
- `/usr/local/sbin` is where local admin tools go; the service file expects
  the script there.
- `waf-steer.env` holds settings. `waf-steer` looks for a container called
  `hiwaf-engine` by default; ours is `cloudinside-waf`. Other settings (see
  the top of `waf-steer.sh`): `FAIL_MODE=open|closed`, `INTERVAL=5`.
- `: > waf-fips` creates the list **empty on purpose**. With an empty list,
  starting `waf-steer` changes no traffic, so you can check everything is
  connected before anything depends on it.

### 4.3 The engine config

```sh
# laptop
ssh -p $PORT $COMPUTE "cat > /etc/hiwaf/engine.json" <<EOF
{"admin": {"disabled": true},
 "apps": {"http": {"servers": {"test": {
   "listen": [":80", ":443"], "automatic_https": {"disable": true},
   "routes": [{"handle": [
     {"handler": "waf", "load_owasp_crs": true,
      "directives": "Include @coraza.conf-recommended\nInclude @crs-setup.conf.example\nInclude @owasp_crs/*.conf\nSecRuleEngine On"},
     {"handler": "reverse_proxy", "upstreams": [{"dial": "$FIP:80"}]}]}]}}}}}
EOF
ssh -p $PORT $COMPUTE 'python3 -m json.tool /etc/hiwaf/engine.json >/dev/null && echo valid'
```

*Why:* this is a hand-written test config; later the manager writes it.

- `admin.disabled`: no admin API, nothing can change the config at runtime.
- `listen :80 :443`: the engine answers on both ports for **every** IP that
  is steered to it, since `waf-steer` redirects them all to it.
- `automatic_https.disable`: no automatic certificates. In transparent mode
  every compute host has an engine, but only the host that owns the IP could
  pass Let's Encrypt's check, so it's off. That's also why **port 443 speaks
  plain HTTP** in this test: HTTPS needs an uploaded certificate (a later step).
- `waf` with the OWASP CRS and `SecRuleEngine On`: inspect every request and
  block attacks (403). `DetectionOnly` would only log.
- `reverse_proxy` to `$FIP:80`: clean requests go on to the customer's
  floating IP, through Neutron's normal path, to the VM.
- The `<<EOF` heredoc puts your `$FIP` into the file; `json.tool` checks it's
  valid JSON before the engine ever reads it.

### 4.4 Start the engine

```sh
# laptop
ssh -p $PORT $COMPUTE 'docker run -d --name cloudinside-waf --network none --cpus 2 --restart unless-stopped \
  -v /etc/hiwaf/engine.json:/etc/hiwaf/engine.json:ro \
  cloudinside-waf:latest hi-waf run --config /etc/hiwaf/engine.json'
ssh -p $PORT $COMPUTE 'sleep 3; docker ps --filter name=cloudinside-waf --format "{{.Names}} {{.Status}}"'
```

*Why each flag:*

- `-d`: run in the background.
- `--name cloudinside-waf`: the name `waf-steer` looks for.
- `--network none`: the container gets **no network at all**, only loopback.
  It can't receive or send anything until `waf-steer` connects it to
  Neutron's fip namespace. This keeps Docker's own networking (its NAT and
  bridge) out of the traffic path.
- `--cpus 2`: caps the engine at 2 CPU threads, so a flood of requests can't
  starve the customer VMs on the same host.
- `--restart unless-stopped`: Docker starts it again after a crash or a
  reboot, unless you stopped it yourself.
- `-v ...:ro`: mounts the config read-only into the container.
- `hi-waf run --config ...`: start the engine with that config.

✅ `cloudinside-waf Up 3 seconds`. In `docker logs cloudinside-waf`, the
warnings `HTTP/2 skipped because it requires TLS` and `admin endpoint
disabled` are normal for this test config.

### 4.5 Start `waf-steer` (with the empty list)

```sh
# laptop
ssh -p $PORT $COMPUTE 'systemctl daemon-reload && systemctl start waf-steer; sleep 6; journalctl -u waf-steer -n 3 -o cat'
```

*Why:* `daemon-reload` makes systemd read the new service file. `start`
runs `waf-steer.sh loop`, which every 5 seconds:

1. finds Neutron's `fip-*` namespace on this host;
2. finds the engine container and, if needed, connects it with a veth pair
   (`hiwaf-h` at `100.64.255.1` in the fip namespace, `100.64.255.2` in the
   engine);
3. makes the engine accept any 80/443 packet (`REDIRECT`);
4. adds the routing (`ip rule` 1455 and 40000, tables 1455 and 1456);
5. marks TCP 80/443 to each IP in `waf-fips` so it's routed into the veth.

It repeats every 5 s because Neutron can rebuild that namespace's rules at
any time; the next pass puts ours back.

✅ `connected the engine (...) to fip-...` then `0 protected, engine up`.

See everything it set up:

```sh
ssh -p $PORT $COMPUTE '/usr/local/sbin/waf-steer.sh status'
```

### 4.6 Check the security group

The VM will see the engine's address `100.64.255.2` as the caller, not the
visitor's. If its security group only allows web traffic from some addresses,
the WAF can't reach it. In the dashboard (Skyline/Horizon), the VM's security
group must allow **TCP 80 and 443 from `0.0.0.0/0`**, or add
`100.64.255.2/32`. On the compute host you can see the rules for all its VMs:

```sh
ssh -p $PORT $COMPUTE "iptables-save | grep -- '-A neutron-openvswi-i' | grep -E 'dport (80|443) '"
```

Lines like `... -p tcp -m tcp --dport 80 -j RETURN` with no `-s` mean
"allowed from anywhere".

---

## Part 5: protect a floating IP

This is the **only step that changes real traffic**, and only TCP 80/443 to
`$FIP`.

```sh
# laptop
ssh -p $PORT $COMPUTE "echo $FIP > /etc/hiwaf/waf-fips; sleep 6; journalctl -u waf-steer -n 1 -o cat"
```

*Why:* the next pass reads the list and adds the mark for this IP. Double
quotes `"..."` (not single) so your laptop fills in `$FIP` before sending.

✅ `1 protected, engine up`.

To protect several IPs, put one per line. Invalid lines are ignored and
logged (`ignoring invalid line`).

**Emergency stop** (traffic back to normal within seconds):

```sh
ssh -p $PORT $COMPUTE 'systemctl stop waf-steer'
```

---

## Part 6: test it

Run these **from your laptop**, so the traffic comes from the internet like a
visitor's.

**1. The page loads through the WAF**

```sh
curl -s -A Mozilla/5.0 http://$FIP/
```

✅ Your page. *Why `-A Mozilla/5.0`:* it sends a browser-like User-Agent so
the request looks like a normal visitor's; some CRS rules score script-like
clients.

**2. An attack is blocked**

```sh
curl -s -A Mozilla/5.0 -o /dev/null -w '%{http_code}\n' "http://$FIP/?id=1%27%20OR%20%271%27=%271"
```

✅ `403`. *Why:* the URL holds a URL-encoded SQL injection (`1' OR '1'='1`).
`-o /dev/null -w '%{http_code}'` throws the body away and prints only the
status code. `200` means it reached the VM: steering isn't on (see
[Troubleshooting](#troubleshooting)).

**3. The VM sees the engine as the caller**

```sh
ssh ubuntu@$FIP 'sudo journalctl -u testsite -n 3 -o cat'
```

✅ The last lines show `100.64.255.2`, not your own IP, and the attack isn't
there at all. *Why:* the engine opens its own connection to the VM. Your real
IP is in the `X-Forwarded-For` header. For an existing VM, look at its web
server's access log instead.

**4. Other ports are untouched**

```sh
ssh -o ConnectTimeout=5 ubuntu@$FIP hostname
```

✅ Works as before: SSH is never steered.

**5. Fail-open: engine down, site stays up**

```sh
ssh -p $PORT $COMPUTE 'docker stop cloudinside-waf; sleep 6; journalctl -u waf-steer -n 1 -o cat'
curl -s -A Mozilla/5.0 http://$FIP/
ssh -p $PORT $COMPUTE 'docker start cloudinside-waf; sleep 6; journalctl -u waf-steer -n 1 -o cat'
```

✅ `ENGINE DOWN: fail-open, traffic goes straight to the VMs`, the page still
loads, then `1 protected, engine up` again. *Why:* by default a dead engine
must not take customer sites down, so steering is removed until it's back.
For the opposite (no unprotected traffic, site down instead), put
`FAIL_MODE=closed` in `/etc/hiwaf/waf-steer.env`.

---

## Part 7: keep it running

```sh
ssh -p $PORT $COMPUTE 'systemctl enable waf-steer'
```

*Why:* `start` only runs it now; `enable` also starts it at boot. The engine
already comes back on its own (`--restart unless-stopped`). After a reboot
there are a few seconds, until Docker and Neutron are up and `waf-steer`
reconnects, where traffic goes straight to the VM.

Daily check:

```sh
ssh -p $PORT $COMPUTE 'journalctl -u waf-steer --since today -o cat | sort | uniq -c'
```

✅ Only `1 protected, engine up`. Any `ENGINE DOWN` or error is worth a look.

What the WAF blocked in the last day:

```sh
ssh -p $PORT $COMPUTE 'docker logs --since 24h cloudinside-waf 2>&1 | grep -c "Anomaly Score Exceeded"'
```

*Why:* the test config has no access log, but Coraza logs every rule that
matched, and CRS rule 949110 ("Inbound Anomaly Score Exceeded") is the one
that blocks. So this counts blocked requests. Drop `-c` to see them.

---

## Undo everything

```sh
# laptop
ssh -p $PORT $COMPUTE 'bash -s' < hiwaf-engine/scripts/waf-reset.sh
```

*Why:* `waf-reset.sh` stops `waf-steer` first (so traffic is back on
Neutron's path), then removes every piece it added (iptables chains, ip
rules, routing tables, the veth) even if the script itself is gone, removes
the container and the image, deletes `/etc/hiwaf` and the service file, and
checks. It's safe to run twice. Add `KEEP_IMAGE=1` to keep the image:
`ssh -p $PORT $COMPUTE 'KEEP_IMAGE=1 bash -s' < hiwaf-engine/scripts/waf-reset.sh`.

✅ `done: host is back to its pre-WAF state`.

Prove it against the snapshot from the start:

```sh
ssh -p $PORT $COMPUTE 'bash -s' < hiwaf-engine/scripts/waf-snapshot.sh > snapshots/compute-after-reset.txt
diff snapshots/compute-before-waf.txt snapshots/compute-after-reset.txt | grep -iE 'hiwaf|1455|1456|cloudinside' || echo clean
```

✅ `clean`. Other differences in the full diff (a new VM, a new port) are
Neutron's own changes, not the WAF's.

If you made a test VM in [Part 0](#part-0-a-vm-to-protect), delete it and
release its floating IP in the dashboard. On the laptop, `rm -rf /tmp/waf-image`.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `gh: command not found` | GitHub CLI not installed | `brew install gh`, then `gh auth login` |
| `HTTP 404` / `Could not resolve to a Repository` from `gh` | Not logged in, or your account has no access to the private repo | `gh auth status`; ask the repo owner for access |
| `RUN` is empty, or `no artifact matches` | No successful build yet, or it's older than 30 days | `gh workflow run engine-image.yml --repo MonthyG/NEW_ENGINE --ref main`, then `gh run watch` |
| `gzip: stdin: not in gzip format` | The download failed or the path is wrong | `ls -lh /tmp/waf-image`; download again |
| `zsh: no such file or directory: hiwaf-engine/scripts/...` | Your laptop terminal isn't in the repo folder | `cd ~/NEW_ENGINE` |
| `zsh: command not found: journalctl` (or `systemctl`, `ip`) | You ran a server command on your laptop | Wrap it: `ssh -p $PORT $COMPUTE '<command>'` |
| `ssh: Could not resolve hostname` / empty `-p` | New terminal, variables not set | Run the [values block](#set-your-values-once) again |
| The attack returns `200`, VM log shows your own IP | Not steered. Usually `waf-fips` is empty | `ssh -p $PORT $COMPUTE 'cat /etc/hiwaf/waf-fips; journalctl -u waf-steer -n 3 -o cat'`; then do [Part 5](#part-5-protect-a-floating-ip) |
| Log says `0 protected` | Same: empty list | [Part 5](#part-5-protect-a-floating-ip) |
| Log says `ENGINE DOWN` | Container stopped or crashed | `docker ps -a`, `docker logs cloudinside-waf`, `docker start cloudinside-waf` |
| Engine exits right after `docker run` | Usually bad JSON in `engine.json` | `python3 -m json.tool /etc/hiwaf/engine.json`; `docker logs cloudinside-waf` |
| Page times out after Part 5 | Security group blocks `100.64.255.2`, or a routing problem | Emergency stop first, then [4.6](#46-check-the-security-group) and `waf-steer.sh status` |
| `no fip namespace here` | No DVR floating IP on this host yet | The protected VM must run on this host with a floating IP |
| `https://$FIP` fails | Expected: the test config has no certificate | Use `http://`; HTTPS needs an uploaded certificate |
| A `pkill -f ...` over SSH kills your session | `pkill -f` also matches its own command line | Use `systemctl stop <unit>`, or `pkill -f "[h]ttp.server"` |

## Limits of this setup

- **Hand-written config.** `engine.json` and `waf-fips` are edited by hand.
  The manager will write both (planned).
- **No HTTPS.** Port 443 is steered but speaks plain HTTP until a certificate
  is uploaded.
- **One host.** Only this compute host has an engine. If the VM migrates to
  another host, it's no longer protected until that host has one too.
- **No alerts.** If the engine dies, fail-open keeps sites up but
  unprotected, and only the daily check shows it.
- **IPv4 only.**
