#!/usr/bin/env bash
# Installs (or upgrades) HostingInside WAF with Docker Compose.
#
#   sudo ./scripts/install.sh [--acme-internal] [--open-firewall]
#
#   --acme-internal  issue site certificates from the WAF's own CA instead of
#                    Let's Encrypt (labs and private domains)
#   --open-firewall  open 80/443 and the console port in firewalld
#
# Environment: HIWAF_DATA (default /data/hiwaf), HIWAF_CONSOLE_PORT (9443).
set -euo pipefail

ACME_INTERNAL=false
OPEN_FW=false
for a in "$@"; do
  case "$a" in
    --acme-internal) ACME_INTERNAL=true ;;
    --open-firewall) OPEN_FW=true ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

SRC="$(cd "$(dirname "$0")/.." && pwd)"
DATA="${HIWAF_DATA:-/data/hiwaf}"
PORT="${HIWAF_CONSOLE_PORT:-9443}"
export HIWAF_DATA="$DATA"

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root"
command -v docker >/dev/null || die "Docker is not installed"
docker compose version >/dev/null 2>&1 || die "the Docker Compose plugin is not installed"

upgrade=false
docker ps --format '{{.Names}}' | grep -q '^hiwaf-engine$' && upgrade=true
if ! $upgrade; then
  for p in 80 443 "$PORT"; do
    if ss -Hltn "sport = :$p" | grep -q .; then
      die "port $p is already in use ($(ss -Hltnp "sport = :$p" | sed -n 's/.*users:((\("[^"]*"\).*/\1/p'))"
    fi
  done
fi

say "Data directory: $DATA"
mkdir -p "$DATA"/{logs,static,feeds,geoip,caddy,caddy-config}

if [ ! -f "$DATA/manager.json" ]; then
  say "Writing $DATA/manager.json"
  cat >"$DATA/manager.json" <<EOF
{
  "listen": ":$PORT",
  "db_path": "/data/waf.db",
  "data_dir": "/data",
  "caddy_admin": "unix:///data/caddy-admin.sock",
  "event_log": "/data/logs/events.log",
  "access_log": "/data/logs/access.log",
  "static_dir": "/data/static",
  "feeds_dir": "/data/feeds",
  "geoip_db": "/data/geoip/country.mmdb",
  "http_port": 80,
  "https_port": 443,
  "acme_internal": $ACME_INTERNAL,
  "self_signed_tls": true
}
EOF
fi

if [ ! -s "$DATA/geoip/country.mmdb" ]; then
  say "Downloading the DB-IP Country Lite database (CC BY 4.0)"
  ok=false
  for m in 0 1 2; do
    ym="$(date -d "$(date +%Y-%m-01) -$m month" +%Y-%m)"
    if curl -fsSL "https://download.db-ip.com/free/dbip-country-lite-$ym.mmdb.gz" | gunzip >"$DATA/geoip/country.mmdb.tmp"; then
      mv "$DATA/geoip/country.mmdb.tmp" "$DATA/geoip/country.mmdb"; ok=true; break
    fi
  done
  $ok || { rm -f "$DATA/geoip/country.mmdb.tmp"; sed -i 's#"geoip_db": "/data/geoip/country.mmdb"#"geoip_db": ""#' "$DATA/manager.json"
           echo "  (download failed; geo features stay off until $DATA/geoip/country.mmdb exists and geoip_db is set)"; }
fi

# Older installs pushed the engine admin API to localhost:2019, open to every
# process on the host network; move it to the owner-only socket.
if grep -q '"caddy_admin": "http://localhost:2019"' "$DATA/manager.json"; then
  say "Moving the engine admin API to a unix socket"
  sed -i 's|"caddy_admin": "http://localhost:2019"|"caddy_admin": "unix:///data/caddy-admin.sock"|' "$DATA/manager.json"
fi

say "Building the image (first run takes a few minutes)"
cd "$SRC"
docker compose build
say "Starting"
docker compose up -d

say "Waiting for the console"
for _ in $(seq 1 60); do
  code="$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:$PORT/api/v1/auth/me" || true)"
  [ "$code" = "401" ] || [ "$code" = "200" ] && break
  sleep 2
done
[ "$code" = "401" ] || [ "$code" = "200" ] || die "the console did not come up; see: docker compose logs manager"

if $OPEN_FW && systemctl is-active -q firewalld; then
  say "Opening 80/tcp, 443/tcp, 443/udp and $PORT/tcp in firewalld"
  firewall-cmd -q --permanent --add-port=80/tcp --add-port=443/tcp --add-port=443/udp --add-port="$PORT/tcp"
  firewall-cmd -q --reload
fi

ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
say "HostingInside WAF is running"
echo "  Console:  https://${ip:-<server-ip>}:$PORT  (self-signed certificate)"
if [ -f "$DATA/initial-admin.txt" ] && ! $upgrade; then
  sed 's/^/  /' "$DATA/initial-admin.txt"
  echo "  (also in $DATA/initial-admin.txt; it is deleted when you change the password)"
elif [ -f "$DATA/initial-admin.txt" ]; then
  echo "  The first admin password is still unchanged (see $DATA/initial-admin.txt)."
  echo "  Change it in the console; the file is deleted when you do."
else
  echo "  Existing install: sign in with your password, or reset it with"
  echo "    docker exec hiwaf-manager manager -config /data/manager.json -resetadmin"
fi
