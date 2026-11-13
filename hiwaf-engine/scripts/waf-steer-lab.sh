#!/usr/bin/env bash
# Tests waf-steer.sh on any Linux host with Docker, without OpenStack. It
# rebuilds a compute host's floating-IP path in network namespaces, runs the
# real engine image with --network none, and checks steering, the WAF,
# fail-open/closed, recovery after Neutron wipes the rules, and rollback.
#
#   sudo ./scripts/waf-steer-lab.sh [engine-image]   (default hiwaf-engine:latest)
#
# Everything it creates is named wsl-* and removed at the end.
#
#   wsl-cli  client 203.0.113.50, also the upstream gateway 198.51.100.193
#     | fg-wsl0 198.51.100.197/24
#   wsl-fip  like Neutron's fip namespace: no conntrack, no default route in main
#     | fpr-wsl0 / rfp-wsl0 169.254.88.135/134
#   wsl-qr   like the qrouter: DNAT floating IP 198.51.100.228 -> 192.168.217.211
#     | qr-wsl0 / vm-wsl0
#   wsl-vm   the customer VM: an origin on 80, 443 and 2222 that echoes who called it
#   wsl-engine (container) joined to wsl-fip by waf-steer's veth
set -uo pipefail

IMAGE=${1:-hiwaf-engine:latest}
HERE=$(cd "$(dirname "$0")" && pwd)
LAB=$(mktemp -d /tmp/wsl.XXXXXX)
FIP=198.51.100.228 CLIENT=203.0.113.50
PASS=0 FAIL=0
export FIP_NS=wsl-fip ENGINE_CONTAINER=wsl-engine ENGINE_NETNS= WAF_FIPS_FILE=$LAB/fips FAIL_MODE=open

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }

cleanup() {
  "$HERE/waf-steer.sh" off 2>/dev/null
  docker rm -f wsl-engine >/dev/null 2>&1
  [ -n "${ORIGIN:-}" ] && kill "$ORIGIN" 2>/dev/null
  for n in wsl-cli wsl-fip wsl-qr wsl-vm; do ip netns del $n 2>/dev/null; done
  rm -rf "$LAB"
}
trap cleanup EXIT
cleanup 2>/dev/null; LAB=$(mktemp -d /tmp/wsl.XXXXXX); export WAF_FIPS_FILE=$LAB/fips

n() { ip netns exec "$@"; }
steer() { "$HERE/waf-steer.sh" apply 2>&1 | sed 's/^/    /'; }
# get PORT [PATH]: what the origin saw, as seen from the client
get() { n wsl-cli curl -sS --max-time 4 --interface $CLIENT -A 'Mozilla/5.0' -H 'Host: a.test' "http://$FIP:$1${2:-/}" -o - -w ' [%{http_code}]' 2>&1; }
check() { # check NAME WANT GOT: GOT contains WANT; an empty WANT means GOT must be empty
  if { [ -z "$2" ] && [ -z "$3" ]; } || { [ -n "$2" ] && [[ $3 == *"$2"* ]]; }; then PASS=$((PASS + 1)); echo "ok    $1"; else FAIL=$((FAIL + 1)); echo "FAIL  $1: want '$2', got '$3'"; fi
}

# --- the topology ---------------------------------------------------------
for ns in wsl-cli wsl-fip wsl-qr wsl-vm; do ip netns add $ns; n $ns ip link set lo up; done
ip link add wsl-c netns wsl-cli type veth peer name fg-wsl0 netns wsl-fip
ip link add fpr-wsl0 netns wsl-fip type veth peer name rfp-wsl0 netns wsl-qr
ip link add qr-wsl0 netns wsl-qr type veth peer name vm-wsl0 netns wsl-vm

n wsl-cli ip addr add 198.51.100.193/24 dev wsl-c
n wsl-cli ip addr add $CLIENT/32 dev lo
n wsl-cli ip link set wsl-c up
# ARP from the interface address, as a router would: requests from the client
# address would be dropped by the fip namespace's reverse-path filter.
n wsl-cli sysctl -qw net.ipv4.conf.wsl-c.arp_announce=2
n wsl-cli ip route add $FIP via 198.51.100.197

n wsl-fip sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=2
n wsl-fip ip addr add 198.51.100.197/24 dev fg-wsl0
n wsl-fip ip addr add 169.254.88.135/31 dev fpr-wsl0
n wsl-fip ip link set fg-wsl0 up
n wsl-fip ip link set fpr-wsl0 up
n wsl-fip ip route add $FIP via 169.254.88.134 dev fpr-wsl0
n wsl-fip ip route add default via 198.51.100.193 dev fg-wsl0 table 777
n wsl-fip ip rule add iif fpr-wsl0 lookup 777 priority 2852018311
n wsl-fip iptables -t raw -A PREROUTING -j CT --notrack # as Neutron does

n wsl-qr sysctl -qw net.ipv4.ip_forward=1
n wsl-qr ip addr add 169.254.88.134/31 dev rfp-wsl0
n wsl-qr ip addr add 192.168.217.1/24 dev qr-wsl0
n wsl-qr ip link set rfp-wsl0 up
n wsl-qr ip link set qr-wsl0 up
n wsl-qr ip route add default via 169.254.88.135 dev rfp-wsl0 table 16
n wsl-qr ip rule add from 192.168.217.211 lookup 16
n wsl-qr iptables -t nat -A PREROUTING -d $FIP/32 -i rfp-wsl0 -j DNAT --to-destination 192.168.217.211

n wsl-vm ip addr add 192.168.217.211/24 dev vm-wsl0
n wsl-vm ip link set vm-wsl0 up
n wsl-vm ip route add default via 192.168.217.1

# Not through n(): $! must be the server itself, or cleanup kills only a wrapper.
ip netns exec wsl-vm python3 -c '
import http.server, threading
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(s):
        b = ("src=%s xff=%s" % (s.client_address[0], s.headers.get("X-Forwarded-For", "-"))).encode()
        s.send_response(200); s.send_header("Content-Length", str(len(b))); s.end_headers(); s.wfile.write(b)
    def log_message(s, *a): pass
for p in (80, 443, 2222):
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", p), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
threading.Event().wait()' &
ORIGIN=$!

# The engine: plain HTTP on 80 and 443, the CRS in blocking mode, proxying to the floating IP.
cat >"$LAB/caddy.json" <<EOF
{"admin": {"disabled": true},
 "apps": {"http": {"servers": {"lab": {
   "listen": [":80", ":443"], "automatic_https": {"disable": true},
   "routes": [{"handle": [
     {"handler": "waf", "load_owasp_crs": true,
      "directives": "Include @coraza.conf-recommended\nInclude @crs-setup.conf.example\nInclude @owasp_crs/*.conf\nSecRuleEngine On"},
     {"handler": "reverse_proxy", "upstreams": [{"dial": "$FIP:80"}]}]}]}}}}}
EOF
chmod 644 "$LAB/caddy.json"; chmod 755 "$LAB"
start_engine() {
  docker rm -f wsl-engine >/dev/null 2>&1
  docker run -d --name wsl-engine --network none -v "$LAB/caddy.json:/lab/caddy.json:ro" "$IMAGE" hi-waf run --config /lab/caddy.json >/dev/null
  local pid i
  for i in $(seq 1 40); do
    pid=$(docker inspect -f '{{.State.Pid}}' wsl-engine)
    nsenter -t "$pid" -n ss -Hltn 2>/dev/null | grep -q ':443 ' && return 0
    sleep 0.25
  done
  echo "engine did not start:" >&2; docker logs wsl-engine 2>&1 | tail -5 >&2; exit 1
}
start_engine
sleep 0.5

# --- the tests ------------------------------------------------------------
echo "1. before waf-steer: the normal path"
check "port 80 goes straight to the VM" "src=$CLIENT xff=-" "$(get 80)"

echo "2. protect the floating IP"
echo "$FIP  # lab" >"$LAB/fips"
echo "not-an-ip; rm -rf /" >>"$LAB/fips"
steer
check "port 80 goes through the WAF, client IP in X-Forwarded-For" "src=100.64.255.2 xff=$CLIENT [200]" "$(get 80)"
check "port 443 goes through the WAF" "src=100.64.255.2 xff=$CLIENT [200]" "$(get 443)"
check "port 2222 (SSH and the rest) still goes straight to the VM" "src=$CLIENT xff=- [200]" "$(get 2222)"
check "an SQL injection is blocked" "[403]" "$(get 80 "/?id=1%27%20OR%20%271%27=%271")"
check "the invalid line in the list never reached iptables" "" "$(n wsl-fip iptables-save | grep 'rm -rf')"

echo "3. UDP 443 (HTTP/3) to a protected IP is dropped"
n wsl-cli bash -c "echo x >/dev/udp/$FIP/443" 2>/dev/null
check "the drop rule counted the packet" "1" "$(n wsl-fip iptables -L HIWAF-FWD -v -n -x | awk 'NR == 3 {print $1}')"

echo "4. a second pass changes nothing"
before=$(n wsl-fip iptables-save | grep -c HIWAF); rules_before=$(n wsl-fip ip rule | wc -l)
steer
check "same iptables rules" "$before" "$(n wsl-fip iptables-save | grep -c HIWAF)"
check "same ip rules" "$rules_before" "$(n wsl-fip ip rule | wc -l)"

echo "5. Neutron rebuilds the fip namespace's tables"
n wsl-fip iptables -t mangle -F PREROUTING
n wsl-fip iptables -t filter -F FORWARD
check "until the next pass, traffic goes straight to the VM" "src=$CLIENT" "$(get 80)"
steer
check "the next pass puts steering back" "src=100.64.255.2" "$(get 80)"

echo "6. the engine stops (fail-open)"
docker stop -t 1 wsl-engine >/dev/null
steer
check "traffic goes straight to the VM, unprotected" "src=$CLIENT xff=- [200]" "$(get 80)"
start_engine
steer
check "a new engine container is reconnected and steered to" "src=100.64.255.2 xff=$CLIENT [200]" "$(get 80)"

echo "7. the engine stops (fail-closed)"
docker stop -t 1 wsl-engine >/dev/null
FAIL_MODE=closed steer
check "protected web ports are unreachable" "[000]" "$(get 80)"
check "port 2222 still works" "src=$CLIENT xff=- [200]" "$(get 2222)"
start_engine
FAIL_MODE=closed steer
check "the engine is back: steered again" "src=100.64.255.2" "$(get 80)"

echo "8. the customer is taken off the list"
: >"$LAB/fips"
steer
check "traffic goes straight to the VM" "src=$CLIENT xff=- [200]" "$(get 80)"

echo "9. rollback"
echo "$FIP" >"$LAB/fips"
steer
"$HERE/waf-steer.sh" off 2>&1 | sed 's/^/    /'
check "no veth left" "" "$(n wsl-fip ip link show hiwaf-h 2>/dev/null)"
check "no ip rules left" "" "$(n wsl-fip ip rule | grep -E '^(1455|40000):')"
check "no chains left" "" "$(n wsl-fip iptables-save | grep HIWAF)"
check "traffic goes straight to the VM" "src=$CLIENT xff=- [200]" "$(get 80)"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
