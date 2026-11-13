#!/usr/bin/env bash
# waf-steer: on a compute host, steers TCP 80/443 of protected floating IPs
# into the WAF engine's network namespace (transparent mode). Other ports,
# and unprotected floating IPs, keep the normal Neutron path.
#
#   waf-steer.sh apply    one idempotent pass: (re)connect the engine, (re)apply the rules
#   waf-steer.sh loop     apply every $INTERVAL seconds (the systemd service)
#   waf-steer.sh off      roll back: everything takes the normal Neutron path again
#   waf-steer.sh status   show what is in place
#
# Path, inside Neutron's fip namespace: packets arriving on fg-* for a
# protected IP get mark 0x1455 -> table 1455 -> veth hiwaf-h/hiwaf-e -> the
# engine's namespace, where 80/443 is redirected to the engine. The engine
# sees the real client IP and proxies to the customer's floating IP; that
# connection re-enters the fip namespace on hiwaf-h, unmarked, and takes the
# normal path (qrouter DNAT) to the VM. Replies to clients leave through
# table 1456, Neutron's own gateway.
#
# Settings: environment, or /etc/hiwaf/waf-steer.env (shell syntax).
#   WAF_FIPS_FILE     protected floating IPs, one per line, # comments (default /etc/hiwaf/waf-fips).
#                     The same list goes to every compute: only IPs living here ever arrive here.
#   ENGINE_CONTAINER  the engine's Docker container, run with --network none (default hiwaf-engine)
#   ENGINE_NETNS      a named network namespace instead of the container (tests)
#   FIP_NS            Neutron's fip namespace (default: the only fip-* namespace)
#   FAIL_MODE         open (default): engine down = traffic goes straight to the VM, unprotected.
#                     closed: engine down = protected web ports are unreachable.
#   INTERVAL          seconds between passes in loop mode (default 5)
set -euo pipefail

if [ -r /etc/hiwaf/waf-steer.env ]; then
  # shellcheck disable=SC1091
  . /etc/hiwaf/waf-steer.env
fi
: "${WAF_FIPS_FILE:=/etc/hiwaf/waf-fips}" "${ENGINE_CONTAINER:=hiwaf-engine}" "${ENGINE_NETNS:=}"
: "${FIP_NS:=}" "${FAIL_MODE:=open}" "${INTERVAL:=5}"

MARK=0x1455/0xffff # low 16 bits; Neutron's fip namespace sets no marks
TABLE=1455         # marked packets -> the engine
RTABLE=1456        # the engine's replies -> Neutron's gateway
RULE_PRIO=1455     # before main
RRULE_PRIO=40000   # after main, so the engine reaches local floating IPs through main
VH=hiwaf-h VE=hiwaf-e
HOST_IP=100.64.255.1 ENG_IP=100.64.255.2 # CGNAT space: tenants can't use it as an upstream

log() { echo "waf-steer: $*" >&2; }

# fx runs a command in the fip namespace, ex in the engine's.
fx() { ip netns exec "$NS" "$@"; }
ex() {
  if [ -n "$ENGINE_NETNS" ]; then ip netns exec "$ENGINE_NETNS" "$@"; else nsenter -t "$ENS" -n "$@"; fi
}

find_fipns() {
  NS=$FIP_NS
  if [ -z "$NS" ]; then
    local l
    mapfile -t l < <(ip netns list | awk '/^fip-/{print $1}')
    [ "${#l[@]}" -eq 1 ] && NS=${l[0]}
  fi
  [ -n "$NS" ] && [ -e "/run/netns/$NS" ]
}

# find_engine sets ENS (a namespace name or a PID) when the engine is running.
find_engine() {
  ENS=
  if [ -n "$ENGINE_NETNS" ]; then
    [ -e "/run/netns/$ENGINE_NETNS" ] && ENS=$ENGINE_NETNS
  else
    ENS=$(docker inspect -f '{{if .State.Running}}{{.State.Pid}}{{end}}' "$ENGINE_CONTAINER" 2>/dev/null || true)
    [ "$ENS" = 0 ] && ENS=
  fi
  [ -n "$ENS" ]
}

engine_listening() {
  local ports
  ports=$(ex ss -Hltn 2>/dev/null | awk '{print $4}') || return 1
  grep -qE ':80$' <<<"$ports" && grep -qE ':443$' <<<"$ports"
}

valid_ip() {
  local o='(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'
  [[ $1 =~ ^$o\.$o\.$o\.$o$ ]]
}

# read_fips fills FIPS. The file comes from the manager: anything that isn't
# a plain IPv4 address is dropped before it can reach iptables-restore.
read_fips() {
  FIPS=()
  if [ ! -r "$WAF_FIPS_FILE" ]; then
    log "no $WAF_FIPS_FILE: nothing is protected"
    return
  fi
  local line
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%%#*}
    line=${line//[[:space:]]/}
    [ -z "$line" ] && continue
    if valid_ip "$line"; then FIPS+=("$line"); else log "ignoring invalid line: $line"; fi
  done <"$WAF_FIPS_FILE"
}

# plumb connects the engine's namespace to the fip namespace. The veth dies
# with the engine's namespace, so an engine restart leaves hiwaf-h missing
# and the next pass recreates it.
plumb() {
  if fx ip link show "$VH" &>/dev/null && ! ex ip link show "$VE" &>/dev/null; then
    fx ip link del "$VH" # its peer is in some other namespace
  fi
  fx ip link show "$VH" &>/dev/null && return
  ip -n "$NS" link add "$VH" type veth peer name "$VE" netns "$ENS"
  fx ip addr add "$HOST_IP/30" dev "$VH"
  fx ip link set "$VH" up
  ex ip link set lo up
  ex ip addr add "$ENG_IP/30" dev "$VE"
  ex ip link set "$VE" up
  ex ip route replace default via "$HOST_IP" dev "$VE"
  log "connected the engine ($ENS) to $NS"
}

engine_nat() {
  ex iptables-restore --noflush <<EOF
*nat
:HIWAF-IN - [0:0]
-A HIWAF-IN -i $VE -p tcp -m multiport --dports 80,443 -j REDIRECT
COMMIT
EOF
  ex iptables -t nat -C PREROUTING -j HIWAF-IN 2>/dev/null || ex iptables -t nat -I PREROUTING 1 -j HIWAF-IN
}

routes() {
  # No early exit in these awk scripts: with pipefail, ip dying of SIGPIPE
  # would fail the pass silently.
  FG=$(fx ip -br link | awk '$1 ~ /^fg-/ && !f {sub(/@.*/, "", $1); print $1; f = 1}')
  [ -n "$FG" ] || { log "no fg-* interface in $NS"; return 1; }
  local gw
  gw=$(fx ip route show table all | awk -v t="table $RTABLE" '$1 == "default" && $2 == "via" && / dev fg-/ && index($0, t) == 0 && !f {print $3; f = 1}')
  [ -n "$gw" ] || { log "no default route through $FG in $NS"; return 1; }
  fx ip route replace default via "$gw" dev "$FG" table "$RTABLE"
  # When hiwaf-h is gone, the via route goes with it and this one is left:
  # with FAIL_MODE=closed the marked packets are dropped, not sent to the VM.
  fx ip route replace blackhole default metric 4000 table "$TABLE"
  if fx ip link show "$VH" &>/dev/null; then
    fx ip route replace default via "$ENG_IP" dev "$VH" table "$TABLE"
  fi
  [ -n "$(fx ip rule show priority "$RULE_PRIO")" ] || fx ip rule add fwmark "$MARK" lookup "$TABLE" priority "$RULE_PRIO"
  [ -n "$(fx ip rule show priority "$RRULE_PRIO")" ] || fx ip rule add iif "$VH" lookup "$RTABLE" priority "$RRULE_PRIO"
}

# steer replaces our two chains in one iptables-restore; active=0 empties them.
steer() {
  local active=$1 f
  {
    echo '*mangle'
    echo ':HIWAF-STEER - [0:0]'
    if [ "$active" = 1 ]; then
      for f in "${FIPS[@]}"; do
        echo "-A HIWAF-STEER -i $FG -d $f/32 -p tcp -m multiport --dports 80,443 -j MARK --set-xmark $MARK"
      done
    fi
    echo 'COMMIT'
    echo '*filter'
    echo ':HIWAF-FWD - [0:0]'
    if [ "$active" = 1 ]; then
      # The engine has no HTTP/3 and UDP isn't steered: without this, a
      # browser that knows the site speaks HTTP/3 would go around the WAF.
      for f in "${FIPS[@]}"; do
        echo "-A HIWAF-FWD -i $FG -d $f/32 -p udp --dport 443 -j DROP"
      done
    fi
    echo 'COMMIT'
  } | fx iptables-restore --noflush
  # Neutron can rebuild these tables; the next pass puts the jumps back.
  fx iptables -t mangle -C PREROUTING -j HIWAF-STEER 2>/dev/null || fx iptables -t mangle -I PREROUTING 1 -j HIWAF-STEER
  fx iptables -t filter -C FORWARD -j HIWAF-FWD 2>/dev/null || fx iptables -t filter -I FORWARD 1 -j HIWAF-FWD
}

apply() {
  read_fips
  find_fipns || { STATE="no fip namespace here"; return 0; }
  local up=0
  if find_engine; then
    plumb
    engine_nat
    engine_listening && up=1
  fi
  routes
  local active=$up
  [ "$FAIL_MODE" = closed ] && active=1
  steer "$active"
  if [ "$up" = 1 ]; then
    STATE="${#FIPS[@]} protected, engine up"
  elif [ "$active" = 1 ]; then
    STATE="${#FIPS[@]} protected, ENGINE DOWN: fail-closed, their web ports are unreachable"
  else
    STATE="${#FIPS[@]} listed, ENGINE DOWN: fail-open, traffic goes straight to the VMs"
  fi
}

off() {
  if find_fipns; then
    fx iptables -t mangle -D PREROUTING -j HIWAF-STEER 2>/dev/null || true
    fx iptables -t filter -D FORWARD -j HIWAF-FWD 2>/dev/null || true
    fx iptables -t mangle -F HIWAF-STEER 2>/dev/null && fx iptables -t mangle -X HIWAF-STEER || true
    fx iptables -t filter -F HIWAF-FWD 2>/dev/null && fx iptables -t filter -X HIWAF-FWD || true
    while fx ip rule del priority "$RULE_PRIO" 2>/dev/null; do :; done
    while fx ip rule del priority "$RRULE_PRIO" 2>/dev/null; do :; done
    fx ip route flush table "$TABLE" 2>/dev/null || true
    fx ip route flush table "$RTABLE" 2>/dev/null || true
    fx ip link del "$VH" 2>/dev/null || true
  fi
  if find_engine; then
    ex iptables -t nat -D PREROUTING -j HIWAF-IN 2>/dev/null || true
    ex iptables -t nat -F HIWAF-IN 2>/dev/null && ex iptables -t nat -X HIWAF-IN || true
  fi
  log "off: all traffic takes the normal Neutron path"
}

status() {
  find_fipns || { echo "no fip namespace"; return 0; }
  echo "fip namespace: $NS"
  if find_engine; then
    echo "engine: $ENS, $(engine_listening && echo listening on 80 and 443 || echo NOT listening)"
  else
    echo "engine: not running"
  fi
  echo "veth: $(fx ip -br addr show "$VH" 2>/dev/null || echo missing)"
  fx ip rule | grep -E "^($RULE_PRIO|$RRULE_PRIO):" || echo "rules: missing"
  echo "table $TABLE:"
  fx ip route show table "$TABLE" | sed 's/^/  /'
  echo "steered (packets bytes destination):"
  fx iptables -t mangle -L HIWAF-STEER -v -n -x 2>/dev/null | awk 'NR > 2 {print "  " $1, $2, $9}' || echo "  chain missing"
}

lock() {
  exec 9>/run/waf-steer.lock
  flock -n 9 || { log "another waf-steer holds /run/waf-steer.lock (is the service running?)"; exit 1; }
}

case "${1:-}" in
apply)
  lock
  apply
  log "$STATE"
  ;;
loop)
  lock
  last=
  while :; do
    # Each pass runs in a subshell: a failure is logged and retried, it
    # doesn't end the loop. State changes are logged once.
    if state=$(apply >&2 && printf '%s' "$STATE"); then
      [ "$state" != "$last" ] && log "$state"
      last=$state
    else
      log "pass failed; retrying in ${INTERVAL}s"
      last=
    fi
    sleep "$INTERVAL"
  done
  ;;
off)
  lock
  off
  ;;
status) status ;;
*)
  sed -n '2,9p' "$0" >&2
  exit 2
  ;;
esac
