#!/usr/bin/env bash
# Puts a compute host back to how it was before the WAF install: traffic on
# Neutron's normal path, no engine container, no waf-steer files. Safe to run
# twice, or when only part of the install happened.
#
#   ssh -p 11911 root@cmpt4 'bash -s' < scripts/waf-reset.sh
#   ssh -p 11911 root@cmpt4 'KEEP_IMAGE=1 bash -s' < scripts/waf-reset.sh   (keep the image)
#
# Then compare with the snapshot from before the install (see waf-snapshot.sh).
set -u
ENGINE=${ENGINE_CONTAINER:-cloudinside-waf}
IMAGE=${IMAGE:-cloudinside-waf}
say() { echo "waf-reset: $*"; }

# 1. Traffic first: once steering is off, nothing depends on the rest.
systemctl disable --now waf-steer 2>/dev/null && say "waf-steer service stopped"
# ExecStopPost runs "off", but run it again in case the service was never installed
# or the script was run by hand.
if [ -x /usr/local/sbin/waf-steer.sh ]; then
  ENGINE_CONTAINER=$ENGINE /usr/local/sbin/waf-steer.sh off
fi

# 2. Belt and braces: remove anything waf-steer adds, even if the script is gone.
for ns in $(ip netns list | awk '$1 ~ /^fip-/ {print $1}'); do
  x() { ip netns exec "$ns" "$@"; }
  while x iptables -t mangle -D PREROUTING -j HIWAF-STEER 2>/dev/null; do :; done
  while x iptables -t filter -D FORWARD -j HIWAF-FWD 2>/dev/null; do :; done
  x iptables -t mangle -F HIWAF-STEER 2>/dev/null; x iptables -t mangle -X HIWAF-STEER 2>/dev/null
  x iptables -t filter -F HIWAF-FWD 2>/dev/null;   x iptables -t filter -X HIWAF-FWD 2>/dev/null
  while x ip rule del priority 1455 2>/dev/null; do :; done
  while x ip rule del priority 40000 2>/dev/null; do :; done
  x ip route flush table 1455 2>/dev/null
  x ip route flush table 1456 2>/dev/null
  x ip link del hiwaf-h 2>/dev/null && say "removed veth from $ns"
done

# 3. The engine.
# docker rm -f succeeds even when there's no such container.
if docker inspect "$ENGINE" >/dev/null 2>&1; then
  docker rm -f "$ENGINE" >/dev/null && say "removed container $ENGINE"
fi
if [ -z "${KEEP_IMAGE:-}" ]; then
  for img in $(docker images --format '{{.Repository}}:{{.Tag}}' "$IMAGE"); do
    docker rmi "$img" >/dev/null && say "removed image $img"
  done
fi

# 4. Files.
rm -f /etc/systemd/system/waf-steer.service /usr/local/sbin/waf-steer.sh /run/waf-steer.lock
rm -rf /etc/hiwaf
systemctl daemon-reload

# 5. Check.
left=0
for ns in $(ip netns list | awk '$1 ~ /^fip-/ {print $1}'); do
  ip netns exec "$ns" iptables-save | grep -q HIWAF && { say "LEFT: iptables chains in $ns"; left=1; }
  [ -n "$(ip netns exec "$ns" ip rule show priority 1455)$(ip netns exec "$ns" ip rule show priority 40000)" ] && { say "LEFT: ip rules in $ns"; left=1; }
  ip netns exec "$ns" ip link show hiwaf-h >/dev/null 2>&1 && { say "LEFT: veth in $ns"; left=1; }
done
docker ps -a --format '{{.Names}}' | grep -qx "$ENGINE" && { say "LEFT: container $ENGINE"; left=1; }
[ "$left" = 0 ] && say "done: host is back to its pre-WAF state"
exit "$left"
