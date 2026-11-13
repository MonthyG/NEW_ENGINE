#!/usr/bin/env bash
# Prints the network and Docker state that the WAF install touches, so a
# snapshot taken before the install can be diffed with one taken after a
# reset. Read-only.
#
#   ssh -p 11911 root@cmpt4 'bash -s' < scripts/waf-snapshot.sh > before.txt
#   ... install, test, waf-reset.sh ...
#   ssh -p 11911 root@cmpt4 'bash -s' < scripts/waf-snapshot.sh > after.txt
#   diff before.txt after.txt
#
# Counters and Neutron's own churn (new ports, VMs) can show up in the diff;
# anything named HIWAF, hiwaf-*, 1455/1456 or cloudinside-waf must not.
set -u
sec() { echo; echo "=== $*"; }
# Rule counters change all the time; strip them so the diff shows real changes.
ipt() { ip netns exec "$1" iptables-save | sed -E '/^#/d; s/\[[0-9]+:[0-9]+\]/[0:0]/'; }

sec host
hostname
sec netns
ip netns list | awk '{print $1}' | sort
for ns in $(ip netns list | awk '$1 ~ /^(fip|qrouter)-/ {print $1}' | sort); do
  sec "$ns: links";  ip netns exec "$ns" ip -br link | sed -E 's/ +/ /g' | sort
  sec "$ns: addrs";  ip netns exec "$ns" ip -br addr | sed -E 's/ +/ /g' | sort
  sec "$ns: rules";  ip netns exec "$ns" ip rule
  sec "$ns: routes"; ip netns exec "$ns" ip route show table all | sort
  sec "$ns: iptables"; ipt "$ns"
done
sec "docker containers"; docker ps -a --format '{{.Names}} {{.Image}}' | sort
sec "docker images";     docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}' | sort
sec "waf files";         ls -la /etc/hiwaf /usr/local/sbin/waf-steer.sh /etc/systemd/system/waf-steer.service 2>&1 | sort
sec "waf units";         systemctl list-units --all --no-legend 'waf*' 2>&1
