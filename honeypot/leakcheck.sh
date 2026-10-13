#!/bin/bash
# Leak check for the public attack feed: no WAN IP, LAN/private addresses, host/device names or SCRUB_WORDS
# in anything nginx can serve. Usage (serv1, docker_user): bash ~/mediaserver/honeypot/leakcheck.sh
set -uo pipefail
cd "$HOME/mediaserver" || exit 2
tok=$(cat secrets/attackfeed_token) || exit 2
dir="appdata/attackfeed/$tok"
[ -d "$dir" ] || { echo "no feed dir"; exit 2; }
unreadable=$(find "$dir" ! -readable 2>/dev/null | head -5)
if [ -n "$unreadable" ]; then echo "UNREADABLE: $(echo "$unreadable" | sed "s#^$dir\$#<token-dir>#; s#$dir/##" | tr '\n' ' ')"; exit 2; fi
wan=$(curl -fsS --max-time 10 https://1.1.1.1/cdn-cgi/trace | sed -n 's/^ip=//p')
[ -n "$wan" ] || { echo "could not determine WAN IP"; exit 2; }
fail=0
check() {  # check <label> <grep -E pattern>
  local hits rc
  hits=$(grep -rlEi -- "$2" "$dir" 2>/dev/null); rc=$?
  if [ $rc -gt 1 ]; then echo "grep error [$1]"; [ $fail -lt 2 ] && fail=2; return; fi
  if [ -n "$hits" ]; then echo "LEAK [$1] in: $(echo "$hits" | sed "s#$dir/##" | tr '\n' ' ')"; [ $fail -lt 1 ] && fail=1; fi
}
check "wan-ip" "(^|[^0-9.])${wan//./\\.}([^0-9]|$)"
check "lan-192.168" "(^|[^0-9.])192\.168\.[0-9]{1,3}\.[0-9]{1,3}"
check "lan-10" "(^|[^0-9.])10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}([^0-9]|$)"
check "tailscale-100.64/10" "(^|[^0-9.])100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}"
check "private-172.16/12" "(^|[^0-9.])172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}"
check "names" "wyatt|guethlein|geet\.dev|docker_user|wyatt-serv1|wyatt-mon|\bserv1\b|\bux7\b|synology"
check "token-in-content" "$tok"
[ $fail -eq 0 ] && echo "leakcheck: clean ($(find "$dir" -type f | wc -l) files)"
exit $fail
