#!/bin/bash
# Cron wrapper for leakcheck.sh (docker_user crontab, every 30 min). Logs every failure to the journal
# (tag attackfeed-leakcheck) and posts one terse line to Discord #security when the result changes:
# a leak (exit 1) at once, a check error (exit 2) only when it repeats, and a line when it is clean again.
# The posted line is leakcheck's own output: match type + file name only, never the value or the token dir.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
state="$HOME/.cache/attackfeed-leakcheck.state"      # last posted status line
webhook_file="$HOME/.config/homelab/security.url"
mkdir -p "$(dirname "$state")"

out=$(bash "$here/leakcheck.sh" 2>&1); rc=$?
line=$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-300)
prev=$(cat "$state" 2>/dev/null || true)

post() {
  local msg="$1"
  python3 - "$webhook_file" "$msg" <<'PY' || { logger -t attackfeed-leakcheck "discord post failed"; return 1; }
import json, sys, urllib.request
url = open(sys.argv[1]).read().strip()
body = json.dumps({"content": sys.argv[2], "allowed_mentions": {"parse": []}}).encode()
req = urllib.request.Request(url, data=body, method="POST",
                             headers={"Content-Type": "application/json", "User-Agent": "attackfeed-leakcheck"})
urllib.request.urlopen(req, timeout=30).read()
PY
}

if [ $rc -eq 0 ]; then
  rm -f "$state.err"
  if [ -n "$prev" ] && [ "$prev" != "clean" ]; then
    post "Attack feed leakcheck clean again" && echo clean > "$state"
  else
    echo clean > "$state"
  fi
  exit 0
fi

logger -t attackfeed-leakcheck "exit $rc: $line"
if [ $rc -eq 1 ]; then
  msg="Attack feed leakcheck: $line"
else
  msg="Attack feed leakcheck error (exit $rc): $line"
  pending="$state.err"
  if [ ! -e "$pending" ]; then touch "$pending"; exit 0; fi   # first error: wait for a repeat
fi
rm -f "$state.err"
[ "$msg" = "$prev" ] && exit 0
post "$msg" && printf '%s' "$msg" > "$state"
exit 0
