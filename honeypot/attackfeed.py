"""attackfeed — builds a scrubbed, public "live attacks" feed from Loki. 2026-10-11.

Every INTERVAL seconds:
  * queries Loki (wyatt-mon) for the last WINDOW of attack events:
      - cowrie   : fake SSH/Telnet logins, commands, connections   (job="cowrie")
      - firewall : inbound connections the UniFi gateway blocked    (job="unifi", non-audit CEF)
      - web      : scanners hitting the web server by bare IP/unknown host (job="traefik", router "-")
  * keeps only public source IPs with a location, scrubs anything that identifies this home
    (our WAN IP, LAN addresses, hostnames), and writes  /out/<token>/feed.json  +  index.html (map).
Stdlib only. Runs as an unprivileged user with a read-only root filesystem; writes only to /out.
"""
import datetime as dt
import ipaddress
import json
import os
import re
import shutil
import sys
import time
import urllib.parse
import urllib.request
from collections import Counter

LOKI = os.environ.get("LOKI_URL", "http://192.168.1.73:3100").rstrip("/")
OUT = "/out"
INTERVAL = int(os.environ.get("INTERVAL", "60"))
WINDOW_H = int(os.environ.get("WINDOW_HOURS", "24"))
MAX_EVENTS = int(os.environ.get("MAX_EVENTS", "3000"))
TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
SCRUB_WORDS = [w for w in os.environ.get("SCRUB_WORDS", "geet.dev,wyatt,guethlein,docker_user").split(",") if w]

QUERIES = {
    "cowrie": '{job="cowrie", eventid=~"cowrie.session.connect|cowrie.login.failed|cowrie.login.success|cowrie.command.input"}',
    # only the gateway's default block rules on the internet side (ulogd: IN=eth1 ... SRC= DPT= PROTO=);
    # never port-forward DNAT/MASQUERADE lines (those are allowed traffic, possibly family using Plex)
    "firewall": '{job="unifi"} |= "Block All Traffic" |~ "WAN_(LOCAL|IN)" |~ "IN=eth"',
    "web": '{job="traefik"} | pattern `<_> - <_> [<_>] "<_> <_> <_>" <_> <_> "<_>" "<_>" <_> "<router>" "<_>" <_>` | router="-"',
}
TRAEFIK_RE = re.compile(r'^(\S+) - \S+ \[[^\]]+\] "(\S+) (\S+) [^"]*" (\d{3})')
CEF_RE = re.compile(r"CEF: \d+\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|([^|]*)\|")
KV_RE = re.compile(r"(?:^|\s)(src|spt|dst|dpt|proto|UNIFIcategory)=(\S+)", re.I)
DESCR_RE = re.compile(r'DESCR="([^"]*)"')


def log(*a):
    print(dt.datetime.now().strftime("%H:%M:%S"), *a, file=sys.stderr, flush=True)


def read_token():
    with open(os.environ.get("TOKEN_FILE", "/run/secrets/attackfeed_token")) as f:
        tok = f.read().strip()
    if not TOKEN_RE.match(tok):
        raise SystemExit("token must be 32 lowercase hex chars")
    return tok


def http_get(url, timeout=60):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read()


def wan_ip():
    """Our public IP (to scrub it from anything attackers typed)."""
    try:
        body = http_get("https://1.1.1.1/cdn-cgi/trace", timeout=10).decode()
        m = re.search(r"^ip=(\S+)$", body, re.M)
        return m.group(1) if m else None
    except Exception as e:  # noqa: BLE001
        log("wan ip lookup failed:", e)
        return None


def loki_query(q, start_ns, end_ns, limit):
    url = f"{LOKI}/loki/api/v1/query_range?" + urllib.parse.urlencode(
        {"query": q, "start": start_ns, "end": end_ns, "limit": limit, "direction": "backward"})
    data = json.loads(http_get(url))
    for stream in data["data"]["result"]:
        labels = stream["stream"]
        for ts, line in stream["values"]:
            yield int(ts), line, labels


def is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global


def geo(labels):
    try:
        lat = round(float(labels["geoip_location_latitude"]), 3)
        lon = round(float(labels["geoip_location_longitude"]), 3)
    except (KeyError, ValueError):
        return None
    return {"lat": lat, "lon": lon, "cc": labels.get("geoip_country_code", ""),
            "country": labels.get("geoip_country_name", ""), "city": labels.get("geoip_city_name", "")}


def scrub(s, home_ip):
    if not s:
        return s
    s = s[:200]
    if home_ip:
        s = s.replace(home_ip, "x.x.x.x")
    s = re.sub(r"\b192\.168\.\d{1,3}\.\d{1,3}\b", "x.x.x.x", s)
    for w in SCRUB_WORDS:
        s = re.sub(re.escape(w), "redacted", s, flags=re.I)
    return s


def parse(source, line, labels, home_ip):
    if source == "cowrie":
        try:
            j = json.loads(line)
        except ValueError:
            return None
        ev = {"cowrie.session.connect": "connect", "cowrie.login.failed": "login-failed",
              "cowrie.login.success": "login-success", "cowrie.command.input": "command"}.get(j.get("eventid"))
        e = {"type": ev, "src": j.get("src_ip"), "proto": j.get("protocol", "ssh"),
             "port": {"ssh": 22, "telnet": 23}.get(j.get("protocol"), j.get("dst_port"))}
        if ev in ("login-failed", "login-success"):
            e["user"] = scrub(j.get("username"), home_ip)
            e["pass"] = scrub(j.get("password"), home_ip)
        if ev == "command":
            e["cmd"] = scrub(j.get("input"), home_ip)
        return e
    if source == "firewall":
        kv = {k.lower(): v for k, v in KV_RE.findall(line)}
        m = CEF_RE.search(line) or DESCR_RE.search(line)
        port = kv.get("dpt")
        return {"type": "blocked", "src": kv.get("src"), "proto": (kv.get("proto") or "").lower(),
                "port": int(port) if port and port.isdigit() else None,
                "detail": scrub(m.group(1) if m else "", home_ip)}
    if source == "web":
        m = TRAEFIK_RE.match(line)
        if not m:
            return None
        return {"type": "web-probe", "src": m.group(1), "proto": "http", "port": 443,
                "method": m.group(2), "path": scrub(m.group(3), home_ip)}
    return None


def build(home_ip):
    now = time.time_ns()
    start = now - WINDOW_H * 3600 * 10**9
    events = []
    for source, q in QUERIES.items():
        try:
            for ts, line, labels in loki_query(q, start, now, 5000):
                e = parse(source, line, labels, home_ip)
                if not e or not e.get("type") or not is_public(e.get("src") or ""):
                    continue
                if home_ip and e["src"] == home_ip:
                    continue
                g = geo(labels)
                if not g:
                    continue
                e.update(g)
                e["t"] = dt.datetime.fromtimestamp(ts / 1e9, dt.timezone.utc).isoformat(timespec="seconds")
                e["source"] = source
                events.append({k: v for k, v in e.items() if v not in (None, "")})
        except Exception as ex:  # noqa: BLE001 — one failing source must not kill the feed
            log(f"query {source} failed:", ex)
    events.sort(key=lambda e: e["t"], reverse=True)

    def top(key, n=10, flt=None):
        c = Counter(e[key] for e in events if key in e and (flt is None or flt(e)))
        return [{"value": k, "count": v} for k, v in c.most_common(n)]

    stats = {
        "window_hours": WINDOW_H,
        "total": len(events),
        "unique_sources": len({e["src"] for e in events}),
        "by_type": dict(Counter(e["type"] for e in events)),
        "top_countries": top("country"),
        "top_ports": top("port"),
        "top_usernames": top("user"),
        "top_passwords": top("pass"),
        "top_commands": top("cmd"),
        "top_sources": top("src"),
    }
    return {"generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "stats": stats, "events": events[:MAX_EVENTS]}


def write_atomic(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(data)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def main():
    token = read_token()
    tdir = os.path.join(OUT, token)
    os.makedirs(tdir, mode=0o755, exist_ok=True)
    os.chmod(tdir, 0o755)
    # remove feed dirs of old tokens — only names that look like tokens, never anything else
    for name in os.listdir(OUT):
        p = os.path.join(OUT, name)
        if TOKEN_RE.match(name) and name != token and os.path.isdir(p) and os.path.dirname(p) == OUT:
            shutil.rmtree(p)
            log("removed old token dir")
    home_ip, home_checked = None, 0.0
    while True:
        if time.time() - home_checked > 3600:
            home_ip = wan_ip() or home_ip
            home_checked = time.time()
        try:
            with open("/app/map.html", encoding="utf-8") as f:
                write_atomic(os.path.join(tdir, "index.html"), f.read())
            feed = build(home_ip)
            write_atomic(os.path.join(tdir, "feed.json"), json.dumps(feed, separators=(",", ":")))
            log(f"feed: {feed['stats']['total']} events, {feed['stats']['unique_sources']} sources")
        except Exception as ex:  # noqa: BLE001
            log("build failed:", ex)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
