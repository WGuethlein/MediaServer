"""One Loki line (+ its labels) -> one normalised event dict, or None."""
import ipaddress, json, math, re

TRAEFIK_RE = re.compile(r'^(\S+) - \S+ \[[^\]]+\] "(\S+) (\S+) [^"]*" (\d{3})')
KV_RE = re.compile(r"(?:^|\s)(src|SRC|dpt|DPT|proto|PROTO)=(\S+)")
CEF_NAME = re.compile(r"CEF:\s*\d+\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|([^|]*)\|")
POLICY = re.compile(r"UNIFIpolicyName=(.+?)(?=\s+\w+=|$)")
DESCR_RE = re.compile(r'DESCR="([^"]*)"')
BAN_RE = re.compile(r"\) (crowdsecurity/\S+|\S+/\S+) by ip (\S+) \((\w*)/(\d*)\) : (\S+) ban on Ip")
COWRIE_TYPES = {"cowrie.session.connect": "connect", "cowrie.login.failed": "login-failed",
                "cowrie.login.success": "login-success", "cowrie.command.input": "command",
                "cowrie.log.closed": "closed", "cowrie.client.version": "client", "cowrie.client.kex": "client",
                "cowrie.session.file_download": "download", "cowrie.direct-tcpip.request": "tcpip"}

def geo(labels):
    try:
        g = {"lat": round(float(labels["geoip_location_latitude"]), 3),
             "lon": round(float(labels["geoip_location_longitude"]), 3)}
        if not (math.isfinite(g["lat"]) and math.isfinite(g["lon"])):
            return None
    except (KeyError, ValueError, TypeError, OverflowError):
        return None
    g["cc"] = labels.get("geoip_country_code", "")
    g["country"] = labels.get("geoip_country_name", "")
    g["city"] = labels.get("geoip_city_name", "")
    asn = labels.get("geoip_autonomous_system_number")
    if asn and str(asn).isascii() and str(asn).isdecimal():
        g["asn"] = int(asn)
    if labels.get("geoip_autonomous_system_organization"):
        g["org"] = labels["geoip_autonomous_system_organization"]
    return g

def kind(e):
    s = e.get("source")
    if s == "firewall": return "blocked"
    if s in ("ips", "crowdsec", "web"): return s
    if e.get("type") in ("login-success", "command", "download"): return "success"
    return "telnet" if e.get("proto") == "telnet" else "ssh"

def _int(v):
    try:
        s = str(v)
        return int(s) if v is not None and s.isascii() and s.isdecimal() else None
    except (ValueError, TypeError):
        return None

# Not attackers: RFC1918, CGNAT/Tailscale, loopback, link-local, multicast, reserved, unspecified.
# Documentation ranges (192.0.2/24, 198.51.100/24, 203.0.113/24) stay allowed (test fixtures use them).
NON_PUBLIC = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4"))

def is_public(src):
    if not isinstance(src, str):
        return False
    try:
        a = ipaddress.ip_address(src)
    except (ValueError, TypeError):
        return False
    if a.version == 4:
        return not any(a in n for n in NON_PUBLIC)
    return a.is_global

def _cowrie(line, sc):
    try:
        j = json.loads(line)
    except ValueError:
        return None
    t = COWRIE_TYPES.get(j.get("eventid"))
    if not t:
        return None
    proto = j.get("protocol") or ("telnet" if j.get("dst_port") in (23, 2223) else "ssh")
    e = {"type": t, "src": j.get("src_ip"), "proto": proto, "session": j.get("session"),
         "port": {"ssh": 22, "telnet": 23}.get(proto)}
    if t in ("login-failed", "login-success"):
        e["user"] = sc.text(j.get("username")); e["pass"] = sc.text(j.get("password"))
    elif t == "command":
        e["cmd"] = sc.text(j.get("input"), cap=500)
    elif t == "closed":
        # real cowrie.log.closed carries duration_ms (not duration)
        e["ttylog"] = j.get("ttylog")
        e["duration"] = float(j["duration"]) if j.get("duration") is not None else float(j.get("duration_ms") or 0) / 1000
    elif t == "client":
        if j.get("eventid") == "cowrie.client.version":
            e["client"] = sc.text(j.get("version"))
        else:
            e["hassh"] = j.get("hassh")
    elif t == "download":
        e["url"] = sc.url(j.get("url")); e["sha256"] = j.get("shasum")
    elif t == "tcpip":
        e["port"] = _int(j.get("dst_port")); e["url"] = sc.text(j.get("dst_ip"))
    return e

def _firewall(line, sc):
    kv = {k.lower(): v for k, v in KV_RE.findall(line)}
    m = DESCR_RE.search(line)
    return {"type": "blocked", "src": kv.get("src"), "proto": (kv.get("proto") or "").lower() or None,
            "port": _int(kv.get("dpt")), "sig": sc.text(m.group(1) if m else None)}

def _ips(line, sc):
    kv = {k.lower(): v for k, v in KV_RE.findall(line)}
    m = POLICY.search(line) or CEF_NAME.search(line)
    return {"type": "ips", "src": kv.get("src"), "proto": (kv.get("proto") or "").lower() or None,
            "port": _int(kv.get("dpt")), "sig": sc.text(m.group(1).strip() if m else None)}

def _web(line, sc):
    m = TRAEFIK_RE.match(line)
    if not m:
        return None
    return {"type": "web-probe", "src": m.group(1), "proto": "http", "port": 443,
            "method": sc.text(m.group(2), cap=12), "path": sc.text(m.group(3))}

def _crowdsec(line, sc):
    m = BAN_RE.search(line)
    if not m:
        return None
    e = {"type": "ban", "src": m.group(2), "scenario": sc.text(m.group(1))}
    if m.group(4):
        e["asn"] = int(m.group(4))
    return e

PARSERS = {"cowrie": _cowrie, "firewall": _firewall, "ips": _ips, "web": _web, "crowdsec": _crowdsec}

def parse(source, line, labels, scrub):
    p = PARSERS.get(source)
    try:
        e = p(line, scrub) if p else None
    except Exception:   # one malformed line must never abort a cycle (OverflowError, RecursionError, ...)
        return None
    if not e or not e.get("type") or not is_public(e.get("src")) or e["src"] == getattr(scrub, "home_ip", None) \
            or e["src"] in getattr(scrub, "home_ips", ()):
        return None
    e["source"] = source
    try:
        g = geo(labels or {})
    except Exception:
        g = None
    if g:
        for k, v in g.items():
            e.setdefault(k, v)
    return {k: v for k, v in e.items() if v not in (None, "")}
