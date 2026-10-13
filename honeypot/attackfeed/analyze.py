"""Everything the page learns from the 7-day store. Pure functions over event dicts (with ts in ns)."""
import datetime as dt
import hashlib
import re
import statistics
from collections import Counter, defaultdict
from .parse import kind

NS, H, D = 10**9, 3600 * 10**9, 86400 * 10**9
RESEARCH_ORGS = re.compile(r"censys|shodan|shadowserver|palo alto|expanse|rapid7|binaryedge|stretchoid|onyphe|"
                           r"internet measurement|leakix|driftnet|criminal ?ip|recyber|alpha strike|ipip\.net", re.I)
DROP_RE = re.compile(r"\b(wget|curl|tftp|ftpget)\b|echo -(?:e|ne|en) ['\"]?\\x", re.I)
URL_RE = re.compile(r"\b(?:https?|ftp|hxxps?)://[^\s;|&'\"]+", re.I)
TFTP_RE = re.compile(r"tftp\s+(?:-g\s+)?(?:-r\s+(\S+)\s+)?(\d{1,3}(?:\.\d{1,3}){3})(?:\s+-c\s+get\s+(\S+))?", re.I)
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b")
TOKEN_RE = re.compile(r"\b(?=[A-Za-z0-9_]*\d)[A-Za-z0-9_]{8,}\b|\b[0-9a-fA-F]{8,}\b")
BOT_VOCAB = {"uname", "cat", "cd", "wget", "curl", "chmod", "sh", "echo", "nproc", "free", "ls", "rm", "mkdir",
             "crontab", "which", "busybox", "enable", "system", "shell", "tftp", "ftpget", "grep", "head", "awk",
             "lscpu", "top", "w", "uptime", "ps", "history", "export", "passwd", "chpasswd", "exit", "nohup", "pkill"}


def iso(ns):
    return dt.datetime.fromtimestamp(ns / NS, dt.timezone.utc).isoformat(timespec="seconds")


def _top(counter, n=10):
    return [{"value": k, "count": v} for k, v in counter.most_common(n)]


def _recent(events, now_ns, hours):
    lo = now_ns - hours * H
    return [x for x in events if lo <= x["ts"] <= now_ns]


def counts(events, now_ns, hours=24):
    ev = _recent(events, now_ns, hours)

    def c(key):
        return Counter(x[key] for x in ev if x.get(key) not in (None, ""))

    creds = [x for x in ev if x["type"] in ("login-failed", "login-success")]
    return {"window_hours": hours, "total": len(ev), "unique_sources": len({x["src"] for x in ev}),
            "countries": len({x["cc"] for x in ev if x.get("cc")}),
            "by_source": dict(Counter(x["source"] for x in ev)), "by_type": dict(Counter(x["type"] for x in ev)),
            "by_kind": dict(Counter(kind(x) for x in ev)), "top_countries": _top(c("country")),
            "top_ports": _top(c("port")), "top_usernames": _top(Counter(x.get("user") for x in creds if x.get("user"))),
            "top_passwords": _top(Counter(x.get("pass") for x in creds if x.get("pass"))),
            "top_commands": _top(c("cmd")), "top_sources": _top(c("src")), "top_orgs": _top(c("org"))}


def locations(events, now_ns, hours=24):
    g = {}
    for x in _recent(events, now_ns, hours):
        if "lat" not in x or "lon" not in x:
            continue
        L = g.setdefault((x["lat"], x["lon"]), {
            "lat": x["lat"], "lon": x["lon"], "cc": x.get("cc", ""), "country": x.get("country", ""),
            "city": x.get("city", ""), "n": 0, "kinds": Counter(), "_src": Counter()})
        L["n"] += 1
        L["kinds"][kind(x)] += 1
        L["_src"][x["src"]] += 1
    out = []
    for L in g.values():
        L["kinds"] = dict(L["kinds"])
        L["top_src"] = L.pop("_src").most_common(1)[0][0]
        out.append(L)
    return sorted(out, key=lambda L: -L["n"])


def normalise_cmd(cmd):
    s = URL_RE.sub("URL", cmd or "")
    s = IP_RE.sub("IP", s)
    s = TOKEN_RE.sub("X", s)
    return re.sub(r"\s+", " ", s).strip()


def _file_of(cmd):
    m = URL_RE.search(cmd or "")
    if m:
        name = m.group(0).rstrip("/").rsplit("/", 1)[-1]
        if name and not name.replace(".", "").isdigit():
            return name[:40]
    t = TFTP_RE.search(cmd or "")
    if t and (t.group(1) or t.group(3)):
        return (t.group(1) or t.group(3))[:40]
    return None


def campaigns(events):
    by_session = defaultdict(list)
    for x in events:
        if x.get("session") and x["type"] in ("command", "login-failed", "login-success"):
            by_session[x["session"]].append(x)
    scripts, pwlists = defaultdict(list), defaultdict(list)
    for sid, rows in by_session.items():
        rows.sort(key=lambda r: r["ts"])
        cmds = [r["cmd"] for r in rows if r["type"] == "command" and r.get("cmd")]
        if cmds:
            fp = hashlib.sha1("\n".join(normalise_cmd(c) for c in cmds).encode()).hexdigest()[:8]
            scripts[fp].append((sid, rows, cmds))
        creds = tuple(f"{r.get('user', '')} / {r.get('pass', '')}" for r in rows if r["type"].startswith("login"))[:3]
        if len(creds) == 3:
            fp = hashlib.sha1("|".join(creds).encode()).hexdigest()[:8]
            pwlists[fp].append((sid, rows, list(creds)))
    out = []
    for kindname, groups, need in (("script", scripts, 2), ("passwords", pwlists, 3)):
        for fp, members in groups.items():
            ips = {m[1][0]["src"] for m in members}
            if len(ips) < need:
                continue
            rows = [r for m in members for r in m[1]]
            if kindname == "script":
                label = next((f for c in members[0][2] if (f := _file_of(c))), None) or members[0][2][0][:40]
            else:
                label = ", ".join(members[0][2])[:40]
            out.append({"id": fp, "kind": kindname, "label": label, "ips": len(ips),
                        "countries": [k for k, _ in Counter(r.get("country") for r in rows if r.get("country")).most_common(5)],
                        "n_countries": len({r.get("country") for r in rows if r.get("country")}),
                        "orgs": [k for k, _ in Counter(r.get("org") for r in rows if r.get("org")).most_common(3)],
                        "first": iso(min(r["ts"] for r in rows)), "last": iso(max(r["ts"] for r in rows)),
                        "sample_session": members[-1][0], "members": sorted(ips)})
    return sorted(out, key=lambda c: -c["ips"])


def verdict(p, research_ips=frozenset()):
    """First match wins: research scanner, hands-on, dropper, password bot, port scanner, web scanner, mixed."""
    kinds = set(p.get("kinds") or {})
    cmds = p.get("cmds") or []
    if RESEARCH_ORGS.search(p.get("org") or "") or p.get("ip") in research_ips:
        return "research scanner"
    if p.get("hands_on"):
        return "hands-on"
    if any(DROP_RE.search(c) for c in cmds):
        return "dropper"
    if kinds and not cmds and kinds <= {"ssh", "telnet", "success"}:
        return "password bot"
    if kinds and kinds <= {"blocked", "ips"}:
        return "port scanner"
    if kinds and kinds <= {"web", "crowdsec"}:
        return "web scanner"
    return "mixed"


def _first_word(cmd):
    w = (cmd or "").split()
    return w[0].rsplit("/", 1)[-1] if w else ""


def _hands_on(rows, session_gaps):
    """Slow typing (median input gap > 2 s over >= 3 commands in a session), or off-vocabulary commands (>= 3 total)."""
    cmd_rows = [r for r in rows if r["type"] == "command" and r.get("cmd")]
    per_session = Counter(r["session"] for r in cmd_rows if r.get("session"))
    if any(n >= 3 and session_gaps.get(sid, 0) > 2.0 for sid, n in per_session.items()):
        return True
    return len(cmd_rows) >= 3 and any(_first_word(r["cmd"]) not in BOT_VOCAB for r in cmd_rows if _first_word(r["cmd"]))


def profiles(events, now_ns, camps, research_ips=frozenset(), session_gaps=None):
    """session_gaps: {session: MEDIAN inter-input gap in seconds} (tty sessions only)."""
    session_gaps = session_gaps or {}
    by_ip = defaultdict(list)
    for x in events:
        by_ip[x["src"]].append(x)
    camp_of = defaultdict(list)
    for c in camps:
        for ip in c["members"]:
            camp_of[ip].append(c["id"])
    out = {}
    for ip, rows in by_ip.items():
        rows.sort(key=lambda r: r["ts"])
        g = next((r for r in rows if "lat" in r), rows[-1])
        cmds = list(dict.fromkeys(r["cmd"] for r in rows if r.get("cmd")))
        sessions = sorted({r["session"] for r in rows if r.get("session")})
        p = {"ip": ip, "asn": g.get("asn"), "org": g.get("org"), "cc": g.get("cc"), "country": g.get("country"),
             "city": g.get("city"), "first": iso(rows[0]["ts"]), "last": iso(rows[-1]["ts"]),
             "returning": rows[0]["ts"] // D < rows[-1]["ts"] // D,
             "kinds": dict(Counter(kind(r) for r in rows)),
             "ports": _top(Counter(r["port"] for r in rows if r.get("port")), 8),
             "creds": _top(Counter(f"{r.get('user', '')} / {r.get('pass', '')}" for r in rows if r["type"].startswith("login")), 8),
             "cmds": cmds[:20], "sessions": sessions[-10:], "campaigns": camp_of.get(ip, []),
             "n24": sum(1 for r in rows if r["ts"] >= now_ns - D), "n7": len(rows)}
        p["verdict"] = verdict({**p, "cmds": cmds, "hands_on": _hands_on(rows, session_gaps)}, research_ips)
        out[ip] = {k: v for k, v in p.items() if v not in (None, "")}
    return out


CHANNEL = {"firewall": "firewall", "ips": "ips", "web": "web", "cowrie": "honeypot", "crowdsec": "crowdsec"}


def trends(events, now_ns):
    chans = list(dict.fromkeys(CHANNEL.values()))
    grid = {c: [[0] * 24 for _ in range(7)] for c in chans}
    days = {c: [0] * 7 for c in chans}
    hourly = {c: [0] * 24 for c in chans}
    today = dt.datetime.fromtimestamp(now_ns / NS, dt.timezone.utc).date()
    for x in events:
        age = now_ns - x["ts"]
        c = CHANNEL.get(x["source"])
        if age < 0 or not c:
            continue
        t = dt.datetime.fromtimestamp(x["ts"] / NS, dt.timezone.utc)
        back = (today - t.date()).days                  # grid rows are UTC calendar days, row 6 = today so far
        if back <= 6:
            grid[c][6 - back][t.hour] += 1
        if age >= 7 * D:
            continue
        d = int(age // D)                               # today_vs_usual stays on rolling 24 h windows
        days[c][d] += 1
        if age < D:
            hourly[c][23 - int(age // H)] += 1
    # Previous days count (zeros included) only where the store's history fully covers them.
    oldest_age = max((now_ns - x["ts"] for x in events if x["ts"] <= now_ns), default=0)
    covered = [d for d in range(1, 7) if (d + 1) * D <= oldest_age or (d == 6 and oldest_age >= 6 * D)]
    tvu = {}
    for c in chans:
        med = statistics.median([days[c][d] for d in covered]) if covered else 0
        tvu[c] = round(days[c][0] / med, 2) if med else None
    grid_days = [(today - dt.timedelta(days=6 - i)).isoformat() for i in range(7)]
    return {"grid": grid, "grid_days": grid_days, "today_vs_usual": tvu, "hourly24": hourly}


def _defang(u):
    if "[.]" in u:
        return u
    u = re.sub(r"^http", "hxxp", u, flags=re.I)
    scheme, _, rest = u.partition("://")
    host, sep, path = rest.partition("/")
    i = host.rfind(".")
    host = host[:i] + "[.]" + host[i + 1:] if i > 0 else host
    return f"{scheme}://{host}{sep}{path}"


def malware(events):
    m = {}
    for x in events:
        urls, sha = [], None
        if x["type"] == "download" and x.get("url"):
            urls, sha = [x["url"]], x.get("sha256")
        elif x["type"] == "command" and x.get("cmd"):
            urls = [re.sub(r"^http", "hxxp", u, flags=re.I) for u in URL_RE.findall(x["cmd"])]
            t = TFTP_RE.search(x["cmd"])
            if t and (t.group(1) or t.group(3)):
                urls.append(f"tftp://{t.group(2)}/{t.group(1) or t.group(3)}")
        for u in urls:
            u = _defang(u)
            path = u.partition("://")[2].partition("/")[2].rstrip("/")
            f = path.rsplit("/", 1)[-1][:60] or None
            r = m.setdefault(u, {"url": u, "file": f, "sha256": None, "first": x["ts"], "last": x["ts"], "_ips": set()})
            r["first"] = min(r["first"], x["ts"])
            r["last"] = max(r["last"], x["ts"])
            r["_ips"].add(x["src"])
            if sha:
                r["sha256"] = sha
    out = []
    for r in m.values():
        r["ips"] = len(r.pop("_ips"))
        r["first"], r["last"] = iso(r["first"]), iso(r["last"])
        r["links"] = ({"malwarebazaar": f"https://bazaar.abuse.ch/browse.php?search=sha256%3A{r['sha256']}",
                       "virustotal": f"https://www.virustotal.com/gui/file/{r['sha256']}"} if r["sha256"] else {})
        out.append({k: v for k, v in r.items() if v is not None})
    out.sort(key=lambda r: r["last"], reverse=True)
    return sorted(out, key=lambda r: -r["ips"])
