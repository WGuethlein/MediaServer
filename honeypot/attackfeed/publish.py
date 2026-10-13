"""Builds and atomically writes the public files. Only scrubbed, whitelisted fields leave this module."""
import json, os, re
from .analyze import iso
from .parse import kind

NS = 10**9
OUT_FIELDS = ("source", "type", "src", "proto", "port", "user", "pass", "cmd", "path", "method", "sig", "session",
              "client", "url", "sha256", "duration", "scenario", "lat", "lon", "cc", "country", "city", "asn", "org", "verdict")
SESSION_ID = re.compile(r"^[0-9a-f]{8,32}$")
SESSION_FILE = re.compile(r"^[0-9a-f]{8,32}\.json$")


def event_out(e, verdicts=None):
    o = {"t": iso(e["ts"])}
    for k in OUT_FIELDS:
        if e.get(k) not in (None, ""):
            o[k] = e[k]
    o["kind"] = kind(e)
    if verdicts and e["src"] in verdicts:
        o["verdict"] = verdicts[e["src"]]
    return o


def thin(events, max_events, newest_firewall=1500):
    """All non-firewall events, the newest firewall events, then an evenly spaced sample of older firewall."""
    fw = sorted((e for e in events if e["source"] == "firewall"), key=lambda e: -e["ts"])
    other = sorted((e for e in events if e["source"] != "firewall"), key=lambda e: e["ts"])
    room = max(max_events - len(other), 0)
    keep = fw[:min(newest_firewall, room)]
    rest, left = fw[len(keep):], room - len(keep)
    if left > 0 and rest:
        step = len(rest) / left
        keep += [rest[int(i * step)] for i in range(min(left, len(rest)))]
    out = other[-max_events:] + keep
    return sorted(out, key=lambda e: -e["ts"])[:max_events]


def build_feed(events, stats, now_ns, max_events, verdicts=None, window_hours=24):
    lo = now_ns - window_hours * 3600 * NS
    recent = [e for e in events if lo <= e["ts"] <= now_ns]
    return {"generated": iso(now_ns), "stats": stats, "events": [event_out(e, verdicts) for e in thin(recent, max_events)]}


def build_live(events, stats, now_ns, minutes, verdicts=None):
    lo = now_ns - minutes * 60 * NS
    ev = sorted((e for e in events if lo <= e["ts"] <= now_ns), key=lambda e: -e["ts"])
    return {"generated": iso(now_ns), "stats": stats, "events": [event_out(e, verdicts) for e in ev]}


def build_insights(now_ns, history_days, locations, profiles, camps, trends, baseline_view, malware, session_index,
                   live_hours=24):
    return {"generated": iso(now_ns), "window": {"live_hours": live_hours, "history_days": history_days},
            "locations": locations, "profiles": profiles,
            "campaigns": [{k: v for k, v in c.items() if k != "members"} | {"members": c["members"][:50]} for c in camps[:40]],
            "trends": trends, "baseline": baseline_view, "malware": malware[:50], "sessions": session_index}


def guard(obj, scrub):
    """Last line before anything is written: drops every record (dict with src/ip, dict key, bare string) that is a
    known home IP and re-scrubs every string uncapped. Rows stored before a WAN change was learned are caught here."""
    homes = scrub.home_ips

    def home(v):
        return isinstance(v, dict) and (v.get("src") in homes or v.get("ip") in homes) or \
            isinstance(v, str) and v in homes

    def walk(v):
        if isinstance(v, str):
            return scrub.text(v, cap=None)
        if isinstance(v, dict):
            return {k: walk(x) for k, x in v.items() if not home(x) and not (isinstance(k, str) and k in homes)}
        if isinstance(v, (list, tuple)):
            return [walk(x) for x in v if not home(x)]
        return v
    return walk(obj)


def write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, separators=(",", ":"), ensure_ascii=False)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def write_text(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def sync_sessions(d, sessions, remove=True):
    """Writes <id>.json for each session with a safe id; removes only stale files named like a session
    (remove=False: write only, so the caller can publish the new index before stale files go)."""
    os.makedirs(d, mode=0o755, exist_ok=True)
    good = [s for s in sessions if SESSION_ID.match(str(s.get("id", "")))]
    want = {f"{s['id']}.json" for s in good}
    for s in good:
        write_json(os.path.join(d, f"{s['id']}.json"), s)
    removed = 0
    for name in (os.listdir(d) if remove else ()):
        if SESSION_FILE.match(name) and name not in want:
            os.remove(os.path.join(d, name)); removed += 1
    return len(good), removed


def campaign_lines(camps):
    return ["CAMPAIGN " + json.dumps({k: v for k, v in c.items() if k != "members"}, separators=(",", ":")) for c in camps]
