"""Global baseline from SANS ISC / DShield. Fetched at most daily; failures fall back to the cache.

Endpoints (verified live 2026-10-12):
- ports:     /api/topports/records/20/<YYYY-MM-DD>?json  -> {"0": {rank, targetport, records, targets, sources}, ...}
             The dateless form returns only {"date", "limit"} (empty), so an explicit, complete (yesterday UTC) date is required.
- usernames: /api/topusernames?json -> [{username, attempts, date}, ...]  (/feeds/sshallusernames.json does not exist: HTML error page)
- research:  /api/threatcategory/research?json -> [{ipv4, added, lastseen, type}, ...]
"""
import datetime as dt
import json
import time
import urllib.error
import urllib.request

ISC = "https://isc.sans.edu"
ATTRIBUTION = "Global baseline: SANS Internet Storm Center / DShield (CC BY-NC-SA 4.0)"


def _urls(now):
    day = (dt.datetime.fromtimestamp(now, dt.timezone.utc) - dt.timedelta(days=1)).strftime("%Y-%m-%d")
    return {"ports": f"{ISC}/api/topports/records/20/{day}?json",
            "usernames": f"{ISC}/api/topusernames?json",
            "research": f"{ISC}/api/threatcategory/research?json"}


def default_get(url, ua):
    req = urllib.request.Request(url, headers={"User-Agent": ua})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


class Baseline:
    def __init__(self, store, http_get=default_get, contact="", now=time.time):
        self.s, self.get_url, self.now = store, http_get, now
        self.ua = "homelab-attackfeed/2.0" + (f" (+{contact})" if contact else "")

    def _fetch(self):
        raw, limited = {}, False
        for k, url in _urls(self.now()).items():
            try:
                raw[k] = json.loads(self.get_url(url, self.ua))
            except urllib.error.HTTPError as e:
                raw[k] = None
                if e.code == 429:
                    limited = True
                    break
            except Exception:  # noqa: BLE001 - partial data is fine
                raw[k] = None
        return raw, limited

    def get(self):
        last = self.s.meta("baseline_fetched")
        retry = float(self.s.meta("baseline_retry_after") or 0)
        if (last is None or self.now() - float(last) > 86400) and self.now() > retry:
            raw, limited = self._fetch()
            if limited or not any(v is not None for v in raw.values()):
                self.s.set_meta("baseline_retry_after", str(self.now() + 3600))
            else:
                old = json.loads(self.s.meta("baseline_json") or "{}")
                for k, v in raw.items():          # keep the last good data for a source that failed
                    if v is None:
                        raw[k] = old.get(k)
                self.s.set_meta("baseline_json", json.dumps(raw))
                self.s.set_meta("baseline_fetched", str(self.now()))
        raw = json.loads(self.s.meta("baseline_json") or "{}")
        fetched = self.s.meta("baseline_fetched")
        return {"ports": _ports(raw.get("ports")), "usernames": _users(raw.get("usernames")),
                "research_ips": frozenset(_ips(raw.get("research"))), "attribution": ATTRIBUTION,
                "fetched": dt.datetime.fromtimestamp(float(fetched), dt.timezone.utc).isoformat(timespec="seconds")
                if fetched else None}


def _int(v):
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def _ports(j):
    rows = j.values() if isinstance(j, dict) else (j or [])
    out = [{"port": int(r["targetport"]), "records": _int(r.get("records")), "targets": _int(r.get("targets")),
            "sources": _int(r.get("sources"))}
           for r in rows if isinstance(r, dict) and str(r.get("targetport", "")).isdigit()]
    return out[:20]


def _users(j):
    rows = j if isinstance(j, list) else (j or {}).get("usernames", []) if isinstance(j, dict) else []
    out = [{"value": r.get("username"), "count": _int(r.get("attempts", r.get("count")))}
           for r in rows if isinstance(r, dict) and r.get("username")]
    return sorted(out, key=lambda r: -r["count"])[:20]


def _ips(j):
    rows = j if isinstance(j, list) else []
    return [r.get("ipv4") or r.get("ip") for r in rows if isinstance(r, dict) and (r.get("ipv4") or r.get("ip"))]


def compare(ours_top, theirs, key):
    rank = {r[key]: i + 1 for i, r in enumerate(theirs)}
    return [{"value": o["value"], "ours_rank": i + 1, "ours_count": o["count"], "global_rank": rank.get(o["value"])}
            for i, o in enumerate(ours_top)]
