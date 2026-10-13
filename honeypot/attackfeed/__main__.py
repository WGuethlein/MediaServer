"""attackfeed-gen v2 main loop. See docs/honeypot.md."""
import datetime as dt, json, os, re, shutil, sys, time, urllib.request
from collections import Counter
from . import analyze as A, ingest as I, publish as P, sessions as S
from .baseline import ATTRIBUTION, Baseline, compare
from .config import load
from .loki import query_range
from .scrub import Scrubber
from .store import Store

NS, H, D = 10**9, 3600 * 10**9, 86400 * 10**9
WAN_RECHECK_S = 300           # a WAN change is learned (and scrubbed) within 5 min
TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
EMPTY_BASELINE = {"ports": [], "usernames": [], "research_ips": frozenset(), "fetched": None, "attribution": ATTRIBUTION}


def log(*a):
    print(dt.datetime.now().strftime("%H:%M:%S"), *a, file=sys.stderr, flush=True)


def wan_ip():
    try:
        with urllib.request.urlopen("https://1.1.1.1/cdn-cgi/trace", timeout=10) as r:
            m = re.search(r"^ip=(\S+)$", r.read().decode(), re.M)
            return m.group(1) if m else None
    except Exception as e:  # noqa: BLE001
        log("wan ip lookup failed:", e)
        return None


def load_homes(scrub, store):
    """Past home IPs from the store: a restart or WAN change must still scrub an old WAN in 7-day data."""
    try:
        ips = json.loads(store.meta("home_ips") or "[]")
    except ValueError:
        ips = []
    for ip in ips if isinstance(ips, list) else []:
        if isinstance(ip, str):
            scrub.remember(ip)


def set_home(scrub, store, ip):
    if scrub.set_home(ip):
        store.set_meta("home_ips", json.dumps(sorted(scrub.home_ips)))
        log("home ip added to scrub list")


def _try(log, what, fn, default):
    try:
        return fn()
    except Exception as ex:  # noqa: BLE001 - one broken part must not stop the rest of the cycle
        log(f"{what} failed: {ex!r}")
        return default


def _pull(store, fetch, scrub, now_ns, days, log, sleep):
    """Backfill any source without a cursor first, then ingest only cursored sources (a failed backfill
    stays a hole that the next cycle retries, instead of being covered by a 1-h ingest cursor)."""
    if not scrub.home_ip:
        log("no wan ip yet, not ingesting")
        return
    if any(store.cursor(s) is None for s in I.QUERIES):
        I.backfill(store, fetch, now_ns, days, scrub, sleep=sleep, log=log)
    ready = [s for s in I.QUERIES if store.cursor(s) is not None]
    I.ingest(store, fetch, now_ns, scrub, log=log, sources=ready)


def _baseline_view(b, stats, scrub):
    if not b["fetched"]:
        return None
    users = [{"value": scrub.text(u["value"]), "count": u["count"]} for u in b["usernames"]]
    return {"ports": compare(stats["top_ports"], b["ports"], "port"),
            "usernames": compare(stats["top_usernames"], users, "value"),
            "global_ports": b["ports"], "global_usernames": users,
            "fetched": b["fetched"], "attribution": b["attribution"]}


def load_rows(store, now_ns, cfg):
    """Memory-bounded loading: full rows only for the last 24 h (all sources) and for the 7 days of cowrie rows
    (small). Everything else that spans 7 days comes from SQL aggregates (trends, per-IP summaries, ports)."""
    lo = now_ns - max(cfg.window_hours, 24) * H
    recent = store.events(lo)
    old_cowrie = store.events(now_ns - cfg.history_days * D, sources=("cowrie",), until=lo)
    cowrie = old_cowrie + [e for e in recent if e["source"] == "cowrie"]
    return recent, cowrie, old_cowrie + recent


def cycle(cfg, store, fetch, scrub, baseline, now_ns, tdir, log=log, sleep=time.sleep):
    _try(log, "ingest", lambda: _pull(store, fetch, scrub, now_ns, cfg.history_days, log, sleep), None)
    since7 = now_ns - cfg.history_days * D
    recent, cowrie, rows = load_rows(store, now_ns, cfg)
    stats = A.counts(recent, now_ns, cfg.window_hours)
    b = _try(log, "baseline", baseline.get, None) or EMPTY_BASELINE
    camps = _try(log, "campaigns", lambda: A.campaigns(cowrie), [])
    sess = _try(log, "sessions", lambda: S.build(cowrie, cfg.tty_dir, scrub, log=log), None)
    sessions_ok = sess is not None                  # a failed build must never prune the published session files
    sess = sess or {}
    gaps = {k: v.get("gaps_median", 0) for k, v in sess.items() if v.get("has_tty")}

    def build_profiles():                           # every IP seen in 24 h or in cowrie (verdicts); no ports yet
        summ = store.ip_summary(since7, {e["src"] for e in rows})
        return A.build_profiles(summ, rows, now_ns, camps, b["research_ips"], gaps)
    profs = _try(log, "profiles", build_profiles, {})
    verdicts = {ip: p["verdict"] for ip, p in profs.items() if p.get("verdict")}
    replayable = {k: v for k, v in sess.items() if v.get("lines") and P.SESSION_ID.match(str(v.get("id", "")))}
    chosen = _try(log, "session select", lambda: S.select(replayable, profs, camps, cfg.max_sessions), None)
    sessions_ok = sessions_ok and chosen is not None
    chosen = chosen or []
    write = lambda name, obj: P.write_json(os.path.join(tdir, name), P.guard(obj, scrub))

    def insights():
        keep = {ip for c in camps for ip in c["members"][:50]} | {s["src"] for s in chosen}
        top = sorted(profs.values(), key=lambda p: -p.get("n24", 0))[:300]
        pub_profiles = {p["ip"]: p for p in top} | {ip: profs[ip] for ip in keep if ip in profs}
        ports = _try(log, "ports", lambda: store.top_ports(since7, set(pub_profiles)), {})
        pub_profiles = {ip: {**p, "ports": A._top(ports.get(ip, Counter()), 8)} for ip, p in pub_profiles.items()}
        part = lambda what, fn, d: _try(log, what, fn, d)
        ins = P.build_insights(
            now_ns, cfg.history_days, part("locations", lambda: A.locations(recent, now_ns, cfg.window_hours), []),
            pub_profiles, camps, part("trends", lambda: A.trends_from(store.trend_counts(since7, now_ns), now_ns), {}),
            part("baseline view", lambda: _baseline_view(b, stats, scrub), None), part("malware", lambda: A.malware(cowrie), []),
            [S.index_entry(s, profs, camps) for s in chosen], cfg.window_hours)
        write("insights.json", ins)

    def index_html():
        with open(cfg.map_html, encoding="utf-8") as f:
            P.write_text(os.path.join(tdir, "index.html"), f.read())

    sdir = os.path.join(tdir, "sessions")
    pub_sessions = P.guard([{k: v for k, v in s.items() if k not in ("gaps_median", "has_tty")} for s in chosen], scrub)
    _try(log, "index.html", index_html, None)
    _try(log, "sessions write", lambda: P.sync_sessions(sdir, pub_sessions, remove=False), None)   # new files first,
    if _try(log, "insights", lambda: insights() or True, False) and sessions_ok:                   # then the index,
        _try(log, "sessions prune", lambda: P.sync_sessions(sdir, pub_sessions), None)             # then stale removal
    _try(log, "live", lambda: write("live.json", P.build_live(recent, stats, now_ns, cfg.live_minutes, verdicts)), None)
    _try(log, "feed", lambda: write("feed.json", P.build_feed(recent, stats, now_ns, cfg.max_events, verdicts,
                                                              cfg.window_hours)), None)
    return {"events": stats["total"], "sources": stats["unique_sources"], "campaigns": len(camps),
            "sessions": len(chosen), "camps": camps}


def main():
    cfg = load()
    with open(cfg.token_file) as f:
        token = f.read().strip()
    if not TOKEN_RE.match(token):
        raise SystemExit("token must be 32 lowercase hex chars")
    tdir = os.path.join(cfg.out_dir, token)
    os.makedirs(tdir, mode=0o755, exist_ok=True)
    os.chmod(tdir, 0o755)
    for name in os.listdir(cfg.out_dir):                         # old token dirs only
        p = os.path.join(cfg.out_dir, name)
        if TOKEN_RE.match(name) and name != token and os.path.isdir(p):
            shutil.rmtree(p)
            log("removed old token dir")
    store = Store(os.path.join(cfg.state_dir, "attackfeed.db"))
    scrub = Scrubber(None, cfg.scrub_words)
    fetch = lambda q, s, e, limit: query_range(cfg.loki_url, q, s, e, limit)
    baseline = Baseline(store, contact=cfg.dshield_contact)
    load_homes(scrub, store)
    while not scrub.home_ip:                                     # no WAN ip -> scrubbing would miss it: parse nothing
        set_home(scrub, store, wan_ip())
        if not scrub.home_ip:
            log("no wan ip, retrying in 60 s")
            time.sleep(60)
    home_checked, last_prune, last_camp = time.time(), 0.0, 0.0
    while True:
        now = time.time()
        if now - home_checked > WAN_RECHECK_S:
            set_home(scrub, store, wan_ip())
            home_checked = now
        try:
            r = cycle(cfg, store, fetch, scrub, baseline, time.time_ns(), tdir)
            log(f"feed: {r['events']} events, {r['sources']} sources, {r['campaigns']} campaigns, {r['sessions']} sessions")
            if now - last_prune > 3600:
                store.prune(time.time_ns() - cfg.history_days * D)
                last_prune = now
            if now - last_camp > 600:
                for line in P.campaign_lines(r["camps"][:20]):
                    print(line, flush=True)
                last_camp = now
        except Exception as ex:  # noqa: BLE001 - never die; keep last published files
            log("cycle failed:", repr(ex))
        time.sleep(cfg.interval)


if __name__ == "__main__":
    main()
