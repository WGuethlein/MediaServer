"""Incremental Loki -> store. Each source has its own cursor; a failing source keeps its cursor."""
import time
from .loki import fetch_window
from .parse import parse

NS = 10**9
GIVE_UP = 3          # consecutive failed backfill attempts before a source accepts the gap and goes live
WEB = '{job="traefik"} | pattern `<_> - <_> [<_>] "<_> <_> <_>" <_> <_> "<_>" "<_>" <_> "<router>" "<_>" <_>` | router="-"'
QUERIES = {
    "cowrie": '{job="cowrie", eventid=~"cowrie.session.connect|cowrie.login.failed|cowrie.login.success|cowrie.command.input|cowrie.log.closed|cowrie.client.version|cowrie.client.kex|cowrie.session.file_download|cowrie.direct-tcpip.request"}',
    "firewall": '{job="unifi"} |= "Block All Traffic" |~ "WAN_(LOCAL|IN)" |~ "IN=eth"',
    "ips": '{job="unifi"} |~ "UNIFIpolicyType=IDS/IPS"',
    "web": WEB,
    "crowdsec": '{container="crowdsec"} |= " ban on Ip "',
}

def _rows(source, rows, scrub):
    out = []
    for ts, line, labels in rows:
        e = parse(source, line, labels, scrub)
        if e:
            e["ts"] = ts; e["line"] = line
            out.append(e)
    return out

def ingest(store, fetch, now_ns, scrub, overlap_ns=120 * NS, log=print, sources=None):
    """sources: only these (default all). The main loop passes only backfilled sources, so a 1-h
    first cursor can never paper over a backfill hole."""
    added = {}
    for source, q in QUERIES.items():
        if sources is not None and source not in sources:
            continue
        cur = store.cursor(source)
        start = max((now_ns - 3600 * NS if cur is None else cur) - overlap_ns, 0)
        try:
            rows = fetch_window(fetch, q, start, now_ns, log=log)
            added[source] = store.add(_rows(source, rows, scrub))
        except Exception as ex:  # noqa: BLE001 - keep the cursor, retry next cycle
            log(f"ingest {source}: {ex}")
            continue
        store.set_cursor(source, now_ns)
    return added

def backfill(store, fetch, now_ns, days, scrub, sleep=time.sleep, log=print):
    """Fill only sources without a cursor; a source with any failed window gets no cursor, so the next call retries it.
    After GIVE_UP consecutive failed calls the source accepts the gap: cursor = now, live ingest starts."""
    total, start = 0, now_ns - days * 86400 * NS
    for source, q in QUERIES.items():
        if store.cursor(source) is not None:
            continue
        t, failed = start, False
        while t < now_ns:
            end = min(t + 3600 * NS, now_ns)
            try:
                total += store.add(_rows(source, fetch_window(fetch, q, t, end, log=log), scrub))
            except Exception as ex:  # noqa: BLE001
                failed = True
                log(f"backfill {source} {t}: {ex}")
                break                    # no cursor either way, the next call refills from the start
            t = end
            sleep(1.0)
        key = f"backfill_fail_{source}"
        if failed:
            n = int(store.meta(key) or 0) + 1
            if n >= GIVE_UP:
                store.set_cursor(source, now_ns)
                store.set_meta(key, "0")
                log(f"backfill {source}: giving up on gap, starting live")
            else:
                store.set_meta(key, str(n))
                log(f"backfill {source}: incomplete, cursor not set")
        else:
            store.set_cursor(source, now_ns)
            store.set_meta(key, "0")
            log(f"backfill {source}: done")
    return total
