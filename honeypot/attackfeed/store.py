"""7-day event store (SQLite). Lives in /state, never in the served directory."""
import hashlib, json, sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (ts INTEGER NOT NULL, source TEXT NOT NULL, type TEXT NOT NULL, src TEXT NOT NULL,
  session TEXT, data TEXT NOT NULL, key TEXT NOT NULL UNIQUE);
CREATE INDEX IF NOT EXISTS ev_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ev_src ON events(src);
CREATE TABLE IF NOT EXISTS cursors (source TEXT PRIMARY KEY, ns INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
"""

class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.executescript(SCHEMA)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA temp_store=MEMORY")   # read-only rootfs, no /tmp: temp tables/sorts in RAM

    def add(self, events):
        n = 0
        with self.db:
            for e in events:
                e = dict(e)
                line = e.pop("line", None)
                key = hashlib.sha1(f"{e['ts']}|{e['source']}|{line if line is not None else json.dumps(e, sort_keys=True)}".encode()).hexdigest()
                cur = self.db.execute("INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?)",
                                      (e["ts"], e["source"], e["type"], e["src"], e.get("session"), json.dumps(e), key))
                n += cur.rowcount
        return n

    def events(self, since_ns, sources=None, until=None):
        """Full event dicts, ts in [since_ns, until). Materialises every row: keep windows small (24 h, or cowrie only)."""
        q, args = "SELECT data FROM events WHERE ts >= ?", [since_ns]
        if until is not None:
            q += " AND ts < ?"; args.append(until)
        if sources:
            q += f" AND source IN ({','.join('?' * len(sources))})"; args += list(sources)
        return [json.loads(r[0]) for r in self.db.execute(q + " ORDER BY ts", args)]

    def trend_counts(self, since_ns, now_ns):
        """Hourly counts for analyze.trends_from: by (source, UTC hour) and by (source, hours ago), plus the oldest ts."""
        H, w = 3600 * 10**9, "FROM events WHERE ts >= ? AND ts <= ?"
        by_hour = {(s, h): n for s, h, n in self.db.execute(
            f"SELECT source, ts / {H}, COUNT(*) {w} GROUP BY 1, 2", (since_ns, now_ns))}
        by_age = {(s, a): n for s, a, n in self.db.execute(
            f"SELECT source, (? - ts) / {H}, COUNT(*) {w} GROUP BY 1, 2", (now_ns, since_ns, now_ns))}
        oldest = self.db.execute(f"SELECT MIN(ts) {w}", (since_ns, now_ns)).fetchone()[0]
        return {"by_hour": by_hour, "by_age": by_age, "oldest": oldest}

    def _want(self, ips):
        self.db.execute("CREATE TEMP TABLE IF NOT EXISTS want (src TEXT PRIMARY KEY)")
        self.db.execute("DELETE FROM temp.want")
        self.db.executemany("INSERT OR IGNORE INTO temp.want VALUES (?)", ((ip,) for ip in ips))

    def ip_summary(self, since_ns, ips):
        """Per-IP 7-day aggregates for the given IPs (same shape as analyze.ip_summary), without loading rows."""
        from .analyze import ip_summary_add
        self._want(ips)
        out = {}
        for src, source, typ, proto, n, lo, hi in self.db.execute(
                "SELECT src, source, type, CASE WHEN source = 'cowrie' THEN json_extract(data, '$.proto') END,"
                " COUNT(*), MIN(ts), MAX(ts) FROM events WHERE ts >= ? AND src IN (SELECT src FROM temp.want)"
                " GROUP BY 1, 2, 3, 4 ORDER BY 6", (since_ns,)):
            ip_summary_add(out, {"src": src, "source": source, "type": typ, "proto": proto}, n, lo, hi)
        return out

    def top_ports(self, since_ns, ips):
        """{ip: Counter(port)} over the window, in first-seen order (matches Counter over ts-ordered rows)."""
        from collections import Counter
        self._want(ips)
        out = {}
        for src, port, n in self.db.execute(
                "SELECT src, p, n FROM (SELECT src, json_extract(data, '$.port') AS p, COUNT(*) AS n, MIN(ts) AS lo"
                " FROM events WHERE ts >= ? AND src IN (SELECT src FROM temp.want) GROUP BY 1, 2)"
                " WHERE p IS NOT NULL AND p != 0 AND p != '' ORDER BY lo", (since_ns,)):
            out.setdefault(src, Counter())[port] = n
        return out

    def cursor(self, source):
        r = self.db.execute("SELECT ns FROM cursors WHERE source=?", (source,)).fetchone()
        return r[0] if r else None

    def set_cursor(self, source, ns):
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO cursors VALUES (?,?)", (source, ns))

    def meta(self, k):
        r = self.db.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return r[0] if r else None

    def set_meta(self, k, v):
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (k, v))

    def prune(self, before_ns):
        with self.db:
            return self.db.execute("DELETE FROM events WHERE ts < ?", (before_ns,)).rowcount

    def count(self):
        return self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def close(self):
        self.db.close()
