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

    def events(self, since_ns, sources=None):
        q, args = "SELECT data FROM events WHERE ts >= ?", [since_ns]
        if sources:
            q += f" AND source IN ({','.join('?' * len(sources))})"; args += list(sources)
        return [json.loads(r[0]) for r in self.db.execute(q + " ORDER BY ts", args)]

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
