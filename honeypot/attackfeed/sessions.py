"""Cowrie sessions -> replayable line lists. Reads tty logs read-only; never raises on bad files."""
import os, statistics, struct
from collections import defaultdict
from .analyze import iso
from .scrub import strip_ansi

TTY = struct.Struct("<iLiiLL")
OP_WRITE, TYPE_INPUT, TYPE_OUTPUT = 3, 1, 2
NS = 10**9
RANK = {"hands-on": 0, "dropper": 1}

def parse_ttylog(path, scrub, max_bytes=65536, max_events=2000):
    """Cowrie logs one record per keystroke, so text is buffered per direction and scrubbed
    only as complete lines (a secret typed char-by-char must not slip past the scrubber)."""
    try:
        with open(path, "rb") as f:
            data = f.read(4 * 1024 * 1024)
    except OSError:
        return []
    out, used = [], [0]
    buf = {TYPE_INPUT: ["", 0.0], TYPE_OUTPUT: ["", 0.0]}   # direction -> [raw text, t of first record]

    def emit(direction, raw, t):
        if len(out) >= max_events or used[0] >= max_bytes:
            return
        text = scrub.text(strip_ansi(raw), cap=max_bytes - used[0])
        if not text:
            return
        used[0] += len(text)
        out.append([round(t, 3), "i" if direction == TYPE_INPUT else "o", text])

    pos, t0 = 0, None
    while pos + TTY.size <= len(data) and len(out) < max_events and used[0] < max_bytes:
        op, _tty, length, direction, sec, usec = TTY.unpack_from(data, pos)
        pos += TTY.size
        if op not in (1, 2, 3, 4):
            break                                   # corruption
        t = sec + usec / 1e6
        t0 = t if t0 is None else t0
        if op != OP_WRITE:
            continue
        if length < 0 or pos + length > len(data):
            break
        chunk, pos = data[pos:pos + length], pos + length
        if direction not in buf:
            continue
        b = buf[direction]
        if not b[0]:
            b[1] = t - t0
        b[0] += chunk.decode("utf-8", "replace")
        while "\n" in b[0]:
            line, b[0] = b[0].split("\n", 1)
            emit(direction, line + "\n", b[1])
            b[1] = t - t0
    for direction, b in buf.items():
        if b[0]:
            emit(direction, b[0], b[1])
    out.sort(key=lambda r: r[0])
    return out

def build(events, tty_dir, scrub):
    by = defaultdict(list)
    for e in events:
        if e.get("source") == "cowrie" and e.get("session"):
            by[e["session"]].append(e)
    out = {}
    for sid, rows in by.items():
        rows.sort(key=lambda r: r["ts"])
        login = next((r for r in rows if r["type"] == "login-success"), None)
        cmds = [r for r in rows if r["type"] == "command"]
        closed = next((r for r in rows if r["type"] == "closed"), None)
        if not login or not (cmds or (closed and closed.get("ttylog"))):
            continue
        lines, has_tty = [], False
        if closed and closed.get("ttylog"):
            lines = parse_ttylog(os.path.join(tty_dir, os.path.basename(closed["ttylog"])), scrub)
            has_tty = bool(lines)
        if not lines:
            t0 = login["ts"]
            lines = [[round((r["ts"] - t0) / NS, 3), "i", r["cmd"]] for r in cmds]
        ins = [t for t, d, _ in lines if d == "i"]
        gaps = [b - a for a, b in zip(ins, ins[1:])]
        client = next((r.get("client") for r in rows if r.get("client")), None)
        out[sid] = {k: v for k, v in {
            "id": sid, "src": login["src"], "start": iso(login["ts"]),
            "duration": closed.get("duration") if closed else round((rows[-1]["ts"] - login["ts"]) / NS, 1),
            "user": login.get("user"), "pass": login.get("pass"), "proto": login.get("proto"), "client": client,
            "lines": lines, "gaps_median": statistics.median(gaps) if gaps else 0.0, "has_tty": has_tty}.items()
            if v is not None}
    return out

def _camp_of_src(camps):
    m = {}
    for c in camps:
        for ip in c["members"]:
            m.setdefault(ip, c["id"])
    return m

def select(sessions, profiles, camps, n=30):
    camp_of = _camp_of_src(camps)
    ordered = sorted(sessions.values(), key=lambda s: s["start"], reverse=True)      # newest first
    ordered.sort(key=lambda s: (RANK.get(profiles.get(s["src"], {}).get("verdict"), 2),
                                0 if s["src"] in camp_of else 1))                    # stable
    seen, ranked = set(), []
    for s in ordered:
        c = camp_of.get(s["src"])
        if c:
            if c in seen:
                continue
            seen.add(c)
        ranked.append(s)
        if len(ranked) == n:
            break
    return ranked

def index_entry(s, profiles, camps):
    p = profiles.get(s["src"], {})
    camp = _camp_of_src(camps).get(s["src"])
    n_in = sum(1 for _, d, _ in s["lines"] if d == "i")
    return {k: v for k, v in {"id": s["id"], "src": s["src"], "start": s["start"], "duration": s.get("duration"),
            "verdict": p.get("verdict"), "campaign": camp, "city": p.get("city"), "country": p.get("country"),
            "summary": f"{n_in} commands as {s.get('user', '?')}"}.items() if v is not None}
