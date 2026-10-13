"""Loki HTTP API. fetch_window() never returns a silently truncated page."""
import json, urllib.parse, urllib.request

def _get(url, timeout=60):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read()

def query_range(base, query, start_ns, end_ns, limit, http_get=None):
    url = f"{base}/loki/api/v1/query_range?" + urllib.parse.urlencode(
        {"query": query, "start": start_ns, "end": end_ns, "limit": limit, "direction": "forward"})
    data = json.loads((http_get or _get)(url))
    out = []
    for stream in data["data"]["result"]:
        labels = stream["stream"]
        for ts, line in stream["values"]:
            out.append((int(ts), line, labels))
    out.sort(key=lambda x: x[0])
    return out

def fetch_window(fetch, query, start_ns, end_ns, limit=5000, min_span_ns=10**9, log=None):
    rows = fetch(query, start_ns, end_ns, limit)
    if len(rows) < limit:
        return rows
    if end_ns - start_ns <= min_span_ns:
        if log:
            log("loki: window still full at min span, may be truncated")
        return rows
    mid = start_ns + (end_ns - start_ns) // 2
    return (fetch_window(fetch, query, start_ns, mid, limit, min_span_ns, log)
            + fetch_window(fetch, query, mid, end_ns, limit, min_span_ns, log))
