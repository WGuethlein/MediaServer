"""Removes anything that identifies this home from attacker-supplied text."""
import re

ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][0-9A-Za-z]|\r")
PRIVATE = re.compile(r"\b(?:192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
                     r"|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}"
                     r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")
PARTIAL_IP = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){0,2}\.?$")
HOSTS = ("wyatt-serv1", "wyatt-mon", "serv1", "ux7", "synology")

def strip_ansi(s: str) -> str:
    return ANSI.sub("", s)

class Scrubber:
    def __init__(self, home_ip, words):
        self.home_ip = home_ip                              # current WAN (gates ingest)
        self.home_ips = {home_ip} if home_ip else set()     # every WAN ever seen: all are scrubbed
        self.words = tuple(sorted({*HOSTS, *words}, key=len, reverse=True))   # longest first

    def remember(self, ip):
        """Adds a past home IP (scrubbed, dropped as a source) without making it current. True if new."""
        if not ip or ip in self.home_ips:
            return False
        self.home_ips.add(ip)
        return True

    def set_home(self, ip):
        new = self.remember(ip)
        if ip:
            self.home_ip = ip
        return new

    def text(self, s, cap=200):
        if not s:
            return s
        s = str(s)
        for ip in self.home_ips:
            s = re.sub(rf"(?<!\d){re.escape(ip)}(?!\d)", "x.x.x.x", s)
        s = PRIVATE.sub("x.x.x.x", s)
        for w in self.words:
            s = re.sub(re.escape(w), "redacted", s, flags=re.I)
        if len(s) > cap:                       # scrub first, then cap
            s = PARTIAL_IP.sub("", s[:cap])    # never leave a cut-off address behind
        return s

    def url(self, s):
        s = self.text(s, cap=300)
        if not s:
            return s
        s = re.sub(r"^http", "hxxp", s, flags=re.I)
        host_end = s.find("/", s.find("://") + 3) if "://" in s else -1
        head, tail = (s, "") if host_end < 0 else (s[:host_end], s[host_end:])
        i = head.rfind(".")
        return (head[:i] + "[.]" + head[i + 1:] if i > head.find("://") else head) + tail
