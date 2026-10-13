"""Settings from the environment (compose file). Defaults match production."""
import os
from dataclasses import dataclass

@dataclass(frozen=True)
class Config:
    loki_url: str; out_dir: str; state_dir: str; tty_dir: str; interval: int; window_hours: int
    history_days: int; max_events: int; live_minutes: int; max_sessions: int; token_file: str
    scrub_words: tuple; dshield_contact: str; map_html: str

def load(env=None) -> Config:
    e = os.environ if env is None else env
    g = lambda k, d: e.get(k, d)
    return Config(
        loki_url=g("LOKI_URL", "http://192.168.1.73:3100").rstrip("/"), out_dir=g("OUT_DIR", "/out"),
        state_dir=g("STATE_DIR", "/state"), tty_dir=g("TTY_DIR", "/tty"), interval=int(g("INTERVAL", "20")),
        window_hours=int(g("WINDOW_HOURS", "24")), history_days=int(g("HISTORY_DAYS", "7")),
        max_events=int(g("MAX_EVENTS", "6000")), live_minutes=int(g("LIVE_MINUTES", "15")),
        max_sessions=int(g("MAX_SESSIONS", "30")), token_file=g("TOKEN_FILE", "/run/secrets/attackfeed_token"),
        scrub_words=tuple(w for w in g("SCRUB_WORDS", "geet.dev,wyatt,guethlein,docker_user").split(",") if w),
        dshield_contact=g("DSHIELD_CONTACT", ""), map_html=g("MAP_HTML", "/app/map.html"))
