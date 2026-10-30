"""Browser requests are authenticated with the admin UI's own session.

The browser sends FTL's `sid` cookie (cookies ignore ports, RFC 6265 §8.5). The engine asks
FTL whether that session is live and caches the answer briefly. Writes must also carry the
session's CSRF token in X-CSRF-TOKEN, the same rule FTL applies to cookie-authenticated calls.
"""
import threading
import time
from urllib.parse import urlsplit

import requests

from . import config

CACHE_SECONDS = 10
MAX_CACHE = 256


class SessionCheck:
    def __init__(self, url=None):
        self.url = url or config.FTL_URL
        self.http = requests.Session()
        self.cache = {}  # sid -> (csrf or None, expires)
        self.lock = threading.Lock()

    def csrf_for(self, sid):
        """The CSRF token of the admin-UI session `sid`, or None if it isn't a live session."""
        if not sid or len(sid) > 64:
            return None
        now = time.monotonic()
        with self.lock:
            hit = self.cache.get(sid)
            if hit and hit[1] > now:
                return hit[0]
        try:
            r = self.http.get(f"{self.url}/api/auth", headers={"X-FTL-SID": sid}, timeout=5)
            session = r.json().get("session", {}) if r.status_code == 200 else {}
        except (requests.RequestException, ValueError):
            return None  # don't cache: FTL may just be restarting
        # Without an admin password FTL answers "valid" with no sid at all. That is not a
        # session, so it doesn't count; the engine needs a password-protected admin UI.
        ok = session.get("valid") and session.get("sid") == sid and session.get("csrf")
        csrf = session["csrf"] if ok else None
        with self.lock:
            if len(self.cache) >= MAX_CACHE:
                self.cache = {k: v for k, v in self.cache.items() if v[1] > now}
            self.cache[sid] = (csrf, now + CACHE_SECONDS)
        return csrf


def origin_allowed(origin, host):
    """CORS for the cross-port setup: the admin UI's origin on the same host, or one listed
    in KESTREL_UI_ORIGINS. Never "*": credentials are involved."""
    if not origin:
        return False
    if origin in config.UI_ORIGINS:
        return True
    try:
        o = urlsplit(origin)
        return o.scheme in ("http", "https") and bool(o.hostname) and o.hostname == urlsplit(f"//{host}").hostname
    except ValueError:
        return False
