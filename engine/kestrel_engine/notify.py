"""Notifications: ntfy or a JSON webhook. Off until a URL is set in AI settings.

Events are buffered and sent at most once per SEND_EVERY seconds as one combined message, so a
busy minute never turns into a burst. Notifications carry domain names to the address you
configure; nothing is sent anywhere unless you set one.

Events: auto_blocked, pending (approvals backlog), probation_reverted, list_false_positive.
"""
import logging
import threading
import time
from urllib.parse import urlsplit

import requests

from . import store

log = logging.getLogger("kestrel.notify")

EVENTS = ("auto_blocked", "pending", "probation_reverted", "list_false_positive")
SEND_EVERY = 300
PENDING_EVERY = 86400
TITLES = {"auto_blocked": "Blocked automatically", "pending": "Waiting for approval",
          "probation_reverted": "Trial block withdrawn", "list_false_positive": "Possible false block"}

_lock = threading.Lock()
_buffer = []  # [(event, text)]


def valid_url(url):
    try:
        u = urlsplit(url)
    except ValueError:
        return False
    return u.scheme in ("http", "https") and bool(u.hostname)


def add(db, event, text):
    """Queue a message if notifications are on and this event is wanted."""
    s = store.get_settings(db)
    if not s["notify_url"] or event not in s["notify_events"]:
        return
    with _lock:
        _buffer.append((event, text))


def check_pending(db):
    """A daily nudge when approvals pile up."""
    s = store.get_settings(db)
    if not s["notify_url"] or "pending" not in s["notify_events"]:
        return
    n = db.execute("select count(*) from verdicts where status = ?", (store.PENDING,)).fetchone()[0]
    last = float(store.get_state(db, "notify_pending_at", 0) or 0)
    if n >= s["notify_pending_at"] and time.time() - last > PENDING_EVERY:
        add(db, "pending", f"{n} suggested blocks are waiting for your approval")
        store.set_state(db, "notify_pending_at", time.time())


def send(settings, items, timeout=10):
    """Send one combined message. Raises requests.RequestException on failure."""
    url, kind = settings["notify_url"], settings["notify_kind"]
    if not valid_url(url):
        raise ValueError("The notification address must be an http(s) URL")
    events = sorted({e for e, _ in items})
    title = "KestrelPro: " + (TITLES.get(events[0], events[0]) if len(events) == 1 else f"{len(items)} updates")
    body = "\n".join(f"• {text}" for _, text in items)
    if kind == "ntfy":
        tags = "no_entry" if "auto_blocked" in events else "bird"
        r = requests.post(url, data=body.encode(), timeout=timeout,
                          headers={"Title": title, "Tags": tags, "Content-Type": "text/plain; charset=utf-8"})
    else:
        r = requests.post(url, timeout=timeout, json={
            "source": "kestrelpro", "title": title, "text": body,
            "events": [{"event": e, "text": t} for e, t in items], "sent_at": time.time()})
    r.raise_for_status()


def flush(db, force=False):
    """Send what's buffered if it's time. Called from the review loop."""
    s = store.get_settings(db)
    last = float(store.get_state(db, "notify_sent_at", 0) or 0)
    with _lock:
        if not _buffer or (not force and time.time() - last < SEND_EVERY):
            return False
        items, _buffer[:] = list(_buffer), []
    if not s["notify_url"]:
        return False
    try:
        send(s, items)
        store.set_state(db, "notify_sent_at", time.time())
        store.set_state(db, "notify_error", "")
        return True
    except (requests.RequestException, ValueError) as e:
        log.warning("notification failed: %s", e)
        store.set_state(db, "notify_error", f"Couldn't send a notification: {e}")
        with _lock:  # keep them for the next try, without growing without bound
            _buffer[:0] = items[-50:]
            del _buffer[100:]
        return False


def status(db):
    return {"error": store.get_state(db, "notify_error", ""),
            "sent_at": float(store.get_state(db, "notify_sent_at", 0) or 0),
            "queued": len(_buffer)}

