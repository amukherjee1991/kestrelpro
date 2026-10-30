"""Safety net for automatic blocks: a trial period, pause/resume, and "what broke on device X".

Trial period ("probation"). For probation_hours after an automatic block, the block is
withdrawn and the domain goes back to Needs approval if either
  - the user unblocks a sibling domain (same registrable domain), or
  - several devices hammer the blocked domain (a retry storm: storm_devices or more devices,
    each with storm_lookups or more blocked lookups within STORM_WINDOW seconds). Apps that
    break retry like this; pages that merely load an ad don't.
Blocks the user made or approved never go on probation.

Pause disables every KestrelPro entry in the deny list without deleting anything; resume
re-enables them. While paused, Automatic mode queues suggestions instead of blocking.
"""
import json
import logging
import time

import requests

from . import config, ftl as ftl_api, notify, store

log = logging.getLogger("kestrel.safety")

STORM_WINDOW = 300
BLOCKED_STATUSES = {"DENYLIST", "DENYLIST_CNAME"}

# Two-label public suffixes that are common enough to matter for "same site" grouping.
# Not a full public-suffix list; good enough to keep shop.example.co.uk and
# ads.example.co.uk together and apart from other.co.uk.
_SECOND_LEVEL = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "co.jp", "ne.jp", "or.jp",
    "com.au", "net.au", "org.au", "co.nz", "org.nz", "co.in", "net.in", "org.in", "co.za",
    "com.br", "com.cn", "com.hk", "com.mx", "com.sg", "com.tr", "com.tw", "co.kr", "co.il",
    "github.io", "herokuapp.com", "appspot.com", "cloudfront.net", "azurewebsites.net",
}


def registrable(domain):
    """example.co.uk for a.b.example.co.uk; example.com for x.example.com."""
    parts = domain.lower().rstrip(".").split(".")
    n = 3 if ".".join(parts[-2:]) in _SECOND_LEVEL else 2
    return ".".join(parts[-n:])


def is_paused(db):
    return store.get_state(db, "paused", "0") == "1"


def probation_until(settings, now):
    return now + settings["probation_hours"] * 3600


def revert(ftl, db, domain, reason):
    """Withdraw an automatic block and send the domain back to Needs approval."""
    ftl.remove_deny(domain)
    row = db.execute("select * from verdicts where domain = ?", (domain,)).fetchone()
    db.execute("update verdicts set status = ?, updated_at = ?, probation_until = null where domain = ?",
               (store.PENDING, time.time(), domain))
    store.log_event(db, domain, store.PROBATION_REVERTED, row["category"] if row else None,
                    row["confidence"] if row else None, reason, row["clients"] if row else "[]")
    db.commit()
    log.info("probation: withdrew the block on %s (%s)", domain, reason)
    notify.add(db, "probation_reverted", f"{domain}: block withdrawn, back to Needs approval ({reason})")


def on_probation(db, now=None):
    now = now or time.time()
    return {r[0] for r in db.execute("select domain from verdicts where status = ? and probation_until > ?",
                                     (store.BLOCKED, now))}


def revert_siblings(ftl, db, domain):
    """The user unblocked `domain`: withdraw automatic blocks on the same site still on probation."""
    site = registrable(domain)
    reverted = []
    for d in sorted(on_probation(db)):
        if d != domain and registrable(d) == site:
            revert(ftl, db, d, f"you unblocked {domain}, from the same site")
            reverted.append(d)
    return reverted


class StormWatch:
    """Counts blocked lookups of domains on probation, per device, in a sliding window."""

    def __init__(self):
        self.hits = {}  # domain -> ip -> [timestamps]

    def feed(self, ftl, db, queries, settings):
        watched = on_probation(db)
        if not watched:
            self.hits.clear()
            return []
        now = time.time()
        for q in queries:
            if q.get("status") not in BLOCKED_STATUSES:
                continue
            d = (q.get("domain") or "").lower().rstrip(".")
            if d in watched:
                ip = (q.get("client") or {}).get("ip") or "?"
                self.hits.setdefault(d, {}).setdefault(ip, []).append(q.get("time") or now)
        reverted = []
        for d in list(self.hits):
            if d not in watched:
                del self.hits[d]
                continue
            per_device = {ip: [t for t in ts if t > now - STORM_WINDOW] for ip, ts in self.hits[d].items()}
            self.hits[d] = {ip: ts for ip, ts in per_device.items() if ts}
            storming = [ip for ip, ts in self.hits[d].items() if len(ts) >= settings["storm_lookups"]]
            if len(storming) >= settings["storm_devices"]:
                revert(ftl, db, d, f"{len(storming)} devices kept retrying it, which usually means something broke")
                del self.hits[d]
                reverted.append(d)
        return reverted


def _mine(ftl, kinds=("exact", "regex")):
    """KestrelPro's deny entries (exact domains and site-wide regex rules), tagged with their kind."""
    out = []
    for kind in kinds:
        out += [{**e, "kind": kind} for e in ftl.list_domains(f"deny/{kind}")
                if (e.get("comment") or "").startswith(config.TAG)]
    return out


def pause(ftl, db):
    """Disable every KestrelPro entry in the deny list. Nothing is deleted."""
    entries = _mine(ftl)
    for e in entries:
        if e.get("enabled", True):
            ftl.set_enabled(e["domain"], e["comment"], False, e["kind"])
    store.set_state(db, "paused", "1")
    store.set_state(db, "paused_at", time.time())
    log.info("paused: %d KestrelPro block(s) disabled", len(entries))
    return len(entries)


def resume(ftl, db):
    entries = _mine(ftl)
    for e in entries:
        if not e.get("enabled", True):
            ftl.set_enabled(e["domain"], e["comment"], True, e["kind"])
    store.set_state(db, "paused", "0")
    log.info("resumed: %d KestrelPro block(s) enabled", len(entries))
    return len(entries)


def broke(ftl, db, client_ip, minutes):
    """KestrelPro blocks that device `client_ip` ran into in the last `minutes`, busiest first."""
    since = time.time() - minutes * 60
    hits, other = {}, 0
    start, cursor = 0, None
    while True:
        page = ftl.queries(start=start, length=ftl_api.MAX_ROWS, cursor=cursor, since=since, client_ip=client_ip)
        rows = page.get("queries") or []
        if cursor is None and rows:
            cursor = max(q["id"] for q in rows)
        for q in rows:
            if q.get("status") in BLOCKED_STATUSES:
                d = q["domain"].lower().rstrip(".")
                h = hits.setdefault(d, {"domain": d, "lookups": 0, "last_seen": 0})
                h["lookups"] += 1
                h["last_seen"] = max(h["last_seen"], q.get("time") or 0)
            elif q.get("status") not in ftl_api.ALLOWED_STATUSES:
                other += 1
        if len(rows) < ftl_api.MAX_ROWS:
            break
        start += len(rows)
    mine = {e["domain"]: e for e in _mine(ftl, ("exact",))}
    out = []
    for d, h in hits.items():
        if d not in mine:
            other += h["lookups"]
            continue
        row = db.execute("select category, confidence, reason, status, probation_until from verdicts "
                         "where domain = ?", (d,)).fetchone()
        out.append({**h, **(dict(row) if row else {}), "enabled": mine[d].get("enabled", True)})
    out.sort(key=lambda h: (-h["lookups"], h["domain"]))
    return {"client": client_ip, "minutes": minutes, "blocks": out, "other_blocked": other}


def devices(ftl):
    """Devices that used the DNS server recently, busiest first, for the "what broke" picker."""
    try:
        clients = ftl.request("GET", "/stats/top_clients", params={"count": 100})["clients"]
    except (requests.RequestException, KeyError, TypeError):
        return []
    return [{"ip": c["ip"], "name": c.get("name") or "", "count": c.get("count", 0)} for c in clients]


def explain(db, domains):
    """Verdicts for the query log: {domain: verdict} for those that have one."""
    domains = sorted({d.lower().rstrip(".") for d in domains if d})[:1000]
    out = {}
    for i in range(0, len(domains), 500):
        chunk = domains[i:i + 500]
        for r in db.execute("select domain, category, confidence, reason, status, model, judged_at, updated_at, "
                            f"probation_until, evidence from verdicts where domain in ({','.join('?' * len(chunk))})",
                            chunk):
            out[r["domain"]] = {**dict(r), "evidence": json.loads(r["evidence"] or "{}")}
    return out


def summary(db):
    now = time.time()
    return {"paused": is_paused(db),
            "paused_at": float(store.get_state(db, "paused_at", 0) or 0),
            "on_probation": len(on_probation(db, now)),
            "reverted_24h": db.execute("select count(*) from events where action = ? and at > ?",
                                       (store.PROBATION_REVERTED, now - 86400)).fetchone()[0]}

