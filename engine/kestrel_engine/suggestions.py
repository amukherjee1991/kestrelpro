"""Suggestions that go beyond one domain at a time, always through review.

Block-list false positives. The block lists are maintained by people who can't test every
household: a login, CDN or API on a list breaks something, and that is the main pain of DNS
blocking. A few domains the lists blocked (most-requested first) are shown to the model every
hour while it is otherwise idle; ones it calls legitimate are suggested for the allow list,
with the list(s) responsible. Each domain is checked once a week at most.

Site-wide rules. When three or more domains of one site are blocked by KestrelPro, one regex
rule `(^|\\.)site$` can replace the next twenty exact ones. It also catches subdomains nobody
has seen yet, so it is only ever a suggestion.
"""
import json
import logging
import re
import threading
import time

import requests

from . import classify, config, notify, policies, policy, safety, store

log = logging.getLogger("kestrel.suggestions")

LIST_STATUSES = {"GRAVITY", "GRAVITY_CNAME"}
RECHECK_SECONDS = 7 * 86400
SUGGEST_CONFIDENCE = 0.8
MAX_PENDING = 500
SITE_MIN_BLOCKED = 3
SUGGESTED, AGREED, ALLOWED, DISMISSED = "suggested", "agreed", "allowed", "dismissed"


class ListChecks:
    """Domains blocked by the lists, waiting for a second look."""

    def __init__(self, ftl):
        self.ftl = ftl
        self.lock = threading.Lock()
        self.pending = {}   # domain -> {"lookups", "devices": {ip: {...}}}
        self.window = []    # times of recent checks, for the hourly budget

    def collect(self, queries):
        with self.lock:
            for q in queries:
                if q.get("status") not in LIST_STATUSES or not q.get("domain"):
                    continue
                d = q["domain"].lower().rstrip(".")
                item = self.pending.setdefault(d, {"lookups": 0, "devices": {}})
                item["lookups"] += 1
                ip = (q.get("client") or {}).get("ip") or "?"
                dev = item["devices"].setdefault(ip, {"ip": ip, "name": (q.get("client") or {}).get("name"),
                                                      "network": policy.network_of(ip), "lookups": 0})
                dev["lookups"] += 1
            if len(self.pending) > MAX_PENDING:
                keep = sorted(self.pending, key=lambda d: (len(self.pending[d]["devices"]), self.pending[d]["lookups"]),
                              reverse=True)[:MAX_PENDING]
                self.pending = {d: self.pending[d] for d in keep}

    def due(self, settings, now=None):
        """How many checks the hourly budget allows right now."""
        now = now or time.time()
        self.window = [t for t in self.window if t > now - 3600]
        return max(0, settings["list_checks_per_hour"] - len(self.window))

    def run(self, db, settings, batch_size=10):
        """Check one batch. Returns the number checked. Caller runs it only when the model is idle."""
        n = min(batch_size, self.due(settings))
        if n <= 0:
            return 0
        now = time.time()
        recent = {r[0] for r in db.execute("select domain from gravity_checks where updated_at > ?",
                                           (now - RECHECK_SECONDS,))}
        with self.lock:
            for d in list(self.pending):
                # Local names never go to the model; never-block domains are kept: they are prime suspects.
                if d in recent or (policy.skip_domain(d) and not policy.is_protected(d)):
                    del self.pending[d]
            picked = sorted(self.pending, key=lambda d: (len(self.pending[d]["devices"]), self.pending[d]["lookups"]),
                            reverse=True)[:n]
            items = {d: self.pending.pop(d) for d in picked}
        if not items:
            return 0
        try:
            verdicts = classify.classify([(d, it["lookups"], len(it["devices"])) for d, it in items.items()],
                                         settings["model"])
        except requests.RequestException:
            with self.lock:
                self.pending.update(items)
            raise
        self.window += [now] * len(items)
        found = 0
        for d, it in items.items():
            v = verdicts.get(d)
            if not v:
                continue
            suggest = v["category"] == "legitimate" and v["confidence"] >= SUGGEST_CONFIDENCE
            lists = _lists_for(self.ftl, d) if suggest else []
            clients = json.dumps(sorted(it["devices"].values(), key=lambda x: -x["lookups"]))
            db.execute("insert or replace into gravity_checks (domain, category, confidence, reason, lookups, devices, "
                       "clients, lists, status, judged_at, updated_at) values (?,?,?,?,?,?,?,?,?,?,?)",
                       (d, v["category"], v["confidence"], v["reason"], it["lookups"], len(it["devices"]), clients,
                        json.dumps(lists), SUGGESTED if suggest else AGREED, now, now))
            if suggest:
                found += 1
                log.info("possible block-list false positive: %s (%s)", d, v["reason"])
        db.commit()
        if found:
            notify.add(db, "list_false_positive", f"{found} domain(s) blocked by your lists look legitimate; "
                       "see Suggestions")
        return len(items)


def _lists_for(ftl, domain):
    """The block lists (and rules) that block `domain`, from the DNS server's search."""
    try:
        r = ftl.request("GET", f"/search/{domain}", params={"N": 20})["search"]
    except (requests.RequestException, KeyError, TypeError):
        return []
    out = [{"kind": "list", "address": g.get("address"), "comment": g.get("comment")}
           for g in r.get("gravity") or [] if g.get("type", "block") == "block"]
    out += [{"kind": e.get("kind"), "address": e.get("domain"), "comment": e.get("comment")}
            for e in r.get("domains") or [] if e.get("type") == "deny"]
    return out


def false_positives(db, status=SUGGESTED, limit=200):
    rows = db.execute("select * from gravity_checks where status = ? order by devices desc, lookups desc limit ?",
                      (status, limit)).fetchall()
    return [{**dict(r), "clients": json.loads(r["clients"] or "[]"), "lists": json.loads(r["lists"] or "[]")}
            for r in rows]


def allow(ftl, db, domain):
    """Add a suspected false positive to the allow list (every group), and remember why."""
    row = db.execute("select * from gravity_checks where domain = ?", (domain,)).fetchone()
    if not row:
        raise ValueError(f"{domain} isn't a suggestion")
    comment = f"{config.TAG}: allowed, block-list false positive ({row['reason'] or 'looks legitimate'})"[:200]
    try:
        ftl.request("POST", "/domains/allow/exact", json={"domain": domain, "comment": comment, "enabled": True})
    except requests.HTTPError as e:
        text = e.response.text if e.response is not None else ""
        if "already present" not in text and "UNIQUE" not in text:
            raise
    db.execute("update gravity_checks set status = ?, updated_at = ? where domain = ?", (ALLOWED, time.time(), domain))
    store.log_event(db, domain, store.LIST_ALLOWED, row["category"], row["confidence"],
                    "allowed: block-list false positive", row["clients"])
    db.commit()


def dismiss(db, kind, key):
    db.execute("insert or replace into dismissed values (?, ?, ?)", (kind, key, time.time()))
    if kind == "list":
        db.execute("update gravity_checks set status = ?, updated_at = ? where domain = ?", (DISMISSED, time.time(), key))
    db.commit()


# ---- site-wide rules --------------------------------------------------------------------

def site_regex(site):
    return r"(^|\.)" + re.escape(site) + "$"


def sites(db, settings):
    """Sites with SITE_MIN_BLOCKED or more domains blocked by KestrelPro, not yet covered or dismissed."""
    blocked = [r[0] for r in db.execute("select domain from verdicts where status in (?, ?)",
                                        (store.BLOCKED, store.USER_BLOCKED))]
    groups = {}
    for d in blocked:
        groups.setdefault(safety.registrable(d), []).append(d)
    done = {r[0] for r in db.execute("select site from site_rules")}
    dismissed = {r[0] for r in db.execute("select key from dismissed where kind = 'site'")}
    out = []
    for site, domains in groups.items():
        if (len(domains) < SITE_MIN_BLOCKED or site in done or site in dismissed
                or policy.is_protected(site, settings["protected_extra"])):
            continue
        out.append({"site": site, "regex": site_regex(site), "domains": sorted(domains)})
    return sorted(out, key=lambda x: -len(x["domains"]))


def rules(db):
    return [dict(r) for r in db.execute("select * from site_rules order by added_at desc")]


def block_site(ftl, db, site):
    settings = store.get_settings(db)
    if policy.is_protected(site, settings["protected_extra"]):
        raise ValueError(f"{site} is on the never-block list")
    match = next((s for s in sites(db, settings) if s["site"] == site), None)
    if not match:
        raise ValueError(f"{site} isn't a current suggestion")
    regex = match["regex"]
    comment = f"{config.TAG}: whole site {site} ({len(match['domains'])} domains were blocked)"[:200]
    everyone = policies.Directory(ftl).everyone()
    try:
        ftl.request("POST", "/domains/deny/regex", json={"domain": regex, "comment": comment, "groups": everyone,
                                                          "enabled": True})
    except requests.HTTPError as e:
        text = e.response.text if e.response is not None else ""
        if "already present" not in text and "UNIQUE" not in text:
            raise
        ftl.request("PUT", f"/domains/deny/regex/{requests.utils.quote(regex, safe='')}",
                    json={"comment": comment, "groups": everyone, "enabled": True})
    db.execute("insert or replace into site_rules values (?, ?, ?, ?)", (site, regex, len(match["domains"]), time.time()))
    store.log_event(db, site, store.SITE_BLOCKED, reason=f"site-wide rule {regex}")
    db.commit()
    return regex


def unblock_site(ftl, db, site):
    row = db.execute("select * from site_rules where site = ?", (site,)).fetchone()
    if not row:
        raise ValueError(f"No site-wide rule for {site}")
    try:
        ftl.request("DELETE", f"/domains/deny/regex/{requests.utils.quote(row['regex'], safe='')}")
    except requests.HTTPError as e:
        if e.response is None or e.response.status_code != 404:
            raise
    db.execute("delete from site_rules where site = ?", (site,))
    store.log_event(db, site, store.SITE_UNBLOCKED, reason=f"removed site-wide rule {row['regex']}")
    db.commit()
