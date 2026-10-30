"""Per-device policies through the DNS server's groups.

Devices are put in groups in the admin UI (Group Management → Clients), as usual. Each group
can have a KestrelPro policy: inherit the global settings, Review first, Automatic or Off,
optionally with its own confidence threshold and categories. Group 0 ("Default") always
follows the global AI settings.

For a domain the model flags, every group of every device that looked it up is evaluated.
Groups whose policy blocks automatically get the deny entry (it is assigned to just those
groups, so other devices are unaffected); groups in Review first queue it for approval.
A block you make or approve yourself applies to every group.
"""
import ipaddress
import json
import logging
import threading
import time

import requests

log = logging.getLogger("kestrel.policies")

MODES = ("inherit", "review", "auto", "off")
DEFAULT_GROUP = 0
REFRESH_SECONDS = 60


class Directory:
    """Groups and the clients assigned to them, from the DNS server, cached for a minute."""

    def __init__(self, ftl):
        self.ftl = ftl
        self.lock = threading.Lock()
        self.at = 0.0
        self.groups = {}   # id -> {"id", "name", "enabled", "comment"}
        self.clients = []  # [{"match": ip_network | str, "groups": [...]}]

    def refresh(self, force=False):
        with self.lock:
            if not force and time.time() - self.at < REFRESH_SECONDS:
                return
            try:
                groups = self.ftl.request("GET", "/groups")["groups"]
                clients = self.ftl.request("GET", "/clients")["clients"]
            except (requests.RequestException, KeyError, TypeError) as e:
                log.warning("couldn't read groups and clients: %s", e)
                return
            self.groups = {g["id"]: {"id": g["id"], "name": g.get("name") or f"Group {g['id']}",
                                     "enabled": g.get("enabled", True), "comment": g.get("comment") or ""}
                           for g in groups}
            self.clients = []
            for c in clients:
                spec = (c.get("client") or "").strip()
                try:
                    match = ipaddress.ip_network(spec, strict=False)
                except ValueError:
                    match = spec.lower()  # a hostname (MAC and interface entries never match an IP)
                self.clients.append({"match": match, "groups": c.get("groups") or [DEFAULT_GROUP],
                                     "client": spec, "name": c.get("name") or ""})
            self.at = time.time()

    def groups_for(self, ip, name=None):
        """Enabled groups of a device. Devices not listed under Clients are in Default only."""
        self.refresh()
        found = set()
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            addr = None
        name = (name or "").lower()
        for c in self.clients:
            m = c["match"]
            if (addr is not None and isinstance(m, (ipaddress.IPv4Network, ipaddress.IPv6Network))
                    and addr.version == m.version and addr in m) or (name and m == name):
                found.update(c["groups"])
        found = found or {DEFAULT_GROUP}
        return {g for g in found if self.groups.get(g, {}).get("enabled", True)}

    def everyone(self):
        """Every enabled group: what a block you make yourself is assigned to."""
        self.refresh()
        return sorted(g for g, info in self.groups.items() if info["enabled"]) or [DEFAULT_GROUP]

    def clients_in(self, group_id):
        self.refresh()
        return [c["client"] for c in self.clients if group_id in c["groups"]]


def load(db):
    out = {}
    for r in db.execute("select * from policies"):
        out[r["group_id"]] = {"mode": r["mode"], "min_confidence": r["min_confidence"],
                              "block_categories": json.loads(r["block_categories"]) if r["block_categories"] else None}
    return out


def save(db, group_id, mode, min_confidence=None, block_categories=None):
    if group_id == DEFAULT_GROUP:
        raise ValueError("the Default group follows the global AI settings")
    if mode not in MODES:
        raise ValueError(f"mode must be one of {', '.join(MODES)}")
    db.execute("insert or replace into policies (group_id, mode, min_confidence, block_categories, updated_at) "
               "values (?, ?, ?, ?, ?)",
               (group_id, mode, min_confidence,
                json.dumps(block_categories) if block_categories is not None else None, time.time()))
    db.commit()


def effective(settings, policy):
    """The rules a group actually follows: its own where set, the global settings otherwise."""
    policy = policy or {}
    mode = policy.get("mode") or "inherit"
    return {
        "mode": settings["mode"] if mode == "inherit" else mode,
        "min_confidence": policy.get("min_confidence") if policy.get("min_confidence") is not None
        else settings["min_confidence"],
        "block_categories": policy.get("block_categories") if policy.get("block_categories") is not None
        else settings["block_categories"],
    }


def decide(verdict, settings, policies, groups, paused=False):
    """Split `groups` into those that block `verdict` automatically and those that want review."""
    auto, review = [], []
    for g in sorted(groups):
        p = effective(settings, policies.get(g) if g != DEFAULT_GROUP else None)
        if p["mode"] == "off":
            continue
        if verdict["category"] in p["block_categories"] and verdict["confidence"] >= p["min_confidence"]:
            (auto if p["mode"] == "auto" and not paused else review).append(g)
    return auto, review


def summary(db, directory, settings):
    """Groups with their policy, client entries and block-list count, for the Policies page.
    A device only in a non-Default group gets no block lists unless they're assigned to that
    group too (standard DNS-server behaviour), so the page warns about groups without any."""
    directory.refresh(force=True)
    saved = load(db)
    try:
        lists = [l for l in directory.ftl.request("GET", "/lists")["lists"]
                 if l.get("type", "block") == "block" and l.get("enabled", True)]
    except (requests.RequestException, KeyError, TypeError):
        lists = None
    out = []
    for gid, info in sorted(directory.groups.items()):
        own = saved.get(gid) if gid != DEFAULT_GROUP else None
        out.append({**info, "clients": directory.clients_in(gid),
                    "policy": own or {"mode": "inherit", "min_confidence": None, "block_categories": None},
                    "effective": effective(settings, own), "default": gid == DEFAULT_GROUP,
                    "block_lists": None if lists is None else sum(gid in (l.get("groups") or []) for l in lists)})
    return out

