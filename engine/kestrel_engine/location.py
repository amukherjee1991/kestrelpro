"""Location shield: block the services devices use to find out where they are.

Each service is a short list of domains. Turning a service on for some device groups adds
those domains to the DNS server's deny list, assigned to just those groups and marked
`location-shield: <service>` in the comment. The deny entries are the only record of what is
on: there is no separate setting to drift out of step, and the entries show up (and can be
edited) under Domains like any other.

This stops location *lookups*. It doesn't fake a location, and services can still estimate
where a network is from its public IP address; a DNS server can't change that.

The marker deliberately doesn't start with config.TAG, so pausing or undoing KestrelPro's
AI blocks never lifts the shield.
"""
import time

import requests

MARK = "location-shield"
REPORT_DAYS = 7

# Blocked statuses as FTL reports them; a shielded lookup shows up as DENYLIST.
BLOCKED = {"GRAVITY", "REGEX", "DENYLIST", "GRAVITY_CNAME", "REGEX_CNAME", "DENYLIST_CNAME",
           "EXTERNAL_BLOCKED_IP", "EXTERNAL_BLOCKED_NULL", "EXTERNAL_BLOCKED_NXRA", "SPECIAL_DOMAIN"}

SERVICES = [
    {"id": "microsoft", "name": "Microsoft location service",
     "domains": ["inference.location.live.net", "inference.location.live.com",
                 "location-inference-westus.cloudapp.net"],
     "what": "Windows works out where it is from nearby Wi-Fi networks through this service. Teams uses it "
             "for the emergency address and location sharing; so do Maps, Weather, Find my device and Edge.",
     "breaks": "Windows can't detect its location. Teams asks for an emergency address to be typed in; "
               "Maps and Weather need a place entered by hand."},
    {"id": "apple", "name": "Apple location service",
     "domains": ["gs-loc.apple.com", "gs-loc-cn.apple.com"],
     "what": "iPhones, iPads and Macs work out where they are from nearby Wi-Fi networks through this "
             "service, and so does every app on them (Teams on a Mac included).",
     "breaks": "Indoors, Find My, Maps, Weather and family-location apps lose accuracy; iPhones still use "
               "GPS outdoors. Macs can't find their location at all."},
    {"id": "google", "name": "Google location history",
     "domains": ["locationhistory-pa.googleapis.com", "locationhistoryplacedetails-pa.googleapis.com"],
     "what": "Where phones upload Google Maps Timeline (Location History).",
     "breaks": "Timeline stops recording places from these devices. Positioning itself keeps working: "
               "Android and Chrome use a shared Google address that can't be blocked by name."},
    {"id": "ip_lookup", "name": "IP-address location lookups",
     "domains": ["ip-api.com", "pro.ip-api.com", "ipapi.co", "ipinfo.io", "api.ipgeolocation.io", "ipwho.is",
                 "ipwhois.app", "freeipapi.com", "geolocation-db.com", "extreme-ip-lookup.com", "get.geojs.io",
                 "ip-api.io", "geo.ipify.org", "api.ip2location.io", "geoip.maxmind.com",
                 "geolocation.onetrust.com"],
     "what": "Services that apps and websites ask \"where is this internet address?\".",
     "breaks": "Some sites guess the wrong region or show their cookie banner every time; store finders "
               "and region checks may ask you to choose. Sites can still look up your address themselves."},
    {"id": "mozilla", "name": "Mozilla location service",
     "domains": ["location.services.mozilla.com"],
     "what": "Mozilla's former Wi-Fi location service, still asked by some Firefox versions and Linux desktops.",
     "breaks": "Websites asking Firefox for your location get no answer from this service."},
]
BY_ID = {s["id"]: s for s in SERVICES}


def comment_for(service):
    return f"{MARK}: {service['id']} - {service['name']}"


def service_of(comment):
    """The service id in a shield comment, or None for any other deny entry."""
    comment = comment or ""
    if not comment.startswith(MARK + ":"):
        return None
    rest = comment[len(MARK) + 1:].strip()
    return rest.split(" ", 1)[0] or None


def _entries(ftl):
    return {e["domain"]: e for e in ftl.list_domains("deny/exact")}


def apply(ftl, directory, service_id, groups):
    """Turn a service on for exactly `groups` (empty: off). Returns what changed.

    A domain that's already on the deny list for another reason (your own block, an AI block)
    is left as it is and reported, so the shield never takes over or removes someone else's entry.
    """
    service = BY_ID.get(service_id)
    if not service:
        raise ValueError(f"unknown service {service_id!r}")
    directory.refresh(force=True)
    known = set(directory.groups)
    bad = [g for g in groups if g not in known]
    if bad:
        raise ValueError(f"no such group: {', '.join(map(str, bad))}")
    groups = sorted(set(groups))
    entries = _entries(ftl)
    comment = comment_for(service)
    out = {"added": [], "updated": [], "removed": [], "left_alone": []}
    for domain in service["domains"]:
        e = entries.get(domain)
        ours = e is not None and service_of(e.get("comment")) == service_id
        if e is not None and not ours:
            out["left_alone"].append(domain)
            continue
        if not groups:
            if ours:
                ftl.remove_deny(domain)
                out["removed"].append(domain)
        elif e is None:
            ftl.deny(domain, comment, groups=groups)
            out["added"].append(domain)
        elif sorted(e.get("groups") or []) != groups or not e.get("enabled", True):
            ftl.set_groups(domain, comment, groups)
            out["updated"].append(domain)
    return out


def _lookups(ftl, domains, since):
    """{domain: [query rows]} for the report; a failing domain just has no rows."""
    out = {}
    for d in domains:
        try:
            out[d] = ftl.queries(length=10000, since=since, domain=d).get("queries") or []
        except requests.RequestException:
            out[d] = []
    return out


def summary(ftl, directory, now=None):
    """Every service with the groups it's on for and which devices asked it lately."""
    now = now or time.time()
    directory.refresh(force=True)
    entries = _entries(ftl)
    lookups = _lookups(ftl, [d for s in SERVICES for d in s["domains"]], now - REPORT_DAYS * 86400)
    out = []
    for s in SERVICES:
        ours = [entries[d] for d in s["domains"] if d in entries and service_of(entries[d].get("comment")) == s["id"]]
        others = [d for d in s["domains"] if d in entries and service_of(entries[d].get("comment")) != s["id"]]
        groups = sorted({g for e in ours if e.get("enabled", True) for g in (e.get("groups") or [])})
        devices = {}
        for d in s["domains"]:
            for q in lookups.get(d, []):
                c = q.get("client") or {}
                ip = c.get("ip") or "?"
                dev = devices.setdefault(ip, {"ip": ip, "name": c.get("name") or "", "lookups": 0, "blocked": 0,
                                              "last": 0.0})
                dev["lookups"] += 1
                dev["blocked"] += q.get("status") in BLOCKED
                dev["last"] = max(dev["last"], float(q.get("time") or 0))
        out.append({
            "id": s["id"], "name": s["name"], "what": s["what"], "breaks": s["breaks"], "domains": s["domains"],
            "groups": groups,
            "group_names": [directory.groups.get(g, {}).get("name", f"Group {g}") for g in groups],
            # Some domains of the service missing or disabled: e.g. one deleted under Domains.
            "partial": bool(groups) and len([e for e in ours if e.get("enabled", True)]) < len(s["domains"]) - len(others),
            "already_blocked": others,
            "devices": sorted(devices.values(), key=lambda v: (-v["lookups"], v["ip"])),
        })
    return {"services": out, "days": REPORT_DAYS,
            "groups": [{"id": g, "name": info["name"], "enabled": info["enabled"],
                        "clients": directory.clients_in(g)} for g, info in sorted(directory.groups.items())]}
