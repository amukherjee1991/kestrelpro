"""What to skip, what to flag, and the user's own decisions."""
import ipaddress
import time

import requests

from . import config, policies, safety, store

# Never auto-block these or anything under them; a false positive here breaks
# logins, updates or core apps. Users add more via the dashboard.
# Kept to logins, OS and software updates, app stores, messaging and the big CDNs: things
# whose loss breaks a household quickly. Anything else belongs in the user's own list.
PROTECTED_BUILTIN = {
    # Apple, Google, Microsoft: sign-in, updates, app stores
    "apple.com", "icloud.com", "mzstatic.com", "apple-cloudkit.com", "cdn-apple.com",
    "google.com", "googleapis.com", "gstatic.com", "youtube.com", "googlevideo.com", "ytimg.com",
    "microsoft.com", "microsoftonline.com", "live.com", "office.com", "office.net", "windows.com",
    "windowsupdate.com", "msftconnecttest.com", "azureedge.net",
    # Linux and software updates, developer infrastructure
    "ubuntu.com", "canonical.com", "debian.org", "fedoraproject.org", "archlinux.org",
    "flathub.org", "snapcraft.io", "github.com", "githubusercontent.com", "docker.io", "docker.com",
    "pypi.org",
    # Messaging and calls
    "whatsapp.com", "whatsapp.net", "signal.org", "discord.com", "discord.gg", "zoom.us",
    # CDNs and cloud
    "cloudflare.com", "akamaized.net", "fastly.net", "amazonaws.com",
}

# CDN and traffic-manager zones. Names under them are shared infrastructure for many sites:
# random-looking edge names (e1234.a.akamaiedge.net, d15nwp.cloudfront.net) or load-balancer
# names that embed the customer's host (gtm.secure.chase.com.akadns.net). The model can't tell
# who they serve and has blocked banks' logins and Apple push through them, so it never judges them.
INFRA_ZONES = (
    "akadns.net", "akamaiedge.net", "akamaihd.net", "akamai.net", "edgekey.net", "edgesuite.net",
    "akamaized.net", "cloudfront.net", "azurefd.net", "azureedge.net", "trafficmanager.net",
    "fastly.net", "fastlylb.net", "cdn.cloudflare.net",
)
PROTECTED_BUILTIN |= set(INFRA_ZONES)

# Last labels that make an infra name's prefix look like a real host (gtm.secure.chase.com.akadns.net
# embeds secure.chase.com; e1234.a.akamaiedge.net embeds nothing). Not every TLD: just enough to
# recognise the customer names these zones carry.
_EMBED_TLDS = {
    "com", "net", "org", "io", "co", "us", "uk", "ca", "au", "de", "fr", "nl", "es", "it", "jp", "in",
    "br", "mx", "se", "no", "dk", "fi", "ch", "at", "be", "ie", "nz", "sg", "app", "dev", "me", "tv",
    "info", "biz", "edu", "gov", "mil", "ai", "cloud",
}

# Local names plus the reserved test TLDs (RFC 2606/6761), e.g. Chrome's
# "this-url-does-not-exist-....invalid" DNS-hijack probe.
LOCAL_SUFFIXES = (".lan", ".local", ".arpa", ".home", ".internal", ".invalid", ".test", ".example", ".localhost")


def network_of(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "home"
    return "vpn" if any(addr.version == n.version and addr in n for n in config.VPN_SUBNETS) else "home"


def is_protected(domain, extra=()):
    protected = PROTECTED_BUILTIN | set(extra)
    parts = domain.split(".")
    return any(".".join(parts[i:]) in protected for i in range(len(parts)))


def skip_domain(domain, extra=()):
    return ("." not in domain or domain.endswith(LOCAL_SUFFIXES)
            or domain.replace(".", "").isdigit() or is_protected(domain, extra))


def in_infra(domain):
    return any(domain == z or domain.endswith("." + z) for z in INFRA_ZONES)


def embedded_host(domain):
    """The customer host an infra name carries: secure.chase.com for gtm.secure.chase.com.akadns.net.
    Only under INFRA_ZONES, which nobody else can register names in; elsewhere a name like
    chase.com.login-check.xyz is phishing, not Chase."""
    domain = domain.lower().rstrip(".")
    for z in INFRA_ZONES:
        if domain.endswith("." + z):
            labels = domain[:-len(z) - 1].split(".")
            if len(labels) >= 2 and labels[-1] in _EMBED_TLDS:
                return ".".join(labels)
            return None
    return None


# Platforms where every customer gets a subdomain: one tenant says nothing about the others,
# and a phishing page on Cloud Run must not protect all of Cloud Run.
HOSTING_ZONES = (
    "run.app", "appspot.com", "web.app", "firebaseapp.com", "cloudfunctions.net", "vercel.app",
    "netlify.app", "pages.dev", "workers.dev", "r2.dev", "trycloudflare.com", "github.io",
    "gitlab.io", "herokuapp.com", "azurewebsites.net", "azurestaticapps.net", "onrender.com",
    "fly.dev", "replit.app", "repl.co", "glitch.me", "ngrok.io", "ngrok-free.app", "amazonaws.com",
    "blogspot.com", "wordpress.com", "wixsite.com", "duckdns.org", "ddns.net", "no-ip.org",
)


def learn_site(domain):
    """The site a "keep this working" decision on `domain` should protect, or None.
    gtm.secure.chase.com.akadns.net -> chase.com; cdn.example.co.uk -> example.co.uk;
    e1234.a.akamaiedge.net -> None (it names no site, and protecting Akamai is already built in);
    x-abc-uc.a.run.app -> itself (hosting platforms: only that tenant)."""
    domain = domain.lower().rstrip(".")
    host = embedded_host(domain)
    if host is None and in_infra(domain):
        return None
    host = host or domain
    if any(host == z or host.endswith("." + z) for z in HOSTING_ZONES):
        # Only the exact tenant; the platform itself is never learned.
        return None if host in HOSTING_ZONES or is_protected(host) else host
    site = safety.registrable(host)
    if "." not in site or is_protected(site):
        return None
    return site


def learned_backfill(db):
    """Once: learn from unblocks made before learning existed. Bulk `undo` removals don't count,
    nor domains you have blocked again since."""
    if store.get_state(db, "learned_backfilled") == "1":
        return
    rows = db.execute(
        "select distinct e.domain from events e join verdicts v on v.domain = e.domain "
        "where e.action in (?, ?) and coalesce(e.reason, '') not like ? and v.status = ?",
        (store.UNBLOCKED, store.REJECTED, "%undo`%", store.USER_ALLOWED)).fetchall()
    for (d,) in rows:
        site = learn_site(d)
        if site:
            store.add_learned(db, site, d)
    store.set_state(db, "learned_backfilled", "1")


def never_block(db, settings):
    """Your never-block list plus the sites learned from your unblocks."""
    learned_backfill(db)
    return list(settings["protected_extra"]) + store.learned_sites(db)


def learn_from(db, domain, settings=None):
    """You kept `domain` working: protect its site from the model from now on. Returns the site or None."""
    settings = settings or store.get_settings(db)
    if not settings.get("learn_from_unblocks", True):
        return None
    site = learn_site(domain)
    if not site or is_protected(site, never_block(db, settings)):
        return None
    store.add_learned(db, site, domain)
    return site


def flags(verdict, settings):
    return verdict["category"] in settings["block_categories"] and verdict["confidence"] >= settings["min_confidence"]


def expires_at(verdict, now):
    ttl = store.VERDICT_TTL.get(verdict["category"])
    return now + ttl if ttl else None


def comment_for(v):
    return f"{config.TAG}: {v['category']} {v['confidence']:.2f} - {v['reason']}"[:200]


def set_status(ftl, db, domain, status, action=None):
    """Apply a user decision: block, approve, unblock or reject a domain, and record it in the history."""
    domain = domain.strip().lower().rstrip(".")
    row = db.execute("select * from verdicts where domain = ?", (domain,)).fetchone()
    if status in (store.BLOCKED, store.USER_BLOCKED):
        # Your own block applies to every group, also when an automatic one covered only some.
        everyone = policies.Directory(ftl).everyone()
        comment = comment_for(dict(row)) if row else f"{config.TAG}: blocked by you"
        ftl.deny(domain, comment, groups=everyone)
        if row and row["block_groups"]:
            ftl.set_groups(domain, comment, everyone)
    else:
        ftl.remove_deny(domain)
    now = time.time()
    if row:
        # A user's decision is final: it no longer expires and is off probation.
        db.execute("update verdicts set status = ?, updated_at = ?, expires_at = null, probation_until = null, "
                   "block_groups = null where domain = ?", (status, now, domain))
    else:
        db.execute("insert into verdicts (domain, category, confidence, reason, status, queries, devices, "
                   "judged_at, updated_at) values (?, 'ads', 1.0, 'blocked by you', ?, 0, 0, ?, ?)",
                   (domain, status, now, now))
    if action:
        r = dict(row) if row else {"category": "ads", "confidence": 1.0, "reason": "blocked by you", "clients": "[]"}
        store.log_event(db, domain, action, r["category"], r["confidence"], r["reason"], r["clients"])
    db.commit()
    # Keeping a domain working teaches the engine to leave its whole site alone.
    if action in (store.UNBLOCKED, store.REJECTED):
        learn_from(db, domain)
    # Unblocking one domain of a site is a hint that its siblings' fresh blocks may be wrong too.
    if action == store.UNBLOCKED:
        return safety.revert_siblings(ftl, db, domain)
    return []


def undo(ftl, db):
    """Remove every deny entry the engine (or the old add-on) ever added, site-wide rules included."""
    for e in ftl.list_domains("deny/regex"):
        if (e.get("comment") or "").startswith(config.TAG):
            ftl.request("DELETE", f"/domains/deny/regex/{requests.utils.quote(e['domain'], safe='')}")
    db.execute("delete from site_rules")
    mine = [e["domain"] for e in ftl.list_domains("deny/exact") if (e.get("comment") or "").startswith(config.TAG)]
    for d in mine:
        ftl.remove_deny(d)
        db.execute("update verdicts set status = ?, updated_at = ?, expires_at = null where domain = ?",
                   (store.USER_ALLOWED, time.time(), d))
        store.log_event(db, d, store.UNBLOCKED, reason="removed by `kestrel undo`")
    db.commit()
    return mine
