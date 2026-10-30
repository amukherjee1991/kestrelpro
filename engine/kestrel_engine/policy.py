"""What to skip, what to flag, and the user's own decisions."""
import ipaddress
import time

from . import config, policies, safety, store

# Never auto-block these or anything under them; a false positive here breaks
# logins, updates or core apps. Users add more via the dashboard.
PROTECTED_BUILTIN = {
    "apple.com", "icloud.com", "mzstatic.com", "apple-cloudkit.com", "cdn-apple.com",
    "google.com", "googleapis.com", "gstatic.com", "youtube.com", "googlevideo.com", "ytimg.com",
    "microsoft.com", "microsoftonline.com", "live.com", "office.com", "office.net", "windows.com",
    "windowsupdate.com", "msftconnecttest.com", "azureedge.net",
    "github.com", "githubusercontent.com", "codeberg.org", "docker.io", "docker.com", "pypi.org",
    "ubuntu.com", "canonical.com", "zorin.com", "zorinos.com", "flathub.org", "snapcraft.io",
    "whatsapp.com", "whatsapp.net", "discord.com", "discord.gg", "zoom.us",
    "anthropic.com", "claude.ai", "cloudflare.com", "akamaized.net", "fastly.net", "amazonaws.com",
}

# Local names plus the reserved test TLDs (RFC 2606/6761), e.g. Chrome's
# "this-url-does-not-exist-....invalid" DNS-hijack probe.
LOCAL_SUFFIXES = (".lan", ".local", ".arpa", ".home", ".internal", ".invalid", ".test", ".example", ".localhost")


def network_of(ip):
    try:
        return "vpn" if ipaddress.ip_address(ip) in config.VPN_SUBNET else "home"
    except ValueError:
        return "home"


def is_protected(domain, extra=()):
    protected = PROTECTED_BUILTIN | set(extra)
    parts = domain.split(".")
    return any(".".join(parts[i:]) in protected for i in range(len(parts)))


def skip_domain(domain, extra=()):
    return ("." not in domain or domain.endswith(LOCAL_SUFFIXES)
            or domain.replace(".", "").isdigit() or is_protected(domain, extra))


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
    # Unblocking one domain of a site is a hint that its siblings' fresh blocks may be wrong too.
    if action == store.UNBLOCKED:
        return safety.revert_siblings(ftl, db, domain)
    return []


def undo(ftl, db):
    """Remove every deny entry the engine (or the old add-on) ever added."""
    mine = [e["domain"] for e in ftl.list_domains("deny/exact") if (e.get("comment") or "").startswith(config.TAG)]
    for d in mine:
        ftl.remove_deny(d)
        db.execute("update verdicts set status = ?, updated_at = ?, expires_at = null where domain = ?",
                   (store.USER_ALLOWED, time.time(), d))
        store.log_event(db, d, store.UNBLOCKED, reason="removed by `kestrel undo`")
    db.commit()
    return mine
