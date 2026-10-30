"""Local evidence beyond the domain name, from the query log the engine already reads.

Small models judge a domain by its name, which is their main failure mode. These signals come
only from this network's own lookups (nothing is looked up on the internet):

- devices: which devices looked it up (a smart TV and nothing else says something);
- clockwork: the same device repeats it at a steady interval (telemetry and tracking beacons
  do; people browsing don't);
- next to blocked: how often a device's lookup came within two seconds of a lookup that was
  blocked (ad and tracking calls tend to come in bursts with other ad calls).

They are hints for the model, not rules; the prompt says so.
"""
import bisect
import statistics

# Statuses meaning the DNS server blocked the lookup (FTL v6 query statuses).
BLOCKED_ANY = {"GRAVITY", "REGEX", "DENYLIST", "GRAVITY_CNAME", "REGEX_CNAME", "DENYLIST_CNAME",
               "EXTERNAL_BLOCKED_IP", "EXTERNAL_BLOCKED_NULL", "EXTERNAL_BLOCKED_NXRA"}
NEAR_SECONDS = 2.0
MAX_TIMES = 60         # lookup times kept per device per queued domain
MIN_CLOCKWORK = 4      # lookups needed before calling a rhythm
CLOCKWORK_CV = 0.25    # interval spread (coefficient of variation) below which it's steady
MIN_PERIOD = 15        # seconds; faster repeats are retries, not beacons


def blocked_times(queries):
    """ip -> sorted lookup times of blocked queries, for the next-to-blocked signal."""
    out = {}
    for q in queries:
        if q.get("status") in BLOCKED_ANY:
            out.setdefault((q.get("client") or {}).get("ip"), []).append(q.get("time") or 0)
    for times in out.values():
        times.sort()
    return out


def near_blocked(blocked, ip, t):
    times = blocked.get(ip)
    if not times:
        return False
    i = bisect.bisect_left(times, t - NEAR_SECONDS)
    return i < len(times) and times[i] <= t + NEAR_SECONDS


def clockwork(times):
    """The steady period in seconds if these lookup times repeat like a beacon, else None."""
    if len(times) < MIN_CLOCKWORK:
        return None
    ts = sorted(times)
    gaps = [b - a for a, b in zip(ts, ts[1:]) if b > a]
    if len(gaps) < MIN_CLOCKWORK - 1:
        return None
    mean = statistics.fmean(gaps)
    if mean < MIN_PERIOD:
        return None
    cv = statistics.pstdev(gaps) / mean
    return round(mean) if cv <= CLOCKWORK_CV else None


HISTORY_SECONDS = 3600


def add_history(ftl, domain, item, now):
    """Fill in the device rhythm from the DNS server's last hour of lookups of `domain`.

    In real-time mode a domain is judged seconds after its first lookup, before any rhythm can
    show; the server's own log has the longer view for domains it has seen before (re-reviews,
    Eco mode). A domain seen for the very first time still has just the one lookup."""
    try:
        rows = ftl.queries(start=0, length=500, since=now - HISTORY_SECONDS, domain=domain).get("queries") or []
    except Exception:  # evidence is best effort; the verdict doesn't depend on it
        return
    for q in rows:
        ip = (q.get("client") or {}).get("ip") or "?"
        dev = item["devices"].setdefault(ip, {"ip": ip, "name": (q.get("client") or {}).get("name"),
                                              "network": "home", "lookups": 0, "times": [], "history_only": True})
        times = dev.setdefault("times", [])
        t = q.get("time") or 0
        if t not in times and len(times) < MAX_TIMES:
            times.append(t)


def summarise(item):
    """Evidence for one queued domain: a dict to store and a short line for the prompt."""
    devices = sorted(item["devices"].values(), key=lambda d: -d["lookups"])
    names = [d.get("name") or d["ip"] for d in devices if not d.get("history_only")]
    periods = [p for p in (clockwork(d.get("times", [])) for d in devices) if p]
    near = item.get("near_blocked", 0)
    share = near / item["lookups"] if item["lookups"] else 0.0
    ev = {"devices": names[:6], "clockwork_seconds": sorted(periods)[:3], "near_blocked": round(share, 2)}
    parts = [f"devices: {', '.join(names[:4])}" + (f" +{len(names) - 4}" if len(names) > 4 else "")]
    if periods:
        parts.append(f"repeats every ~{min(periods)} s on {len(periods)} device(s)")
    if near and item["lookups"] >= 2:
        parts.append(f"{round(share * 100)}% of lookups came right next to blocked ad/tracker lookups")
    return ev, "; ".join(parts)

