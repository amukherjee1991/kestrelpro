"""Fill a KestrelPro engine database with made-up decisions, for trying the UI and taking
documentation screenshots without exposing anyone's real browsing.

Run inside a *test* container, never on a real installation:
  docker cp engine/tools/seed_demo.py <container>:/tmp/
  docker exec <container> su-exec kestrel:pihole env PYTHONPATH=/opt/kestrel-engine python3 /tmp/seed_demo.py

Blocked samples are also added to the DNS server's deny list (with a "kestrel:" comment),
so the engine's reconcile step sees a consistent state.
"""
import json
import random
import time

from kestrel_engine import ftl as ftl_api, policy, store

random.seed(7)
NOW = time.time()

HOME = [("192.168.1.20", "Living-Room-TV"), ("192.168.1.31", "Pixel-8"), ("192.168.1.42", "iPad"),
        ("192.168.1.55", "Work-Laptop"), ("192.168.1.60", "Smart-Speaker")]
VPN = [("10.8.0.2", "Laptop-VPN"), ("10.8.0.3", "Phone-VPN")]

# domain, category, confidence, reason, status
SAMPLES = [
    ("cdn.taboola.com", "ads", .97, "Taboola sponsored-content and native ad network.", "blocked"),
    ("trc.taboola.com", "tracking", .95, "Taboola click and impression tracking.", "blocked"),
    ("widgets.outbrain.com", "ads", .96, "Outbrain recommendation ads widget.", "blocked"),
    ("sb.scorecardresearch.com", "tracking", .94, "Comscore audience measurement beacon.", "blocked"),
    ("pixel.adsafeprotected.com", "tracking", .92, "Integral Ad Science ad-verification pixel.", "blocked"),
    ("c.amazon-adsystem.com", "ads", .97, "Amazon advertising bid and ad delivery.", "blocked"),
    ("ads.samsungads.com", "ads", .93, "Samsung Smart TV home-screen advertising.", "blocked"),
    ("device-metrics-us.amazon.com", "telemetry", .9, "Fire TV device metrics upload.", "allowed"),
    ("api.mixpanel.com", "tracking", .91, "Mixpanel product analytics events.", "pending"),
    ("cdn.segment.com", "tracking", .9, "Segment analytics loader script.", "pending"),
    ("bat.bing.com", "tracking", .93, "Microsoft Advertising conversion tracking.", "blocked"),
    ("ct.pinterest.com", "tracking", .92, "Pinterest conversion tag.", "blocked"),
    ("secure-login-verify-acct.top", "malicious", .96, "Look-alike login page on a throwaway domain.", "blocked"),
    ("free-prize-claim.click", "malicious", .95, "Prize scam landing page.", "blocked"),
    ("api.spotify.com", "legitimate", .98, "Spotify app API.", "allowed"),
    ("i.scdn.co", "legitimate", .97, "Spotify image CDN.", "allowed"),
    ("api.weather.gov", "legitimate", .96, "US National Weather Service API.", "allowed"),
    ("cdn.jsdelivr.net", "legitimate", .97, "Public CDN for web libraries.", "allowed"),
    ("fonts.bunny.net", "legitimate", .95, "Privacy-friendly web font CDN.", "allowed"),
    ("sdk.split.io", "tracking", .9, "Feature-flag SDK used by apps.", "user_allowed"),
    ("events.launchdarkly.com", "telemetry", .88, "Feature-flag event reporting.", "allowed"),
    ("app.unknown-saas.io", "unknown", .5, "No public information about this service.", "allowed"),
    ("tags.tiqcdn.com", "tracking", .9, "Tealium tag manager loading trackers.", "pending"),
    ("ads.yieldmo.com", "ads", .95, "Yieldmo mobile ad exchange.", "blocked"),
    ("match.adsrvr.org", "tracking", .94, "The Trade Desk cookie matching.", "blocked"),
]
STATUS_EVENT = {"blocked": store.AUTO_BLOCKED, "user_blocked": store.MANUAL_BLOCKED,
                "pending": store.FLAGGED, "user_allowed": store.REJECTED}


def seed(db, ftl):
    for i, (domain, cat, conf, reason, status) in enumerate(SAMPLES):
        who = random.sample(HOME, random.randint(1, 3)) + (random.sample(VPN, 1) if i % 3 == 0 else [])
        clients = [{"ip": ip, "name": name, "network": "vpn" if (ip, name) in VPN else "home",
                    "lookups": random.randint(2, 60)} for ip, name in who]
        clients.sort(key=lambda c: -c["lookups"])
        at = NOW - random.uniform(0.2, 6.5) * 86400 if i > 4 else NOW - random.uniform(600, 20000)
        verdict = {"category": cat, "confidence": conf, "reason": reason}
        if status in (store.BLOCKED, store.USER_BLOCKED):
            ftl.deny(domain, policy.comment_for(verdict))
        db.execute("insert or replace into verdicts (domain, category, confidence, reason, status, queries, devices, "
                   "judged_at, updated_at, clients, expires_at, model, prompt_version) "
                   "values (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (domain, cat, conf, reason, status, sum(c["lookups"] for c in clients), len(clients), at, at,
                    json.dumps(clients), policy.expires_at(verdict, at) if status == store.ALLOWED else None,
                    "gemma4:12b", "demo"))
        if status in STATUS_EVENT:
            db.execute("insert into events (at, domain, action, category, confidence, reason, clients) "
                       "values (?,?,?,?,?,?,?)", (at, domain, STATUS_EVENT[status], cat, conf, reason, json.dumps(clients)))
    # One mistake caught and undone, to show the Undone filter.
    db.execute("insert into events (at, domain, action, category, confidence, reason, clients) values (?,?,?,?,?,?,?)",
               (NOW - 2 * 86400 + 600, "sdk.split.io", store.UNBLOCKED, "tracking", .9, "Feature-flag SDK used by apps.",
                json.dumps([{"ip": "192.168.1.31", "name": "Pixel-8", "network": "home", "lookups": 12}])))
    # Bulk of "legitimate" verdicts so the category chart looks like a real week.
    for n in range(640):
        db.execute("insert or replace into verdicts (domain, category, confidence, reason, status, queries, devices, "
                   "judged_at, updated_at, expires_at) values (?,?,?,?,?,?,?,?,?,?)",
                   (f"content-{n}.example-cdn.net", random.choice(["legitimate"] * 12 + ["unknown", "telemetry"]),
                    .95, "Content delivery.", store.ALLOWED, 3, 1, NOW - random.uniform(0, 86400), NOW, NOW + 30 * 86400))
    store.save_settings(db, {"mode": "review"})
    db.commit()


if __name__ == "__main__":
    ftl = ftl_api.FTL()
    try:
        seed(store.open_db(), ftl)
    finally:
        ftl.logout()
    print(f"seeded {len(SAMPLES) + 640} made-up verdicts")
