"""SQLite store: verdicts, history events, settings and ingest state, with migrations."""
import json
import sqlite3
import time

from . import config

# Decision statuses stored per domain.
BLOCKED, PENDING, ALLOWED, USER_ALLOWED, USER_BLOCKED = "blocked", "pending", "allowed", "user_allowed", "user_blocked"

# History actions (one row per event in the `events` table).
AUTO_BLOCKED, FLAGGED, APPROVED, MANUAL_BLOCKED, UNBLOCKED, REJECTED = (
    "auto_blocked", "flagged", "approved", "user_blocked", "unblocked", "rejected")

# How long the model's "this is fine" stands before the domain is reviewed again.
# Flagged domains and the user's own decisions never expire on their own.
VERDICT_TTL = {"legitimate": 30 * 86400, "unknown": 7 * 86400}


def _columns(db, table):
    return {r[1] for r in db.execute(f"pragma table_info({table})")}


def _m1_base(db):
    """The schema of the original Kestrel add-on (v0.1.0); a no-op on its databases."""
    db.execute("""create table if not exists verdicts (
        domain text primary key, category text, confidence real, reason text,
        status text, queries integer, devices integer, judged_at real, updated_at real)""")
    db.execute("create table if not exists state (key text primary key, value text)")
    db.execute("create index if not exists verdicts_status on verdicts (status, updated_at)")
    if "clients" not in _columns(db, "verdicts"):
        db.execute("alter table verdicts add column clients text not null default '[]'")
    db.execute("""create table if not exists events (
        id integer primary key, at real, domain text, action text, category text,
        confidence real, reason text, clients text not null default '[]')""")
    db.execute("create index if not exists events_at on events (at)")


def _m2_provenance(db):
    """Verdict expiry and what produced each verdict."""
    have = _columns(db, "verdicts")
    for col, decl in [("expires_at", "real"), ("model", "text"), ("model_digest", "text"),
                      ("prompt_version", "text"), ("policy_id", "integer")]:
        if col not in have:
            db.execute(f"alter table verdicts add column {col} {decl}")
    for category, ttl in VERDICT_TTL.items():
        db.execute("update verdicts set expires_at = judged_at + ? where status = ? and category = ? "
                   "and expires_at is null", (ttl, ALLOWED, category))
    db.execute("create index if not exists verdicts_expiry on verdicts (expires_at)")


MIGRATIONS = [_m1_base, _m2_provenance]


def open_db(path=None):
    db = sqlite3.connect(path or config.DB_PATH, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("pragma journal_mode=wal")
    db.execute("create table if not exists state (key text primary key, value text)")
    version = int(get_state(db, "schema_version", 0))
    for i, migrate in enumerate(MIGRATIONS[version:], start=version + 1):
        with db:
            migrate(db)
            db.execute("insert or replace into state values ('schema_version', ?)", (str(i),))
    return db


def get_state(db, key, default=None):
    row = db.execute("select value from state where key = ?", (key,)).fetchone()
    return row[0] if row else default


def set_state(db, key, value):
    db.execute("insert or replace into state values (?, ?)", (key, str(value)))
    db.commit()


def get_settings(db):
    saved = json.loads(get_state(db, "settings", "{}"))
    return {**config.DEFAULT_SETTINGS, **{k: v for k, v in saved.items() if k in config.DEFAULT_SETTINGS}}


def save_settings(db, changes):
    settings = {**get_settings(db), **{k: v for k, v in changes.items() if k in config.DEFAULT_SETTINGS}}
    set_state(db, "settings", json.dumps(settings))
    return settings


def log_event(db, domain, action, category=None, confidence=None, reason=None, clients="[]"):
    db.execute("insert into events (at, domain, action, category, confidence, reason, clients) "
               "values (?, ?, ?, ?, ?, ?, ?)", (time.time(), domain, action, category, confidence, reason, clients))


def decided(db, domains, now=None):
    """The subset of `domains` that already has a verdict which hasn't expired."""
    now = now or time.time()
    out = set()
    domains = list(domains)
    for i in range(0, len(domains), 500):
        chunk = domains[i:i + 500]
        out |= {r[0] for r in db.execute(
            f"select domain from verdicts where domain in ({','.join('?' * len(chunk))}) "
            "and (expires_at is null or expires_at > ?)", chunk + [now])}
    return out
