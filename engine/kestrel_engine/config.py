"""Engine configuration from the environment.

DEFAULT_SETTINGS are starting values only: once changed in the dashboard they live
in the database (store.get_settings).
"""
import ipaddress
import os

# Inside the KestrelPro container FTL is on localhost; start.sh exports the real port.
FTL_URL = os.environ.get("FTL_URL", os.environ.get("PIHOLE_URL", "http://127.0.0.1")).rstrip("/")
# FTL rewrites its CLI password on every start. Sessions made with it can read data and
# manage lists but cannot change FTL's configuration, which is all the engine needs.
CLI_PW_PATH = os.environ.get("FTL_CLI_PW", "/etc/pihole/cli_pw")
# Fallback when the engine runs outside the container: an app password (app_sudo=false).
FTL_PASSWORD = os.environ.get("FTL_PASSWORD") or os.environ.get("PIHOLE_PASSWORD") or ""
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://ollama:11434").rstrip("/")
DB_PATH = os.environ.get("DB_PATH", "/etc/kestrel/kestrel.db")
# Devices in this range are VPN (WireGuard) clients; everything else is the home network.
VPN_SUBNET = ipaddress.ip_network(os.environ.get("VPN_SUBNET", "10.8.0.0/24"))
API_HOST = os.environ.get("ENGINE_HOST", "0.0.0.0")
API_PORT = int(os.environ.get("ENGINE_PORT", "8090"))
# Same path as the reverse-proxy route, so the admin UI's pages work either way.
API_PREFIX = "/admin/api/kestrel"
# Extra admin-UI origins allowed to call the engine cross-port (the UI's own host is always allowed).
UI_ORIGINS = {o.strip().rstrip("/") for o in os.environ.get("KESTREL_UI_ORIGINS", "").split(",") if o.strip()}

# Prefix of the comment on every Pi-hole deny entry the engine adds. Kept as "kestrel"
# so entries made by the old add-on stay recognisable (undo, reconcile).
TAG = "kestrel"


def _list(name, default=""):
    return [x.strip().lower() for x in os.environ.get(name, default).split(",") if x.strip()]


DEFAULT_SETTINGS = {
    "mode": "review" if os.environ.get("DRY_RUN", "true").lower() in ("1", "true", "yes") else "auto",
    "model": os.environ.get("MODEL", "gemma4:12b"),
    # realtime: poll FTL every poll_seconds and classify in micro-batches.
    # eco: the old behaviour, one pass every interval_seconds.
    "cadence": os.environ.get("CADENCE", "realtime"),
    "poll_seconds": int(os.environ.get("POLL_SECONDS", "3")),
    "flush_size": int(os.environ.get("FLUSH_SIZE", "10")),
    "flush_seconds": int(os.environ.get("FLUSH_SECONDS", "3")),
    "interval_seconds": int(os.environ.get("INTERVAL_SECONDS", "600")),
    "min_confidence": float(os.environ.get("MIN_CONFIDENCE", "0.85")),
    "block_categories": _list("BLOCK_CATEGORIES", "ads,tracking,malicious"),
    "batch_size": int(os.environ.get("BATCH_SIZE", "25")),
    "max_domains_per_cycle": int(os.environ.get("MAX_DOMAINS_PER_CYCLE", "300")),
    "protected_extra": _list("PROTECTED_DOMAINS"),
    # Safety net (safety.py): trial period for automatic blocks and what counts as a retry storm.
    "probation_hours": int(os.environ.get("PROBATION_HOURS", "24")),
    "storm_lookups": int(os.environ.get("STORM_LOOKUPS", "20")),
    "storm_devices": int(os.environ.get("STORM_DEVICES", "2")),
    # Feedback (accuracy.py): show the model recent examples of your own decisions.
    "few_shot": os.environ.get("FEW_SHOT", "true").lower() in ("1", "true", "yes"),
    # Model pinning (models.py): the digest of `model` when it was chosen; a change is flagged.
    "model_digest": os.environ.get("MODEL_DIGEST", ""),
    # Block-list false positives (suggestions.py): how many blocked domains to check per hour; 0 = off.
    "list_checks_per_hour": int(os.environ.get("LIST_CHECKS_PER_HOUR", "60")),
    # Notifications (notify.py). Off until a URL is set; nothing leaves the network otherwise.
    "notify_kind": os.environ.get("NOTIFY_KIND", "ntfy"),          # ntfy | webhook
    "notify_url": os.environ.get("NOTIFY_URL", ""),
    "notify_events": _list("NOTIFY_EVENTS", "auto_blocked,pending,probation_reverted,list_false_positive"),
    "notify_pending_at": int(os.environ.get("NOTIFY_PENDING_AT", "10")),
}
