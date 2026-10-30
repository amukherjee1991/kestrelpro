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
# P2 keeps the old :8090 dashboard and its login; P3 replaces it with the web fork's pages.
DASHBOARD_PASSWORD = (os.environ.get("DASHBOARD_PASSWORD") or FTL_PASSWORD
                      or os.environ.get("FTLCONF_webserver_api_password", ""))

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
}
