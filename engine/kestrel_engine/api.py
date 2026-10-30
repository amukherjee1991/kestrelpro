"""Engine HTTP API and the interim :8090 dashboard.

The dashboard and its own login stay only until P3, when the pages move into the web
fork and requests are authenticated with the admin UI's session instead.
"""
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from datetime import timedelta

import requests
from flask import Flask, abort, g, jsonify, redirect, request, send_from_directory, session

from . import classify, config, ftl as ftl_api, ingest, policy, store

STATIC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
OPEN_PATHS = {"/login", "/logout", "/healthz"}
login_lock = threading.Lock()  # failed logins wait their turn, so guessing is slow
STATUS_FILTERS = {
    "flagged": (store.BLOCKED, store.PENDING, store.USER_BLOCKED),
    "blocked": (store.BLOCKED, store.USER_BLOCKED),
    "pending": (store.PENDING,),
    "allowed": (store.ALLOWED, store.USER_ALLOWED),
}
HISTORY_FILTERS = {
    "blocks": (store.AUTO_BLOCKED, store.APPROVED, store.MANUAL_BLOCKED),
    "auto": (store.AUTO_BLOCKED,),
    "undone": (store.UNBLOCKED, store.REJECTED),
    "flagged": (store.FLAGGED,),
}


def secret_key():
    """Signing key for session cookies, kept next to the database so logins survive restarts."""
    path = os.path.join(os.path.dirname(config.DB_PATH) or ".", "session.key")
    try:
        with open(path) as f:
            return f.read().strip()
    except FileNotFoundError:
        key = secrets.token_hex(32)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key)
        return key


def create_app(ftl, worker):
    app = Flask(__name__, static_folder=None)
    app.config.update(SECRET_KEY=secret_key(), SESSION_COOKIE_NAME="kestrel_session",
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      PERMANENT_SESSION_LIFETIME=timedelta(days=30))
    password = config.DASHBOARD_PASSWORD
    # Changing the password signs everyone out: sessions carry a fingerprint of the password they used.
    password_tag = hashlib.sha256(app.config["SECRET_KEY"].encode() + password.encode()).hexdigest()[:16]

    def db():
        if "db" not in g:
            g.db = store.open_db()
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        if "db" in g:
            g.db.close()

    @app.before_request
    def require_login():
        if request.path in OPEN_PATHS or (password and session.get("auth") == password_tag):
            return None
        if request.path.startswith("/api/"):
            return jsonify({"error": "login required"}), 401
        return redirect("/login")

    @app.get("/healthz")
    def healthz():
        return jsonify({"ok": True})

    @app.get("/login")
    def login_page():
        if password and session.get("auth") == password_tag:
            return redirect("/")
        return send_from_directory(STATIC, "login.html")

    @app.post("/login")
    def login():
        if password and hmac.compare_digest(request.form.get("password", "").encode(), password.encode()):
            session.clear()
            session.permanent = request.form.get("remember") == "on"
            session["auth"] = password_tag
            return redirect("/")
        with login_lock:
            time.sleep(1)
        return redirect("/login?failed=1")

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect("/login?signed_out=1")

    @app.get("/")
    def index():
        return send_from_directory(STATIC, "index.html")

    @app.get("/api/status")
    def status():
        d = db()
        day_ago = time.time() - 86400
        counts = {r["status"]: r["n"] for r in d.execute("select status, count(*) n from verdicts group by status")}
        today = d.execute("select count(*) from verdicts where judged_at > ?", (day_ago,)).fetchone()[0]
        blocked_today = d.execute("select count(*) from verdicts where status in (?, ?) and updated_at > ?",
                                  (store.BLOCKED, store.USER_BLOCKED, day_ago)).fetchone()[0]
        auto_today = d.execute("select count(*) from events where action = ? and at > ?",
                               (store.AUTO_BLOCKED, day_ago)).fetchone()[0]
        settings = store.get_settings(d)
        model = {"reachable": False, "loaded": False, "on_gpu": None}
        try:
            ps = requests.get(f"{config.OLLAMA_URL}/api/ps", timeout=3).json().get("models", [])
            model["reachable"] = True
            m = next((m for m in ps if settings["model"] in (m["name"], m["model"])), None)
            if m:
                model["loaded"] = True
                model["on_gpu"] = m.get("size_vram", 0) >= 0.9 * m.get("size", 1)
        except requests.RequestException:
            pass
        return jsonify({
            "running": worker.running,
            "queued": worker.queue_length(),
            "last_started": float(store.get_state(d, "last_started", 0) or 0),
            "last_finished": float(store.get_state(d, "last_finished", 0) or 0),
            "last_error": store.get_state(d, "last_error", ""),
            "warnings": json.loads(store.get_state(d, "warnings", "[]")),
            "reviewed_total": sum(counts.values()),
            "reviewed_today": today,
            "blocked_total": counts.get(store.BLOCKED, 0) + counts.get(store.USER_BLOCKED, 0),
            "blocked_today": blocked_today,
            "auto_blocked_today": auto_today,
            "pending": counts.get(store.PENDING, 0),
            "model": model,
            "prompt_version": classify.PROMPT_VERSION,
            "settings": settings,
        })

    @app.get("/api/charts")
    def charts():
        d = db()
        hours = {}
        try:
            for slot in ftl.history():
                h = int(slot["timestamp"] // 3600 * 3600)
                agg = hours.setdefault(h, {"t": h, "allowed": 0, "blocked": 0})
                agg["blocked"] += slot["blocked"]
                agg["allowed"] += slot["total"] - slot["blocked"]
            s = ftl.summary()
            network = {"queries": s["queries"]["total"], "blocked": s["queries"]["blocked"],
                       "percent_blocked": s["queries"]["percent_blocked"], "devices": s["clients"]["active"],
                       "blocklist_size": s["gravity"]["domains_being_blocked"]}
        except (requests.RequestException, ftl_api.NoCredentials):
            network = None
        flagged = STATUS_FILTERS["flagged"]
        categories = {r["category"]: r["n"] for r in d.execute(
            "select category, count(*) n from verdicts where status in (?, ?, ?) group by category", flagged)}
        reviewed = {r["category"]: r["n"] for r in d.execute("select category, count(*) n from verdicts group by category")}
        return jsonify({
            "traffic": [hours[h] for h in sorted(hours)][-24:],
            "network": network,
            "flagged_by_category": categories,
            "reviewed_by_category": reviewed,
        })

    @app.get("/api/decisions")
    def decisions():
        statuses = STATUS_FILTERS.get(request.args.get("status", "flagged"))
        q = request.args.get("q", "").strip().lower()
        limit = min(int(request.args.get("limit", 200)), 1000)
        sql, args = "select * from verdicts where 1=1", []
        if statuses:
            sql += f" and status in ({','.join('?' * len(statuses))})"
            args += statuses
        if q:
            sql += " and (domain like ? or reason like ?)"
            args += [f"%{q}%", f"%{q}%"]
        sql += " order by updated_at desc limit ?"
        rows = db().execute(sql, args + [limit]).fetchall()
        return jsonify([{**dict(r), "clients": json.loads(r["clients"] or "[]")} for r in rows])

    @app.get("/api/history")
    def history():
        """Every block/unblock event, newest first. Filters: what, network (home|vpn), days, q."""
        actions = HISTORY_FILTERS.get(request.args.get("what", "blocks"))
        network = request.args.get("network")
        days = float(request.args.get("days", 0) or 0)
        q = request.args.get("q", "").strip().lower()
        sql = ("select e.*, v.status current_status from events e left join verdicts v on v.domain = e.domain "
               "where 1=1")
        args = []
        if days:
            sql += " and e.at > ?"
            args.append(time.time() - days * 86400)
        if q:
            sql += " and (e.domain like ? or e.reason like ?)"
            args += [f"%{q}%", f"%{q}%"]
        sql += " order by e.at desc limit 2000"
        in_scope = []  # every event in the chosen period / devices; the summary counts all of these
        for r in db().execute(sql, args):
            clients = json.loads(r["clients"] or "[]")
            if network in ("home", "vpn") and not any(c.get("network") == network for c in clients):
                continue
            in_scope.append({**dict(r), "clients": clients})
        summary = {"auto_blocked": sum(e["action"] == store.AUTO_BLOCKED for e in in_scope),
                   "blocked": sum(e["action"] in HISTORY_FILTERS["blocks"] for e in in_scope),
                   "undone": sum(e["action"] in HISTORY_FILTERS["undone"] for e in in_scope)}
        shown = [e for e in in_scope if not actions or e["action"] in actions]
        return jsonify({"events": shown[:500], "summary": summary})

    @app.post("/api/decisions/<path:domain>")
    def decide(domain):
        action = (request.get_json(silent=True) or {}).get("action")
        status, event = {"block": (store.USER_BLOCKED, store.MANUAL_BLOCKED),
                         "approve": (store.BLOCKED, store.APPROVED),
                         "unblock": (store.USER_ALLOWED, store.UNBLOCKED),
                         "reject": (store.USER_ALLOWED, store.REJECTED)}.get(action, (None, None))
        domain = domain.strip().lower().rstrip(".")
        if not status or "." not in domain or " " in domain:
            abort(400)
        policy.set_status(ftl, db(), domain, status, event)
        return jsonify({"ok": True, "status": status})

    @app.post("/api/pending/approve-all")
    def approve_all():
        rows = db().execute("select domain from verdicts where status = ?", (store.PENDING,)).fetchall()
        for r in rows:
            policy.set_status(ftl, db(), r["domain"], store.BLOCKED, store.APPROVED)
        return jsonify({"ok": True, "approved": len(rows)})

    @app.route("/api/settings", methods=["GET", "POST"])
    def settings():
        if request.method == "GET":
            return jsonify({**store.get_settings(db()), "protected_builtin": sorted(policy.PROTECTED_BUILTIN)})
        body = request.get_json(force=True)
        changes = {}
        if body.get("mode") in ("auto", "review"):
            changes["mode"] = body["mode"]
        if body.get("cadence") in ("realtime", "eco"):
            changes["cadence"] = body["cadence"]
        if "min_confidence" in body:
            changes["min_confidence"] = min(max(float(body["min_confidence"]), 0.5), 1.0)
        if "interval_seconds" in body:
            changes["interval_seconds"] = min(max(int(body["interval_seconds"]), 60), 86400)
        if "block_categories" in body:
            changes["block_categories"] = [c for c in body["block_categories"] if c in classify.CATEGORIES]
        if "protected_extra" in body:
            changes["protected_extra"] = sorted({d.strip().lower() for d in body["protected_extra"] if "." in d.strip()})
        if body.get("model"):
            changes["model"] = str(body["model"]).strip()
        saved = store.save_settings(db(), changes)
        worker.wake()
        return jsonify(saved)

    @app.post("/api/run")
    def run_now():
        worker.wake()
        return jsonify({"ok": True})

    return app


def serve():
    from waitress import serve as waitress_serve

    ftl = ftl_api.FTL()
    worker = ingest.Ingest(ftl)
    threading.Thread(target=worker.loop, daemon=True, name="ingest").start()
    waitress_serve(create_app(ftl, worker), host=config.API_HOST, port=config.API_PORT, threads=4)
