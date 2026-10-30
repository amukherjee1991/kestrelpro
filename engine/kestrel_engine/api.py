"""Engine HTTP API, used by the KestrelPro pages in the admin UI.

There is no separate login: requests are authenticated with the admin UI's session
(see auth.py). Routes live under config.API_PREFIX so the same URLs work through a
reverse proxy on the admin UI's origin or directly on the engine's port.
"""
import json
import threading
import time

import requests
from flask import Blueprint, Flask, abort, g, jsonify, request

from . import accuracy, auth, classify, config, ftl as ftl_api, ingest, models, policies, policy, safety, store

OPEN_PATHS = {"/healthz"}
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
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def create_app(ftl, worker, jobs=None):
    app = Flask(__name__, static_folder=None)
    jobs = jobs or models.Jobs()
    directory = policies.Directory(ftl)
    api = Blueprint("api", __name__, url_prefix=config.API_PREFIX)
    sessions = auth.SessionCheck()

    def db():
        if "db" not in g:
            g.db = store.open_db()
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        if "db" in g:
            g.db.close()

    @app.after_request
    def cors(resp):
        origin = request.headers.get("Origin")
        if auth.origin_allowed(origin, request.host):
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Credentials"] = "true"
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-CSRF-TOKEN"
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE"
            resp.headers["Access-Control-Max-Age"] = "600"
        resp.headers["Vary"] = "Origin"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @api.before_request
    def require_session():
        if request.method == "OPTIONS":  # CORS preflight; the real request is checked
            return app.make_default_options_response()
        if request.path[len(config.API_PREFIX):] in OPEN_PATHS:
            return None
        csrf = sessions.csrf_for(request.cookies.get("sid"))
        if csrf is None:
            return jsonify({"error": "unauthorized", "message": "Sign in to the admin UI first."}), 401
        if request.method in WRITE_METHODS and request.headers.get("X-CSRF-TOKEN") != csrf:
            return jsonify({"error": "forbidden", "message": "Missing or wrong CSRF token."}), 403
        return None

    @app.get("/")
    def root():
        return "KestrelPro engine. Open the admin UI and choose KestrelPro in the menu.\n", 200, {
            "Content-Type": "text/plain; charset=utf-8"}

    @api.get("/healthz")
    def healthz():
        return jsonify({"ok": True, "engine": "kestrelpro", "prompt_version": classify.PROMPT_VERSION})

    @api.get("/status")
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
            "warnings": json.loads(store.get_state(d, "warnings", "[]")) + [w for w in [models.pin_warning(settings)] if w],
            "reviewed_total": sum(counts.values()),
            "reviewed_today": today,
            "blocked_total": counts.get(store.BLOCKED, 0) + counts.get(store.USER_BLOCKED, 0),
            "blocked_today": blocked_today,
            "auto_blocked_today": auto_today,
            "pending": counts.get(store.PENDING, 0),
            "model": model,
            "prompt_version": classify.PROMPT_VERSION,
            "safety": safety.summary(d),
            "settings": settings,
        })

    @api.get("/charts")
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

    @api.get("/decisions")
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
        out = []
        for r in rows:
            row = {**dict(r), "clients": json.loads(r["clients"] or "[]")}
            # Automatic blocks under a group policy apply to those groups only: name them.
            groups = json.loads(r["block_groups"]) if r["block_groups"] else None
            if groups:
                directory.refresh()
                row["block_group_names"] = [directory.groups.get(g, {}).get("name", f"Group {g}") for g in groups]
            row["block_groups"] = groups
            out.append(row)
        return jsonify(out)

    @api.get("/history")
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

    @api.post("/decisions/<path:domain>")
    def decide(domain):
        action = (request.get_json(silent=True) or {}).get("action")
        status, event = {"block": (store.USER_BLOCKED, store.MANUAL_BLOCKED),
                         "approve": (store.BLOCKED, store.APPROVED),
                         "unblock": (store.USER_ALLOWED, store.UNBLOCKED),
                         "reject": (store.USER_ALLOWED, store.REJECTED)}.get(action, (None, None))
        domain = domain.strip().lower().rstrip(".")
        if not status or "." not in domain or " " in domain:
            abort(400)
        reverted = policy.set_status(ftl, db(), domain, status, event)
        return jsonify({"ok": True, "status": status, "reverted": reverted})

    @api.post("/pending/approve-all")
    def approve_all():
        rows = db().execute("select domain from verdicts where status = ?", (store.PENDING,)).fetchall()
        for r in rows:
            policy.set_status(ftl, db(), r["domain"], store.BLOCKED, store.APPROVED)
        return jsonify({"ok": True, "approved": len(rows)})

    @api.route("/settings", methods=["GET", "POST"])
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
        if "probation_hours" in body:
            changes["probation_hours"] = min(max(int(body["probation_hours"]), 0), 24 * 14)
        if "storm_lookups" in body:
            changes["storm_lookups"] = min(max(int(body["storm_lookups"]), 3), 10000)
        if "storm_devices" in body:
            changes["storm_devices"] = min(max(int(body["storm_devices"]), 1), 100)
        if "few_shot" in body:
            changes["few_shot"] = bool(body["few_shot"])
        saved = store.save_settings(db(), changes)
        worker.wake()
        return jsonify(saved)

    @api.post("/pause")
    def pause():
        n = safety.pause(ftl, db())
        return jsonify({"ok": True, "paused": True, "entries": n})

    @api.post("/resume")
    def resume():
        n = safety.resume(ftl, db())
        return jsonify({"ok": True, "paused": False, "entries": n})

    @api.get("/devices")
    def devices():
        return jsonify(safety.devices(ftl))

    @api.get("/broke")
    def broke():
        """KestrelPro blocks one device ran into recently: ?client=<ip>&minutes=30"""
        client = request.args.get("client", "").strip()
        try:
            minutes = min(max(int(request.args.get("minutes", 30)), 1), 24 * 60)
        except ValueError:
            abort(400)
        if not client or len(client) > 64 or any(c in client for c in " /?&#"):
            abort(400)
        return jsonify(safety.broke(ftl, db(), client, minutes))

    @api.post("/explain")
    def explain():
        """Verdicts for the domains on a query-log page. POST {"domains": [...]}"""
        domains = (request.get_json(silent=True) or {}).get("domains") or []
        if not isinstance(domains, list):
            abort(400)
        return jsonify(safety.explain(db(), [d for d in domains if isinstance(d, str)]))

    # ---- per-device policies (policies.py) ----------------------------------------------
    @api.get("/policies")
    def get_policies():
        return jsonify({"groups": policies.summary(db(), directory, store.get_settings(db())),
                        "modes": policies.MODES})

    @api.post("/policies/<int:group_id>")
    def set_policy(group_id):
        body = request.get_json(silent=True) or {}
        conf = body.get("min_confidence")
        cats = body.get("block_categories")
        try:
            if conf is not None:
                conf = min(max(float(conf), 0.5), 1.0)
            if cats is not None:
                cats = [c for c in cats if c in classify.CATEGORIES]
            policies.save(db(), group_id, body.get("mode", "inherit"), conf, cats)
        except (ValueError, TypeError) as e:
            return jsonify({"error": "bad_request", "message": str(e)}), 400
        return jsonify({"ok": True})

    # ---- models (models.py) -----------------------------------------------------------
    def _model_error(e):
        if isinstance(e, ValueError):
            return jsonify({"error": "bad_request", "message": str(e)}), 400
        return jsonify({"error": "model_server", "message": f"The model server didn't answer: {e}"}), 502

    @api.get("/models")
    def list_models():
        settings = store.get_settings(db())
        try:
            installed = models.installed(settings)
        except requests.RequestException as e:
            return _model_error(e)
        return jsonify({"installed": installed, "in_use": settings["model"], "pinned": settings["model_digest"],
                        "pin_warning": models.pin_warning(settings), "jobs": jobs.snapshot(),
                        "benchmarks": models.benchmarks(db())})

    @api.post("/models/pull")
    def pull_model():
        try:
            jobs.pull(str((request.get_json(silent=True) or {}).get("name", "")))
        except ValueError as e:
            return _model_error(e)
        return jsonify({"ok": True})

    @api.post("/models/use")
    def use_model():
        try:
            saved = models.use(db(), str((request.get_json(silent=True) or {}).get("name", "")))
        except (ValueError, requests.RequestException) as e:
            return _model_error(e)
        worker.wake()
        return jsonify(saved)

    @api.post("/models/delete")
    def delete_model():
        try:
            models.delete(store.get_settings(db()), str((request.get_json(silent=True) or {}).get("name", "")))
        except (ValueError, requests.RequestException) as e:
            return _model_error(e)
        return jsonify({"ok": True})

    @api.post("/models/benchmark")
    def benchmark_model():
        try:
            jobs.start_benchmark(str((request.get_json(silent=True) or {}).get("name", "")))
        except ValueError as e:
            return _model_error(e)
        return jsonify({"ok": True})

    @api.get("/models/jobs")
    def model_jobs():
        return jsonify(jobs.snapshot())

    # ---- accuracy (accuracy.py) -------------------------------------------------------
    @api.get("/accuracy")
    def get_accuracy():
        return jsonify(accuracy.report(db(), store.get_settings(db())))

    @api.post("/run")
    def run_now():
        worker.wake()
        return jsonify({"ok": True})

    app.register_blueprint(api)
    return app


def serve():
    from waitress import serve as waitress_serve

    ftl = ftl_api.FTL()
    worker = ingest.Ingest(ftl)
    threading.Thread(target=worker.loop, daemon=True, name="ingest").start()
    waitress_serve(create_app(ftl, worker), host=config.API_HOST, port=config.API_PORT, threads=4)
