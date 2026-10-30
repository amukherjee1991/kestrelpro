"""Model management through Ollama's API: list, pull, delete, choose and pin, benchmark.

Pinning: choosing a model records its digest. If `ollama pull` later replaces it with a
different build under the same name, the status shows a warning until you re-pin it, so the
model's behaviour can't change silently.

Benchmark: runs a model over your labelled decisions (accuracy.py) without the few-shot
examples (they come from the same decisions) and grades it with the current settings. It
runs in the background, one job at a time; the model has to be pulled first.
"""
import json
import logging
import threading
import time

import requests

from . import accuracy, classify, config, store

log = logging.getLogger("kestrel.models")

BENCHMARK_MAX = 80
BENCHMARK_BATCH = 20


def _ollama(method, path, **kw):
    r = requests.request(method, f"{config.OLLAMA_URL}{path}", timeout=kw.pop("timeout", 10), **kw)
    r.raise_for_status()
    return r.json() if r.content else {}


def installed(settings):
    """Installed models with size, digest, whether loaded and where (GPU/CPU)."""
    tags = _ollama("GET", "/api/tags").get("models", [])
    loaded = {m["name"]: m for m in _ollama("GET", "/api/ps").get("models", [])}
    out = []
    for m in sorted(tags, key=lambda m: m["name"]):
        ps = loaded.get(m["name"])
        details = m.get("details") or {}
        out.append({
            "name": m["name"], "size": m.get("size"), "digest": m.get("digest"),
            "modified_at": m.get("modified_at"), "parameter_size": details.get("parameter_size"),
            "quantization": details.get("quantization_level"), "family": details.get("family"),
            "loaded": ps is not None,
            "on_gpu": (ps.get("size_vram", 0) >= 0.9 * ps.get("size", 1)) if ps else None,
            "vram": ps.get("size_vram") if ps else None,
            "in_use": m["name"] == settings["model"] or m["name"] == f"{settings['model']}:latest",
        })
    return out


def pin_warning(settings):
    """A message if the model in use is no longer the build that was pinned."""
    pinned = settings.get("model_digest")
    if not pinned:
        return None
    now = classify.model_digest(settings["model"])
    if now and now != pinned:
        return (f"The model {settings['model']} changed since it was chosen (a newer build was pulled). "
                "Its verdicts may differ. Re-pin it on the Models page to accept the new build.")
    return None


def use(db, name):
    """Switch to an installed model and pin its current digest."""
    tags = {m["name"]: m for m in _ollama("GET", "/api/tags").get("models", [])}
    m = tags.get(name) or tags.get(f"{name}:latest")
    if not m:
        raise ValueError(f"{name} isn't installed; pull it first")
    return store.save_settings(db, {"model": m["name"], "model_digest": m.get("digest", "")})


def delete(settings, name):
    if name in (settings["model"], f"{settings['model']}:latest"):
        raise ValueError("That model is in use; choose another one first")
    # Ollama renamed the field from "name" to "model"; send both.
    r = requests.delete(f"{config.OLLAMA_URL}/api/delete", json={"model": name, "name": name}, timeout=30)
    r.raise_for_status()


class Jobs:
    """Background pulls and benchmarks. State lives in memory; benchmark results in the DB."""

    def __init__(self, db_path=None):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.pulls = {}       # name -> {"status", "completed", "total", "error", "done", "started"}
        self.benchmark = None  # {"model", "done", "progress", "total", "error", "result"}

    def snapshot(self):
        with self.lock:
            return {"pulls": json.loads(json.dumps(self.pulls)), "benchmark": dict(self.benchmark or {}) or None}

    # ---- pull ---------------------------------------------------------------------------
    def pull(self, name):
        name = name.strip()
        if not name or len(name) > 200 or any(c.isspace() for c in name):
            raise ValueError("Enter a model name like gemma4:12b")
        with self.lock:
            job = self.pulls.get(name)
            if job and not job["done"]:
                return
            self.pulls[name] = {"status": "starting", "completed": 0, "total": 0, "error": None,
                                "done": False, "started": time.time()}
        threading.Thread(target=self._pull, args=(name,), daemon=True, name=f"pull-{name}").start()

    def _pull(self, name):
        try:
            with requests.post(f"{config.OLLAMA_URL}/api/pull", json={"model": name, "name": name, "stream": True},
                               stream=True, timeout=(10, 600)) as r:
                r.raise_for_status()
                for line in r.iter_lines():
                    if not line:
                        continue
                    msg = json.loads(line)
                    with self.lock:
                        job = self.pulls[name]
                        if msg.get("error"):
                            job["error"] = msg["error"]
                        job["status"] = msg.get("status", job["status"])
                        if msg.get("total"):
                            job["total"], job["completed"] = msg["total"], msg.get("completed", 0)
        except (requests.RequestException, ValueError) as e:
            with self.lock:
                self.pulls[name]["error"] = str(e)
        with self.lock:
            self.pulls[name]["done"] = True
            log.info("pull %s finished: %s", name, self.pulls[name]["error"] or self.pulls[name]["status"])

    # ---- benchmark ----------------------------------------------------------------------
    def start_benchmark(self, name):
        db = store.open_db(self.db_path)
        rows = accuracy.labelled(db, limit=BENCHMARK_MAX)
        if len(rows) < accuracy.MIN_EXAMPLES:
            raise ValueError(f"Make at least {accuracy.MIN_EXAMPLES} Block / Don't block decisions first; "
                             "the benchmark grades a model against them")
        with self.lock:
            if self.benchmark and not self.benchmark["done"]:
                raise ValueError(f"A benchmark of {self.benchmark['model']} is still running")
            self.benchmark = {"model": name, "done": False, "progress": 0, "total": len(rows),
                              "error": None, "result": None, "started": time.time()}
        threading.Thread(target=self._benchmark, args=(name, rows), daemon=True, name="benchmark").start()

    def _benchmark(self, name, rows):
        db = store.open_db(self.db_path)
        settings = store.get_settings(db)
        started = time.time()
        judged = []
        error = None
        try:
            for i in range(0, len(rows), BENCHMARK_BATCH):
                chunk = rows[i:i + BENCHMARK_BATCH]
                verdicts = classify.classify([(r["domain"], 1, 1) for r in chunk], name)
                for r in chunk:
                    v = verdicts.get(r["domain"])
                    if v:
                        judged.append({**r, "category": v["category"], "confidence": v["confidence"]})
                with self.lock:
                    self.benchmark["progress"] = min(i + BENCHMARK_BATCH, len(rows))
        except requests.RequestException as e:
            error = f"The model didn't answer: {e}"
        seconds = time.time() - started
        g = accuracy.grade(judged, settings)
        digest = classify.model_digest(name)
        # Store the result and mark the job done together, so the page never sees one without the other.
        with self.lock:
            db.execute("insert into benchmarks (model, digest, started_at, finished_at, labelled, agree, "
                       "flagged_right, flagged_wrong, missed, seconds, error) values (?,?,?,?,?,?,?,?,?,?,?)",
                       (name, digest, started, time.time(), g["labelled"], g["agree"], g["flagged_right"],
                        g["flagged_wrong"], g["missed"], seconds, error))
            db.commit()
            self.benchmark.update({"done": True, "error": error, "result": {**g, "seconds": seconds}})
        log.info("benchmark %s: %s/%s agree in %.0f s", name, g["agree"], g["labelled"], seconds)


def benchmarks(db, limit=20):
    return [dict(r) for r in db.execute("select * from benchmarks order by finished_at desc limit ?", (limit,))]
