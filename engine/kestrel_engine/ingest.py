"""Near-real-time review: follow FTL's query log by ID, queue new domains, classify in micro-batches.

Replaces the old 10-minute `from/until` poll, which asked for 100,000 rows while FTL returns
at most 10,000, so busy windows were silently cut short and then skipped for good.
"""
import json
import logging
import threading
import time

import requests

from . import accuracy, classify, config, evidence, ftl as ftl_api, notify, policies, policy, safety, store, suggestions

log = logging.getLogger("kestrel.ingest")

PAGE = 1000
# After a long outage, stop reading further back than this in one poll.
MAX_ROWS_PER_POLL = 100_000
# Queued domains beyond this are dropped, least-seen first; they come back on their next lookup.
MAX_QUEUE = 2000
PREFLIGHT_EVERY = 600


class Ingest:
    def __init__(self, ftl, db_path=None):
        self.ftl, self.db_path = ftl, db_path
        self.queue = {}        # domain -> {"lookups", "devices": {ip: {...}}, "first_seen"}
        self.inflight = set()  # domains being classified right now
        self.lock = threading.Lock()
        self.event = threading.Event()
        self.running = False   # true while the model is working
        self._allow = (0.0, set())
        self.storms = safety.StormWatch()
        self.directory = policies.Directory(ftl)
        self.list_checks = suggestions.ListChecks(ftl)
        self._preflight_at = 0.0

    def wake(self):
        self.event.set()

    def queue_length(self):
        with self.lock:
            return len(self.queue)

    # ---- reading ----------------------------------------------------------------

    def poll(self, db):
        """Queue every allowed query newer than the stored high-water mark. Returns rows read."""
        # -1 = nothing seen yet. FTL numbers the first query of a fresh database 0, so 0 is a real ID.
        hw = int(store.get_state(db, "ingest_hw", -1))
        # First run: look back an hour, as the old add-on did.
        since = time.time() - 3600 if hw < 0 else None
        page = self.ftl.queries(start=0, length=PAGE, since=since)
        rows = page.get("queries") or []
        if not rows:
            return 0
        top = max(q["id"] for q in rows)
        if top < hw:
            # IDs went backwards: FTL's query database was reset or replaced.
            log.warning("query IDs restarted (%d < %d); resetting the high-water mark", top, hw)
            hw = -1
        # Page beneath a fixed cursor so queries arriving meanwhile don't shift the offsets;
        # they are picked up by the next poll.
        fresh = [q for q in rows if q["id"] > hw]
        start = len(rows)
        while len(fresh) == start and len(rows) == PAGE:
            if len(fresh) >= MAX_ROWS_PER_POLL:
                log.warning("over %d new queries since the last poll; older ones skipped", MAX_ROWS_PER_POLL)
                break
            rows = self.ftl.queries(start=start, length=PAGE, cursor=top, since=since).get("queries") or []
            fresh += [q for q in rows if q["id"] > hw]
            start += len(rows)
        self._enqueue(db, fresh)
        self.storms.feed(self.ftl, db, fresh, store.get_settings(db))
        store.set_state(db, "ingest_hw", top)
        return len(fresh)

    def _allowlist(self):
        at, domains = self._allow
        if time.time() - at > 60:
            domains = {e["domain"] for e in self.ftl.list_domains("allow")}
            self._allow = (time.time(), domains)
        return domains

    def _enqueue(self, db, queries):
        s = store.get_settings(db)
        seen = {}
        blocked = evidence.blocked_times(queries)
        self.list_checks.collect(queries)
        for q in queries:
            if q.get("status") not in ftl_api.ALLOWED_STATUSES or not q.get("domain"):
                continue
            d = q["domain"].lower().rstrip(".")
            item = seen.setdefault(d, {"lookups": 0, "devices": {}, "near_blocked": 0})
            item["lookups"] += 1
            ip = (q.get("client") or {}).get("ip") or "?"
            t = q.get("time") or 0
            dev = item["devices"].setdefault(ip, {
                "ip": ip, "name": q["client"].get("name"), "network": policy.network_of(ip), "lookups": 0,
                "times": []})
            dev["lookups"] += 1
            if len(dev["times"]) < evidence.MAX_TIMES:
                dev["times"].append(t)
            if evidence.near_blocked(blocked, ip, t):
                item["near_blocked"] += 1
        if not seen:
            return
        allow = self._allowlist()
        candidates = [d for d in seen if d not in allow and not policy.skip_domain(d, s["protected_extra"])]
        done = store.decided(db, candidates)
        now = time.time()
        with self.lock:
            for d in candidates:
                if d in done or d in self.inflight:
                    continue
                q = self.queue.setdefault(d, {"lookups": 0, "devices": {}, "near_blocked": 0, "first_seen": now})
                _merge(q, seen[d])
            if len(self.queue) > MAX_QUEUE:
                for d in sorted(self.queue, key=lambda d: _priority(self.queue[d]))[:len(self.queue) - MAX_QUEUE]:
                    del self.queue[d]

    # ---- judging ----------------------------------------------------------------

    def flush(self, db, force=False):
        """Classify one batch if it's due (or `force`). Returns the number of domains sent."""
        s = store.get_settings(db)
        with self.lock:
            if not self.queue:
                return 0
            oldest = min(q["first_seen"] for q in self.queue.values())
            if not force and len(self.queue) < s["flush_size"] and time.time() - oldest < s["flush_seconds"]:
                return 0
            picked = sorted(self.queue, key=lambda d: _priority(self.queue[d]), reverse=True)[:s["batch_size"]]
            items = {d: self.queue.pop(d) for d in picked}
            self.inflight |= set(items)
        self.running = True
        try:
            now = time.time()
            for d, it in items.items():
                evidence.add_history(self.ftl, d, it, now)
            notes = {d: evidence.summarise(it) for d, it in items.items()}
            batch = [(d, it["lookups"], len(it["devices"]), notes[d][1]) for d, it in items.items()]
            examples = accuracy.examples(db) if s["few_shot"] else None
            verdicts = classify.classify(batch, s["model"], examples=examples)
        except requests.RequestException:
            with self.lock:  # try these again once the model is back
                for d, it in items.items():
                    _merge(self.queue.setdefault(d, {"lookups": 0, "devices": {}, "near_blocked": 0,
                                                     "first_seen": it["first_seen"]}), it)
            raise
        finally:
            self.running = False
            with self.lock:
                self.inflight -= set(items)
        self._record(db, s, items, verdicts, classify.prompt_version(examples), {d: n[0] for d, n in notes.items()})
        return len(items)

    def _record(self, db, s, items, verdicts, prompt_version=classify.PROMPT_VERSION, notes=None):
        now = time.time()
        digest = classify.model_digest(s["model"])
        # Paused: nothing new is blocked, even in Automatic mode; suggestions wait for approval.
        paused = safety.is_paused(db)
        group_policies = policies.load(db)
        flagged = 0
        for d, it in items.items():
            v = verdicts.get(d)
            if not v:
                continue  # the model skipped it; it is queued again on its next lookup
            # Every group of every device that looked it up gets its own policy's say.
            groups = set()
            for dev in it["devices"].values():
                groups |= self.directory.groups_for(dev["ip"], dev.get("name"))
            auto_groups, review_groups = policies.decide(v, s, group_policies, groups or {policies.DEFAULT_GROUP},
                                                         paused)
            flag = bool(auto_groups or review_groups)
            status, probation, block_groups = store.ALLOWED, None, None
            if auto_groups:
                self.ftl.deny(d, policy.comment_for(v), groups=auto_groups)
                status, probation = store.BLOCKED, safety.probation_until(s, now)
                block_groups = json.dumps(auto_groups)
            elif review_groups:
                status = store.PENDING
            clients = json.dumps(sorted(({k: v for k, v in dev.items() if k != "times"}
                                         for dev in it["devices"].values() if not dev.get("history_only")),
                                        key=lambda x: -x["lookups"]))
            ev = json.dumps((notes or {}).get(d) or {})
            db.execute("insert or replace into verdicts (domain, category, confidence, reason, status, queries, "
                       "devices, judged_at, updated_at, clients, expires_at, model, model_digest, prompt_version, "
                       "probation_until, block_groups, evidence) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (d, v["category"], v["confidence"], v["reason"], status, it["lookups"], len(it["devices"]),
                        now, now, clients, None if flag else policy.expires_at(v, now),
                        s["model"], digest, prompt_version, probation, block_groups, ev))
            if flag:
                flagged += 1
                log.info("%s %s (%s %.2f): %s", status.upper(), d, v["category"], v["confidence"], v["reason"])
            if status == store.BLOCKED:
                notify.add(db, "auto_blocked", f"{d}: {v['category']}, {round(v['confidence'] * 100)}% sure. {v['reason']}")
                store.log_event(db, d, store.AUTO_BLOCKED if status == store.BLOCKED else store.FLAGGED,
                                v["category"], v["confidence"], v["reason"], clients)
        db.commit()
        log.info("reviewed %d domain(s), %d flagged, %d queued", len(items), flagged, self.queue_length())

    # ---- upkeep -----------------------------------------------------------------

    def reconcile(self, db):
        """Blocks removed directly in the admin UI count as the user unblocking them."""
        denied = {e["domain"] for e in self.ftl.list_domains("deny/exact")}
        gone = [r["domain"] for r in db.execute("select domain from verdicts where status in (?, ?)",
                                                 (store.BLOCKED, store.USER_BLOCKED)) if r["domain"] not in denied]
        for d in gone:
            db.execute("update verdicts set status = ?, updated_at = ?, expires_at = null where domain = ?",
                       (store.USER_ALLOWED, time.time(), d))
            store.log_event(db, d, store.UNBLOCKED, reason="removed from the deny list outside KestrelPro")
        db.commit()
        if gone:
            log.info("reconciled %d block(s) removed outside KestrelPro", len(gone))

    def preflight(self, db):
        if time.time() - self._preflight_at > PREFLIGHT_EVERY:
            store.set_state(db, "warnings", json.dumps(self.ftl.preflight()))
            self._preflight_at = time.time()

    def run_once(self, db):
        """Read everything new and judge all of it now (CLI `once`)."""
        self.poll(db)
        budget = store.get_settings(db)["max_domains_per_cycle"]
        done = 0
        while done < budget:
            n = self.flush(db, force=True)
            if not n:
                break
            done += n
        return done

    def loop(self):
        db = store.open_db(self.db_path)
        failures, forced, reconciled = 0, True, False
        while True:
            s = store.get_settings(db)
            eco = s["cadence"] == "eco"
            try:
                if not reconciled:
                    self.reconcile(db)
                    reconciled = True
                self.preflight(db)
                store.set_state(db, "last_started", time.time())
                if eco or forced:
                    self.run_once(db)
                else:
                    self.poll(db)
                    self.flush(db)
                # Second looks at block-list decisions only when the model has nothing else to do.
                if not self.queue_length():
                    self.list_checks.run(db, s)
                notify.check_pending(db)
                notify.flush(db)
                store.set_state(db, "last_finished", time.time())
                store.set_state(db, "last_error", "")
                failures = 0
            except ftl_api.NoCredentials as e:
                failures += 1
                store.set_state(db, "last_error", str(e))
            except requests.HTTPError as e:
                failures += 1
                log.error("request failed: %s", e)
                wrong_password = e.response is not None and e.response.status_code == 401
                store.set_state(db, "last_error", "The DNS server rejected the engine's password."
                                if wrong_password else f"A request failed: {e}")
            except requests.RequestException as e:
                failures += 1
                log.error("unreachable: %s", e)
                url = getattr(e.request, "url", "") or ""
                where = "the model" if url.startswith(config.OLLAMA_URL) else "the DNS server"
                store.set_state(db, "last_error", f"Couldn't reach {where}. It may be restarting; "
                                "KestrelPro will retry shortly.")
            except Exception as e:  # keep the loop alive whatever happens
                failures += 1
                log.exception("cycle failed")
                store.set_state(db, "last_error", str(e))
            # After a failure, retry quickly (30 s, 1 min, 2 min, ...) instead of waiting a full interval.
            interval = s["interval_seconds"] if eco else s["poll_seconds"]
            wait = max(interval, min(s["interval_seconds"], 30 * 2 ** (failures - 1))) if failures else interval
            forced = self.event.wait(wait)
            self.event.clear()


def _priority(item):
    # Domains seen from more devices, then more lookups, go first.
    return (len(item["devices"]), item["lookups"])


def _merge(into, item):
    into["lookups"] += item["lookups"]
    into["near_blocked"] = into.get("near_blocked", 0) + item.get("near_blocked", 0)
    for ip, dev in item["devices"].items():
        mine = into["devices"].setdefault(ip, {**dev, "lookups": 0, "times": []})
        mine["lookups"] += dev["lookups"]
        room = evidence.MAX_TIMES - len(mine.setdefault("times", []))
        if room > 0:
            mine["times"].extend(dev.get("times", [])[:room])
