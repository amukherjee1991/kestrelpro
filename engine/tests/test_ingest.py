import os
import tempfile
import time
import unittest
from unittest import mock

import requests

from kestrel_engine import ingest, store


class FakeFTL:
    """Mimics FTL v6.8 /api/queries: newest first by id, `cursor` means id <= cursor, `start` is an offset."""

    def __init__(self):
        self.rows, self.allowed = [], set()
        self.denied = {}  # domain -> {"comment", "enabled", "groups"}
        self.groups = [{"id": 0, "name": "Default", "enabled": True}]
        self.clients = []  # [{"client": "192.168.1.20", "groups": [0, 1]}]
        self.calls = 0

    def add(self, domain, ip="192.168.1.5", status="FORWARDED", ts=None):
        t = ts or time.time()
        self.rows.append({"id": len(self.rows) + 1, "domain": domain, "status": status,
                          "timestamp": t, "time": t, "client": {"ip": ip, "name": None}})

    def queries(self, start=0, length=1000, cursor=None, since=None, client_ip=None):
        self.calls += 1
        rows = sorted(self.rows, key=lambda q: -q["id"])
        if client_ip:
            rows = [q for q in rows if q["client"]["ip"] == client_ip]
        if cursor is not None:
            rows = [q for q in rows if q["id"] <= cursor]
        if since is not None:
            rows = [q for q in rows if q["timestamp"] >= since]
        return {"queries": rows[start:start + min(length, 10000)],
                "cursor": cursor if cursor is not None else (max((q["id"] for q in self.rows), default=None))}

    def list_domains(self, kind):
        if kind == "allow":
            return [{"domain": d, "comment": None, "enabled": True} for d in self.allowed]
        return [{"domain": d, **e} for d, e in self.denied.items()]

    def request(self, method, path, **kw):
        if (method, path) == ("GET", "/groups"):
            return {"groups": self.groups}
        if (method, path) == ("GET", "/clients"):
            return {"clients": self.clients}
        if (method, path) == ("GET", "/lists"):
            return {"lists": [{"address": "https://example.org/hosts", "type": "block", "enabled": True, "groups": [0]}]}
        raise AssertionError(f"unexpected FTL call {method} {path}")

    def deny(self, domain, comment, groups=(0,)):
        self.denied.setdefault(domain, {"comment": comment, "enabled": True, "groups": list(groups)})

    def set_groups(self, domain, comment, groups, enabled=True):
        self.denied[domain] = {"comment": comment, "enabled": enabled, "groups": list(groups)}

    def set_enabled(self, domain, comment, enabled):
        self.denied[domain] = {**self.denied.get(domain, {}), "comment": comment, "enabled": enabled}

    def remove_deny(self, domain):
        self.denied.pop(domain, None)


def verdicts_for(batch, model, examples=None):
    return {d: {"domain": d, "category": "ads" if d.startswith("ads.") else "legitimate",
                "confidence": 0.95, "reason": "test"} for d, _, _ in batch}


class IngestTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = store.open_db(os.path.join(self.tmp, "k.db"))
        self.ftl = FakeFTL()
        self.ing = ingest.Ingest(self.ftl)

    def test_reads_past_ftl_row_cap_and_only_new_rows(self):
        for i in range(2500):
            self.ftl.add(f"d{i % 700}.example.com")
        with mock.patch.object(ingest, "PAGE", 1000):
            self.assertEqual(self.ing.poll(self.db), 2500)
        self.assertEqual(self.ing.queue_length(), 700)
        self.assertEqual(int(store.get_state(self.db, "ingest_hw")), 2500)
        self.ftl.add("new.example.com")
        self.assertEqual(self.ing.poll(self.db), 1)

    def test_first_query_of_a_fresh_ftl_has_id_0(self):
        self.ftl.add("first.example.com")
        self.ftl.rows[-1]["id"] = 0
        self.ftl.add("second.example.com")
        self.ftl.rows[-1]["id"] = 1
        self.assertEqual(self.ing.poll(self.db), 2)
        self.assertEqual(set(self.ing.queue), {"first.example.com", "second.example.com"})

    def test_ids_going_backwards_resets_high_water_mark(self):
        store.set_state(self.db, "ingest_hw", 99999)
        self.ftl.add("a.example.com")
        self.assertEqual(self.ing.poll(self.db), 1)
        self.assertEqual(int(store.get_state(self.db, "ingest_hw")), 1)  # the new top ID

    def test_skips_blocked_local_protected_allowlisted_and_decided(self):
        self.ftl.allowed.add("ok.example.net")
        self.db.execute("insert into verdicts (domain, status, judged_at, updated_at) values ('seen.example.net', 'allowed', 0, 0)")
        for d, st in [("gravity.example.net", "GRAVITY"), ("printer.lan", "FORWARDED"), ("www.apple.com", "CACHE"),
                      ("ok.example.net", "FORWARDED"), ("seen.example.net", "FORWARDED"), ("fresh.example.net", "FORWARDED")]:
            self.ftl.add(d, status=st)
        self.ing.poll(self.db)
        self.assertEqual(set(self.ing.queue), {"fresh.example.net"})

    def test_expired_verdict_is_reviewed_again(self):
        self.db.execute("insert into verdicts (domain, status, judged_at, updated_at, expires_at) "
                        "values ('old.example.net', 'allowed', 0, 0, 1)")
        self.ftl.add("old.example.net")
        self.ing.poll(self.db)
        self.assertIn("old.example.net", self.ing.queue)

    def test_flush_waits_for_size_or_age_then_records(self):
        self.ftl.add("ads.example.org")
        self.ftl.add("cdn.example.org")
        self.ing.poll(self.db)
        with mock.patch.object(ingest.classify, "classify", side_effect=verdicts_for), \
                mock.patch.object(ingest.classify, "model_digest", return_value="sha256:x"):
            self.assertEqual(self.ing.flush(self.db), 0)  # 2 < flush_size and not old enough
            for q in self.ing.queue.values():
                q["first_seen"] -= 60
            self.assertEqual(self.ing.flush(self.db), 2)
        rows = {r["domain"]: dict(r) for r in self.db.execute("select * from verdicts")}
        self.assertEqual(rows["ads.example.org"]["status"], store.PENDING)  # review mode by default
        self.assertIsNone(rows["ads.example.org"]["expires_at"])
        self.assertEqual(rows["cdn.example.org"]["status"], store.ALLOWED)
        self.assertGreater(rows["cdn.example.org"]["expires_at"], time.time() + 29 * 86400)
        self.assertEqual(rows["cdn.example.org"]["model_digest"], "sha256:x")
        self.assertEqual(set(self.ftl.denied), set())

    def test_auto_mode_blocks(self):
        store.save_settings(self.db, {"mode": "auto"})
        self.ftl.add("ads.example.org")
        self.ing.poll(self.db)
        with mock.patch.object(ingest.classify, "classify", side_effect=verdicts_for), \
                mock.patch.object(ingest.classify, "model_digest", return_value=None):
            self.ing.flush(self.db, force=True)
        self.assertEqual(set(self.ftl.denied), {"ads.example.org"})

    def test_model_failure_requeues_batch(self):
        self.ftl.add("x.example.org", ip="10.8.0.2")
        self.ing.poll(self.db)
        with mock.patch.object(ingest.classify, "classify", side_effect=requests.ConnectionError("down")):
            with self.assertRaises(requests.RequestException):
                self.ing.flush(self.db, force=True)
        self.assertEqual(self.ing.queue["x.example.org"]["lookups"], 1)
        self.assertEqual(self.ing.queue["x.example.org"]["devices"]["10.8.0.2"]["network"], "vpn")
        self.assertEqual(self.ing.inflight, set())

    def test_reconcile_marks_blocks_removed_elsewhere(self):
        self.db.execute("insert into verdicts (domain, status, judged_at, updated_at) values ('gone.example.net', 'blocked', 0, 0)")
        self.ing.reconcile(self.db)
        self.assertEqual(self.db.execute("select status from verdicts").fetchone()[0], store.USER_ALLOWED)


class MigrationTest(unittest.TestCase):
    def test_upgrades_old_addon_database(self):
        path = os.path.join(tempfile.mkdtemp(), "old.db")
        import sqlite3
        old = sqlite3.connect(path)
        old.execute("create table verdicts (domain text primary key, category text, confidence real, reason text, "
                    "status text, queries integer, devices integer, judged_at real, updated_at real)")
        old.execute("create table state (key text primary key, value text)")
        old.execute("insert into verdicts values ('cdn.example.com', 'legitimate', 0.9, 'r', 'allowed', 1, 1, 100, 100)")
        old.commit()
        old.close()
        db = store.open_db(path)
        self.assertEqual(store.get_state(db, "schema_version"), str(len(store.MIGRATIONS)))
        row = db.execute("select * from verdicts").fetchone()
        self.assertEqual(row["expires_at"], 100 + store.VERDICT_TTL["legitimate"])
        self.assertEqual(row["clients"], "[]")
        store.open_db(path)  # idempotent


if __name__ == "__main__":
    unittest.main()
