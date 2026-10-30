import json
import os
import tempfile
import time
import unittest
from unittest import mock

import requests

from kestrel_engine import classify, evidence, ingest, notify, policy, safety, store, suggestions
from tests.test_ingest import FakeFTL, verdicts_for


def q(domain, ip="192.168.1.5", t=0.0, status="FORWARDED", qid=None):
    return {"id": qid or 0, "domain": domain, "status": status, "time": t, "client": {"ip": ip, "name": None}}


class EvidenceTest(unittest.TestCase):
    def test_clockwork(self):
        self.assertEqual(evidence.clockwork([0, 60, 120, 181, 240]), 60)
        self.assertIsNone(evidence.clockwork([0, 5, 200, 210, 900]))   # irregular
        self.assertIsNone(evidence.clockwork([0, 1, 2, 3, 4]))          # retries, not a beacon
        self.assertIsNone(evidence.clockwork([0, 60, 120]))             # too few

    def test_near_blocked(self):
        blocked = evidence.blocked_times([q("ads.x.com", t=100.0, status="GRAVITY"),
                                          q("ads.y.com", ip="10.0.0.9", t=500.0, status="DENYLIST")])
        self.assertTrue(evidence.near_blocked(blocked, "192.168.1.5", 101.5))
        self.assertFalse(evidence.near_blocked(blocked, "192.168.1.5", 103.0))
        self.assertFalse(evidence.near_blocked(blocked, "192.168.1.6", 100.0))

    def test_summary_line(self):
        item = {"lookups": 5, "near_blocked": 4, "devices": {
            "192.168.1.20": {"ip": "192.168.1.20", "name": "Living-Room-TV", "lookups": 5, "times": [0, 60, 120, 180, 240]}}}
        ev, line = evidence.summarise(item)
        self.assertEqual(ev, {"devices": ["Living-Room-TV"], "clockwork_seconds": [60], "near_blocked": 0.8})
        self.assertIn("repeats every ~60 s", line)
        self.assertIn("80% of lookups", line)


class IngestEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.db = store.open_db(os.path.join(tempfile.mkdtemp(), "k.db"))
        self.ftl = FakeFTL()
        self.ing = ingest.Ingest(self.ftl)

    def test_evidence_reaches_prompt_and_verdict_but_not_device_list(self):
        start = time.time() - 600
        for i in range(5):
            self.ftl.add("ads.beacon.com", ip="192.168.1.20", ts=start + i * 60)
            self.ftl.add("pixel.gravity.com", ip="192.168.1.20", status="GRAVITY", ts=start + i * 60 + 1)
        self.ing.poll(self.db)
        seen = {}

        def capture(batch, model, examples=None):
            seen["batch"] = batch
            return verdicts_for(batch, model)
        with mock.patch.object(ingest.classify, "classify", side_effect=capture), \
                mock.patch.object(ingest.classify, "model_digest", return_value=None):
            self.ing.flush(self.db, force=True)
        line = dict((b[0], b[3]) for b in seen["batch"])["ads.beacon.com"]
        self.assertIn("repeats every ~60 s", line)
        self.assertIn("100% of lookups came right next to blocked", line)
        row = self.db.execute("select evidence, clients from verdicts where domain = 'ads.beacon.com'").fetchone()
        self.assertEqual(json.loads(row["evidence"])["clockwork_seconds"], [60])
        self.assertNotIn("times", json.loads(row["clients"])[0])

    def test_rhythm_from_the_servers_history_on_re_review(self):
        start = time.time() - 1800
        for i in range(5):  # looked up every 5 minutes for the last half hour ...
            self.ftl.add("telemetry.vendor.com", ip="192.168.1.20", ts=start + i * 300)
        store.set_state(self.db, "ingest_hw", len(self.ftl.rows))  # ... all before the engine's last poll
        self.ftl.add("telemetry.vendor.com", ip="192.168.1.20", ts=start + 1500)  # one new lookup, on the beat
        self.ing.poll(self.db)
        seen = {}

        def capture(batch, model, examples=None):
            seen["batch"] = batch
            return verdicts_for(batch, model)
        with mock.patch.object(ingest.classify, "classify", side_effect=capture), \
                mock.patch.object(ingest.classify, "model_digest", return_value=None):
            self.ing.flush(self.db, force=True)
        self.assertIn("repeats every ~300 s", seen["batch"][0][3])
        row = self.db.execute("select clients from verdicts").fetchone()
        self.assertEqual(json.loads(row["clients"])[0]["lookups"], 1)  # history isn't counted as new lookups

    def test_prompt_mentions_evidence_only_when_given(self):
        rows = []
        with mock.patch.object(classify.requests, "post") as post:
            post.return_value.json.return_value = {"done_reason": "stop", "message": {"content": '{"verdicts": []}'}}
            classify.classify([("a.com", 1, 1), ("b.com", 2, 1, "devices: TV")], "m")
            rows = post.call_args.kwargs["json"]["messages"][1]["content"].splitlines()
        self.assertIn("a.com\t1 lookups\t1 device(s)", rows)
        self.assertIn("b.com\t2 lookups\t1 device(s)\tdevices: TV", rows)


class ListChecksTest(unittest.TestCase):
    def setUp(self):
        self.db = store.open_db(os.path.join(tempfile.mkdtemp(), "k.db"))
        self.ftl = FakeFTL()
        self.ftl.search["login.example.com"] = {"gravity": [{"address": "https://lists.example/hosts", "type": "block"}],
                                                "domains": []}
        self.checks = suggestions.ListChecks(self.ftl)
        self.settings = store.get_settings(self.db)

    def verdicts(self, batch, model, examples=None):
        say = {"login.example.com": ("legitimate", 0.95), "ads.example.com": ("ads", 0.97),
               "cdn.example.com": ("legitimate", 0.6)}
        return {b[0]: {"domain": b[0], "category": say[b[0]][0], "confidence": say[b[0]][1], "reason": "r"}
                for b in batch if b[0] in say}

    def collect(self):
        self.checks.collect([q("login.example.com", status="GRAVITY"), q("login.example.com", ip="10.8.0.2", status="GRAVITY"),
                             q("ads.example.com", status="GRAVITY"), q("cdn.example.com", status="GRAVITY"),
                             q("printer.lan", status="GRAVITY"), q("fine.example.org")])

    def test_only_confident_legitimate_ones_are_suggested_with_their_list(self):
        self.collect()
        with mock.patch.object(suggestions.classify, "classify", side_effect=self.verdicts):
            self.assertEqual(self.checks.run(self.db, self.settings), 3)  # printer.lan never goes to the model
        fp = suggestions.false_positives(self.db)
        self.assertEqual([r["domain"] for r in fp], ["login.example.com"])
        self.assertEqual(fp[0]["lists"][0]["address"], "https://lists.example/hosts")
        self.assertEqual(fp[0]["devices"], 2)

    def test_hourly_budget_and_weekly_recheck(self):
        self.collect()
        with mock.patch.object(suggestions.classify, "classify", side_effect=self.verdicts):
            self.assertEqual(self.checks.run(self.db, {**self.settings, "list_checks_per_hour": 1}), 1)
            self.assertEqual(self.checks.run(self.db, {**self.settings, "list_checks_per_hour": 1}), 0)
            self.checks.window.clear()
            self.collect()  # seen again: the one already checked is skipped for a week
            self.checks.run(self.db, self.settings)
        self.assertEqual(self.db.execute("select count(*) from gravity_checks").fetchone()[0], 3)
        with mock.patch.object(suggestions.classify, "classify") as never:
            self.assertEqual(self.checks.run(self.db, {**self.settings, "list_checks_per_hour": 0}), 0)
            never.assert_not_called()

    def test_model_down_keeps_them_waiting(self):
        self.collect()
        with mock.patch.object(suggestions.classify, "classify", side_effect=requests.ConnectionError("down")):
            with self.assertRaises(requests.RequestException):
                self.checks.run(self.db, self.settings)
        self.assertIn("login.example.com", self.checks.pending)

    def test_allow_and_dismiss(self):
        self.collect()
        with mock.patch.object(suggestions.classify, "classify", side_effect=self.verdicts):
            self.checks.run(self.db, self.settings)
        suggestions.allow(self.ftl, self.db, "login.example.com")
        self.assertIn("login.example.com", self.ftl.allowed)
        self.assertTrue(self.ftl.allow_exact["login.example.com"]["comment"].startswith("kestrel:"))
        self.assertEqual(suggestions.false_positives(self.db), [])
        self.assertEqual(self.db.execute("select action from events").fetchone()[0], store.LIST_ALLOWED)
        with self.assertRaises(ValueError):
            suggestions.allow(self.ftl, self.db, "never.suggested.com")


class SiteRulesTest(unittest.TestCase):
    def setUp(self):
        self.db = store.open_db(os.path.join(tempfile.mkdtemp(), "k.db"))
        self.ftl = FakeFTL()
        for d in ("ads.tracker.net", "pixel.tracker.net", "cdn.tracker.net", "one.other.org", "ads.google.com",
                  "x.google.com", "y.google.com"):
            self.db.execute("insert into verdicts (domain, status, judged_at, updated_at) values (?, 'blocked', 0, 0)", (d,))
        self.db.commit()

    def test_suggests_sites_with_three_blocks_but_never_protected_ones(self):
        found = suggestions.sites(self.db, store.get_settings(self.db))
        self.assertEqual([s["site"] for s in found], ["tracker.net"])
        self.assertEqual(found[0]["regex"], r"(^|\.)tracker\.net$")

    def test_block_unblock_dismiss(self):
        regex = suggestions.block_site(self.ftl, self.db, "tracker.net")
        self.assertEqual(self.ftl.regex[regex]["groups"], [0])
        self.assertEqual(suggestions.sites(self.db, store.get_settings(self.db)), [])
        self.assertEqual(suggestions.rules(self.db)[0]["blocked"], 3)
        suggestions.unblock_site(self.ftl, self.db, "tracker.net")
        self.assertEqual(self.ftl.regex, {})
        suggestions.dismiss(self.db, "site", "tracker.net")
        self.assertEqual(suggestions.sites(self.db, store.get_settings(self.db)), [])
        with self.assertRaises(ValueError):
            suggestions.block_site(self.ftl, self.db, "google.com")

    def test_pause_and_undo_cover_site_rules(self):
        regex = suggestions.block_site(self.ftl, self.db, "tracker.net")
        safety.pause(self.ftl, self.db)
        self.assertFalse(self.ftl.regex[regex]["enabled"])
        self.assertTrue(self.ftl.regex[regex]["comment"].startswith("kestrel:"))
        safety.resume(self.ftl, self.db)
        self.assertTrue(self.ftl.regex[regex]["enabled"])
        policy.undo(self.ftl, self.db)
        self.assertEqual(self.ftl.regex, {})
        self.assertEqual(suggestions.rules(self.db), [])


class NotifyTest(unittest.TestCase):
    def setUp(self):
        self.db = store.open_db(os.path.join(tempfile.mkdtemp(), "k.db"))
        notify._buffer.clear()
        self.addCleanup(notify._buffer.clear)

    def test_off_until_a_url_is_set(self):
        notify.add(self.db, "auto_blocked", "x")
        self.assertEqual(notify._buffer, [])

    def test_batches_and_sends_ntfy(self):
        store.save_settings(self.db, {"notify_url": "https://ntfy.example/kp", "notify_kind": "ntfy"})
        notify.add(self.db, "auto_blocked", "ads.a.com: ads")
        notify.add(self.db, "auto_blocked", "ads.b.com: ads")
        with mock.patch.object(notify.requests, "post") as post:
            self.assertTrue(notify.flush(self.db))
            self.assertFalse(notify.flush(self.db, force=False))  # nothing left
        args = post.call_args
        self.assertEqual(args.args[0], "https://ntfy.example/kp")
        self.assertIn(b"ads.a.com", args.kwargs["data"])
        self.assertIn(b"ads.b.com", args.kwargs["data"])
        self.assertEqual(post.call_count, 1)

    def test_rate_limit_and_retry(self):
        store.save_settings(self.db, {"notify_url": "https://hooks.example/x", "notify_kind": "webhook"})
        notify.add(self.db, "probation_reverted", "a")
        with mock.patch.object(notify.requests, "post", side_effect=requests.ConnectionError("down")):
            self.assertFalse(notify.flush(self.db))
        self.assertIn("Couldn't send", notify.status(self.db)["error"])
        self.assertEqual(len(notify._buffer), 1)  # kept for later
        with mock.patch.object(notify.requests, "post") as post:
            self.assertTrue(notify.flush(self.db))
            self.assertEqual(post.call_args.kwargs["json"]["events"][0]["event"], "probation_reverted")
            notify.add(self.db, "probation_reverted", "b")
            self.assertFalse(notify.flush(self.db))  # within SEND_EVERY of the last send
            self.assertTrue(notify.flush(self.db, force=True))

    def test_pending_backlog_nudges_once_a_day(self):
        store.save_settings(self.db, {"notify_url": "https://ntfy.example/kp", "notify_pending_at": 2})
        for d in ("a.com", "b.com"):
            self.db.execute("insert into verdicts (domain, status, judged_at, updated_at) values (?, 'pending', 0, 0)", (d,))
        notify.check_pending(self.db)
        notify.check_pending(self.db)
        self.assertEqual([e for e, _ in notify._buffer], ["pending"])

    def test_url_validation(self):
        self.assertTrue(notify.valid_url("https://ntfy.sh/topic"))
        self.assertFalse(notify.valid_url("file:///etc/passwd"))
        self.assertFalse(notify.valid_url("ntfy.sh/topic"))


if __name__ == "__main__":
    unittest.main()
