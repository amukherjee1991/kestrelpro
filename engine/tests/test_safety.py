import os
import tempfile
import time
import unittest
from unittest import mock

from kestrel_engine import ingest, policy, safety, store
from tests.test_ingest import FakeFTL, verdicts_for


class SafetyTest(unittest.TestCase):
    def setUp(self):
        self.db = store.open_db(os.path.join(tempfile.mkdtemp(), "k.db"))
        self.ftl = FakeFTL()
        self.ing = ingest.Ingest(self.ftl)
        store.save_settings(self.db, {"mode": "auto"})

    def auto_block(self, *domains, ip="192.168.1.5"):
        for d in domains:
            self.ftl.add(d, ip=ip)
        self.ing.poll(self.db)
        with mock.patch.object(ingest.classify, "classify", side_effect=verdicts_for), \
                mock.patch.object(ingest.classify, "model_digest", return_value=None):
            self.ing.flush(self.db, force=True)

    def status(self, d):
        return self.db.execute("select status, probation_until from verdicts where domain = ?", (d,)).fetchone()

    def test_registrable(self):
        self.assertEqual(safety.registrable("a.b.example.com"), "example.com")
        self.assertEqual(safety.registrable("ads.shop.example.co.uk"), "example.co.uk")
        self.assertEqual(safety.registrable("example.com."), "example.com")

    def test_automatic_blocks_go_on_probation(self):
        self.auto_block("ads.example.org")
        st, until = self.status("ads.example.org")
        self.assertEqual(st, store.BLOCKED)
        self.assertAlmostEqual(until, time.time() + 24 * 3600, delta=60)

    def test_user_decisions_are_not_on_probation(self):
        self.auto_block("ads.example.org")
        policy.set_status(self.ftl, self.db, "ads.example.org", store.BLOCKED, store.APPROVED)
        self.assertIsNone(self.status("ads.example.org")[1])

    def test_unblocking_a_sibling_reverts_fresh_blocks_on_that_site(self):
        self.auto_block("ads.example.org", "ads.metrics.example.org", "ads.other.net")
        reverted = policy.set_status(self.ftl, self.db, "ads.example.org", store.USER_ALLOWED, store.UNBLOCKED)
        self.assertEqual(reverted, ["ads.metrics.example.org"])
        self.assertEqual(self.status("ads.metrics.example.org")[0], store.PENDING)
        self.assertNotIn("ads.metrics.example.org", self.ftl.denied)
        self.assertEqual(self.status("ads.other.net")[0], store.BLOCKED)  # another site: untouched
        events = [r[0] for r in self.db.execute("select action from events where domain = 'ads.metrics.example.org'")]
        self.assertIn(store.PROBATION_REVERTED, events)

    def test_retry_storm_from_several_devices_reverts(self):
        self.auto_block("ads.example.org")
        for ip in ("192.168.1.20", "192.168.1.21"):
            for _ in range(20):
                self.ftl.add("ads.example.org", ip=ip, status="DENYLIST")
        self.ing.poll(self.db)
        self.assertEqual(self.status("ads.example.org")[0], store.PENDING)
        self.assertNotIn("ads.example.org", self.ftl.denied)

    def test_one_busy_device_is_not_a_storm(self):
        self.auto_block("ads.example.org")
        for _ in range(200):
            self.ftl.add("ads.example.org", ip="192.168.1.20", status="DENYLIST")
        self.ing.poll(self.db)
        self.assertEqual(self.status("ads.example.org")[0], store.BLOCKED)

    def test_no_storm_watch_after_probation(self):
        self.auto_block("ads.example.org")
        self.db.execute("update verdicts set probation_until = 1")
        for ip in ("192.168.1.20", "192.168.1.21", "192.168.1.22"):
            for _ in range(30):
                self.ftl.add("ads.example.org", ip=ip, status="DENYLIST")
        self.ing.poll(self.db)
        self.assertEqual(self.status("ads.example.org")[0], store.BLOCKED)

    def test_pause_disables_without_deleting_and_keeps_comments(self):
        self.auto_block("ads.example.org")
        self.ftl.denied["someone-elses.example"] = {"comment": "my own block", "enabled": True}
        comment = self.ftl.denied["ads.example.org"]["comment"]
        self.assertEqual(safety.pause(self.ftl, self.db), 1)
        self.assertEqual(self.ftl.denied["ads.example.org"], {"comment": comment, "enabled": False})
        self.assertTrue(self.ftl.denied["someone-elses.example"]["enabled"])
        self.assertTrue(safety.is_paused(self.db))
        # While paused, Automatic mode only suggests
        self.auto_block("ads.new.example.net")
        self.assertEqual(self.status("ads.new.example.net")[0], store.PENDING)
        self.assertNotIn("ads.new.example.net", self.ftl.denied)
        safety.resume(self.ftl, self.db)
        self.assertTrue(self.ftl.denied["ads.example.org"]["enabled"])
        self.assertFalse(safety.is_paused(self.db))

    def test_what_broke_on_a_device(self):
        self.auto_block("ads.example.org", "ads.tracker.example.net")
        for _ in range(5):
            self.ftl.add("ads.example.org", ip="192.168.1.20", status="DENYLIST")
        self.ftl.add("ads.tracker.example.net", ip="192.168.1.20", status="DENYLIST")
        self.ftl.add("ads.example.org", ip="192.168.1.99", status="DENYLIST")  # other device
        self.ftl.add("doubleclick.net", ip="192.168.1.20", status="GRAVITY")   # not ours
        r = safety.broke(self.ftl, self.db, "192.168.1.20", 30)
        self.assertEqual([(b["domain"], b["lookups"]) for b in r["blocks"]],
                         [("ads.example.org", 5), ("ads.tracker.example.net", 1)])
        self.assertEqual(r["blocks"][0]["status"], store.BLOCKED)
        self.assertEqual(r["other_blocked"], 1)

    def test_explain(self):
        self.auto_block("ads.example.org", "cdn.example.org")
        out = safety.explain(self.db, ["ADS.example.org.", "cdn.example.org", "never.seen.example"])
        self.assertEqual(set(out), {"ads.example.org", "cdn.example.org"})
        self.assertEqual(out["ads.example.org"]["category"], "ads")

    def test_migration_adds_probation_column(self):
        cols = {r[1] for r in self.db.execute("pragma table_info(verdicts)")}
        self.assertIn("probation_until", cols)


if __name__ == "__main__":
    unittest.main()
