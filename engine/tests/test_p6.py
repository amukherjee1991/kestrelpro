import json
import os
import tempfile
import time
import unittest
from unittest import mock

import requests

from kestrel_engine import accuracy, classify, config, ingest, models, policies, policy, store
from tests.test_ingest import FakeFTL, verdicts_for

KIDS, WORK, QUIET = 1, 2, 3


class Base(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "k.db")
        self.db = store.open_db(self.path)
        self.ftl = FakeFTL()
        self.ftl.groups = [{"id": 0, "name": "Default", "enabled": True},
                           {"id": KIDS, "name": "Kids", "enabled": True},
                           {"id": WORK, "name": "Work", "enabled": True},
                           {"id": QUIET, "name": "Disabled group", "enabled": False}]
        self.ftl.clients = [{"client": "192.168.1.30", "groups": [KIDS]},
                            {"client": "192.168.1.40/30", "groups": [0, WORK]},
                            {"client": "tablet.lan", "groups": [KIDS, QUIET]}]
        self.ing = ingest.Ingest(self.ftl)

    def judge(self, *domains, ip="192.168.1.5", name=None, verdicts=verdicts_for):
        for d in domains:
            self.ftl.add(d, ip=ip)
            if name:
                self.ftl.rows[-1]["client"]["name"] = name
        self.ing.poll(self.db)
        with mock.patch.object(ingest.classify, "classify", side_effect=verdicts), \
                mock.patch.object(ingest.classify, "model_digest", return_value="sha256:abc"):
            self.ing.flush(self.db, force=True)

    def row(self, d):
        return self.db.execute("select * from verdicts where domain = ?", (d,)).fetchone()


class DirectoryTest(Base):
    def test_ip_cidr_hostname_and_default(self):
        d = policies.Directory(self.ftl)
        self.assertEqual(d.groups_for("192.168.1.30"), {KIDS})
        self.assertEqual(d.groups_for("192.168.1.41"), {0, WORK})
        self.assertEqual(d.groups_for("192.168.1.99"), {0})              # not listed: Default
        self.assertEqual(d.groups_for("192.168.1.77", "Tablet.lan"), {KIDS})  # disabled group dropped
        self.assertEqual(d.everyone(), [0, KIDS, WORK])

    def test_ftl_unreachable_means_default(self):
        broken = FakeFTL()
        broken.request = mock.Mock(side_effect=requests.ConnectionError("down"))
        self.assertEqual(policies.Directory(broken).groups_for("192.168.1.30"), {0})


class PolicyTest(Base):
    def test_effective_inherits_unset_fields(self):
        s = store.get_settings(self.db)
        e = policies.effective(s, {"mode": "auto", "min_confidence": None, "block_categories": ["ads"]})
        self.assertEqual((e["mode"], e["min_confidence"], e["block_categories"]), ("auto", s["min_confidence"], ["ads"]))
        self.assertEqual(policies.effective(s, None)["mode"], s["mode"])

    def test_default_group_cannot_be_overridden(self):
        with self.assertRaises(ValueError):
            policies.save(self.db, 0, "auto")
        with self.assertRaises(ValueError):
            policies.save(self.db, KIDS, "sometimes")

    def test_kids_automatic_blocks_only_for_kids(self):
        policies.save(self.db, KIDS, "auto", 0.75)  # global stays Review first
        self.judge("ads.example.org", ip="192.168.1.30")
        r = self.row("ads.example.org")
        self.assertEqual(r["status"], store.BLOCKED)
        self.assertEqual(json.loads(r["block_groups"]), [KIDS])
        self.assertEqual(self.ftl.denied["ads.example.org"]["groups"], [KIDS])
        self.assertIsNotNone(r["probation_until"])

    def test_review_for_default_devices(self):
        policies.save(self.db, KIDS, "auto")
        self.judge("ads.example.org", ip="192.168.1.99")
        self.assertEqual(self.row("ads.example.org")["status"], store.PENDING)
        self.assertNotIn("ads.example.org", self.ftl.denied)

    def test_off_group_never_flags(self):
        policies.save(self.db, KIDS, "off")
        self.judge("ads.example.org", ip="192.168.1.30")
        self.assertEqual(self.row("ads.example.org")["status"], store.ALLOWED)

    def test_own_threshold(self):
        policies.save(self.db, WORK, "auto", 0.99)   # verdicts_for says 0.95
        self.judge("ads.example.org", ip="192.168.1.41")  # Default (review) + Work (auto, too strict)
        self.assertEqual(self.row("ads.example.org")["status"], store.PENDING)

    def test_paused_turns_auto_into_review(self):
        policies.save(self.db, KIDS, "auto")
        store.set_state(self.db, "paused", "1")
        self.judge("ads.example.org", ip="192.168.1.30")
        self.assertEqual(self.row("ads.example.org")["status"], store.PENDING)

    def test_your_approval_blocks_everyone(self):
        policies.save(self.db, KIDS, "auto")
        self.judge("ads.example.org", ip="192.168.1.30")
        policy.set_status(self.ftl, self.db, "ads.example.org", store.BLOCKED, store.APPROVED)
        self.assertEqual(self.ftl.denied["ads.example.org"]["groups"], [0, KIDS, WORK])
        self.assertIsNone(self.row("ads.example.org")["block_groups"])

    def test_summary_for_the_page(self):
        policies.save(self.db, KIDS, "auto", 0.8)
        rows = {g["id"]: g for g in policies.summary(self.db, policies.Directory(self.ftl), store.get_settings(self.db))}
        self.assertTrue(rows[0]["default"])
        self.assertEqual(rows[KIDS]["effective"]["mode"], "auto")
        self.assertEqual(rows[KIDS]["clients"], ["192.168.1.30", "tablet.lan"])
        self.assertEqual((rows[0]["block_lists"], rows[KIDS]["block_lists"]), (1, 0))  # Kids gets no lists


class DecisionsApiTest(Base):
    def test_group_only_blocks_are_named(self):
        from kestrel_engine import api, auth
        policies.save(self.db, KIDS, "auto")
        self.judge("ads.example.org", ip="192.168.1.30")
        with mock.patch.object(config, "DB_PATH", self.path), \
                mock.patch.object(auth.SessionCheck, "csrf_for", lambda self, sid: "tok"):
            client = api.create_app(self.ftl, mock.Mock(running=False, queue_length=lambda: 0)).test_client()
            client.set_cookie("sid", "s")
            rows = client.get(f"{config.API_PREFIX}/decisions?status=blocked").json
        row = next(r for r in rows if r["domain"] == "ads.example.org")
        self.assertEqual((row["block_groups"], row["block_group_names"]), ([KIDS], ["Kids"]))


class AccuracyTest(Base):
    def decide(self, domain, category, conf, action):
        now = time.time()
        self.db.execute("insert or replace into verdicts (domain, category, confidence, reason, status, judged_at, "
                        "updated_at, model) values (?, ?, ?, 'r', 'allowed', ?, ?, 'm1')", (domain, category, conf, now, now))
        store.log_event(self.db, domain, action, category, conf, "r")
        self.db.commit()

    def setUp(self):
        super().setUp()
        self.decide("ads.a.com", "ads", 0.95, store.APPROVED)          # model right
        self.decide("cdn.b.com", "ads", 0.95, store.REJECTED)          # model wrong (false flag)
        self.decide("track.c.com", "legitimate", 0.9, store.MANUAL_BLOCKED)  # model missed
        self.decide("api.d.com", "legitimate", 0.9, store.UNBLOCKED)   # model right
        self.decide("x.e.com", "tracking", 0.95, store.APPROVED)
        store.log_event(self.db, "x.e.com", store.PROBATION_REVERTED, "tracking", 0.95, "storm")  # not yours
        self.db.execute("insert into verdicts (domain, category, confidence, reason, status, judged_at, updated_at) "
                        "values ('mine.f.com', 'ads', 1.0, 'blocked by you', 'user_blocked', 0, 0)")
        store.log_event(self.db, "mine.f.com", store.MANUAL_BLOCKED, "ads", 1.0, "blocked by you")
        self.db.commit()

    def test_grades_against_your_latest_decision(self):
        r = accuracy.report(self.db, store.get_settings(self.db))
        o = r["overall"]
        self.assertEqual((o["labelled"], o["agree"], o["flagged_right"], o["flagged_wrong"], o["missed"]), (5, 3, 2, 1, 1))
        self.assertEqual({d["domain"] for d in r["disagreements"]}, {"cdn.b.com", "track.c.com"})
        self.assertEqual(r["by_model"][0]["model"], "m1")

    def test_latest_decision_wins(self):
        store.log_event(self.db, "cdn.b.com", store.MANUAL_BLOCKED, "ads", 0.95, "r")  # changed your mind
        self.db.commit()
        rows = {r["domain"]: r["blocked"] for r in accuracy.labelled(self.db)}
        self.assertTrue(rows["cdn.b.com"])

    def test_bulk_undo_is_not_a_decision(self):
        self.db.execute("insert or replace into verdicts (domain, category, confidence, reason, status, judged_at, "
                        "updated_at) values ('ads.undo.com', 'ads', 0.95, 'r', 'user_allowed', 0, 0)")
        store.log_event(self.db, "ads.undo.com", store.UNBLOCKED, reason="removed by `kestrel undo`")
        store.log_event(self.db, "ads.a.com", store.UNBLOCKED, reason="removed by `kestrel.py undo`")  # old add-on
        self.db.commit()
        rows = {r["domain"]: r["blocked"] for r in accuracy.labelled(self.db)}
        self.assertNotIn("ads.undo.com", rows)
        self.assertTrue(rows["ads.a.com"])  # your earlier approval still stands

    def test_examples_balanced_and_need_a_minimum(self):
        ex = accuracy.examples(self.db, n=4)
        self.assertEqual(len(ex["blocked"]), 2)
        self.assertEqual(len(ex["kept"]), 2)
        empty = store.open_db(os.path.join(tempfile.mkdtemp(), "e.db"))
        self.assertIsNone(accuracy.examples(empty))

    def test_examples_reach_the_prompt(self):
        ex = {"blocked": ["ads.a.com"], "kept": ["api.d.com"]}
        prompt = classify._system_prompt(ex)
        self.assertIn("ads.a.com", prompt)
        self.assertIn("api.d.com", prompt)
        self.assertEqual(classify.prompt_version(ex), classify.PROMPT_VERSION + "+fs2")
        self.assertEqual(classify._system_prompt(None), classify.SYSTEM_PROMPT)

    def test_ingest_passes_examples_and_records_version(self):
        seen = {}

        def capture(batch, model, examples=None):
            seen["examples"] = examples
            return verdicts_for(batch, model)
        self.judge("new.g.com", verdicts=capture)
        self.assertIsNotNone(seen["examples"])
        self.assertIn("+fs", self.row("new.g.com")["prompt_version"])
        store.save_settings(self.db, {"few_shot": False})
        self.judge("new.h.com", verdicts=capture)
        self.assertIsNone(seen["examples"])


class FakeOllama:
    def __init__(self):
        self.tags = [{"name": "gemma4:12b", "size": 8_000_000_000, "digest": "sha256:aaa",
                      "details": {"parameter_size": "11.9B", "quantization_level": "Q4_K_M"}},
                     {"name": "small:4b", "size": 3_000_000_000, "digest": "sha256:bbb", "details": {}}]
        self.ps = [{"name": "gemma4:12b", "size": 100, "size_vram": 100}]

    def __call__(self, method, path, **kw):
        return {"models": self.tags} if path == "/api/tags" else {"models": self.ps}


class ModelsTest(Base):
    def setUp(self):
        super().setUp()
        self.ollama = FakeOllama()
        p = mock.patch.object(models, "_ollama", self.ollama)
        p.start()
        self.addCleanup(p.stop)
        classify._digests.update({"at": time.time(), "map": {"gemma4:12b": "sha256:aaa", "small:4b": "sha256:bbb"}})
        self.addCleanup(lambda: classify._digests.update({"at": 0.0, "map": {}}))

    def test_installed_marks_in_use_and_gpu(self):
        rows = {m["name"]: m for m in models.installed(store.get_settings(self.db))}
        self.assertTrue(rows["gemma4:12b"]["in_use"] and rows["gemma4:12b"]["on_gpu"])
        self.assertFalse(rows["small:4b"]["loaded"])

    def test_use_pins_and_change_is_flagged(self):
        s = models.use(self.db, "small:4b")
        self.assertEqual((s["model"], s["model_digest"]), ("small:4b", "sha256:bbb"))
        self.assertIsNone(models.pin_warning(s))
        classify._digests["map"]["small:4b"] = "sha256:ccc"  # someone ran `ollama pull small:4b`
        self.assertIn("changed", models.pin_warning(s))
        with self.assertRaises(ValueError):
            models.use(self.db, "not-installed:1b")

    def test_cannot_delete_the_model_in_use(self):
        with self.assertRaises(ValueError):
            models.delete(store.get_settings(self.db), "gemma4:12b")

    def test_pull_tracks_progress(self):
        lines = [json.dumps(x).encode() for x in (
            {"status": "pulling manifest"}, {"status": "pulling abc", "total": 100, "completed": 40},
            {"status": "pulling abc", "total": 100, "completed": 100}, {"status": "success"})]
        resp = mock.MagicMock()
        resp.__enter__.return_value.iter_lines.return_value = lines
        jobs = models.Jobs(self.path)
        with mock.patch.object(models.requests, "post", return_value=resp):
            jobs.pull("small:4b")
            for _ in range(100):
                if jobs.snapshot()["pulls"]["small:4b"]["done"]:
                    break
                time.sleep(0.01)
        job = jobs.snapshot()["pulls"]["small:4b"]
        self.assertEqual((job["status"], job["completed"], job["total"], job["error"]), ("success", 100, 100, None))
        with self.assertRaises(ValueError):
            jobs.pull("two words")

    def test_benchmark_needs_decisions_then_grades(self):
        jobs = models.Jobs(self.path)
        with self.assertRaises(ValueError):
            jobs.start_benchmark("small:4b")
        for d, cat, action in [("ads.a.com", "ads", store.APPROVED), ("cdn.b.com", "ads", store.REJECTED),
                               ("ads.c.com", "ads", store.APPROVED), ("api.d.com", "legitimate", store.UNBLOCKED)]:
            self.db.execute("insert or replace into verdicts (domain, category, confidence, reason, status, judged_at, "
                            "updated_at) values (?, ?, 0.9, 'r', 'allowed', 0, 0)", (d, cat))
            store.log_event(self.db, d, action, cat, 0.9, "r")
        self.db.commit()

        def everything_is_ads(batch, model, examples=None):
            return {d: {"domain": d, "category": "ads", "confidence": 0.99, "reason": "x"} for d, _, _ in batch}
        with mock.patch.object(models.classify, "classify", side_effect=everything_is_ads):
            jobs.start_benchmark("small:4b")
            for _ in range(200):
                if jobs.snapshot()["benchmark"]["done"]:
                    break
                time.sleep(0.01)
        result = jobs.snapshot()["benchmark"]["result"]
        self.assertEqual((result["labelled"], result["agree"], result["flagged_wrong"]), (4, 2, 2))
        self.assertEqual(models.benchmarks(self.db)[0]["model"], "small:4b")


class MigrationTest(unittest.TestCase):
    def test_v4(self):
        db = store.open_db(os.path.join(tempfile.mkdtemp(), "m.db"))
        self.assertEqual(store.get_state(db, "schema_version"), "4")
        self.assertIn("block_groups", {r[1] for r in db.execute("pragma table_info(verdicts)")})
        db.execute("select * from policies")
        db.execute("select * from benchmarks")


if __name__ == "__main__":
    unittest.main()
