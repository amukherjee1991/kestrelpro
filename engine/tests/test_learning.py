"""Protection that learns: CDN names, CNAME chains, sites learned from unblocks, more kept examples."""
import os
import struct
import tempfile
import time
import unittest
from unittest import mock

from kestrel_engine import accuracy, classify, cname, ingest, policy, store
from tests import test_ingest


def dns_response(qid, qname, chain):
    """A DNS answer for `qname` whose CNAME chain is `chain`, using compression pointers like real servers."""
    def enc(name):
        return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    msg = struct.pack(">HHHHHH", qid, 0x8180, 1, len(chain) + 1, 0, 0) + enc(qname) + struct.pack(">HH", 1, 1)
    owner_ptr = 12  # the question name
    for target in chain:
        rdata_at = len(msg) + 2 + 10
        rdata = enc(target)
        msg += struct.pack(">H", 0xC000 | owner_ptr) + struct.pack(">HHIH", cname.CNAME, 1, 300, len(rdata)) + rdata
        owner_ptr = rdata_at
    msg += struct.pack(">H", 0xC000 | owner_ptr) + struct.pack(">HHIH", 1, 1, 20, 4) + bytes([23, 44, 7, 72])
    return msg


class InfraAndLearningTest(unittest.TestCase):
    def setUp(self):
        self.db = store.open_db(os.path.join(tempfile.mkdtemp(), "k.db"))
        self.ftl = test_ingest.FakeFTL()

    def test_cdn_and_traffic_manager_names_are_protected(self):
        for d in ("gtm.secure.chase.com.akadns.net", "e14868.dsce9.akamaiedge.net",
                  "d15nwpqdptxbc3.cloudfront.net", "us-temu-com.trafficmanager.net"):
            self.assertTrue(policy.skip_domain(d), d)
        self.assertFalse(policy.skip_domain("ads.example.com"))

    def test_embedded_host_only_under_infra_zones(self):
        self.assertEqual(policy.embedded_host("gtm.secure.chase.com.akadns.net"), "gtm.secure.chase.com")
        self.assertEqual(policy.embedded_host("www.chase.com.edgekey.net"), "www.chase.com")
        self.assertIsNone(policy.embedded_host("e1234.a.akamaiedge.net"))
        self.assertIsNone(policy.embedded_host("sites.cps-p-gslbc.akadns.net"))
        # Phishing-style names elsewhere must not borrow a protected site's trust.
        self.assertIsNone(policy.embedded_host("chase.com.login-check.xyz"))

    def test_learn_site(self):
        self.assertEqual(policy.learn_site("gtm.secure.chase.com.akadns.net"), "chase.com")
        self.assertEqual(policy.learn_site("us-north-courier-vs.push-apple.com.akadns.net"), "push-apple.com")
        self.assertEqual(policy.learn_site("cdn.shop.example.co.uk"), "example.co.uk")
        self.assertIsNone(policy.learn_site("e1234.a.akamaiedge.net"))   # names no site
        self.assertIsNone(policy.learn_site("creditkarmacdn-a.akamaihd.net"))
        self.assertIsNone(policy.learn_site("prod.ocws1.live.com.akadns.net"))  # live.com is built in

    def test_unblock_protects_the_whole_site_from_the_model(self):
        self.ftl.deny("gtm.secure.chase.com.akadns.net", "kestrel: tracking")
        policy.set_status(self.ftl, self.db, "gtm.secure.chase.com.akadns.net", store.USER_ALLOWED, store.UNBLOCKED)
        self.assertEqual(store.learned_sites(self.db), ["chase.com"])
        protected = policy.never_block(self.db, store.get_settings(self.db))
        self.assertTrue(policy.skip_domain("page-format.chase.com", protected))
        self.assertTrue(policy.skip_domain("reco.chase.com", protected))
        self.assertFalse(policy.skip_domain("ads.example.com", protected))

    def test_dont_block_on_a_suggestion_also_teaches(self):
        policy.set_status(self.ftl, self.db, "api.weather.example.net", store.USER_ALLOWED, store.REJECTED)
        self.assertEqual(store.learned_sites(self.db), ["example.net"])

    def test_learning_can_be_switched_off_and_rules_removed(self):
        store.save_settings(self.db, {"learn_from_unblocks": False})
        policy.set_status(self.ftl, self.db, "x.example.org", store.USER_ALLOWED, store.UNBLOCKED)
        self.assertEqual(store.learned_sites(self.db), [])
        store.save_settings(self.db, {"learn_from_unblocks": True})
        policy.set_status(self.ftl, self.db, "x.example.org", store.USER_ALLOWED, store.UNBLOCKED)
        self.assertTrue(store.remove_learned(self.db, "example.org"))
        self.assertEqual(store.learned_sites(self.db), [])

    def test_blocks_dont_teach(self):
        policy.set_status(self.ftl, self.db, "ads.example.org", store.USER_BLOCKED, store.MANUAL_BLOCKED)
        self.assertEqual(store.learned_sites(self.db), [])

    def test_backfill_learns_past_unblocks_once(self):
        now = time.time()
        for d, status, reason in [("gtm.www.chase.com.akadns.net", store.USER_ALLOWED, None),
                                  ("ads.undo.com", store.USER_ALLOWED, "removed by `kestrel undo`"),
                                  ("ads.again.com", store.USER_BLOCKED, None)]:
            self.db.execute("insert into verdicts (domain, category, confidence, reason, status, judged_at, "
                            "updated_at) values (?, 'ads', 0.9, 'r', ?, ?, ?)", (d, status, now, now))
            store.log_event(self.db, d, store.UNBLOCKED, reason=reason)
        self.db.commit()
        policy.never_block(self.db, store.get_settings(self.db))
        self.assertEqual(store.learned_sites(self.db), ["chase.com"])
        store.remove_learned(self.db, "chase.com")
        policy.never_block(self.db, store.get_settings(self.db))  # removed stays removed
        self.assertEqual(store.learned_sites(self.db), [])


class CnameTest(unittest.TestCase):
    def setUp(self):
        cname._cache.clear()
        self.db = store.open_db(os.path.join(tempfile.mkdtemp(), "k.db"))
        self.ftl = test_ingest.FakeFTL()
        self.ing = ingest.Ingest(self.ftl)

    def test_parse_chain_with_compression(self):
        msg = dns_response(77, "secure.chase.com", ["gtm.secure.chase.com.akadns.net", "e1.a.akamaiedge.net"])
        self.assertEqual(cname.parse_cnames(msg, 77), ["gtm.secure.chase.com.akadns.net", "e1.a.akamaiedge.net"])
        with self.assertRaises(ValueError):
            cname.parse_cnames(msg, 78)

    def test_chain_failure_is_empty_and_cached(self):
        with mock.patch.object(cname, "query", side_effect=OSError("timeout")) as q:
            self.assertEqual(cname.chain("a.example.com", "127.0.0.1"), set())
            self.assertEqual(cname.chain("a.example.com", "127.0.0.1"), set())
        self.assertEqual(q.call_count, 1)

    def add(self, domain, t, ip="192.168.1.150", reply=None):
        self.ftl.add(domain, ip=ip, ts=t)
        if reply:
            self.ftl.rows[-1]["reply"] = {"type": reply}

    def test_cname_targets_of_protected_sites_are_never_judged(self):
        store.save_settings(self.db, {"protected_extra": ["bank.example"]})
        t = time.time()
        self.add("www.bank.example", t, reply="CNAME")
        self.add("www.bank.example.cdn-lb.example.net", t + 0.2)   # in the chain
        self.add("ads.tracker.example.org", t + 0.5)                # not in the chain
        self.add("late.cdn.example.net", t + 30)                    # too late to be the chain
        with mock.patch.object(cname, "query", return_value=["www.bank.example.cdn-lb.example.net"]) as q:
            self.ing.poll(self.db)
        self.assertEqual(set(self.ing.queue), {"ads.tracker.example.org", "late.cdn.example.net"})
        row = self.db.execute("select status, category, reason, expires_at from verdicts where domain = ?",
                              ("www.bank.example.cdn-lb.example.net",)).fetchone()
        self.assertEqual((row["status"], row["category"]), (store.ALLOWED, "legitimate"))
        self.assertIn("www.bank.example", row["reason"])
        self.assertIsNotNone(row["expires_at"])
        q.assert_called_once()  # one resolution, cached, for the protected name

    def test_other_devices_and_non_cname_answers_dont_count(self):
        store.save_settings(self.db, {"protected_extra": ["bank.example"]})
        t = time.time()
        self.add("www.bank.example", t)                                   # an A answer, no chain
        self.add("x.cdn.example.net", t + 0.1)
        self.add("login.bank.example", t, ip="192.168.1.20", reply="CNAME")
        self.add("y.cdn.example.net", t + 0.1)                            # different device
        with mock.patch.object(cname, "query", return_value=["x.cdn.example.net", "y.cdn.example.net"]) as q:
            self.ing.poll(self.db)
        self.assertEqual(set(self.ing.queue), {"x.cdn.example.net", "y.cdn.example.net"})
        q.assert_not_called()


class ExamplesTest(unittest.TestCase):
    def test_old_keep_decisions_stay_in_the_prompt(self):
        db = store.open_db(os.path.join(tempfile.mkdtemp(), "k.db"))
        now = time.time()
        for i in range(20):
            d = f"api{i}.keep.com"
            db.execute("insert into verdicts (domain, category, confidence, reason, status, judged_at, updated_at) "
                       "values (?, 'ads', 0.9, 'r', 'user_allowed', ?, ?)", (d, now, now))
            store.log_event(db, d, store.UNBLOCKED, "ads", 0.9, "r")
        for i in range(10):
            d = f"ads{i}.block.com"
            db.execute("insert into verdicts (domain, category, confidence, reason, status, judged_at, updated_at) "
                       "values (?, 'ads', 0.9, 'r', 'blocked', ?, ?)", (d, now, now))
            store.log_event(db, d, store.APPROVED, "ads", 0.9, "r")
        db.commit()
        ex = accuracy.examples(db, kept=accuracy.KEPT_EXAMPLES)
        self.assertEqual(len(ex["kept"]), 20)
        self.assertEqual(len(ex["blocked"]), 4)
        self.assertEqual(len(accuracy.examples(db)["kept"]), 4)  # the old default is unchanged
        prompt = classify._system_prompt(ex)
        self.assertIn("api0.keep.com", prompt)
        self.assertIn("never block these", prompt)


if __name__ == "__main__":
    unittest.main()
