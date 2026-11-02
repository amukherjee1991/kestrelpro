import os
import socket
import struct
import tempfile
import threading
import time
import unittest
from unittest import mock

from kestrel_engine import config, location, policies, policy, privacy, safety, store
from tests.test_ingest import FakeFTL

MS = location.BY_ID["microsoft"]["domains"]
KIDS = 1


class LocationShieldTest(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "k.db")
        self.db = store.open_db(self.path)
        self.ftl = FakeFTL()
        self.ftl.groups.append({"id": KIDS, "name": "Kids", "enabled": True})
        self.ftl.clients = [{"client": "192.168.1.30", "groups": [KIDS]}]
        self.dir = policies.Directory(self.ftl)

    def test_on_for_everyone_adds_marked_entries(self):
        out = location.apply(self.ftl, self.dir, "microsoft", [0, KIDS])
        self.assertEqual(out["added"], MS)
        for d in MS:
            self.assertEqual(self.ftl.denied[d]["groups"], [0, KIDS])
            self.assertEqual(location.service_of(self.ftl.denied[d]["comment"]), "microsoft")

    def test_change_groups_then_off(self):
        location.apply(self.ftl, self.dir, "microsoft", [0, KIDS])
        out = location.apply(self.ftl, self.dir, "microsoft", [KIDS])
        self.assertEqual(out["updated"], MS)
        self.assertEqual(self.ftl.denied[MS[0]]["groups"], [KIDS])
        self.assertEqual(location.apply(self.ftl, self.dir, "microsoft", [KIDS])["updated"], [])  # nothing to do
        out = location.apply(self.ftl, self.dir, "microsoft", [])
        self.assertEqual(out["removed"], MS)
        self.assertFalse(set(MS) & set(self.ftl.denied))

    def test_other_entries_are_left_alone(self):
        self.ftl.deny("ipinfo.io", f"{config.TAG}: tracking 0.95 - lookup", groups=[0])
        self.ftl.deny("ipapi.co", "my own block", groups=[0])
        out = location.apply(self.ftl, self.dir, "ip_lookup", [KIDS])
        self.assertEqual(sorted(out["left_alone"]), ["ipapi.co", "ipinfo.io"])
        self.assertEqual(self.ftl.denied["ipapi.co"], {"comment": "my own block", "enabled": True, "groups": [0]})
        location.apply(self.ftl, self.dir, "ip_lookup", [])
        self.assertIn("ipinfo.io", self.ftl.denied)
        self.assertIn("ipapi.co", self.ftl.denied)

    def test_rejects_unknown_service_and_group(self):
        with self.assertRaises(ValueError):
            location.apply(self.ftl, self.dir, "nope", [0])
        with self.assertRaises(ValueError):
            location.apply(self.ftl, self.dir, "microsoft", [7])

    def test_pause_and_undo_never_lift_the_shield(self):
        location.apply(self.ftl, self.dir, "microsoft", [0])
        self.ftl.deny("ads.example.org", f"{config.TAG}: ads 0.95 - test")
        safety.pause(self.ftl, self.db)
        self.assertTrue(all(self.ftl.denied[d]["enabled"] for d in MS))
        self.assertFalse(self.ftl.denied["ads.example.org"]["enabled"])
        policy.undo(self.ftl, self.db)
        self.assertTrue(set(MS) <= set(self.ftl.denied))
        self.assertNotIn("ads.example.org", self.ftl.denied)

    def test_summary_counts_devices_and_blocked_lookups(self):
        now = time.time()
        self.ftl.add("inference.location.live.net", ip="192.168.1.148", ts=now - 3600)
        self.ftl.add("inference.location.live.net", ip="192.168.1.148", status="DENYLIST", ts=now - 60)
        self.ftl.add("gs-loc.apple.com", ip="192.168.1.30", ts=now - 120)
        self.ftl.add("gs-loc.apple.com", ip="192.168.1.30", ts=now - 9 * 86400)  # older than the report
        location.apply(self.ftl, self.dir, "microsoft", [0])
        s = {x["id"]: x for x in location.summary(self.ftl, self.dir, now=now)["services"]}
        self.assertEqual((s["microsoft"]["groups"], s["microsoft"]["group_names"]), ([0], ["Default"]))
        self.assertFalse(s["microsoft"]["partial"])
        dev = s["microsoft"]["devices"][0]
        self.assertEqual((dev["ip"], dev["lookups"], dev["blocked"]), ("192.168.1.148", 2, 1))
        self.assertEqual([d["lookups"] for d in s["apple"]["devices"]], [1])
        self.assertEqual(s["apple"]["groups"], [])

    def test_summary_flags_a_deleted_domain(self):
        location.apply(self.ftl, self.dir, "microsoft", [0])
        self.ftl.remove_deny(MS[1])
        s = {x["id"]: x for x in location.summary(self.ftl, self.dir)["services"]}
        self.assertTrue(s["microsoft"]["partial"])

    def test_api(self):
        from kestrel_engine import api, auth
        with mock.patch.object(config, "DB_PATH", self.path), \
                mock.patch.object(auth.SessionCheck, "csrf_for", lambda self, sid: "tok"):
            client = api.create_app(self.ftl, mock.Mock(running=False, queue_length=lambda: 0)).test_client()
            client.set_cookie("sid", "s")
            h = {"X-CSRF-TOKEN": "tok"}
            self.assertEqual(client.post(f"{config.API_PREFIX}/location/microsoft", json={"groups": [KIDS]}).status_code,
                             403)  # no CSRF token
            self.assertEqual(client.post(f"{config.API_PREFIX}/location/microsoft", json={"groups": "all"},
                                         headers=h).status_code, 400)
            r = client.post(f"{config.API_PREFIX}/location/microsoft", json={"groups": [KIDS]}, headers=h)
            self.assertEqual(r.json["added"], MS)
            page = client.get(f"{config.API_PREFIX}/location").json
        self.assertEqual(next(s for s in page["services"] if s["id"] == "microsoft")["group_names"], ["Kids"])
        self.assertEqual([g["name"] for g in page["groups"]], ["Default", "Kids"])


def txt_response(qid, answers, rcode=0):
    """A DNS response to a TXT question for privacy.TEST_NAME, answers using a name pointer."""
    q = privacy._name(privacy.TEST_NAME) + struct.pack(">HH", privacy.TXT, 1)
    out = struct.pack(">HHHHHH", qid, 0x8180 | rcode, 1, len(answers), 0, 0) + q
    for text in answers:
        rdata = bytes([len(text)]) + text.encode()
        out += b"\xc0\x0c" + struct.pack(">HHIH", privacy.TXT, 1, 60, len(rdata)) + rdata
    return out


class FakeDNS:
    """A UDP server on localhost that answers every query with fixed TXT records."""

    def __init__(self, answers):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.answers = answers
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        msg, addr = self.sock.recvfrom(512)
        self.sock.sendto(txt_response(struct.unpack(">H", msg[:2])[0], self.answers), addr)
        self.sock.close()


class PrivacyTest(unittest.TestCase):
    def test_parse_txt_with_name_pointers(self):
        self.assertEqual(privacy.parse_txt(txt_response(7, ["172.253.1.2", "edns0-client-subnet 203.0.113.0/24"]), 7),
                         ["172.253.1.2", "edns0-client-subnet 203.0.113.0/24"])
        with self.assertRaises(ValueError):
            privacy.parse_txt(txt_response(7, []), 8)
        with self.assertRaises(ValueError):
            privacy.parse_txt(txt_response(7, [], rcode=2), 7)

    def test_live_test_over_udp(self):
        dns = FakeDNS(["172.253.1.2", "edns0-client-subnet 203.0.113.0/24"])
        answers = privacy.query_txt(privacy.TEST_NAME, "127.0.0.1", port=dns.port)
        self.assertEqual(answers[1], "edns0-client-subnet 203.0.113.0/24")

    def test_live_test_reports_subnet_and_failure(self):
        with mock.patch.object(privacy, "query_txt", return_value=["172.253.1.2", "edns0-client-subnet 203.0.113.0/24"]):
            self.assertEqual(privacy.live_test("x"), {"resolver": "172.253.1.2", "subnet": "203.0.113.0/24", "error": None})
        with mock.patch.object(privacy, "query_txt", side_effect=socket.timeout("timed out")):
            r = privacy.live_test("x")
        self.assertIsNone(r["subnet"])
        self.assertIn("timed out", r["error"])

    def test_upstreams_and_options(self):
        notes = privacy.upstream_notes(["1.1.1.1", "8.8.8.8#53", "127.0.0.1#5335", "9.9.9.11"])
        self.assertEqual([n["sends_ecs"] for n in notes], [False, True, False, True])
        self.assertIsNone(notes[0]["note"])
        self.assertIn("own network", notes[2]["note"])
        found = privacy.option_findings(["add-subnet=24,96", "cache-size=10000", " add-mac", "log-queries"])
        self.assertEqual([f["line"] for f in found], ["add-subnet=24,96", "add-mac"])

    def test_check_combines_everything(self):
        ftl = mock.Mock()
        values = {"dns/upstreams": ["1.1.1.1", "9.9.9.9"], "misc/dnsmasq_lines": [], "misc/etc_dnsmasq_d": False}
        ftl.config_value.side_effect = lambda p: values[p]
        with mock.patch.object(privacy, "query_txt", return_value=["162.158.1.1"]):
            r = privacy.check(ftl)
        self.assertTrue(r["ok"])
        self.assertEqual(r["live"]["resolver"], "162.158.1.1")
        values["misc/dnsmasq_lines"] = ["add-subnet=32,128"]
        with mock.patch.object(privacy, "query_txt", return_value=["162.158.1.1", "edns0-client-subnet 198.51.100.0/24"]):
            r = privacy.check(ftl)
        self.assertFalse(r["ok"])
        self.assertEqual((r["live"]["subnet"], len(r["options"])), ("198.51.100.0/24", 1))


if __name__ == "__main__":
    unittest.main()
