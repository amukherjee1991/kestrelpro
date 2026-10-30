import os
import tempfile
import unittest
from unittest import mock

from kestrel_engine import api, auth, config, store
from tests.test_ingest import FakeFTL

P = config.API_PREFIX


class FakeResponse:
    def __init__(self, status, body):
        self.status_code, self.body = status, body

    def json(self):
        return self.body


class SessionCheckTest(unittest.TestCase):
    def check(self, status, session, sid="abc"):
        sc = auth.SessionCheck("http://ftl")
        with mock.patch.object(sc.http, "get", return_value=FakeResponse(status, {"session": session})) as get:
            csrf = sc.csrf_for(sid)
            sc.csrf_for(sid)  # cached
        self.assertEqual(get.call_count, 1)
        self.assertEqual(get.call_args.kwargs["headers"], {"X-FTL-SID": sid})
        return csrf

    def test_live_session(self):
        self.assertEqual(self.check(200, {"valid": True, "sid": "abc", "csrf": "tok"}), "tok")

    def test_rejected_session(self):
        self.assertIsNone(self.check(401, {"valid": False, "sid": None}))

    def test_passwordless_ftl_is_not_a_session(self):
        self.assertIsNone(self.check(200, {"valid": True, "sid": None, "validity": -1}))

    def test_no_cookie(self):
        self.assertIsNone(auth.SessionCheck("http://ftl").csrf_for(None))


class OriginTest(unittest.TestCase):
    def test_same_host_any_port(self):
        self.assertTrue(auth.origin_allowed("http://192.168.1.53:8080", "192.168.1.53:8090"))
        self.assertTrue(auth.origin_allowed("https://dns.lan", "dns.lan:8090"))

    def test_other_hosts_and_junk(self):
        self.assertFalse(auth.origin_allowed("http://evil.example", "192.168.1.53:8090"))
        self.assertFalse(auth.origin_allowed("null", "192.168.1.53:8090"))
        self.assertFalse(auth.origin_allowed(None, "192.168.1.53:8090"))
        self.assertFalse(auth.origin_allowed("file://192.168.1.53", "192.168.1.53:8090"))

    def test_configured_origin(self):
        with mock.patch.object(config, "UI_ORIGINS", {"https://admin.example"}):
            self.assertTrue(auth.origin_allowed("https://admin.example", "10.0.0.2:8090"))


class ApiTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp()
        self.patches = [mock.patch.object(config, "DB_PATH", os.path.join(tmp, "k.db")),
                        mock.patch.object(auth.SessionCheck, "csrf_for",
                                          lambda self, sid: "tok" if sid == "good" else None)]
        for p in self.patches:
            p.start()
        self.ftl = FakeFTL()
        self.client = api.create_app(self.ftl, mock.Mock(running=False, queue_length=lambda: 0)).test_client()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def test_requires_admin_session(self):
        self.assertEqual(self.client.get(f"{P}/decisions").status_code, 401)
        self.client.set_cookie("sid", "bad")
        self.assertEqual(self.client.get(f"{P}/decisions").status_code, 401)
        self.client.set_cookie("sid", "good")
        self.assertEqual(self.client.get(f"{P}/decisions").status_code, 200)

    def test_healthz_is_open(self):
        self.assertEqual(self.client.get(f"{P}/healthz").json["engine"], "kestrelpro")

    def test_writes_need_csrf(self):
        self.client.set_cookie("sid", "good")
        url = f"{P}/decisions/ads.example.org"
        self.assertEqual(self.client.post(url, json={"action": "block"}).status_code, 403)
        self.assertEqual(self.client.post(url, json={"action": "block"}, headers={"X-CSRF-TOKEN": "nope"}).status_code, 403)
        r = self.client.post(url, json={"action": "block"}, headers={"X-CSRF-TOKEN": "tok"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.ftl.denied, {"ads.example.org"})

    def test_cors_only_for_admin_origin(self):
        self.client.set_cookie("sid", "good")
        ok = self.client.get(f"{P}/status", headers={"Origin": "http://localhost:8080"})
        self.assertEqual(ok.headers.get("Access-Control-Allow-Origin"), "http://localhost:8080")
        self.assertEqual(ok.headers.get("Access-Control-Allow-Credentials"), "true")
        bad = self.client.get(f"{P}/status", headers={"Origin": "http://evil.example"})
        self.assertNotIn("Access-Control-Allow-Origin", bad.headers)

    def test_preflight_needs_no_session(self):
        r = self.client.options(f"{P}/settings", headers={
            "Origin": "http://localhost:8080", "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type, x-csrf-token"})
        self.assertIn(r.status_code, (200, 204))
        self.assertIn("X-CSRF-TOKEN", r.headers["Access-Control-Allow-Headers"])

    def test_settings_roundtrip(self):
        self.client.set_cookie("sid", "good")
        r = self.client.post(f"{P}/settings", json={"mode": "auto", "cadence": "eco", "min_confidence": 2},
                             headers={"X-CSRF-TOKEN": "tok"})
        self.assertEqual((r.json["mode"], r.json["cadence"], r.json["min_confidence"]), ("auto", "eco", 1.0))
        self.assertEqual(store.get_settings(store.open_db())["mode"], "auto")


if __name__ == "__main__":
    unittest.main()
