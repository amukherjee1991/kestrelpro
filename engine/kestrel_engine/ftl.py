"""Client for FTL's v6 REST API; safe to share between threads."""
import threading

import requests

from . import config

# Query statuses that mean "FTL let it through".
ALLOWED_STATUSES = {"FORWARDED", "CACHE", "CACHE_STALE", "RETRIED", "RETRIED_DNSSEC", "IN_PROGRESS"}
# FTL clamps /api/queries to 10,000 rows per call (API_QUERIES_MAX_ROWS in src/api/queries.c).
MAX_ROWS = 10000


class NoCredentials(RuntimeError):
    pass


class FTL:
    def __init__(self, url=config.FTL_URL, cli_pw_path=config.CLI_PW_PATH, password=config.FTL_PASSWORD):
        self.url, self.cli_pw_path, self.password = url, cli_pw_path, password
        self.sid = None
        self.http = requests.Session()
        self.lock = threading.Lock()

    def _secret(self):
        # Re-read every time: FTL writes a new CLI password whenever it restarts.
        try:
            with open(self.cli_pw_path) as f:
                pw = f.read().strip()
            if pw:
                return pw
        except OSError:
            pass
        if self.password:
            return self.password
        raise NoCredentials(f"No FTL credentials: {self.cli_pw_path} is unreadable and FTL_PASSWORD is not set.")

    def _login(self):
        r = self.http.post(f"{self.url}/api/auth", json={"password": self._secret()}, timeout=15)
        r.raise_for_status()
        self.sid = r.json()["session"]["sid"]

    def request(self, method, path, **kw):
        with self.lock:
            if not self.sid:
                self._login()
            for attempt in range(2):
                r = self.http.request(method, f"{self.url}/api{path}", headers={"X-FTL-SID": self.sid}, timeout=60, **kw)
                if r.status_code == 401 and attempt == 0:
                    self._login()
                    continue
                r.raise_for_status()
                return r.json() if r.content else None

    def logout(self):
        with self.lock:
            if self.sid:
                try:
                    self.http.delete(f"{self.url}/api/auth", headers={"X-FTL-SID": self.sid}, timeout=5)
                except requests.RequestException:
                    pass
                self.sid = None

    def queries(self, start=0, length=1000, cursor=None, since=None):
        """One page of the query log, newest first. Without a cursor FTL returns the
        current largest query ID as `cursor`; passing it back keeps later pages stable."""
        params = {"start": start, "length": min(length, MAX_ROWS)}
        if cursor is not None:
            params["cursor"] = cursor
        if since is not None:
            params["from"] = int(since)
        return self.request("GET", "/queries", params=params)

    def list_domains(self, kind):
        return self.request("GET", f"/domains/{kind}")["domains"]

    def deny(self, domain, comment, groups=(0,)):
        try:
            self.request("POST", "/domains/deny/exact",
                         json={"domain": domain, "comment": comment, "groups": list(groups), "enabled": True})
        except requests.HTTPError as e:
            # Already on the deny list is fine.
            if e.response is None or e.response.status_code != 400 or "UNIQUE" not in e.response.text:
                raise

    def remove_deny(self, domain):
        try:
            self.request("DELETE", f"/domains/deny/exact/{domain}")
        except requests.HTTPError as e:
            if e.response is None or e.response.status_code != 404:
                raise

    def summary(self):
        return self.request("GET", "/stats/summary")

    def history(self):
        """Last 24 h of query counts in 10-minute slots."""
        return self.request("GET", "/history")["history"]

    def config_value(self, path):
        """e.g. config_value("dns/queryLogging") -> True"""
        node = self.request("GET", f"/config/{path}")["config"]
        for part in path.split("/"):
            node = node[part]
        return node

    def preflight(self):
        """Pi-hole settings the engine depends on; returns a list of problems to show."""
        problems = []
        checks = [("dns/queryLogging", True, "Query logging is off (dns.queryLogging), so KestrelPro sees no queries."),
                  ("misc/privacylevel", 0, "Privacy level is above 0 (misc.privacylevel), so domains are hidden from KestrelPro.")]
        for path, want, message in checks:
            try:
                if self.config_value(path) != want:
                    problems.append(message)
            except (requests.RequestException, KeyError, TypeError):
                pass
        try:
            api = self.request("GET", "/config/webserver/api")["config"]["webserver"]["api"]
            if api.get("excludeDomains") or api.get("excludeClients"):
                problems.append("Some domains or clients are excluded from the API "
                                "(webserver.api.excludeDomains/excludeClients); KestrelPro can't review them.")
        except (requests.RequestException, KeyError, TypeError):
            pass
        return problems
