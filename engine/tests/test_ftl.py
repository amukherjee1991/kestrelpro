import unittest
from unittest import mock

import requests

from kestrel_engine import ftl as ftl_api


def http_error(status, text):
    response = mock.Mock(status_code=status, text=text)
    return requests.HTTPError(response=response)


class DenyTest(unittest.TestCase):
    def deny_with(self, error):
        f = ftl_api.FTL("http://ftl", "/nonexistent", "pw")
        with mock.patch.object(f, "request", side_effect=error):
            f.deny("ads.example.org", "kestrel: test")

    def test_already_present_is_fine(self):
        # FTL v6.8's exact answer for a duplicate
        self.deny_with(http_error(400, '{"error":{"key":"database_error","message":"Could not add to gravity '
                                       'database","hint":"The item is already present"}}'))
        self.deny_with(http_error(400, "UNIQUE constraint failed: domainlist.domain"))

    def test_other_errors_raise(self):
        with self.assertRaises(requests.HTTPError):
            self.deny_with(http_error(400, '{"error":{"key":"bad_request","message":"Invalid domain"}}'))
        with self.assertRaises(requests.HTTPError):
            self.deny_with(http_error(401, "unauthorized"))


if __name__ == "__main__":
    unittest.main()
