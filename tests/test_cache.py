"""The forge client's cache stays bounded: per-commit bodies age out, archives aren't kept."""
import unittest
from unittest import mock

import httpx

from dashboard import sources


def client(calls):
    def handler(req):
        calls.append(req.url.path)
        return httpx.Response(200, content=b"x" * 10)
    f = sources.Forgejo(base="http://forge", token="")
    f.http = httpx.Client(base_url="http://forge/api/v1", transport=httpx.MockTransport(handler))
    return f


class Cache(unittest.TestCase):
    def test_archive_is_not_kept(self):
        f = client([])
        f.get("/repos/o/r/archive/abc.tar.gz", raw=True, store=False)
        self.assertEqual(f._cache, {})

    def test_old_entries_age_out(self):
        f = client([])
        t = [1000.0]
        with mock.patch.object(sources.time, "monotonic", lambda: t[0]):
            f.get("/repos/o/r/raw/a?ref=1", raw=True, ttl=3600)
            t[0] += f.MAX_TTL + 1
            f.get("/repos/o/r/raw/a?ref=2", raw=True, ttl=3600)
        self.assertEqual(list(f._cache), ["/repos/o/r/raw/a?ref=2"])
