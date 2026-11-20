"""Adding an app: names, sources, the pending record. Run: python -m pytest"""
import unittest

import yaml

from dashboard import enroll
from dashboard.model import Model
from dashboard.sources import FORGE


class Names(unittest.TestCase):
    def test_names(self):
        for bad in ("A", "ab", "-abc", "abc-", "has_underscore", "dev", "x" * 26):
            with self.assertRaises(enroll.EnrollError, msg=bad):
                enroll.check_name(bad, {})
        enroll.check_name("my-app2", {})
        with self.assertRaises(enroll.EnrollError):
            enroll.check_name("demo", {"demo": {}})

    def test_local_repo(self):
        self.assertEqual(enroll.local_repo(f"{FORGE}/ffwf/cicd-demo-app.git"), "ffwf/cicd-demo-app")
        self.assertEqual(enroll.local_repo(f"{FORGE}/ffwf/cicd-demo-app"), "ffwf/cicd-demo-app")
        self.assertIsNone(enroll.local_repo("https://github.com/ffwf/cicd-demo-app.git"))

    def test_pending_record(self):
        t = yaml.safe_load(enroll.tenant_doc("shop", "acme", "acme/shop", "ada", "main"))
        self.assertEqual(t["metadata"]["name"], "shop")
        self.assertEqual({k: t["spec"][k] for k in ("tenant", "repo", "status", "requestedBy", "defaultBranch")},
                         {"tenant": "acme", "repo": "acme/shop", "status": "pending", "requestedBy": "ada", "defaultBranch": "main"})


class FakeForge:
    def __init__(self, statuses):
        self.statuses = statuses

    def get(self, path, ttl=None, raw=False):
        return self.statuses


class ContractStatuses(unittest.TestCase):
    def test_only_the_latest_runs_checks(self):
        st = [  # newest first, as the forge lists them
            {"id": 9, "context": "cicd/contract/base-pinned", "status": "warning", "description": "rule 9: pin"},
            {"id": 8, "context": "cicd/contract", "status": "warning", "description": "1 to fix", "target_url": "u"},
            {"id": 3, "context": "cicd/contract/tests", "status": "warning", "description": "old run"},
            {"id": 2, "context": "cicd/contract", "status": "warning", "description": "2 to fix"},
            {"id": 1, "context": "ci/other", "status": "success"},
        ]
        m = Model.__new__(Model)
        m.forge = FakeForge(st)
        c = m.contract("o/r", "a" * 40)
        self.assertEqual((c["state"], c["summary"], [i["check"] for i in c["items"]]), ("warning", "1 to fix", ["base-pinned"]))
