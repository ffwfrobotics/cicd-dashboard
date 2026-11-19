"""The road-to-prod rules. Run: python -m unittest discover -s tests -v"""
import datetime as dt
import unittest

from dashboard.destiny import Facts, destiny, overall
from dashboard.model import branch_slug

NOW = dt.datetime(2026, 11, 19, 20, 0, tzinfo=dt.timezone.utc)
SHA = "a" * 40


def facts(**kw):
    base = dict(sha=SHA, branch="main", dev_branch="main", author="ada", when="2026-11-19T19:00:00Z",
                message="m", now=NOW)
    base.update(kw)
    return Facts(**base)


def states(f):
    return {s.key: s.state for s in destiny(f)}


LIVE = {"env": "dev", "env_dir": "dev", "image": "r/demo@sha256:" + "b" * 64, "at": "", "run_url": None,
        "hosts": ["demo-dev.c-local.k.ffwf.net"], "live": True, "superseded_by": None}


class Destiny(unittest.TestCase):
    def test_just_pushed(self):
        s = states(facts(jobs={"test": {"status": "running"}}))
        self.assertEqual((s["committed"], s["tests"], s["build"], s["prod"]), ("ok", "run", "todo", "todo"))

    def test_tests_failed_skips_delivery(self):
        s = states(facts(jobs={"test": {"status": "failure"}}))
        self.assertEqual((s["tests"], s["build"], s["deployed"]), ("fail", "skip", "skip"))

    def test_deliver_failed(self):
        s = states(facts(jobs={"test": {"status": "success"}, "deliver": {"status": "failure", "url": "u"}}))
        self.assertEqual(s["build"], "fail")

    def test_dev_with_findings_warns_and_previews_prod_blockers(self):
        f = facts(jobs={"test": {"status": "success"}, "deliver": {"status": "success"}}, deploy=LIVE,
                  security={"status": "warn"}, failing=[{"rule": "GHSA-x", "category": "vuln"}])
        stages = {s.key: s for s in destiny(f)}
        self.assertEqual(stages["security"].state, "warn")
        self.assertEqual(stages["deployed"].state, "ok")
        self.assertIn("GHSA-x", stages["promotion"].preview)
        self.assertIn("GHSA-x", stages["prod"].preview)
        self.assertEqual(overall(list(stages.values())), "warn")

    def test_branch_commit_cannot_be_promoted(self):
        d = dict(LIVE, env="branch", env_dir="branch-feat")
        s = {x.key: x for x in destiny(facts(branch="feat", deploy=d, security={"status": "pass"}))}
        self.assertEqual(s["promotion"].state, "skip")
        self.assertIn("merge to main", s["promotion"].detail)

    def test_superseded_dev_build(self):
        d = dict(LIVE, live=False, superseded_by="c" * 40)
        s = {x.key: x for x in destiny(facts(deploy=d, security={"status": "pass"}))}
        self.assertEqual(s["promotion"].state, "skip")
        self.assertIn("superseded", s["deployed"].detail)

    def test_promotion_waiting_for_second_person(self):
        p = {"id": "x", "state": "pending", "not_before": "2026-11-19T19:00:00Z", "requested_by": "ada",
             "approval": None, "applied_at": None, "security": None,
             "pr": {"number": 4, "url": "u", "state": "open", "merged": False, "author": "bot", "merged_by": None,
                    "approvers": ["ada"]}}
        s = {x.key: x for x in destiny(facts(deploy=LIVE, security={"status": "pass"}, promotion=p))}
        self.assertEqual(s["promotion"].state, "run")
        self.assertEqual(s["approved"].state, "run")          # ada approving her own request doesn't count
        self.assertIn("other than ada", s["approved"].detail)

    def test_self_merged_promotion_is_refused(self):
        p = {"id": "x", "state": "pending", "not_before": "2026-11-19T19:00:00Z", "requested_by": "ada",
             "approval": None, "applied_at": None, "security": None,
             "pr": {"number": 4, "url": "u", "state": "closed", "merged": True, "author": "bot", "merged_by": "ada",
                    "approvers": []}}
        s = {x.key: x for x in destiny(facts(deploy=LIVE, security={"status": "pass"}, promotion=p))}
        self.assertEqual(s["approved"].state, "fail")

    def test_merged_and_due_then_applied(self):
        pr = {"number": 4, "url": "u", "state": "closed", "merged": True, "author": "bot", "merged_by": "bob", "approvers": []}
        p = {"id": "x", "state": "pending", "not_before": "2026-11-19T21:00:00Z", "requested_by": "ada",
             "approval": None, "applied_at": None, "security": None, "pr": pr}
        s = {x.key: x for x in destiny(facts(deploy=LIVE, security={"status": "pass"}, promotion=p))}
        self.assertEqual((s["approved"].state, s["scheduled"].state), ("ok", "run"))
        self.assertIn("not before", s["scheduled"].detail)
        p = dict(p, state="done", approval="PR #4 merged by bob", applied_at="2026-11-19T21:01:00Z")
        s = states(facts(deploy=LIVE, security={"status": "pass"}, promotion=p, in_prod=True))
        self.assertEqual(set(s[k] for k in ("promotion", "approved", "scheduled", "prod")), {"ok"})

    def test_skipped_later_job_does_not_hide_result(self):
        from dashboard.model import Model

        class F:
            def get(self, path, ttl=None, raw=False):
                return {"workflow_runs": [
                    {"id": 1, "head_sha": SHA, "name": "test", "status": "success"},
                    {"id": 2, "head_sha": SHA, "name": "test", "status": "skipped"}]}
        m = Model.__new__(Model)
        m.forge = F()
        self.assertEqual(m._jobs("r")[SHA]["test"]["status"], "success")


class Slug(unittest.TestCase):
    def test_same_as_cicd_ref_arch(self):
        self.assertEqual(branch_slug("hello", "feat/Login-Page_v2"), "feat-login-page-v2")
        self.assertEqual(branch_slug("hello", "dev"), "dev-br")
        long = "feature/" + "x" * 100
        self.assertLessEqual(len("hello-" + branch_slug("hello", long)), 63)


if __name__ == "__main__":
    unittest.main()
