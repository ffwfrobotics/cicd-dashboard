"""The platform pipeline's trigger and its runs, as the dashboard sees them."""
import hashlib
import hmac
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from dashboard import platform


class FakeForge:
    def __init__(self, files):
        self.files = files

    def get(self, path, ttl=None, raw=False):
        for k, v in self.files.items():
            if path.startswith(k):
                return v
        return None


TENANTS = {
    "/repos/ffwf/cicd-ref-arch/contents/tenants": [{"type": "file", "name": "demo.yaml"}, {"type": "file", "name": "_limits.yaml"}],
    "/repos/ffwf/cicd-ref-arch/raw/tenants/demo.yaml": b"metadata: {name: demo}\nspec: {repo: o/demo-app}\n",
}


class Hook(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        Path(self.d, "hook-secret").write_text("s3\n")
        Path(self.d, "token").write_text("t")
        p = mock.patch.object(platform, "SECRET_DIR", Path(self.d))
        p.start()
        self.addCleanup(p.stop)

    def test_signature(self):
        body = b'{"x":1}'
        good = hmac.new(b"s3", body, hashlib.sha256).hexdigest()
        self.assertTrue(platform.signature_ok(body, good))
        self.assertFalse(platform.signature_ok(body, "0" * 64))
        self.assertFalse(platform.signature_ok(body, ""))

    def test_push_to_an_enrolled_repo_dispatches_its_app(self):
        sent = []
        with mock.patch.object(platform, "dispatch", lambda inputs: (sent.append(inputs), (True, ""))[1]):
            done = platform.on_push(FakeForge(TENANTS), "push", {
                "ref": "refs/heads/feat", "after": "b" * 40, "repository": {"full_name": "o/demo-app"}, "pusher": {"login": "ada"}})
        self.assertEqual(sent, [{"app": "demo", "branch": "feat", "sha": "b" * 40, "action": "deploy", "actor": "ada"}])
        self.assertEqual(len(done), 1)

    def test_a_redelivery_of_a_built_commit_is_not_rebuilt_but_a_failed_one_is(self):
        def runs(status):
            return dict(TENANTS, **{"/repos/ffwf/cicd-ref-arch/actions/runs": {"workflow_runs": [
                {"status": status, "event_payload": json.dumps({"inputs": {"app": "demo", "sha": "b" * 40}})}]}})
        push = {"ref": "refs/heads/main", "after": "b" * 40, "repository": {"full_name": "o/demo-app"}}
        sent = []
        with mock.patch.object(platform, "dispatch", lambda inputs: (sent.append(inputs), (True, ""))[1]):
            platform.on_push(FakeForge(runs("success")), "push", push)
            self.assertEqual(sent, [])
            platform.on_push(FakeForge(runs("failure")), "push", push)
            self.assertEqual(len(sent), 1)

    def test_other_repos_and_tags_are_ignored(self):
        with mock.patch.object(platform, "dispatch", side_effect=AssertionError):
            self.assertEqual(platform.on_push(FakeForge(TENANTS), "push", {"ref": "refs/heads/x", "after": "b" * 40,
                                                                           "repository": {"full_name": "o/other"}}), [])
            self.assertEqual(platform.on_push(FakeForge(TENANTS), "push", {"ref": "refs/tags/v1", "after": "b" * 40,
                                                                           "repository": {"full_name": "o/demo-app"}}), [])


class Runs(unittest.TestCase):
    def test_jobs_are_keyed_by_the_app_commit_in_the_inputs(self):
        ev = lambda app, sha, action="deploy": json.dumps({"inputs": {"app": app, "sha": sha, "action": action}})
        forge = FakeForge({
            "/repos/ffwf/cicd-ref-arch/actions/runs": {"workflow_runs": [
                {"index_in_repo": 12, "event_payload": ev("demo", "a" * 40)},
                {"index_in_repo": 11, "event_payload": ev("other", "c" * 40)},
                {"index_in_repo": 10, "event_payload": ev("demo", "", "pause")}]},
            "/repos/ffwf/cicd-ref-arch/actions/tasks": {"workflow_runs": [
                {"id": 5, "run_number": 12, "workflow_id": "pipeline.yaml", "name": "test", "status": "success"},
                {"id": 6, "run_number": 12, "workflow_id": "pipeline.yaml", "name": "deliver", "status": "running"},
                {"id": 4, "run_number": 11, "workflow_id": "pipeline.yaml", "name": "test", "status": "failure"},
                {"id": 3, "run_number": 9, "workflow_id": "environments.yaml", "name": "reconcile", "status": "success"}]},
        })
        jobs = platform.pipeline_jobs(forge, "demo")
        self.assertEqual(set(jobs), {"a" * 40})
        self.assertEqual({k: v["status"] for k, v in jobs["a" * 40].items()}, {"test": "success", "deliver": "running"})
