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


class Projects(unittest.TestCase):
    def test_folders_and_submodule_contents(self):
        from dashboard import enroll as E

        class R:
            def __init__(self, code, data=None, text=""):
                self.status_code, self._d, self.text = code, data, text

            def json(self):
                return self._d

        trees = {
            "/repos/f/mono/git/trees/HEAD": {"tree": [{"type": "blob", "path": "apps/a/cicd.yaml"}, {"type": "blob", "path": "apps/b/Dockerfile"},
                                                      {"type": "blob", "path": "README.md"}, {"type": "commit", "path": "config"}]},
            "/repos/f/fx-config/git/trees/HEAD": {"tree": [{"type": "blob", "path": "apps/c/cicd.yaml"}]},
        }

        class C:
            def get(self, path, params=None):
                if path.endswith("/.gitmodules"):
                    return R(200, text='[submodule "config"]\n\tpath = config\n\turl = ../fx-config.git\n')
                return R(200, trees[path]) if path in trees else R(404)
        self.assertEqual(E.projects(C(), "f/mono"), ["apps/a", "apps/b", "config/apps/c"])


class ReadOnly(unittest.TestCase):
    """CI/CD only reads a developer's repo: the bot gets read on it, and direct or monorepo enrollment
    (which makes the repo an IaC root CI/CD writes to) is refused for anything but CI/CD's own repos."""

    class R:
        def __init__(self, code, data=None):
            self.status_code, self._d, self.text = code, data, ""

        def json(self):
            return self._d

    def run_enroll(self, mode, repo="dev/app"):
        from unittest import mock

        from dashboard import platform
        calls = []
        R = self.R

        class User:          # the developer's session
            def get(self, path, **k):
                return R(200, {"permissions": {"admin": True}, "full_name": repo, "default_branch": "main", "empty": True}) \
                    if path == f"/repos/{repo}" else R(200, [])

            def put(self, path, json=None):
                calls.append(("PUT", path, json))
                return R(204)

            def post(self, path, json=None, **k):
                calls.append(("POST", path, json))
                return R(201, {})

        class Bot:
            def get(self, path, **k):
                return R(200, {"login": "ffwfbot"}) if path == "/user" else R(200, {"permissions": {}})

            def post(self, path, json=None, **k):
                calls.append(("BOT POST", path, None))
                return R(201, {})

        class Forge:
            _cache = {}

            def get(self, path, ttl=None, raw=False):
                return b"owners: [ffwf-iac]\nrepos: [ffwf/cicd-dashboard]\n" if path.startswith(f"/repos/{platform.STATE_REPO}/raw/tenants/_writable.yaml") else None

        with mock.patch.object(platform, "configured", return_value=True), \
                mock.patch.object(platform, "_secret", return_value="s"), \
                mock.patch.object(platform, "tenants", return_value={}), \
                mock.patch.object(platform, "dispatch", return_value=(True, "")), \
                mock.patch.object(enroll, "bot_client", return_value=Bot()):
            done = enroll.enroll(User(), Forge(), "ada", name="my-app", source=f"{FORGE}/{repo}", owner="dev",
                                 mirror=False, private=True, source_token="", hook_url="https://d/hooks/forge", mode=mode)
        return done, calls

    def test_direct_on_a_developers_repo_is_refused(self):
        for mode in ("direct", "monorepo"):
            with self.assertRaises(enroll.EnrollError, msg=mode):
                self.run_enroll(mode)

    def test_wrapped_grants_read_only(self):
        done, calls = self.run_enroll("wrapped")
        grants = [c for c in calls if c[1] == "/repos/dev/app/collaborators/ffwfbot"]
        self.assertEqual(grants, [("PUT", "/repos/dev/app/collaborators/ffwfbot", {"permission": "read"})])

    def test_ci_cds_own_repo_may_be_direct(self):
        done, calls = self.run_enroll("direct", repo="ffwf/cicd-dashboard")
        self.assertTrue(any(c[0] == "BOT POST" and "tenants/my-app.yaml" in c[1] for c in calls))


class FactoryGrants(unittest.TestCase):
    """A grant is the bot as a collaborator, set as the user (an admin of the repo), then recorded."""

    class R:
        def __init__(self, code, data=None):
            self.status_code, self._d, self.text, self.content = code, data, "", b"x"

        def json(self):
            return self._d

    def clients(self, admin=True):
        R, calls = self.R, []

        class User:
            def get(self, path, **k):
                return R(200, {"permissions": {"admin": admin, "push": True}})

            def put(self, path, json=None):
                calls.append(("user PUT", path, json))
                return R(204)

            def delete(self, path):
                calls.append(("user DELETE", path, None))
                return R(204)

        class Bot:
            def get(self, path, **k):
                return R(200, {"login": "ffwfbot"}) if path == "/user" else R(404)

            def post(self, path, json=None):
                calls.append(("bot POST", path, None))
                return R(201)

            def put(self, path, json=None):
                calls.append(("bot PUT", path, None))
                return R(200)

            def request(self, m, path, json=None):
                calls.append((f"bot {m}", path, None))
                return R(200)
        return User(), Bot(), calls

    def test_grant_sets_the_collaborator_as_the_user_then_records_it(self):
        from dashboard import factory
        u, b, calls = self.clients()
        factory.grant(u, b, "ada", "dev/app", "write", 30)
        self.assertEqual(calls[0], ("user PUT", "/repos/dev/app/collaborators/ffwfbot", {"permission": "write"}))
        self.assertEqual(calls[1][:2], ("bot POST", f"/repos/{factory.REPO}/contents/grants/dev/app.yaml"))

    def test_only_an_admin_grants(self):
        from dashboard import factory
        u, b, calls = self.clients(admin=False)
        with self.assertRaises(factory.FactoryError):
            factory.grant(u, b, "ada", "dev/app", "write", None)
        self.assertEqual(calls, [])

    def test_revoke_keeps_read_where_ci_cd_builds_from_the_repo(self):
        from unittest import mock

        from dashboard import factory, platform
        for tenants, want in (({"x": {"repo": "ffwf-iac/x", "sources": [{"repo": "dev/app"}]}}, "user PUT"), ({}, "user DELETE")):
            u, b, calls = self.clients()
            with mock.patch.object(platform, "tenants", return_value=tenants):
                factory.revoke(u, b, None, "ada", "dev/app")
            self.assertEqual(calls[0][0], want)
