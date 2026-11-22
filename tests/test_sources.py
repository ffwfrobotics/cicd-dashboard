"""The platform repo's records as the dashboard reads them: stacks and targets (cicd-ref-arch docs/stacks.md)."""
import json
import unittest

import yaml

from dashboard.sources import parse_state


def env(app, d, kind, **kw):
    return yaml.safe_dump({"app": app, "dir": d, "env": kind, "image": "r/x@sha256:" + "a" * 64, "hosts": [], **kw}).encode()


class Records(unittest.TestCase):
    def test_stacks_and_target_environments(self):
        files = {
            "tenants/x.yaml": yaml.safe_dump({"metadata": {"name": "x"}, "spec": {"repo": "o/x"}}).encode(),
            "clusters/c-nested/target.yaml": yaml.safe_dump({"spec": {"managedBy": "stack/ffwf-iac/stack-ref"}}).encode(),
            "envs/c-local/x/dev/cicd-env.yaml": env("x", "dev", "dev", commit="1" * 40),
            "envs/c-nested/x/prod/cicd-env.yaml": env("x", "prod", "prod", commit="1" * 40, builtOn="c-local"),
            "envs/c-other/x/prod/cicd-env.yaml": env("x", "prod", "prod", commit="2" * 40),     # not a target: not read
            "stacks/c-local/s/runs/7.json": json.dumps({"run": "7", "word": "ready"}).encode(),
            "stacks/c-local/s/runs/12.json": json.dumps({"run": "12", "word": "not-ready x"}).encode(),
        }
        st = parse_state("h", files, "c-local")
        envs = {(e.dir, e.target) for e in st.envs["x"]}
        self.assertEqual(envs, {("dev", None), ("prod", "c-nested")})
        self.assertEqual(st.targets["c-nested"]["managedBy"], "stack/ffwf-iac/stack-ref")
        self.assertEqual([r["run"] for r in st.stacks["s"]["runs"]], ["12", "7"])
        self.assertEqual(st.stacks["s"]["latest"]["word"], "not-ready x")


if __name__ == "__main__":
    unittest.main()
