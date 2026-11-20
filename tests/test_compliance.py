import sys
import unittest
from pathlib import Path

from dashboard import compliance as comp
from dashboard import versions

HERE = Path(__file__).resolve().parent


class Import(unittest.TestCase):
    def test_tenable_rows_become_checks(self):
        rows = comp.parse_tenable((HERE.parent / "examples" / "it-security-scan-demo.csv").read_bytes(), "alice", "scan.csv")
        self.assertEqual(len(rows), 2)                                  # the informational row is skipped
        pkg, hsts = rows
        self.assertEqual(pkg["check"], {"type": "package", "name": "gunicorn", "affected": "<25.0"})
        self.assertEqual(pkg["severity"], "high")
        self.assertEqual(hsts["check"], {"type": "endpoint", "path": "/", "header": "Strict-Transport-Security"})
        self.assertEqual(hsts["source"]["imported_by"], "alice")
        self.assertTrue(pkg["id"].startswith("TEN-990001-"))

    def test_reimport_keeps_status_and_reopens_closed(self):
        rows = comp.parse_tenable((HERE.parent / "examples" / "it-security-scan-demo.csv").read_bytes(), "a", "x.csv")
        led, added, seen = comp.merge_import([], rows)
        self.assertEqual((added, seen), (2, 0))
        led[0]["status"] = "closed"
        led[1]["status"] = "accepted"
        again = comp.parse_tenable((HERE.parent / "examples" / "it-security-scan-demo.csv").read_bytes(), "b", "y.csv")
        led, added, seen = comp.merge_import(led, again)
        self.assertEqual((added, seen), (0, 2))
        self.assertEqual([f["status"] for f in led], ["open", "accepted"])


class Packages(unittest.TestCase):
    def test_release_package_is_unaltered_and_hashed(self):
        files = {"envs/c/demo/prod/evidence/sbom.cdx.json": b"{}", "envs/c/demo/prod/app.yaml": b"a: 1\n",
                 "envs/c/demo/prod/kustomization.yaml": b"x", "envs/c/demo/dev/app.yaml": b"dev"}
        ops, m = comp.release_package("demo-1", "demo", ["prod"], files, "abc", "alice", "", "c")
        self.assertEqual(sorted(m["files"]), ["prod/app.yaml", "prod/evidence/sbom.cdx.json"])
        import hashlib
        self.assertEqual(m["files"]["prod/app.yaml"]["sha256"], hashlib.sha256(b"a: 1\n").hexdigest())
        self.assertEqual(ops[-1]["path"], "releases/demo-1/manifest.json")


class SameRulesAsThePlatform(unittest.TestCase):
    def test_versions_match_cicd_ref_arch(self):
        plat = Path.home() / "Development" / "cicd-ref-arch" / "tools"
        if not (plat / "external.py").exists():
            self.skipTest("cicd-ref-arch not checked out next to this repo")
        sys.path.insert(0, str(plat))
        import external
        for v, spec in [("23.0.0", "<25"), ("3.5.1-r0", "<3.5.0"), ("3.0.0rc1", "<3.0.0"), ("1.2", "==1.2.0")]:
            self.assertEqual(versions.affected(v, spec), external.affected(v, spec), (v, spec))
