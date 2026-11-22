"""Evidence kept as releases on the evidence repo: packages from the release's SBOM (once per sha256),
files served from it, and altered or missing files flagged rather than trusted."""
import hashlib
import json

import httpx
import pytest

from dashboard import sources

SBOM = json.dumps({"components": [{"name": "flask", "version": "3.0.0", "purl": "pkg:pypi/flask@3.0.0"}]}).encode()
URL = "http://forge/cicd/evidence/releases/download/c-local/app/dev/abc/sbom.cdx.json"


def repo(blobs: dict[str, bytes], calls: list):
    def handler(req):
        calls.append(str(req.url))
        b = blobs.get(str(req.url))
        return httpx.Response(200, content=b) if b is not None else httpx.Response(404)
    f = sources.Forgejo(base="http://forge", token="")
    f.http = httpx.Client(base_url="http://forge/api/v1", transport=httpx.MockTransport(handler))
    return sources.StateRepo(f, repo="o/state", cluster="c-local")


def state(sha=None):
    manifest = {"schema": "evidence/v1", "repo": "cicd/evidence", "tag": "c-local/app/dev/abc",
                "release": "http://forge/cicd/evidence/releases/tag/c-local/app/dev/abc",
                "files": {"sbom.cdx.json": {"sha256": sha or hashlib.sha256(SBOM).hexdigest(), "bytes": len(SBOM), "url": URL}}}
    d = "envs/c-local/app/dev/"
    files = {"tenants/app.yaml": b"metadata: {name: app}\nspec: {repo: o/app}\n",
             d + "cicd-env.yaml": b"app: app\ndir: dev\nenv: dev\nimage: r/app@sha256:1\ncommit: c1\n",
             d + "evidence/evidence.json": json.dumps(manifest).encode()}
    return sources.parse_state("h1", files, "c-local")


def test_packages_come_from_the_release_once_per_sbom():
    calls = []
    r = repo({URL: SBOM}, calls)
    for _ in range(2):          # two heads, same SBOM
        st = state()
        r._release_packages(st)
    e = st.envs["app"][0]
    assert [p["name"] for p in e.packages] == ["flask"]
    assert e.evidence_state == "kept"
    assert calls == [URL]


def test_altered_sbom_is_flagged_not_used():
    r = repo({URL: SBOM}, [])
    st = state(sha="0" * 64)
    r._release_packages(st)
    e = st.envs["app"][0]
    assert e.evidence_state == "altered" and e.packages == []


def test_missing_sbom_is_flagged():
    r = repo({}, [])
    st = state()
    r._release_packages(st)
    assert st.envs["app"][0].evidence_state == "missing"


def test_evidence_file_reads_release_or_inline():
    r = repo({URL: SBOM}, [])
    st = state()
    assert r.evidence_file(st, "app", "dev", "evidence/sbom.cdx.json") == SBOM
    assert r.evidence_file(st, "app", "dev", "evidence/ssp.json") is None
    st.files["envs/c-local/app/dev/evidence/ssp.json"] = b"{}"
    assert r.evidence_file(st, "app", "dev", "evidence/ssp.json") == b"{}"
    with pytest.raises(sources.EvidenceAltered):
        repo({URL: b"{}"}, []).evidence_file(st, "app", "dev", "evidence/sbom.cdx.json")
