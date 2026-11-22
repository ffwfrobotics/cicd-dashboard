"""Where the dashboard's facts come from: Forgejo's API and the platform's state repo.

Nothing here writes. Git (the state repo) and Forgejo stay the record; the dashboard is a read
model rebuilt from them, cached for a few seconds.
"""
from __future__ import annotations

import dataclasses
import hashlib

import io
import json
import os
import re
import tarfile
import time
from dataclasses import dataclass, field

import httpx
import yaml

FORGE = os.environ.get("FORGE_URL", "https://forge.goblincorps.com").rstrip("/")
STATE_REPO = os.environ.get("STATE_REPO", "ffwf/cicd-ref-arch")
STATE_BRANCH = os.environ.get("STATE_BRANCH", "master")
CLUSTER = os.environ.get("CLUSTER", "c-local")


def _read_token() -> str:
    """FORGEJO_TOKEN if set; else the platform token (dashboard/platform.py), whose bot can read every
    enrolled repo, private ones and ones under users with a limited profile included; else anonymous."""
    if os.environ.get("FORGEJO_TOKEN"):
        return os.environ["FORGEJO_TOKEN"]
    try:
        d = os.environ.get("PLATFORM_SECRET_DIR", "/var/run/secrets/dashboard-platform")
        with open(os.path.join(d, "token")) as f:
            return f.read().strip()
    except OSError:
        return ""


TOKEN = _read_token()


class Forgejo:
    """A small, cached Forgejo API client, with the read token above (anonymous without one)."""

    def __init__(self, base: str = FORGE, token: str = TOKEN, ttl: float = 8.0):
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"token {token}"
        self.http = httpx.Client(base_url=f"{base}/api/v1", headers=headers, timeout=20)
        self.ttl = ttl
        self._cache: dict[str, tuple[float, object]] = {}

    MAX_TTL = 3600.0

    def get(self, path: str, ttl: float | None = None, raw: bool = False, store: bool = True):
        """GET with a time-bounded cache. Entries older than MAX_TTL are dropped on each miss, so
        per-commit paths don't accumulate; store=False fetches without keeping the body."""
        ttl = self.ttl if ttl is None else ttl
        now = time.monotonic()
        hit = self._cache.get(path)
        if hit and now - hit[0] < ttl:
            return hit[1]
        r = self.http.get(path)
        if r.status_code == 404:
            val = None
        else:
            r.raise_for_status()
            val = r.content if raw else r.json()
        for k in [k for k, (t, _) in self._cache.items() if now - t >= self.MAX_TTL]:
            del self._cache[k]
        if store:
            self._cache[path] = (now, val)
        return val

    def asset(self, url: str, sha256: str) -> bytes:
        """A release asset of the evidence repo (an absolute URL), checked against the sha256 that the
        platform repo's evidence.json records. Not cached: callers keep what they derive from it."""
        r = self.http.get(url, follow_redirects=True)
        if r.status_code == 404:
            raise EvidenceMissing(url)
        r.raise_for_status()
        if hashlib.sha256(r.content).hexdigest() != sha256:
            raise EvidenceAltered(url)
        return r.content


class EvidenceMissing(Exception):
    """A file evidence.json lists isn't on the evidence repo (retention removed it, or someone did)."""


class EvidenceAltered(Exception):
    """A file on the evidence repo doesn't match the sha256 the platform repo recorded for it."""


@dataclass
class Env:
    app: str
    dir: str            # dev | branch-<slug> | prod
    kind: str           # dev | branch | prod
    branch: str | None
    commit: str | None
    image: str
    hosts: list[str]
    rendered_at: str | None
    security: dict | None          # the gate summary from security-record.json
    failing: list[dict] = field(default_factory=list)   # findings with outcome fail
    promotion: str | None = None
    assessment: dict | None = None     # evidence/assessment-summary.json (the OSCAL self-assessment, short)
    external: list[dict] = field(default_factory=list)  # IT Security's findings as tests, this env's last gate
    packages: list[dict] = field(default_factory=list)  # from evidence/sbom.cdx.json: name, version, purl, ecosystem
    sources: list[dict] = field(default_factory=list)   # [{path, repo, commit}]: the source commits it runs (wrapped/monorepo)
    target: str | None = None      # the cluster it runs on, when not this one (docs/stacks.md "Targets")
    evidence: dict | None = None   # evidence/evidence.json: the release on the evidence repo that holds its scans
    evidence_state: str = "inline"  # inline | kept | missing | altered (the SBOM, checked when the head loads)


@dataclass
class Promotion:
    id: str
    app: str
    state: str          # requested (PR open) | pending (merged, not yet applied) | done
    commit: str | None
    image: str
    not_before: str
    requested_by: str
    reason: str
    approval: str | None = None
    separated: bool | None = None     # the platform's record: did a second person approve or merge it
    security: str | None = None
    applied_at: str | None = None
    pr: dict | None = None


@dataclass
class Deploy:
    """A bot commit in the state repo that deployed one app commit to one environment."""
    app: str
    env: str            # dev | branch
    image: str
    branch: str | None
    commit: str         # the app's commit
    state_sha: str      # the state repo commit
    at: str
    run_url: str | None


@dataclass
class State:
    head: str
    cluster: dict
    tenants: dict[str, dict]
    envs: dict[str, list[Env]]
    promotions: list[Promotion]
    configs: dict[str, dict]       # app -> its cicd.yaml as last deployed (dev preferred)
    paused: dict[str, dict]        # app -> {branch: {by, at}}
    limits: dict                   # tenants/_limits.yaml
    fetched: float
    files: dict[str, bytes] = field(default_factory=dict, repr=False)   # envs/ as archived (release packages)
    stacks: dict[str, dict] = field(default_factory=dict)   # stack -> {latest, runs}: stacks/<cluster>/<name>/ (docs/stacks.md)
    targets: dict[str, dict] = field(default_factory=dict)  # target -> clusters/<target>/target.yaml spec


DEPLOY_RE = re.compile(r"^deploy (dev|branch): (\S+) (\S+)")
BODY_RE = re.compile(r"branch (.+), commit ([0-9a-f]{40})")


class StateRepo:
    """The platform's state repo, read as one archive per head commit."""

    def __init__(self, forge: Forgejo, repo: str = STATE_REPO, branch: str = STATE_BRANCH, cluster: str = CLUSTER):
        self.forge, self.repo, self.branch, self.cluster = forge, repo, branch, cluster
        self._state: State | None = None
        self._pkgs: dict[str, list[dict]] = {}     # SBOM sha256 -> its packages (evidence kept as releases)

    def head(self) -> str:
        b = self.forge.get(f"/repos/{self.repo}/branches/{self.branch}", ttl=5)
        return b["commit"]["id"]

    def load(self) -> State:
        """The state at the branch head (cached per head), plus promotions still waiting in their
        PRs: those live on promote/<id> branches until merged, so they aren't in the head yet."""
        base = self._load_head()
        st = dataclasses.replace(base, promotions=base.promotions + self._requested(base))
        self._attach_prs(st)
        return st

    def _requested(self, base: State) -> list[Promotion]:
        known = {p.id for p in base.promotions}
        prs = self.forge.get(f"/repos/{self.repo}/pulls?state=open&limit=50", ttl=15) or []
        out = []
        for pr in prs:
            ref = pr["head"]["ref"]
            if not ref.startswith("promote/") or ref[len("promote/"):] in known:
                continue
            pid = ref[len("promote/"):]
            raw = self.forge.get(f"/repos/{self.repo}/raw/promotions/pending/{pid}/promotion.yaml?ref={pr['head']['sha']}",
                                 ttl=3600, raw=True)
            d = yaml.safe_load(raw) if raw else None
            if d and d.get("cluster") == self.cluster:
                out.append(promotion_of(d, "requested"))
        return out

    def _load_head(self) -> State:
        head = self.head()
        if self._state and self._state.head == head:
            return self._state
        blob = self.forge.get(f"/repos/{self.repo}/archive/{head}.tar.gz", raw=True, store=False)  # parsed state is kept, not the tarball
        files: dict[str, bytes] = {}
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
            for m in tar.getmembers():
                if not m.isfile():
                    continue
                name = m.name.split("/", 1)[1] if "/" in m.name else m.name  # drop the archive's top dir
                if name.startswith(("tenants/", "envs/", "promotions/", "clusters/", "stacks/")):
                    files[name] = tar.extractfile(m).read()
        st = parse_state(head, files, self.cluster)
        self._release_packages(st)
        self._state = st
        return self._state

    def _release_packages(self, st: State):
        """Packages of SBOMs kept on the evidence repo: fetched once per SBOM (by sha256), not per commit."""
        used = set()
        for e in (e for es in st.envs.values() for e in es):
            f = ((e.evidence or {}).get("files") or {}).get("sbom.cdx.json")
            if e.evidence is None or not e.evidence.get("tag"):
                continue
            e.evidence_state = "kept"
            if not f:
                continue
            used.add(f["sha256"])
            if f["sha256"] not in self._pkgs:
                try:
                    self._pkgs[f["sha256"]] = sbom_packages(self.forge.asset(f["url"], f["sha256"]))
                except EvidenceMissing:
                    e.evidence_state = "missing"
                    continue
                except EvidenceAltered:
                    e.evidence_state = "altered"
                    continue
                except httpx.HTTPError:
                    continue            # the forge is away: no packages this time, tried again next head
            e.packages = self._pkgs[f["sha256"]]
        for k in set(self._pkgs) - used:
            del self._pkgs[k]

    def evidence_file(self, st: State, app: str, env_dir: str, rel: str) -> bytes | None:
        """One of an environment's evidence files: inline in the platform repo, or from its release."""
        prefix = f"envs/{self.cluster}/{app}/{env_dir}/"
        if prefix + rel in st.files:
            return st.files[prefix + rel]
        raw = st.files.get(prefix + "evidence/evidence.json")
        m = json.loads(raw) if raw else {}
        f = (m.get("files") or {}).get(rel.removeprefix("evidence/")) if rel.startswith("evidence/") else None
        return self.forge.asset(f["url"], f["sha256"]) if f and f.get("url") else None

    def _attach_prs(self, st: State):
        prs = self.forge.get(f"/repos/{self.repo}/pulls?state=all&limit=50", ttl=15) or []
        by_head = {p["head"]["ref"]: p for p in prs}
        for p in st.promotions:
            pr = by_head.get(f"promote/{p.id}")
            if pr and pr.get("merged") and not pr.get("merged_by"):
                pr = self.forge.get(f"/repos/{self.repo}/pulls/{pr['number']}", ttl=300) or pr  # the list omits merged_by
            if pr:
                reviews = self.forge.get(f"/repos/{self.repo}/pulls/{pr['number']}/reviews", ttl=15) or []
                p.pr = {"number": pr["number"], "url": pr["html_url"], "state": pr["state"],
                        "merged": pr.get("merged", False), "author": pr["user"]["login"],
                        "merged_by": (pr.get("merged_by") or {}).get("login"),
                        "approvers": sorted({r["user"]["login"] for r in reviews if r.get("state") == "APPROVED"}),
                        "title": pr["title"]}

    def deploys(self, app: str, limit: int = 40) -> list[Deploy]:
        """Recent deploy commits for an app: they name the app commit each environment got."""
        commits = self.forge.get(
            f"/repos/{self.repo}/commits?sha={self.branch}&path=envs/{self.cluster}/{app}&limit={limit}&stat=false&files=false&verification=false",
            ttl=10) or []
        out = []
        for c in commits:
            msg = c["commit"]["message"]
            m = DEPLOY_RE.match(msg)
            b = BODY_RE.search(msg)
            if not (m and b):
                continue
            run = next((line for line in msg.splitlines() if line.startswith("http")), None)
            out.append(Deploy(app=app, env=m.group(1), image=m.group(3), branch=b.group(1), commit=b.group(2),
                              state_sha=c["sha"], at=c["commit"]["committer"]["date"], run_url=run))
        return out

    def assessment_at(self, state_sha: str, app: str, env_dir: str) -> dict | None:
        path = f"envs/{self.cluster}/{app}/{env_dir}/evidence/assessment-summary.json"
        raw = self.forge.get(f"/repos/{self.repo}/raw/{path}?ref={state_sha}", ttl=3600, raw=True)
        return json.loads(raw) if raw else None

    def security_record_at(self, state_sha: str, app: str, env_dir: str) -> dict | None:
        path = f"envs/{self.cluster}/{app}/{env_dir}/security-record.json"
        raw = self.forge.get(f"/repos/{self.repo}/raw/{path}?ref={state_sha}", ttl=3600, raw=True)
        return json.loads(raw) if raw else None


def promotion_of(d: dict, state: str) -> Promotion:
    return Promotion(
        id=d["id"], app=d["app"], state=state, commit=d.get("commit"), image=d["image"],
        not_before=d.get("notBefore", ""), requested_by=d.get("requestedBy", ""), reason=d.get("reason", ""),
        approval=d.get("approval"), security=d.get("security"), applied_at=d.get("appliedAt"),
        separated=(d.get("approvalRecord") or {}).get("separated"))


def parse_state(head: str, files: dict[str, bytes], cluster: str) -> State:
    y = lambda p: yaml.safe_load(files[p]) if p in files else None  # noqa: E731
    tenants = {}
    for p in files:
        if p.startswith("tenants/") and p.endswith(".yaml") and not p.startswith("tenants/_"):
            t = yaml.safe_load(files[p])
            tenants[t["metadata"]["name"]] = t
    envs: dict[str, list[Env]] = {}
    target_names = [m.group(1) for p in files if (m := re.match(r"clusters/([^/]+)/target\.yaml$", p))]
    prefix = f"envs/{cluster}/"
    for p in sorted(files):
        on = next((t for t in target_names if p.startswith(f"envs/{t}/")), None)
        if (p.startswith(prefix) or on) and p.endswith("/cicd-env.yaml"):
            meta = yaml.safe_load(files[p])
            d = p[: -len("cicd-env.yaml")]
            rec = json.loads(files[d + "security-record.json"]) if d + "security-record.json" in files else None
            summ = json.loads(files[d + "evidence/assessment-summary.json"]) if d + "evidence/assessment-summary.json" in files else None
            envs.setdefault(meta["app"], []).append(Env(
                app=meta["app"], dir=meta["dir"], kind=meta["env"], branch=meta.get("branch"),
                commit=meta.get("commit"), image=meta["image"], hosts=meta.get("hosts", []),
                rendered_at=meta.get("renderedAt"), security=(rec or {}).get("gate"),
                failing=[f for f in (rec or {}).get("findings", []) if f.get("outcome") == "fail"],
                promotion=meta.get("promotion"), assessment=summ, external=(rec or {}).get("external") or [],
                packages=sbom_packages(files.get(d + "evidence/sbom.cdx.json")), sources=meta.get("sources") or [], target=on,
                evidence=json.loads(files[d + "evidence/evidence.json"]) if d + "evidence/evidence.json" in files else None))
    paused = {}
    for p in files:
        m = re.match(rf"{re.escape(prefix)}([^/]+)/paused.yaml$", p)
        if m:
            paused[m.group(1)] = (yaml.safe_load(files[p]) or {}).get("branches") or {}
    configs: dict[str, dict] = {}
    for p in sorted(files, key=lambda p: (not p.endswith("/dev/cicd.yaml"), p)):
        if p.startswith(prefix) and p.endswith("/cicd.yaml"):
            c = yaml.safe_load(files[p])
            configs.setdefault(c["metadata"]["name"], c)
    promotions = []
    for p in sorted(files):
        m = re.match(r"promotions/(pending|done)/([^/]+)/promotion.yaml$", p)
        if not m:
            continue
        d = yaml.safe_load(files[p])
        if d.get("cluster") != cluster:
            continue
        promotions.append(promotion_of(d, m.group(1)))
    stacks: dict[str, dict] = {}
    for p in files:
        m = re.match(rf"stacks/{re.escape(cluster)}/([^/]+)/runs/([^/]+)\.json$", p)
        if m:
            try:
                stacks.setdefault(m.group(1), {"runs": []})["runs"].append(json.loads(files[p]))
            except ValueError:
                continue
    for s in stacks.values():
        s["runs"].sort(key=lambda r: int(r.get("run") or 0) if str(r.get("run", "")).isdigit() else 0, reverse=True)
        s["latest"] = s["runs"][0] if s["runs"] else None
    targets = {}
    for p in files:
        m = re.match(r"clusters/([^/]+)/target\.yaml$", p)
        if m:
            targets[m.group(1)] = (yaml.safe_load(files[p]) or {}).get("spec") or {}
    return State(head=head, cluster=y(f"clusters/{cluster}/cicd-cluster.yaml") or {}, tenants=tenants, stacks=stacks, targets=targets,
                 envs=envs, promotions=promotions, configs=configs, paused=paused,
                 limits=y("tenants/_limits.yaml") or {}, fetched=time.time(),
                 files={k: v for k, v in files.items() if k.startswith(prefix) or any(k.startswith(f"envs/{t}/") for t in target_names)})


def sbom_packages(raw: bytes | None) -> list[dict]:
    if not raw:
        return []
    out = []
    for c in json.loads(raw).get("components") or []:
        purl = c.get("purl") or ""
        eco = purl[4:].split("/", 1)[0] if purl.startswith("pkg:") else ""
        if c.get("name") and c.get("version"):
            out.append({"name": c["name"], "version": c["version"], "purl": purl, "ecosystem": eco})
    return out
