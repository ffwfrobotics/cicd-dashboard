"""The read model: tenants, applications, repos, branches, commits, and each commit's destiny.

Built on demand from the state repo and Forgejo (sources.py); nothing is stored.
"""
from __future__ import annotations

import fnmatch
import hashlib
import re
from dataclasses import dataclass, field

from .destiny import Facts, Stage, destiny, overall
from .sources import Env, Forgejo, State, StateRepo

LABEL_MAX = 63


def branch_slug(app: str, branch: str) -> str:
    """The same slug cicd-ref-arch's tools/cicd.py gives a branch (environment directory name)."""
    budget = LABEL_MAX - len(app) - 1
    s = re.sub(r"[^a-z0-9]+", "-", branch.lower()).strip("-") or "x"
    if len(s) > budget:
        s = s[: budget - 7].rstrip("-") + "-" + hashlib.sha1(branch.encode()).hexdigest()[:6]
    return s + "-br" if s in ("dev", "prod") else s


@dataclass
class AppInfo:
    name: str
    tenant: str
    repos: list[str]
    path: str
    owners: list[str]
    dev_branch: str
    exclude: list[str]
    envs: list[Env] = field(default_factory=list)

    def env(self, d: str) -> Env | None:
        return next((e for e in self.envs if e.dir == d), None)


@dataclass
class CommitRow:
    sha: str
    short: str
    message: str
    author: str
    when: str
    branch: str
    repo: str
    stages: list[Stage]
    overall: str


@dataclass
class BranchRow:
    name: str
    repo: str
    env: Env | None
    head: CommitRow
    active: bool


class Model:
    def __init__(self, forge: Forgejo | None = None, state: StateRepo | None = None):
        self.forge = forge or Forgejo()
        self.state_repo = state or StateRepo(self.forge)

    # ------------------------------------------------------------ tenants and applications
    def state(self) -> State:
        return self.state_repo.load()

    def apps(self) -> list[AppInfo]:
        st = self.state()
        out = []
        for name, t in sorted(st.tenants.items()):
            spec = t["spec"]
            cfg = (st.configs.get(name) or {}).get("spec", {}).get("environments", {})
            out.append(AppInfo(
                name=name, tenant=spec.get("tenant", "default"),
                repos=spec.get("repos") or [spec["repo"]], path=spec.get("path", "."), owners=spec.get("owners", []),
                dev_branch=(cfg.get("dev") or {}).get("branch", "master"),
                exclude=(cfg.get("branch") or {}).get("exclude", ["promote/*"]),
                envs=sorted(st.envs.get(name, []), key=lambda e: (e.kind != "prod", e.kind != "dev", e.dir))))
        return out

    def app(self, name: str) -> AppInfo | None:
        return next((a for a in self.apps() if a.name == name), None)

    def tenants(self) -> dict[str, list[AppInfo]]:
        out: dict[str, list[AppInfo]] = {}
        for a in self.apps():
            out.setdefault(a.tenant, []).append(a)
        return out

    # ------------------------------------------------------------ commits
    def _jobs(self, repo: str) -> dict[str, dict[str, dict]]:
        """head_sha -> job name -> its latest task."""
        data = self.forge.get(f"/repos/{repo}/actions/tasks?limit=50") or {}
        out: dict[str, dict[str, dict]] = {}
        for t in sorted(data.get("workflow_runs", []), key=lambda t: t["id"]):
            jobs = out.setdefault(t["head_sha"], {})
            # a later run that skipped this job (a branch delete, say) doesn't hide a real result
            if t["status"] == "skipped" and t["name"] in jobs and jobs[t["name"]]["status"] != "skipped":
                continue
            jobs[t["name"]] = t
        return out

    def facts(self, app: AppInfo, repo: str, commit: dict, branch: str, jobs=None, deploys=None) -> Facts:
        sha = commit["sha"] if "sha" in commit else commit["id"]
        c = commit.get("commit", commit)
        author = (c.get("author") or {}).get("name", "?")
        when = (c.get("author") or {}).get("date") or c.get("timestamp", "")
        f = Facts(sha=sha, branch=branch, dev_branch=app.dev_branch, author=author, when=when,
                  message=c.get("message", "").splitlines()[0] if c.get("message") else "",
                  jobs=(jobs if jobs is not None else self._jobs(repo)).get(sha, {}),
                  branch_excluded=bool(branch) and branch != app.dev_branch
                  and any(fnmatch.fnmatch(branch, p) for p in app.exclude))
        f.jobs = {k: {"status": v["status"], "url": v.get("url")} for k, v in f.jobs.items()}
        st = self.state()
        deploys = deploys if deploys is not None else self.state_repo.deploys(app.name)
        dep = next((d for d in deploys if d.commit == sha), None)
        if dep:
            env_dir = "dev" if dep.env == "dev" else f"branch-{branch_slug(app.name, dep.branch or '')}"
            cur = app.env(env_dir)
            live = bool(cur and cur.commit == sha)
            f.deploy = {"env": dep.env, "env_dir": env_dir, "image": dep.image, "at": dep.at, "run_url": dep.run_url,
                        "hosts": cur.hosts if cur else [], "live": live,
                        "superseded_by": cur.commit if (cur and not live) else None}
            if live:
                f.security, f.failing = cur.security, cur.failing
            else:
                rec = self.state_repo.security_record_at(dep.state_sha, app.name, env_dir)
                if rec:
                    f.security = rec.get("gate")
                    f.failing = [x for x in rec.get("findings", []) if x.get("outcome") == "fail"]
        prod = app.env("prod")
        f.in_prod = bool(prod and prod.commit and prod.commit.startswith(sha[:7]) and sha.startswith(prod.commit[:7]))
        promos = [p for p in st.promotions if p.app == app.name and p.commit and p.commit == sha]
        if promos:
            p = sorted(promos, key=lambda p: (p.state != "done", p.id))[-1] if len(promos) > 1 else promos[0]
            f.promotion = {"id": p.id, "state": p.state, "not_before": p.not_before, "requested_by": p.requested_by,
                           "approval": p.approval, "applied_at": p.applied_at, "pr": p.pr, "security": p.security,
                           "reason": p.reason}
        return f

    def commit_row(self, app: AppInfo, repo: str, commit: dict, branch: str, jobs=None, deploys=None) -> CommitRow:
        f = self.facts(app, repo, commit, branch, jobs, deploys)
        stages = destiny(f)
        return CommitRow(sha=f.sha, short=f.sha[:7], message=f.message, author=f.author, when=f.when,
                         branch=branch, repo=repo, stages=stages, overall=overall(stages))

    def branches(self, app: AppInfo) -> list[BranchRow]:
        deploys = self.state_repo.deploys(app.name)
        rows = []
        for repo in app.repos:
            jobs = self._jobs(repo)
            for b in self.forge.get(f"/repos/{repo}/branches?limit=50") or []:
                env_dir = "dev" if b["name"] == app.dev_branch else f"branch-{branch_slug(app.name, b['name'])}"
                head = self.commit_row(app, repo, b["commit"], b["name"], jobs, deploys)
                excluded = b["name"] != app.dev_branch and any(fnmatch.fnmatch(b["name"], p) for p in app.exclude)
                rows.append(BranchRow(name=b["name"], repo=repo, env=app.env(env_dir), head=head, active=not excluded))
        return sorted(rows, key=lambda r: (r.name != app.dev_branch, r.name))

    def history(self, app: AppInfo, branch: str | None = None, limit: int = 8) -> list[CommitRow]:
        branch = branch or app.dev_branch
        repo = app.repos[0]
        commits = self.forge.get(f"/repos/{repo}/commits?sha={branch}&limit={limit}&stat=false&files=false&verification=false") or []
        jobs, deploys = self._jobs(repo), self.state_repo.deploys(app.name)
        return [self.commit_row(app, repo, c, branch, jobs, deploys) for c in commits]

    def commit(self, app: AppInfo, sha: str, branch: str | None = None) -> tuple[CommitRow, Facts] | None:
        repo = app.repos[0]
        c = self.forge.get(f"/repos/{repo}/git/commits/{sha}?stat=false&files=false&verification=false")
        if not c:
            return None
        if branch is None:
            dep = next((d for d in self.state_repo.deploys(app.name) if d.commit == c["sha"]), None)
            branch = dep.branch if dep else app.dev_branch
        f = self.facts(app, repo, c, branch)
        stages = destiny(f)
        row = CommitRow(sha=f.sha, short=f.sha[:7], message=f.message, author=f.author, when=f.when,
                        branch=branch, repo=repo, stages=stages, overall=overall(stages))
        return row, f
