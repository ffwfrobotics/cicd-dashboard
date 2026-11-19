"""A commit's destiny: the stages from push to prod, and where this commit stands on each.

Pure functions over facts already fetched, so the rules are easy to read and to test.

Glyphs (state):  ok ✓ green · warn ⚠ yellow · fail ✗ red · run ◌ spinner · todo ○ grey · skip ⊘ grey
Dev shows findings as warnings; the prod-side stages show what would block there, ahead of time.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

STAGES = [
    ("committed", "Committed"),
    ("tests", "Tests"),
    ("build", "Build"),
    ("security", "Security"),
    ("deployed", "Deployed"),
    ("assessed", "Assessed"),
    ("review", "Review"),
    ("promotion", "Promotion PR"),
    ("approved", "Approved"),
    ("scheduled", "Scheduled"),
    ("prod", "In prod"),
]
PROD_SIDE = {"promotion", "approved", "scheduled", "prod"}
GLYPH = {"ok": "✓", "warn": "⚠", "fail": "✗", "run": "◌", "todo": "○", "skip": "⊘"}
RUNNING = {"running", "waiting", "queued", "blocked"}


@dataclass
class Stage:
    key: str
    label: str
    state: str = "todo"
    detail: str = ""
    href: str | None = None
    preview: str = ""          # prod-side only: "would block at prod: ..."

    @property
    def glyph(self) -> str:
        return GLYPH[self.state]


@dataclass
class Facts:
    sha: str
    branch: str | None
    dev_branch: str
    author: str
    when: str
    message: str
    jobs: dict[str, dict] = field(default_factory=dict)         # job name -> latest task {status, url}
    deploy: dict | None = None        # {env, env_dir, image, at, run_url, hosts, live: bool, superseded_by}
    security: dict | None = None      # gate summary {status, counts, blocking, ...}
    failing: list[dict] = field(default_factory=list)           # findings that fail (dev policy)
    promotion: dict | None = None     # {id, state, not_before, requested_by, approval, applied_at, pr, security}
    in_prod: bool = False
    prod_superseded: bool = False
    branch_excluded: bool = False
    now: dt.datetime | None = None


def job_state(task: dict | None) -> str | None:
    if not task:
        return None
    s = task["status"]
    if s in RUNNING:
        return "run"
    return {"success": "ok", "failure": "fail", "cancelled": "fail", "skipped": "skip"}.get(s, "todo")


def destiny(f: Facts) -> list[Stage]:
    st = {k: Stage(k, label) for k, label in STAGES}
    now = f.now or dt.datetime.now(dt.timezone.utc)

    st["committed"].state = "ok"
    st["committed"].detail = f"{f.author} · {f.when[:16].replace('T', ' ')}"

    # tests
    t = f.jobs.get("test")
    s = job_state(t)
    if s:
        st["tests"].state = s
        st["tests"].detail = {"ok": "passed", "fail": "failed", "run": "running", "skip": "skipped"}.get(s, t["status"])
        st["tests"].href = t.get("url")

    # build, security, deployed: the deliver job, and what it left in the state repo
    d = f.jobs.get("deliver")
    ds = job_state(d)
    if f.deploy:
        st["build"].state = "ok"
        st["build"].detail = f.deploy["image"].split("@")[-1][:19]
        st["build"].href = f.deploy.get("run_url")
        sec = f.security or {}
        if sec:
            st["security"].state = {"pass": "ok", "warn": "warn", "fail": "fail"}.get(sec.get("status"), "todo")
            n = len(f.failing)
            st["security"].detail = "no findings over the threshold" if not n else f"{n} finding{'s' if n > 1 else ''} (report-only here)"
        else:
            st["security"].state = "skip"
            st["security"].detail = "no record (built before the security node)"
        dep = st["deployed"]
        if f.deploy.get("live"):
            dep.state = "ok"
            hosts = f.deploy.get("hosts") or []
            dep.detail = hosts[0] if hosts else f.deploy["env_dir"]
            dep.href = f"https://{hosts[0]}/" if hosts else None
        else:
            dep.state = "ok"
            dep.detail = f"was live in {f.deploy['env_dir']}; superseded" + (
                f" by {f.deploy['superseded_by'][:7]}" if f.deploy.get("superseded_by") else "")
    elif ds == "run" or (s == "ok" and d is None and f.jobs):
        for k in ("build", "security", "deployed"):
            st[k].state = "run" if k == "build" else "todo"
        st["build"].detail = "deliver running"
        st["build"].href = (d or {}).get("url")
    elif ds == "fail":
        st["build"].state = "fail"
        st["build"].detail = "deliver failed (build, scan or deploy): open the run"
        st["build"].href = d.get("url")
    elif ds == "ok":
        why = "excluded branch" if f.branch_excluded else "not deployed (excluded, or over the tenant limit)"
        for k in ("build", "security", "deployed"):
            st[k].state = "skip"
            st[k].detail = why if k == "build" else ""
    elif s == "fail":
        for k in ("build", "security", "deployed"):
            st[k].state = "skip"
        st["build"].detail = "tests failed"

    # assessment and review: Plan 2 (OSCAL) is not built yet
    st["assessed"].detail = "OSCAL self-assessment: coming"
    st["review"].detail = "findings triage: coming"

    # promotion side
    p = f.promotion
    on_dev = f.branch == f.dev_branch
    if f.in_prod:
        for k in PROD_SIDE:
            st[k].state = "ok"
    if p:
        pr = p.get("pr") or {}
        st["promotion"].state = "ok" if (pr.get("merged") or p["state"] == "done") else ("run" if pr.get("state") == "open" else "fail" if pr.get("state") == "closed" else "run")
        st["promotion"].detail = f"#{pr['number']} by {p['requested_by']}" if pr else f"requested by {p['requested_by']}"
        if pr.get("state") == "closed" and not pr.get("merged"):
            st["promotion"].detail += ": closed without merging"
        st["promotion"].href = pr.get("url")
        approvers = [a for a in pr.get("approvers", []) if a not in (p["requested_by"], pr.get("author"))]
        merger = pr.get("merged_by")
        if p.get("approval"):
            st["approved"].state = "ok"
            st["approved"].detail = p["approval"]
        elif approvers or (merger and merger not in (p["requested_by"], pr.get("author"))):
            st["approved"].state = "ok"
            st["approved"].detail = "approved by " + ", ".join(approvers or [merger])
        elif pr.get("merged"):
            st["approved"].state = "fail"
            st["approved"].detail = f"merged by {merger}, who requested it: the platform won't apply this"
        elif pr.get("state") == "open":
            st["approved"].state = "run"
            st["approved"].detail = f"waiting for someone other than {p['requested_by']}"
        nb = p.get("not_before") or ""
        if p["state"] == "done":
            st["scheduled"].state = "ok"
            st["scheduled"].detail = f"applied {str(p.get('applied_at', ''))[:16].replace('T', ' ')}"
        elif pr.get("merged"):
            due = dt.datetime.fromisoformat(nb.replace("Z", "+00:00")) if nb else now
            st["scheduled"].state = "run"
            st["scheduled"].detail = "due now: applying within 5 minutes" if due <= now else f"not before {nb[:16].replace('T', ' ')}"
        if p["state"] == "done" and not f.in_prod:
            st["prod"].state = "ok"
            st["prod"].detail = "was in prod; superseded"
    elif not f.in_prod:
        superseded = bool(f.deploy and not f.deploy.get("live"))
        st["promotion"].state = "skip" if (not on_dev or superseded) else "todo"
        st["promotion"].detail = (f"merge to {f.dev_branch} to promote" if not on_dev
                                  else "superseded: only what dev runs now can be promoted" if superseded
                                  else "ready to request" if f.deploy else "")
    if f.in_prod:
        st["prod"].detail = "running in prod now"

    # blockers to prod, shown ahead of time on the prod side
    if f.failing and not f.in_prod and st["promotion"].state != "skip":
        rules = ", ".join(sorted({x["rule"] for x in f.failing}))[:120]
        for k in PROD_SIDE:
            if st[k].state not in ("ok",):
                st[k].preview = f"would block at prod: {rules}"
    if f.security and f.security.get("status") == "fail" and not f.deploy:
        st["deployed"].state = "fail"

    return [st[k] for k, _ in STAGES]


def overall(stages: list[Stage]) -> str:
    """One word for a list row: the furthest stage reached and its state."""
    if any(s.state == "run" for s in stages):
        return "run"
    if any(s.state == "fail" for s in stages):
        return "fail"
    if any(s.state == "warn" or s.preview for s in stages):
        return "warn"
    return "ok"
