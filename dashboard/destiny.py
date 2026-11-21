"""A commit's destiny: the stages from push to prod, and where this commit stands on each.

Pure functions over facts already fetched, so the rules are easy to read and to test.

States: ok, warn, fail, run, todo, skip (the templates give each an icon and a colour).
A stage's `detail` is a few words; `tip` is the longer hover text. Dev shows findings as warnings;
the first prod-side stage not yet passed carries what would block there (`blockers`), ahead of time.
"""
from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field

STAGES = [
    ("committed", "Committed"),
    ("contract", "Contract"),
    ("tests", "Tests"),
    ("build", "Build"),
    ("deployed", "Running"),   # deployed, and the runtime check after it (cicd/runtime)
    ("security", "Security"),
    ("assessed", "Assessed"),
    ("review", "Findings"),
    ("promotion", "Promotion"),
    ("approved", "Approved"),
    ("scheduled", "Scheduled"),
    ("prod", "Prod"),
]
PROD_SIDE = ("promotion", "approved", "scheduled", "prod")
# Fewer, bigger checkmarks: the stages grouped by who answers for them (key, label, role, stage keys).
PHASES = [
    ("develop", "Develop", "Developers: commit, test, build, run", ("committed", "contract", "tests", "build", "deployed")),
    ("assess", "Assess", "Sysadmins: scans, self-assessment, IT Security's findings", ("security", "assessed", "review")),
    ("release", "Release", "System owner: approves what goes to prod", PROD_SIDE),
]
RUNNING = {"running", "waiting", "queued", "blocked"}


@dataclass
class Stage:
    key: str
    label: str
    state: str = "todo"
    detail: str = ""
    href: str | None = None
    tip: str = ""              # hover text: the longer explanation
    action: str | None = None  # what a person with write on the app can do here now (e.g. request-promotion)
    blockers: list[dict] = field(default_factory=list)   # what would block prod: [{category, rules}]


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
    not_in_cicd: str = ""             # this branch's pushes skip CI/CD: "paused" or "waiting" (tenant limit)
    not_in_cicd_why: str = ""
    assessment: dict | None = None    # the commit's OSCAL self-assessment (summary)
    contract: dict | None = None      # intake's commit statuses: {state, summary, url, items: [{check, state, description}]}
    runtime: dict | None = None       # the runtime check's commit status (cicd/runtime): {state, summary, url}
    request: dict | None = None       # the latest request-promotion run for it, before its PR: {status, url, actor, at}
    external: list[dict] = field(default_factory=list)   # IT Security's findings and advisories, as tests
    now: dt.datetime | None = None


def job_state(task: dict | None) -> str | None:
    if not task:
        return None
    s = task["status"]
    if s in RUNNING:
        return "run"
    return {"success": "ok", "failure": "fail", "cancelled": "fail", "skipped": "skip"}.get(s, "todo")


def _when(v) -> dt.datetime:
    try:
        return dt.datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return dt.datetime.min.replace(tzinfo=dt.timezone.utc)


def runtime_word(summary: str) -> str:
    """The class word that starts the cicd/runtime description ("crash (app: exits 3). It exits...")."""
    return re.split(r" \(|: |\. ", summary, maxsplit=1)[0]


def destiny(f: Facts) -> list[Stage]:
    st = {k: Stage(k, label) for k, label in STAGES}
    now = f.now or dt.datetime.now(dt.timezone.utc)

    st["committed"].state = "ok"
    st["committed"].detail = f.author

    # the contract (intake, the pipeline's first step): what to fix, or that there's nothing to run
    c, route = st["contract"], job_state(f.jobs.get("route"))
    if f.contract:
        c.state = {"success": "ok", "warning": "warn", "failure": "fail"}.get(f.contract["state"], "todo")
        c.detail = "met" if c.state == "ok" else f.contract["summary"] if c.state == "warn" else "nothing to run"
        c.tip = "\n".join(i["description"] for i in f.contract["items"]) or f.contract["summary"]
        c.href = f.contract.get("url")
    elif route == "run":
        c.state, c.detail = "run", "checking"
    elif route in ("ok", "fail"):
        c.state, c.detail, c.tip = "skip", "not checked", "This run predates the contract check"
    if c.state == "fail":
        for k in ("tests", "build", "deployed"):
            st[k].state, st[k].detail = "skip", ""
        st["tests"].detail, st["tests"].tip = "nothing to run", f.contract["summary"]
        return [st[k] for k, _ in STAGES]

    if f.not_in_cicd and not f.deploy:
        for k in ("tests", "build", "security", "deployed"):
            st[k].state = "skip"
        st["tests"].detail, st["tests"].tip = f.not_in_cicd, f.not_in_cicd_why
        return [st[k] for k, _ in STAGES]

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
            st["security"].detail = f"{n} finding{'s' if n > 1 else ''}" if n else ""
            st["security"].tip = "Reported here; blocks a promotion to prod" if n else "No findings over the threshold"
        else:
            st["security"].state = "skip"
            st["security"].detail = "no record"
        dep = st["deployed"]
        if f.deploy.get("live"):
            dep.state = "ok"
            hosts = f.deploy.get("hosts") or []
            dep.detail = hosts[0] if hosts else f.deploy["env_dir"]
            dep.href = f"https://{hosts[0]}/" if hosts else None
            rt, rs = f.runtime, job_state(f.jobs.get("runtime"))
            if rt:   # what the runtime check saw: one word, the hint in the hover, the run behind it
                dep.state = {"success": "ok", "warning": "warn", "failure": "fail"}.get(rt["state"], "todo")
                dep.detail = runtime_word(rt["summary"])
                dep.tip = rt["summary"] + (f"\n{hosts[0]}" if hosts else "")
                if dep.state != "ok":
                    dep.href = rt.get("url") or dep.href
            elif rs == "run":
                dep.state, dep.detail = "run", "checking"
        else:
            dep.state = "ok"
            dep.detail = "superseded" + (f" by {f.deploy['superseded_by'][:7]}" if f.deploy.get("superseded_by") else "")
            dep.tip = f"Was live in {f.deploy['env_dir']}"
    elif ds == "run" or (s == "ok" and d is None and f.jobs):
        for k in ("build", "security", "deployed"):
            st[k].state = "run" if k == "build" else "todo"
        st["build"].detail = "running"
        st["build"].href = (d or {}).get("url")
    elif ds == "fail":
        st["build"].state = "fail"
        st["build"].detail = "failed"
        st["build"].tip = "The deliver job failed (build, scan or deploy)"
        st["build"].href = d.get("url")
    elif ds == "ok":
        why = "excluded" if f.branch_excluded else "not deployed"
        for k in ("build", "security", "deployed"):
            st[k].state = "skip"
            st[k].detail = why if k == "build" else ""
    elif s == "fail":
        for k in ("build", "security", "deployed"):
            st[k].state = "skip"

    # the commit's OSCAL self-assessment, and IT Security's findings as tests
    a = f.assessment
    if a:
        gaps = assessment_gaps(a)
        n, total = a["counts"]["satisfied"], len(a["objectives"])
        unc = a["coverage"].get("uncovered", 0)
        st["assessed"].state = "warn" if gaps["blocking"] else "ok"
        st["assessed"].detail = f"{n}/{total}"
        st["assessed"].tip = f"{n} of {total} objectives satisfied" + (f", {unc} uncovered" if unc else "") + (
            f". Blocking: {', '.join(gaps['blocking'])}" if gaps["blocking"] else "")
        st["assessed"].href = "controls"
    elif f.deploy:
        st["assessed"].state = "skip"
        st["assessed"].detail = "none"
    ext = f.external or []
    if ext:
        bad = [t for t in ext if t["result"] == "fail"]
        acc = [t for t in ext if t["result"] == "accepted"]
        st["review"].state = "warn" if bad else "ok"
        st["review"].detail = f"{len(bad)} open" if bad else f"{len(acc)} accepted" if acc else f"{len(ext)} fixed"
        st["review"].tip = "; ".join(f"{t['test'].split('/', 1)[1]}: {t['result']}" for t in ext)
        st["review"].href = "findings"
    elif a:
        st["review"].state = "ok"
        st["review"].tip = "Nothing from IT Security"      # no detail: the phase shows the assessment's score

    # promotion side
    p = f.promotion
    on_dev = f.branch == f.dev_branch
    if f.in_prod:
        for k in PROD_SIDE:
            st[k].state = "ok"
    if p:
        pr = p.get("pr") or {}
        st["promotion"].state = "ok" if (pr.get("merged") or p["state"] == "done") else ("run" if pr.get("state") == "open" else "fail" if pr.get("state") == "closed" else "run")
        st["promotion"].detail = (f"#{pr['number']} · " if pr else "") + p["requested_by"]
        st["promotion"].tip = f"Requested by {p['requested_by']}"
        if pr.get("state") == "closed" and not pr.get("merged"):
            st["promotion"].detail = f"#{pr['number']} closed"
        st["promotion"].href = pr.get("url")
        approvers = [a for a in pr.get("approvers", []) if a not in (p["requested_by"], pr.get("author"))]
        merger = pr.get("merged_by")
        if p.get("approval"):
            st["approved"].state = "ok"
            st["approved"].detail = p["approval"].rsplit(" by ", 1)[-1]      # the platform's record: "PR #8 merged by john"
            st["approved"].tip = p["approval"]
        elif approvers or (merger and merger not in (p["requested_by"], pr.get("author"))):
            st["approved"].state = "ok"
            st["approved"].detail = ", ".join(approvers or [merger])
        elif pr.get("merged"):
            st["approved"].state = "fail"
            st["approved"].detail = "self-merged"
            st["approved"].tip = f"Merged by {merger}, who requested it: it won't be applied"
        elif pr.get("state") == "open":
            st["approved"].state = "run"
            st["approved"].detail = "pending"
            st["approved"].tip = f"Awaiting an approver other than {p['requested_by']}"
        nb = p.get("not_before") or ""
        if p["state"] == "done":
            st["scheduled"].state = "ok"
            st["scheduled"].detail = "applied"
            st["scheduled"].tip = f"Applied {str(p.get('applied_at', ''))[:16].replace('T', ' ')} UTC"
        elif pr.get("merged"):
            due = dt.datetime.fromisoformat(nb.replace("Z", "+00:00")) if nb else now
            st["scheduled"].state = "run"
            st["scheduled"].detail = "due" if due <= now else nb[5:16].replace("T", " ")
            st["scheduled"].tip = "Applied within 5 minutes" if due <= now else f"Not before {nb[:16].replace('T', ' ')} UTC"
        if p["state"] == "done" and not f.in_prod:
            st["prod"].state = "ok"
            st["prod"].detail = "superseded"
    elif not f.in_prod:
        superseded = bool(f.deploy and not f.deploy.get("live"))
        st["promotion"].state = "skip" if (not on_dev or superseded) else "todo"
        rq = f.request if (on_dev and not superseded) else None
        rs = rq and job_state({"status": rq["status"]})
        if rs == "ok" and now - _when(rq.get("at")) < dt.timedelta(minutes=10):
            rs = "run"                  # done, and its PR not read yet (the forge is read with a short cache)
        if rs == "run":                 # dispatched; the PR comes when the run finishes
            st["promotion"].state, st["promotion"].detail = "run", "requested"
            st["promotion"].tip = f"Requested by {rq['actor']}: opening the promotion PR"
            st["promotion"].href = rq.get("url")
        elif rs == "fail":
            st["promotion"].state, st["promotion"].detail = "fail", "request failed"
            st["promotion"].tip = f"The request by {rq['actor']} didn't open a PR: see the run"
            st["promotion"].href = rq.get("url")
        if st["promotion"].state in ("todo", "fail"):
            st["promotion"].action = "request-promotion"
        st["promotion"].tip = (f"Merge to {f.dev_branch} to promote" if not on_dev
                               else "Only what dev runs now can be promoted" if superseded else "")
    if f.in_prod:
        st["prod"].detail = "live"

    # blockers to prod, shown ahead of time on the prod side
    if f.failing and not f.in_prod and st["promotion"].state != "skip":
        by: dict[str, set] = {}
        for x in f.failing:
            by.setdefault(x.get("category") or "finding", set()).add(x["rule"])
        first = next((st[k] for k in PROD_SIDE if st[k].state != "ok"), None)
        if first:
            first.blockers = [{"category": c, "rules": sorted(r)} for c, r in sorted(by.items())]
    if f.security and f.security.get("status") == "fail" and not f.deploy:
        st["deployed"].state = "fail"

    return [st[k] for k, _ in STAGES]


# failing evidence of these kinds would block a prod promotion that requires the assessment
BLOCKING_KINDS = ("findings", "scan", "sbom", "ci-result", "gate", "vuln-db", "attested")


def assessment_gaps(a: dict) -> dict:
    """{'blocking': objective ids whose failing evidence would block prod, 'other': the rest unsatisfied}"""
    blocking, other = [], []
    for o in a["objectives"]:
        if o["state"] == "satisfied":
            continue
        bad = [e for e in o.get("evidence", []) if not e["holds"] and (e.get("selector") or "").split(":")[0] in BLOCKING_KINDS]
        (blocking if bad and o["coverage"] not in ("uncovered", "not-applicable") else other).append(o["id"])
    return {"blocking": blocking, "other": other}


@dataclass
class Phase:
    key: str
    label: str
    role: str
    stages: list[Stage]
    state: str = "todo"
    detail: str = ""
    blockers: list[dict] = field(default_factory=list)

    @property
    def tip(self) -> str:
        return " · ".join(f"{s.label}: {s.detail or s.state}" for s in self.stages)


def phases(stages: list[Stage]) -> list[Phase]:
    """The stages folded into PHASES. A phase takes its worst state; its detail is the stage that decides it."""
    by = {s.key: s for s in stages}
    out = []
    for key, label, role, keys in PHASES:
        ss = [by[k] for k in keys if k in by]
        states = {s.state for s in ss}
        state = next((x for x in ("fail", "run", "warn") if x in states), None)
        if not state:
            state = "ok" if "ok" in states else "skip" if ss[0].state == "skip" else "todo" if "todo" in states else "skip"
        if state in ("todo", "skip"):     # nothing has happened yet, or it won't (e.g. a superseded commit can't be promoted)
            out.append(Phase(key, label, role, ss, state, "", [b for s in ss for b in s.blockers]))
            continue
        # the deciding stage: the first one in that state, or (when done) the last one with something to say
        pick = [s for s in ss if s.state == state] if state != "ok" else [s for s in reversed(ss) if s.detail and s.state == "ok"]
        deciding = pick[0] if pick else None
        detail = "" if not deciding else deciding.detail if state == "ok" else \
            f"{deciding.label}: {deciding.detail}" if deciding.detail else deciding.label
        out.append(Phase(key, label, role, ss, state, detail, [b for s in ss for b in s.blockers]))
    return out


def overall(stages: list[Stage]) -> str:
    """One word for a list row: the furthest stage reached and its state."""
    if any(s.state == "run" for s in stages):
        return "run"
    if any(s.state == "fail" for s in stages):
        return "fail"
    if any(s.state == "warn" or s.blockers for s in stages):
        return "warn"
    return "ok"
