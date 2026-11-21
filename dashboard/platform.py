"""The dashboard's side of the platform-owned pipeline (cicd-ref-arch .forgejo/workflows/pipeline.yaml).

App repos hold no workflow and no token. The dashboard:
- turns the forge's push webhooks on enrolled repos into dispatches of the pipeline;
- dispatches self-service actions for users with write on the app repo, naming them;
- reads each app commit's jobs from the platform repo's pipeline runs (told apart by their inputs).

The platform token (it can dispatch workflows in the platform repo) and the webhook secret are
files in /var/run/secrets/dashboard-platform (`token`, `hook-secret`), created out of band in dev
and prod only. Without them the dashboard reads as before and refuses to dispatch.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path

import httpx
import yaml

from .sources import FORGE, STATE_BRANCH, STATE_REPO, Forgejo

SECRET_DIR = Path(os.environ.get("PLATFORM_SECRET_DIR", "/var/run/secrets/dashboard-platform"))
WORKFLOW = "pipeline.yaml"
ZERO = "0" * 40


def _secret(name: str) -> str:
    try:
        return (SECRET_DIR / name).read_text().strip()
    except OSError:
        return ""


def configured() -> bool:
    return bool(_secret("token"))


def dispatch(inputs: dict) -> tuple[bool, str]:
    """Start the platform pipeline. (ok, message)"""
    token = _secret("token")
    if not token:
        return False, "the dashboard has no platform token here"
    r = httpx.post(f"{FORGE}/api/v1/repos/{STATE_REPO}/actions/workflows/{WORKFLOW}/dispatches",
                   headers={"Authorization": f"token {token}", "Accept": "application/json"},
                   json={"ref": STATE_BRANCH, "inputs": {k: str(v) for k, v in inputs.items()}}, timeout=20)
    if r.status_code in (200, 201, 204):
        return True, ""
    return False, f"the forge answered {r.status_code}"


def signature_ok(body: bytes, sig: str) -> bool:
    key = _secret("hook-secret")
    if not key or not sig:
        return False
    want = hmac.new(key.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, sig.strip().lower().removeprefix("sha256="))


def tenants(forge: Forgejo) -> dict[str, dict]:
    """Enrolled apps (tenants/<app>.yaml in the platform repo): name -> spec."""
    out = {}
    for f in forge.get(f"/repos/{STATE_REPO}/contents/tenants?ref={STATE_BRANCH}", ttl=60) or []:
        if f["type"] != "file" or f["name"].startswith("_") or not f["name"].endswith(".yaml"):
            continue
        raw = forge.get(f"/repos/{STATE_REPO}/raw/tenants/{f['name']}?ref={STATE_BRANCH}", ttl=60, raw=True)
        try:
            t = yaml.safe_load(raw or b"") or {}
            out[t["metadata"]["name"]] = t.get("spec") or {}
        except (yaml.YAMLError, KeyError, TypeError):
            continue
    return out


def on_push(forge: Forgejo, event: str, payload: dict) -> list[str]:
    """A forge webhook: dispatch the pipeline for each app enrolled from this repo. Returns what it did."""
    repo = (payload.get("repository") or {}).get("full_name", "")
    ref = payload.get("ref", "")
    if event != "push" or not ref.startswith("refs/heads/"):
        return []
    branch, sha = ref[len("refs/heads/"):], payload.get("after", "")
    who = (payload.get("pusher") or {}).get("login") or (payload.get("pusher") or {}).get("username") or ""
    done = []
    for name, spec in tenants(forge).items():
        if spec.get("repo") != repo or repo == STATE_REPO:
            continue
        if sha == ZERO:   # a branch deleted: the environments workflow removes its environment
            ok, _ = environments(forge)
            done.append(f"{name}: {branch} deleted" + ("" if ok else " (cleanup within 5 minutes)"))
            continue
        if already_run(forge, name, sha):   # a redelivery or test delivery: don't rebuild what built or is building
            done.append(f"{name}: {branch} {sha[:7]} already run")
            continue
        ok, msg = dispatch({"app": name, "branch": branch, "sha": sha, "action": "deploy", "actor": who})
        done.append(f"{name}: {branch} {sha[:7]}" + ("" if ok else f" not started: {msg}"))
    # a push to an app's source (wrapped and monorepo modes, docs/enrollment.md): move its submodule
    # in the app's IaC root; that commit is then an ordinary push there, and deploys
    for name, spec in tenants(forge).items():
        if repo not in [x.get("repo") for x in spec.get("sources") or []]:
            continue
        ok, msg = dispatch({"app": name, "branch": branch, "sha": sha, "action": "bump", "source": repo, "actor": who})
        done.append(f"{name}: bump from {repo} {branch} {sha[:7]}" + ("" if ok else f" not started: {msg}"))
    return done


def already_run(forge: Forgejo, app: str, sha: str) -> bool:
    """A recent pipeline run for this app commit that hasn't failed (a failed one may be retried)."""
    runs = (forge.get(f"/repos/{STATE_REPO}/actions/runs?workflow_id={WORKFLOW}&limit=50", ttl=0) or {}).get("workflow_runs") or []
    for r in runs:
        try:
            inp = json.loads(r.get("event_payload") or "{}").get("inputs") or {}
        except ValueError:
            continue
        if inp.get("app") == app and inp.get("sha") == sha and (inp.get("action") or "deploy") == "deploy" \
                and r.get("status") not in ("failure", "cancelled"):
            return True
    return False


def promotion_requests(forge: Forgejo, app: str) -> dict[str, dict]:
    """app commit sha -> its latest request-promotion run: {status, url, actor, at}. The run turns the
    request into a promotion PR in a minute or two; until then this is the only sign of it."""
    runs = (forge.get(f"/repos/{STATE_REPO}/actions/runs?workflow_id={WORKFLOW}&limit=50", ttl=4) or {}).get("workflow_runs") or []
    out: dict[str, dict] = {}
    for r in sorted(runs, key=lambda r: r.get("index_in_repo", 0), reverse=True):
        try:
            inp = json.loads(r.get("event_payload") or "{}").get("inputs") or {}
        except ValueError:
            continue
        if inp.get("app") == app and inp.get("action") == "request-promotion" and inp.get("sha"):
            out.setdefault(inp["sha"], {"status": r.get("status"), "url": r.get("html_url"), "actor": inp.get("actor", ""),
                                        "at": r.get("created")})
    return out


def environments(forge: Forgejo) -> tuple[bool, str]:
    token = _secret("token")
    if not token:
        return False, "no platform token"
    r = httpx.post(f"{FORGE}/api/v1/repos/{STATE_REPO}/actions/workflows/environments.yaml/dispatches",
                   headers={"Authorization": f"token {token}"}, json={"ref": STATE_BRANCH}, timeout=20)
    return r.status_code in (200, 201, 204), str(r.status_code)


def pipeline_jobs(forge: Forgejo, app: str, pages: int = 4) -> dict[str, dict[str, dict]]:
    """app commit sha -> job name -> its latest task, from the platform pipeline's runs for `app`."""
    runs = (forge.get(f"/repos/{STATE_REPO}/actions/runs?workflow_id={WORKFLOW}&limit=50", ttl=4) or {}).get("workflow_runs") or []
    mine: dict[int, str] = {}
    for r in runs:
        try:
            inp = json.loads(r.get("event_payload") or "{}").get("inputs") or {}
        except ValueError:
            continue
        if inp.get("app") == app and inp.get("sha") and (inp.get("action") or "deploy") == "deploy":
            mine[r["index_in_repo"]] = inp["sha"]
    out: dict[str, dict[str, dict]] = {}
    if not mine:
        return out
    tasks = []
    for page in range(1, pages + 1):
        got = (forge.get(f"/repos/{STATE_REPO}/actions/tasks?limit=50&page={page}", ttl=4) or {}).get("workflow_runs") or []
        tasks += got
        if len(got) < 50 or min(t["run_number"] for t in got) < min(mine):
            break
    for t in sorted(tasks, key=lambda t: t["id"]):
        sha = mine.get(t["run_number"]) if t.get("workflow_id") == WORKFLOW else None
        if not sha or t["name"] == "manage":
            continue
        jobs = out.setdefault(sha, {})
        if t["status"] == "skipped" and t["name"] in jobs and jobs[t["name"]]["status"] != "skipped":
            continue
        jobs[t["name"]] = t
    return out
