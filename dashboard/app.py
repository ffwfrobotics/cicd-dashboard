"""cicd-dashboard: the information system owner's view of their applications on cicd-ref-arch.

Tenants, applications, environments, branches and each commit's road to prod (steps 1-2); the
commit's OSCAL self-assessment and control coverage (3); IT Security's findings as failing tests
(4); advisories matched against live SBOMs (5); release packages for IT Security (6). Pages update
live over server-sent events; the same data is JSON under /api/.
"""
from __future__ import annotations

import asyncio
import dataclasses
import datetime as dt
import re
import hashlib
import json
import os
from pathlib import Path

import yaml
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import auth
from . import compliance as comp
from .destiny import GLYPH, PROD_SIDE, STAGES
from .model import Model
from .sources import STATE_REPO

HERE = Path(__file__).parent
VERSION = "0.2.0"

app = FastAPI(title="cicd-dashboard", version=VERSION, docs_url="/api/docs", redoc_url=None)
app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
templates = Jinja2Templates(directory=HERE / "templates")
templates.env.globals.update(STAGES=STAGES, GLYPH=GLYPH, PROD_SIDE=PROD_SIDE, VERSION=VERSION,
                             COMMIT=os.environ.get("APP_COMMIT", "dev"), FORGE=os.environ.get("FORGE_URL", "https://forge.goblincorps.com"))
model = Model()


def page(request: Request, name: str, **ctx):
    user = auth.current(request)
    ctx.setdefault("user", user)
    ctx.setdefault("auth_enabled", auth.ENABLED)
    ctx.setdefault("msg", request.query_params.get("msg", ""))
    if "a" in ctx and user is not None:
        ctx.setdefault("can_write", can_write(user, ctx["a"]))
    ctx.setdefault("can_write", False)
    return templates.TemplateResponse(request, name, ctx)


_perm_cache: dict[tuple[str, str], tuple[float, bool]] = {}


def can_write(user, a) -> bool:
    """Write on the app's repo: the platform's test for self-service on its environments."""
    import time
    key = (user.login, a.repos[0])
    hit = _perm_cache.get(key)
    if hit and time.time() - hit[0] < 60:
        return hit[1]
    with auth.as_user(user) as c:
        r = c.get(f"/repos/{a.repos[0]}")
        ok = r.status_code == 200 and bool(r.json().get("permissions", {}).get("push"))
    _perm_cache[key] = (time.time(), ok)
    return ok


def app_or_404(name: str):
    a = model.app(name)
    if a is None:
        raise HTTPException(404, f"no enrolled application {name!r}")
    return a


# ---------------------------------------------------------------- pages and fragments


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return page(request, "index.html", tenants=model.tenants(), state=model.state())


@app.get("/a/{name}", response_class=HTMLResponse)
def app_page(request: Request, name: str):
    a = app_or_404(name)
    return page(request, "app.html", a=a, branches=model.branches(a), history=model.history(a), usage=model.usage(a.tenant))


@app.get("/a/{name}/fragment/body", response_class=HTMLResponse)
def app_body(request: Request, name: str):
    a = app_or_404(name)
    return page(request, "_app_body.html", a=a, branches=model.branches(a), history=model.history(a), usage=model.usage(a.tenant))


@app.get("/a/{name}/c/{sha}", response_class=HTMLResponse)
def commit_page(request: Request, name: str, sha: str, branch: str | None = None):
    a = app_or_404(name)
    got = model.commit(a, sha, branch)
    if got is None:
        raise HTTPException(404, f"no commit {sha} in {a.repos[0]}")
    row, facts = got
    return page(request, "commit.html", a=a, c=row, f=facts)


@app.get("/a/{name}/c/{sha}/fragment", response_class=HTMLResponse)
def commit_fragment(request: Request, name: str, sha: str, branch: str | None = None):
    a = app_or_404(name)
    got = model.commit(a, sha, branch)
    if got is None:
        raise HTTPException(404)
    row, facts = got
    return page(request, "_commit_body.html", a=a, c=row, f=facts)


# ---------------------------------------------------------------- step 3: controls and OSCAL


@app.get("/a/{name}/controls", response_class=HTMLResponse)
def controls_page(request: Request, name: str):
    a = app_or_404(name)
    return page(request, "controls.html", a=a, t=model.controls(a))


OSCAL_DOCS = {"assessment-results": "evidence/assessment-results.json", "assessment-summary": "evidence/assessment-summary.json",
              "ssp": "evidence/ssp.json", "sbom": "evidence/sbom.cdx.json", "security": "evidence/security.json"}


@app.get("/api/apps/{name}/envs/{env}/{doc}")
def api_env_doc(name: str, env: str, doc: str):
    """The records an environment keeps, unaltered: OSCAL assessment results and SSP, SBOM, security record."""
    app_or_404(name)
    if doc not in OSCAL_DOCS:
        raise HTTPException(404, f"one of {', '.join(OSCAL_DOCS)}")
    st = model.state()
    raw = st.files.get(f"envs/{model.state_repo.cluster}/{name}/{env}/{OSCAL_DOCS[doc]}")
    if raw is None:
        raise HTTPException(404, f"{env} keeps no {doc}")
    return Response(raw, media_type="application/json")


# ---------------------------------------------------------------- step 4: IT Security's findings


def compliance_access(user) -> dict | None:
    if user is None:
        return None
    with auth.as_user(user) as c:
        return comp.access(c, user.login)


@app.get("/a/{name}/findings", response_class=HTMLResponse)
def findings_page(request: Request, name: str):
    a = app_or_404(name)
    user = auth.current(request)
    perms = compliance_access(user)
    led = []
    if perms:
        with auth.as_user(user) as c:
            led = comp.ledger(c, user.login, name)
    results = {e.dir: {t["test"].split("/", 1)[1]: t for t in e.external if t["test"].startswith("external/")} for e in a.envs}
    return page(request, "findings.html", a=a, ledger=led, perms=perms, results=results, repo=comp.COMPLIANCE_REPO,
                today=dt.date.today().isoformat())


def require_compliance_write(request: Request, csrf: str):
    user = auth.require(request)
    auth.check_csrf(user, csrf)
    perms = compliance_access(user)
    if not perms or not perms.get("push"):
        raise HTTPException(403, f"you need write access to {comp.COMPLIANCE_REPO} for this")
    return user


@app.post("/a/{name}/findings/import")
async def findings_import(request: Request, name: str, csrf: str = Form(""), file: UploadFile = File(...)):
    user = require_compliance_write(request, csrf)
    app_or_404(name)
    data = await file.read()
    new = comp.parse_tenable(data, user.login, file.filename or "upload.csv")
    if not new:
        return back(f"/a/{name}/findings", "No findings in that file (a Tenable CSV with Plugin ID, Host, Risk, Name...).")
    with auth.as_user(user) as c:
        led, added, seen = comp.merge_import(comp.ledger(c, user.login, name), new)
        ok, err = comp.save_ledger(c, name, led, f"ledger {name}: import {file.filename} ({added} new, {seen} seen again)")
    comp.forget(user.login)
    if not ok:
        return back(f"/a/{name}/findings", f"Not saved: the forge answered {err}")
    return back(f"/a/{name}/findings", f"Imported {added} new findings ({seen} already known) as {user.login}. "
                                        "Every environment of the app is re-assessed within a few minutes, without a rebuild.")


@app.post("/a/{name}/findings/{fid}/{verb}")
def findings_act(request: Request, name: str, fid: str, verb: str, csrf: str = Form(""), reason: str = Form(""),
                 expires: str = Form("")):
    user = require_compliance_write(request, csrf)
    app_or_404(name)
    if verb not in ("accept", "close", "reopen"):
        raise HTTPException(400, "accept, close or reopen")
    if verb in ("accept", "close") and not reason.strip():
        return back(f"/a/{name}/findings", "Say why: the reason goes to the assessor with the claim.")
    if verb == "accept":
        try:
            if dt.date.fromisoformat(expires) <= dt.date.today():
                raise ValueError
        except ValueError:
            return back(f"/a/{name}/findings", "A risk acceptance needs an expiry date in the future (YYYY-MM-DD).")
    with auth.as_user(user) as c:
        led = comp.ledger(c, user.login, name)
        f = next((x for x in led if x["id"] == fid), None)
        if f is None:
            raise HTTPException(404, "no such finding")
        if verb == "accept":
            f["status"], f["accepted"] = "accepted", {"by": user.login, "at": comp.now(), "reason": reason.strip(), "expires": expires}
        elif verb == "close":
            f["status"], f["closed"] = "closed", {"by": user.login, "at": comp.now(), "reason": reason.strip()}
        else:
            f["status"] = "open"
            f.pop("accepted", None)
            f.pop("closed", None)
        ok, err = comp.save_ledger(c, name, led, f"ledger {name}: {verb} {fid}" + (f": {reason.strip()[:80]}" if reason else ""))
    comp.forget(user.login)
    return back(f"/a/{name}/findings", (f"{fid}: {verb}ed as {user.login}; re-assessing." if ok else f"Not saved: {err}"))


# ---------------------------------------------------------------- step 5: advisories


@app.get("/advisories", response_class=HTMLResponse)
def advisories_page(request: Request):
    user = auth.current(request)
    perms = compliance_access(user)
    advs = []
    if perms:
        with auth.as_user(user) as c:
            advs = comp.advisories(c, user.login)
    hits = {a["id"]: model.advisory_hits(a) for a in advs}
    return page(request, "advisories.html", advs=advs, hits=hits, perms=perms, osv=None, repo=comp.COMPLIANCE_REPO,
                npkgs=len(model.live_packages()))


@app.post("/advisories")
def advisories_announce(request: Request, csrf: str = Form(""), id: str = Form(...), title: str = Form(""),
                        severity: str = Form("high"), name: str = Form(...), ecosystem: str = Form(""),
                        affected: str = Form(...), fixed: str = Form(""), source: str = Form("")):
    user = require_compliance_write(request, csrf)
    aid = re.sub(r"[^A-Za-z0-9._-]+", "-", id.strip())[:80]
    if not aid or not affected.strip():
        return back("/advisories", "An advisory needs an id and an affected range (e.g. <3.1.10).")
    adv = {"id": aid, "title": title.strip() or aid, "severity": severity if severity in ("critical", "high", "medium", "low") else "high",
           "package": {"name": name.strip(), **({"ecosystem": ecosystem.strip()} if ecosystem.strip() else {}),
                       "affected": affected.strip(), **({"fixed": fixed.strip()} if fixed.strip() else {})},
           "announced": comp.now(), "announced_by": user.login, **({"source": source.strip()} if source.strip() else {})}
    hits = model.advisory_hits(adv)
    with auth.as_user(user) as c:
        ok, err = comp.put_file(c, f"advisories/{aid}.yaml", "# Announced in cicd-dashboard (cicd-ref-arch docs/oscal.md).\n"
                                + yaml.safe_dump(adv, sort_keys=False), f"advisory {aid}: {name} {affected}")
    comp.forget(user.login)
    if not ok:
        return back("/advisories", f"Not saved: {err}")
    where = ", ".join(f"{a.name}/{e.dir}" for a, e, _ in hits) or "no live environment"
    return back("/advisories", f"Announced {aid} as {user.login}. It matches {where}; only those are re-scanned now.")


@app.post("/advisories/osv", response_class=HTMLResponse)
def advisories_osv(request: Request, csrf: str = Form("")):
    user = require_compliance_write(request, csrf)
    pkgs = model.live_packages()
    try:
        found = comp.osv_query(pkgs)
    except Exception as e:
        return back("/advisories", f"OSV didn't answer: {type(e).__name__}")
    with auth.as_user(user) as c:
        advs = comp.advisories(c, user.login)
    known = {a["id"] for a in advs}
    return page(request, "advisories.html", advs=advs, hits={a["id"]: model.advisory_hits(a) for a in advs},
                perms=compliance_access(user), osv=[o for o in found if o["id"] not in known], repo=comp.COMPLIANCE_REPO,
                npkgs=len(pkgs))


# ---------------------------------------------------------------- step 6: releases to IT Security


def release_rule(cfg: dict) -> dict:
    r = (cfg or {}).get("release") or {}
    return {"rule": r.get("rule", "second-person"), "approvers": r.get("approvers") or []}


def may_release(user, perms, rule: dict, author: str) -> tuple[bool, str]:
    if user.login == author:
        return False, "you prepared this package; someone else has to release it"
    if rule["rule"] == "approvers" and user.login not in rule["approvers"]:
        return False, f"releases need one of: {', '.join(rule['approvers'])}"
    if not (perms or {}).get("push"):
        return False, f"releases need merge rights on {comp.COMPLIANCE_REPO}"
    return True, ""


@app.get("/a/{name}/releases", response_class=HTMLResponse)
def releases_page(request: Request, name: str):
    a = app_or_404(name)
    user = auth.current(request)
    perms = compliance_access(user)
    rels, prs, rule = [], [], release_rule({})
    if perms:
        with auth.as_user(user) as c:
            rels = comp.releases(c, user.login, name)
            prs = [p for p in comp.release_prs(c, user.login) if f"`{name}`" in p["body"] or p["id"].startswith(name + "-")]
            rule = release_rule(comp.app_config(c, user.login, name))
        for p in prs:
            p["may"], p["why"] = may_release(user, perms, rule, p["author"])
    return page(request, "releases.html", a=a, rels=rels, prs=prs, perms=perms, rule=rule, repo=comp.COMPLIANCE_REPO)


@app.post("/a/{name}/releases")
def releases_prepare(request: Request, name: str, csrf: str = Form(""), envs: list[str] = Form([]), note: str = Form("")):
    user = require_compliance_write(request, csrf)
    a = app_or_404(name)
    envs = [e for e in envs if a.env(e)]
    if not envs:
        return back(f"/a/{name}/releases", "Choose at least one environment to release.")
    st = model.state()
    rid = f"{name}-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    ops, manifest = comp.release_package(rid, name, envs, st.files, st.head, user.login, note.strip(), model.state_repo.cluster)
    lines = "\n".join(f"| `{e}` | `{(a.env(e).commit or '')[:7]}` | "
                       + (f"{a.env(e).assessment['counts']['satisfied']}/{len(a.env(e).assessment['objectives'])}" if a.env(e).assessment else "none")
                       + f" | {(a.env(e).security or {}).get('status', '?')} |" for e in envs)
    body = (f"Release package `{rid}` of `{name}` to IT Security, prepared by **{user.login}**.\n\n"
            f"| environment | commit | self-assessment | security gate |\n|---|---|---|---|\n{lines}\n\n"
            f"{len(manifest['files'])} files, unaltered, from the state repo at `{st.head[:12]}`; sha256 of each in `manifest.json`.\n\n"
            + (f"Note: {note.strip()}\n\n" if note.strip() else "")
            + "**Merging this pull request is the release.** It must be merged by someone other than the person who prepared it.")
    with auth.as_user(user) as c:
        r = c.post(f"/repos/{comp.COMPLIANCE_REPO}/contents", json={
            "branch": comp.BRANCH, "new_branch": f"release/{rid}", "message": f"release {rid}: {name} ({', '.join(envs)})",
            "files": ops})
        if r.status_code not in (200, 201):
            return back(f"/a/{name}/releases", f"Package not written: {comp._err(r)}")
        r = c.post(f"/repos/{comp.COMPLIANCE_REPO}/pulls", json={"head": f"release/{rid}", "base": comp.BRANCH,
                                                                  "title": f"Release {name} to IT Security ({rid})", "body": body})
    comp.forget(user.login)
    if r.status_code not in (200, 201):
        return back(f"/a/{name}/releases", f"Package written, pull request not opened: {comp._err(r)}")
    return back(f"/a/{name}/releases", f"Package {rid} prepared as {user.login} ({len(manifest['files'])} files). "
                                        "Someone else releases it by merging.")


@app.post("/releases/{number}/{verb}")
def releases_review(request: Request, number: int, verb: str, csrf: str = Form(""), next: str = Form("/")):
    user = auth.require(request)
    auth.check_csrf(user, csrf)
    url = next if next.startswith("/") else "/"
    perms = compliance_access(user)
    with auth.as_user(user) as c:
        pr = c.get(f"/repos/{comp.COMPLIANCE_REPO}/pulls/{number}")
        if pr.status_code != 200 or not pr.json()["head"]["ref"].startswith("release/"):
            raise HTTPException(404, "no such release pull request")
        pr = pr.json()
        rid = pr["head"]["ref"][len("release/"):]
        app_name = rid.rsplit("-", 1)[0]
        ok, why = may_release(user, perms, release_rule(comp.app_config(c, user.login, app_name)), pr["user"]["login"])
        if not ok:
            return back(url, why[0].upper() + why[1:] + ".")
        if verb == "approve":
            r = c.post(f"/repos/{comp.COMPLIANCE_REPO}/pulls/{number}/reviews", json={"event": "APPROVED", "body": "Reviewed in cicd-dashboard."})
        elif verb == "merge":
            r = c.post(f"/repos/{comp.COMPLIANCE_REPO}/pulls/{number}/merge",
                       json={"Do": "merge", "MergeTitleField": f"Release {rid} to IT Security", "delete_branch_after_merge": True})
        else:
            raise HTTPException(400, "approve or merge")
    comp.forget(user.login)
    if r.status_code not in (200, 201, 204):
        return back(url, f"{verb} failed: {forge_error(r)}")
    return back(url, f"Released {rid} to IT Security as {user.login}." if verb == "merge" else f"Approved {rid} as {user.login}.")


# ---------------------------------------------------------------- sign-in


@app.get("/auth/login")
def auth_login(request: Request, next: str = "/"):
    return auth.login(request, next)


@app.get("/auth/callback")
def auth_callback(request: Request, code: str = "", state: str = "", error: str = ""):
    if error:
        raise HTTPException(400, f"the forge said: {error}")
    return auth.callback(request, code, state)


@app.get("/auth/logout")
def auth_logout(request: Request):
    return auth.logout(request)


# ---------------------------------------------------------------- actions, as the signed-in user


def back(url: str, msg: str) -> RedirectResponse:
    from urllib.parse import quote
    return RedirectResponse(f"{url}{'&' if '?' in url else '?'}msg={quote(msg)}", status_code=303)


def forge_error(r) -> str:
    try:
        m = r.json().get("message", "")
    except Exception:
        m = r.text[:200]
    return f"the forge answered {r.status_code}{': ' + m if m else ''}"


@app.post("/a/{name}/act")
def act(request: Request, name: str, action: str = Form(...), branch: str = Form(""), reason: str = Form(""),
        not_before: str = Form(""), csrf: str = Form(""), next: str = Form("")):
    """Self-service on an app: dispatched to the app's own pipeline as the user, who needs write on
    its repo. Apps that live in the platform repo itself (hello) can only request promotions."""
    user = auth.require(request)
    auth.check_csrf(user, csrf)
    a = app_or_404(name)
    url = next if next.startswith("/") else f"/a/{name}"
    if action not in ("pause", "resume", "remove-env", "request-promotion"):
        raise HTTPException(400, "unknown action")
    repo = a.repos[0]
    with auth.as_user(user) as c:
        if repo == STATE_REPO:
            if action != "request-promotion":
                return back(url, f"{action} isn't available for apps inside the platform repo")
            r = c.post(f"/repos/{repo}/actions/workflows/request-promotion.yaml/dispatches",
                       json={"ref": "master", "inputs": {"app": name, "from": "dev", "not_before": not_before, "reason": reason}})
        else:
            r = c.post(f"/repos/{repo}/actions/workflows/cicd.yaml/dispatches",
                       json={"ref": a.dev_branch, "inputs": {"action": action, "branch": branch,
                                                             "not_before": not_before, "reason": reason}})
    if r.status_code not in (200, 201, 204):
        return back(url, f"{action} was not started: {forge_error(r)}")
    what = {"request-promotion": "Promotion requested: the PR opens in about a minute",
            "pause": f"Pausing {branch}: its environment goes away within a minute",
            "resume": f"Resuming {branch}: its next push goes through CI/CD again",
            "remove-env": f"Removing the environment of {branch}"}[action]
    return back(url, f"{what} (as {user.login}).")


def promotion_or_404(pid: str):
    p = next((p for p in model.state().promotions if p.id == pid), None)
    if p is None or not p.pr:
        raise HTTPException(404, "no open promotion with that id")
    return p


@app.post("/promotions/{pid}/{verb}")
def review(request: Request, pid: str, verb: str, csrf: str = Form(""), next: str = Form("/")):
    """Approve or merge a promotion PR as the signed-in user. The platform only applies it if that
    person is neither the requester nor the PR's author, so the dashboard won't even try."""
    user = auth.require(request)
    auth.check_csrf(user, csrf)
    p = promotion_or_404(pid)
    url = next if next.startswith("/") else "/"
    if user.login in (p.requested_by, p.pr["author"]):
        return back(url, f"You {'requested' if user.login == p.requested_by else 'opened'} this promotion, so your "
                         "approval wouldn't count: the platform refuses to apply it. Ask someone else.")
    with auth.as_user(user) as c:
        if verb == "approve":
            r = c.post(f"/repos/{STATE_REPO}/pulls/{p.pr['number']}/reviews",
                       json={"event": "APPROVED", "body": "Approved in cicd-dashboard."})
        elif verb == "merge":
            r = c.post(f"/repos/{STATE_REPO}/pulls/{p.pr['number']}/merge",
                       json={"Do": "merge", "MergeTitleField": f"Promote {p.app} to prod ({p.id})"})
        else:
            raise HTTPException(400, "approve or merge")
    if r.status_code not in (200, 201, 204):
        return back(url, f"{verb} failed: {forge_error(r)}")
    model.forge._cache.clear()
    return back(url, f"{'Approved' if verb == 'approve' else 'Merged'} as {user.login}. "
                     + ("It is applied once due, after a final security scan." if verb == "merge" else ""))


# ---------------------------------------------------------------- live updates


def fingerprint() -> str:
    """Changes whenever anything the pages show could have changed."""
    h = hashlib.sha1(model.state_repo.head().encode())
    for pr in model.forge.get(f"/repos/{STATE_REPO}/pulls?state=all&limit=20", ttl=4) or []:   # promotions and approvals
        h.update(f"{pr['number']}:{pr['state']}:{pr.get('updated_at')}".encode())
    for a in model.apps():
        for repo in a.repos:
            tasks = model.forge.get(f"/repos/{repo}/actions/tasks?limit=20", ttl=4) or {}
            for t in tasks.get("workflow_runs", []):
                h.update(f"{t['id']}:{t['status']}".encode())
            for b in model.forge.get(f"/repos/{repo}/branches?limit=50", ttl=4) or []:
                h.update(f"{b['name']}:{b['commit']['id']}".encode())
    return h.hexdigest()


@app.get("/events")
async def events(request: Request):
    async def stream():
        last = None
        yield "retry: 5000\n\n"
        while not await request.is_disconnected():
            try:
                fp = await asyncio.to_thread(fingerprint)
            except Exception as e:  # the forge is briefly unreachable: keep the page, try again
                yield f"event: error\ndata: {type(e).__name__}\n\n"
                fp = last
            if last is not None and fp != last:
                yield "event: changed\ndata: x\n\n"
            last = fp
            yield ": keepalive\n\n"
            await asyncio.sleep(5)
    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------- JSON API (agents read this)


def plain(obj):
    return json.loads(json.dumps(obj, default=lambda o: dataclasses.asdict(o) if dataclasses.is_dataclass(o) else str(o)))


@app.get("/api/tenants")
def api_tenants():
    return JSONResponse(plain({t: [a.name for a in apps] for t, apps in model.tenants().items()}))


@app.get("/api/apps/{name}")
def api_app(name: str):
    a = app_or_404(name)
    return JSONResponse(plain({"app": a, "branches": model.branches(a)}))


@app.get("/api/apps/{name}/commits/{sha}")
def api_commit(name: str, sha: str, branch: str | None = None):
    a = app_or_404(name)
    got = model.commit(a, sha, branch)
    if got is None:
        raise HTTPException(404)
    row, facts = got
    return JSONResponse(plain({"commit": row, "facts": facts}))


@app.get("/healthz", response_class=PlainTextResponse)
def healthz():
    return "ok\n"
