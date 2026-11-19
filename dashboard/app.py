"""cicd-dashboard: the information system owner's view of their applications on cicd-ref-arch.

Step 1 (read-only): tenants, applications, environments, branches, and each commit's road to
prod. Pages update live over server-sent events; the same data is JSON under /api/.
"""
from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import os
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import auth
from .destiny import GLYPH, PROD_SIDE, STAGES
from .model import Model
from .sources import STATE_REPO

HERE = Path(__file__).parent
VERSION = "0.1.0"

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
