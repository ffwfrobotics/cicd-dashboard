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

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .destiny import GLYPH, PROD_SIDE, STAGES
from .model import Model

HERE = Path(__file__).parent
VERSION = "0.1.0"

app = FastAPI(title="cicd-dashboard", version=VERSION, docs_url="/api/docs", redoc_url=None)
app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
templates = Jinja2Templates(directory=HERE / "templates")
templates.env.globals.update(STAGES=STAGES, GLYPH=GLYPH, PROD_SIDE=PROD_SIDE, VERSION=VERSION,
                             COMMIT=os.environ.get("APP_COMMIT", "dev"), FORGE=os.environ.get("FORGE_URL", "https://forge.goblincorps.com"))
model = Model()


def page(request: Request, name: str, **ctx):
    return templates.TemplateResponse(request, name, ctx)


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
    return page(request, "app.html", a=a, branches=model.branches(a), history=model.history(a))


@app.get("/a/{name}/fragment/body", response_class=HTMLResponse)
def app_body(request: Request, name: str):
    a = app_or_404(name)
    return page(request, "_app_body.html", a=a, branches=model.branches(a), history=model.history(a))


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
