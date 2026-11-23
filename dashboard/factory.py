"""The software factory (ffwf/cicd-factory), seen from the dashboard: grants, providers and sessions.

- **A grant** is the bot account as a collaborator on a repo (Read or Write), set here **as the user**,
  who must be an admin of the repo. It is recorded in the factory repo (`grants/<owner>/<repo>.yaml`),
  and the collaborator entry stays visible and revocable in the repo's settings. CI/CD shares the bot
  account but never uses a grant: it only reads developers' repos.
- **Sessions and providers** go to the factory's controller, with the shared API token, naming the user.
  The dashboard checks the user's own access to the repo first.
"""
from __future__ import annotations

import base64
import datetime as dt
import os
from pathlib import Path

import httpx
import yaml

from . import platform

URL = os.environ.get("FACTORY_URL", "http://controller.factory.svc.cluster.local:8080").rstrip("/")
REPO = os.environ.get("FACTORY_REPO", "ffwf/cicd-factory")
SECRET = Path("/var/run/secrets/dashboard-factory/token")
ROLES = ("read", "write")


class FactoryError(Exception):
    pass


def configured() -> bool:
    return SECRET.exists() or bool(os.environ.get("FACTORY_API_TOKEN"))


def _client() -> httpx.Client:
    token = SECRET.read_text().strip() if SECRET.exists() else os.environ.get("FACTORY_API_TOKEN", "")
    return httpx.Client(base_url=URL, timeout=30, headers={"Authorization": f"Bearer {token}"})


def _call(method: str, path: str, **kw):
    try:
        with _client() as c:
            r = c.request(method, path, **kw)
    except httpx.HTTPError as e:
        raise FactoryError(f"the factory didn't answer ({type(e).__name__})")
    if r.status_code >= 400:
        try:
            msg = r.json().get("detail")
        except ValueError:
            msg = r.text[:200]
        raise FactoryError(msg if isinstance(msg, str) else f"the factory answered {r.status_code}")
    return r.json() if r.content else None


# ---------------------------------------------------------------- grants


def grants(forge) -> dict[str, dict]:
    """repo -> grant record, from the factory repo."""
    out = {}
    for owner in forge.get(f"/repos/{REPO}/contents/grants", ttl=30) or []:
        if owner["type"] != "dir":
            continue
        for f in forge.get(f"/repos/{REPO}/contents/grants/{owner['name']}", ttl=30) or []:
            if f["type"] == "file" and f["name"].endswith(".yaml"):
                raw = forge.get(f"/repos/{REPO}/raw/grants/{owner['name']}/{f['name']}", ttl=30, raw=True)
                try:
                    g = yaml.safe_load(raw or b"") or {}
                except yaml.YAMLError:
                    continue
                if g.get("repo"):
                    out[g["repo"]] = g
    return out


def admin_repos(c: httpx.Client) -> list[str]:
    """Repos the user administers (where they may grant), from their own session."""
    out, page = [], 1
    while page <= 10:
        r = c.get("/user/repos", params={"limit": 50, "page": page})
        if r.status_code != 200:
            break
        got = r.json()
        out += [x["full_name"] for x in got if (x.get("permissions") or {}).get("admin") and not x.get("archived")]
        if len(got) < 50:
            break
        page += 1
    return sorted(out)


def _bot_login(bot: httpx.Client) -> str:
    return bot.get("/user").json()["login"]


def _record(bot: httpx.Client, repo: str, text: str | None, message: str) -> None:
    path = f"/repos/{REPO}/contents/grants/{repo}.yaml"
    cur = bot.get(path)
    sha = cur.json().get("sha") if cur.status_code == 200 else None
    if text is None:
        if sha:
            r = bot.request("DELETE", path, json={"sha": sha, "message": message, "branch": "main"})
            if r.status_code not in (200, 204):
                raise FactoryError(f"the grant record was not removed ({r.status_code})")
        return
    body = {"content": base64.b64encode(text.encode()).decode(), "message": message, "branch": "main"}
    r = bot.put(path, json={**body, "sha": sha}) if sha else bot.post(path, json=body)
    if r.status_code not in (200, 201):
        raise FactoryError(f"the grant record was not written ({r.status_code})")


def grant(c: httpx.Client, bot: httpx.Client, login: str, repo: str, role: str, days: int | None) -> str:
    """As the user: the bot becomes a collaborator (role) on the repo; then the record."""
    if role not in ROLES:
        raise FactoryError("Role: read or write")
    r = c.get(f"/repos/{repo}")
    if r.status_code != 200 or not (r.json().get("permissions") or {}).get("admin"):
        raise FactoryError(f"Granting {repo} needs admin on it")
    who = _bot_login(bot)
    r = c.put(f"/repos/{repo}/collaborators/{who}", json={"permission": role})
    if r.status_code not in (200, 204):
        raise FactoryError(f"Adding {who} to {repo}: the forge answered {r.status_code}")
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    until = (now + dt.timedelta(days=days)).isoformat().replace("+00:00", "Z") if days else None
    doc = {"repo": repo, "role": role, "by": login, "at": now.isoformat().replace("+00:00", "Z"), "until": until}
    _record(bot, repo, yaml.safe_dump(doc, sort_keys=False),
            f"grant {repo} ({role}{', until ' + until if until else ''}) by {login}\n\nAuthorized-by: cicd-dashboard")
    return f"{repo}: granted ({role}{', until ' + until[:10] if until else ''})"


def revoke(c: httpx.Client, bot: httpx.Client, forge, login: str, repo: str) -> str:
    """As the user: the bot goes back to read if CI/CD builds from the repo (an enrolled app's source),
    and is removed otherwise. Running sessions keep their token until they end; none start after this."""
    r = c.get(f"/repos/{repo}")
    if r.status_code != 200 or not (r.json().get("permissions") or {}).get("admin"):
        raise FactoryError(f"Revoking {repo} needs admin on it")
    who = _bot_login(bot)
    ci = any(repo == s.get("repo") or repo in [x.get("repo") for x in s.get("sources") or []]
             for s in platform.tenants(forge).values())
    r = c.put(f"/repos/{repo}/collaborators/{who}", json={"permission": "read"}) if ci \
        else c.delete(f"/repos/{repo}/collaborators/{who}")
    if r.status_code not in (200, 204, 404):
        raise FactoryError(f"Changing {who} on {repo}: the forge answered {r.status_code}")
    _record(bot, repo, None, f"revoke {repo} by {login}\n\nAuthorized-by: cicd-dashboard")
    return f"{repo}: revoked" + (" (CI/CD keeps read: it builds from this repo)" if ci else "")


# ---------------------------------------------------------------- sessions and providers


def can_write(c: httpx.Client, repo: str) -> bool:
    r = c.get(f"/repos/{repo}")
    return r.status_code == 200 and bool((r.json().get("permissions") or {}).get("push"))


def start(c: httpx.Client, login: str, repo: str, harness: str, provider: str, prompt: str, ttl: int) -> dict:
    if not can_write(c, repo):
        raise FactoryError(f"A session on {repo} needs write on it")
    return _call("POST", "/sessions", json={"user": login, "repo": repo, "harness": harness, "provider": provider or "local",
                                           "prompt": prompt, "ttl_minutes": ttl})


def sessions(login: str) -> list[dict]:
    return _call("GET", "/sessions", params={"user": login})


def session(login: str, sid: str) -> dict:
    s = _call("GET", f"/sessions/{sid}")
    if s.get("user") != login:
        raise FactoryError("Not your session")
    return s


def stop(login: str, sid: str) -> None:
    session(login, sid)
    _call("DELETE", f"/sessions/{sid}")


def providers(login: str) -> list[dict]:
    return _call("GET", f"/providers/{login}")


def attach(login: str, name: str, kind: str, model: str, base_url: str, secrets: dict[str, str]) -> dict:
    return _call("PUT", f"/providers/{login}/{name}", json={"kind": kind, "model": model, "base_url": base_url, "secrets": secrets})


def detach(login: str, name: str) -> None:
    _call("DELETE", f"/providers/{login}/{name}")


HARNESSES = ("tau", "opencode", "pi", "claude-code", "codex")
# what each kind of account is, and the key names it takes (the controller keeps only these)
KINDS = {"anthropic": ("ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"), "openai": ("OPENAI_API_KEY",),
         "compatible": ("MODEL_API_KEY",)}
