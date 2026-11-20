"""Add an app from the dashboard: import its repo into the managed forge, and enroll it as pending.

Who does what, so each step is done by someone allowed to:
- the signed-in user (their forge token): imports the repo into an owner they can create repos in
  (or names a repo they administer on this forge), gives the platform bot write on it (to check
  it out and post the contract statuses), and adds the push webhook to the dashboard;
- the dashboard (the platform token): writes tenants/<app>.yaml in the platform repo with
  status pending and the requester's login, then starts the first pipeline run;
- an admin (write on the platform repo, their own token): approves, which is a commit to the same
  file in their name. Until then the app gets branch environments only: no dev host, no promotion.
"""
from __future__ import annotations

import base64
import datetime as dt
import re
from urllib.parse import urlparse

import httpx
import yaml

from . import platform
from .sources import CLUSTER, FORGE, STATE_BRANCH, STATE_REPO, Forgejo

# app names become hostnames (<app>-<branch>.<cluster>.<zone>) and namespaces
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,23}[a-z0-9]$")
RESERVED = {"dev", "prod", "branch", "manage", "platform", "admin", "dashboard-dev"}


class EnrollError(Exception):
    pass


def bot_client() -> httpx.Client:
    return httpx.Client(base_url=f"{FORGE}/api/v1", timeout=120,
                        headers={"Authorization": f"token {platform._secret('token')}", "Accept": "application/json"})


def _err(r: httpx.Response, what: str) -> EnrollError:
    try:
        m = r.json().get("message", "")
    except Exception:
        m = r.text[:200]
    return EnrollError(f"{what}: the forge answered {r.status_code}{': ' + m if m else ''}")


def owners(c: httpx.Client, login: str) -> list[str]:
    """Where the user can create a repo: themselves, and orgs that let them."""
    out = [login]
    r = c.get("/user/orgs?limit=50")
    for o in (r.json() if r.status_code == 200 else []):
        p = c.get(f"/users/{login}/orgs/{o['username']}/permissions")
        if p.status_code == 200 and (p.json().get("can_create_repository") or p.json().get("is_owner")):
            out.append(o["username"])
    return out


def local_repo(url: str) -> str | None:
    """owner/name if the URL is a repo on this forge."""
    u, f = urlparse(url.strip()), urlparse(FORGE)
    if u.netloc and u.netloc == f.netloc:
        parts = [p for p in u.path.removesuffix(".git").split("/") if p]
        if len(parts) == 2:
            return "/".join(parts)
    return None


def check_name(name: str, enrolled: dict) -> None:
    if not NAME_RE.match(name) or name in RESERVED:
        raise EnrollError("Name: 3 to 25 lowercase letters, digits and dashes, starting with a letter")
    if name in enrolled:
        raise EnrollError(f"{name} is already enrolled")


def tenant_doc(name: str, owner: str, repo: str, requester: str, default_branch: str) -> str:
    t = {"apiVersion": "cicd.ffwf.net/v1alpha1", "kind": "Tenant", "metadata": {"name": name},
         "spec": {"tenant": owner, "repo": repo, "path": ".", "clusters": [CLUSTER], "owners": [requester],
                  "enrolled": dt.date.today().isoformat(), "status": "pending", "requestedBy": requester,
                  "defaultBranch": default_branch}}
    return ("# Enrolled from cicd-dashboard (pending until an admin approves it: branch environments only).\n"
            + yaml.safe_dump(t, sort_keys=False))


def enroll(c: httpx.Client, forge: Forgejo, login: str, *, name: str, source: str, owner: str,
           mirror: bool, private: bool, source_token: str, hook_url: str) -> list[str]:
    """Do it; returns what was done. Raises EnrollError with what to fix."""
    if not platform.configured():
        raise EnrollError("The dashboard has no platform token here")
    hook_secret = platform._secret("hook-secret")
    check_name(name, platform.tenants(forge))
    done: list[str] = []
    bot = bot_client()
    bot_login = bot.get("/user").json()["login"]

    # 1. the repo, on this forge
    repo = local_repo(source) if source else None
    if repo:
        r = c.get(f"/repos/{repo}")
        if r.status_code != 200:
            raise _err(r, f"Reading {repo}")
        if not r.json().get("permissions", {}).get("admin"):
            raise EnrollError(f"You need admin on {repo} to enroll it (it gets a webhook)")
        info = r.json()
        done.append(f"using {repo}")
    else:
        if owner not in owners(c, login):
            raise EnrollError(f"You can't create repositories in {owner}")
        if source:
            u = urlparse(source.strip())
            if u.scheme not in ("https", "http") or not u.netloc:
                raise EnrollError("Source: an https:// clone URL")
            body = {"clone_addr": source.strip(), "repo_name": name, "repo_owner": owner, "mirror": mirror,
                    "private": private, "service": "git", "wiki": False, "issues": False, "pull_requests": False,
                    "releases": False, "description": f"imported from {source.strip()}"}
            if source_token:
                body["auth_token"] = source_token
            r = c.post("/repos/migrate", json=body, timeout=300)
            if r.status_code not in (200, 201):
                raise _err(r, "Importing")
            done.append(f"imported {source.strip()}" + (" (mirrored)" if mirror else ""))
        else:
            path = "/user/repos" if owner == login else f"/orgs/{owner}/repos"
            r = c.post(path, json={"name": name, "private": private, "default_branch": "main", "auto_init": False})
            if r.status_code not in (200, 201):
                raise _err(r, "Creating the repository")
            done.append("created an empty repository")
        info = r.json()
        repo = info["full_name"]

    # 2. the bot can check it out and post statuses
    if not (bot.get(f"/repos/{repo}").json() or {}).get("permissions", {}).get("push"):
        r = c.put(f"/repos/{repo}/collaborators/{bot_login}", json={"permission": "write"})
        if r.status_code not in (200, 204):
            raise _err(r, f"Adding {bot_login} to {repo}")
        done.append(f"{bot_login} can read it and post statuses")

    # 3. the push webhook
    hooks = c.get(f"/repos/{repo}/hooks")
    if not any((h.get("config") or {}).get("url") == hook_url for h in (hooks.json() if hooks.status_code == 200 else [])):
        r = c.post(f"/repos/{repo}/hooks", json={"type": "forgejo", "active": True, "events": ["push"], "branch_filter": "*",
                                                   "config": {"url": hook_url, "content_type": "json", "secret": hook_secret}})
        if r.status_code not in (200, 201):
            raise _err(r, "Adding the webhook")
        done.append("webhook added")

    # 4. the tenant record, pending
    default_branch = info.get("default_branch") or "main"
    text = tenant_doc(name, repo.split("/")[0], repo, login, default_branch)
    r = bot.post(f"/repos/{STATE_REPO}/contents/tenants/{name}.yaml", json={
        "content": base64.b64encode(text.encode()).decode(), "branch": STATE_BRANCH,
        "message": f"enroll {name} from {repo} (pending), requested by {login} in cicd-dashboard"})
    if r.status_code not in (200, 201):
        raise _err(r, "Writing the enrollment")
    done.append("enrolled, pending approval")
    forge._cache.clear()

    # 5. the first run (a mirror's first sync, or an empty repo's first push, triggers its own)
    if not info.get("empty"):
        b = bot.get(f"/repos/{repo}/branches/{default_branch}")
        if b.status_code == 200:
            ok, msg = platform.dispatch({"app": name, "branch": default_branch, "sha": b.json()["commit"]["id"],
                                         "action": "deploy", "actor": login})
            done.append("first run started" if ok else f"first run not started ({msg}): the next push starts it")
    return done


def approve(c: httpx.Client, forge: Forgejo, login: str, name: str) -> str:
    """As an admin (write on the platform repo): status approved, in a commit in their name."""
    r = c.get(f"/repos/{STATE_REPO}")
    if r.status_code != 200 or not r.json().get("permissions", {}).get("push"):
        raise EnrollError(f"Approving needs write on {STATE_REPO}")
    path = f"/repos/{STATE_REPO}/contents/tenants/{name}.yaml?ref={STATE_BRANCH}"
    r = c.get(path)
    if r.status_code != 200:
        raise _err(r, f"Reading tenants/{name}.yaml")
    cur = r.json()
    doc = yaml.safe_load(base64.b64decode(cur["content"]))
    spec = doc["spec"]
    if spec.get("status", "approved") == "approved":
        raise EnrollError(f"{name} is already approved")
    spec["status"] = "approved"
    spec["approved"] = {"by": login, "at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    text = "# Enrolled from cicd-dashboard; approved by an admin.\n" + yaml.safe_dump(doc, sort_keys=False)
    r = c.put(f"/repos/{STATE_REPO}/contents/tenants/{name}.yaml", json={
        "content": base64.b64encode(text.encode()).decode(), "sha": cur["sha"], "branch": STATE_BRANCH,
        "message": f"approve {name} (requested by {spec.get('requestedBy', '?')})"})
    if r.status_code not in (200, 201):
        raise _err(r, "Approving")
    forge._cache.clear()
    branch = spec.get("defaultBranch") or "main"
    ok, _ = platform.dispatch({"app": name, "branch": branch, "action": "deploy", "actor": login})
    return f"Approved. {branch} deploys to dev next." if ok else f"Approved. The next push to {branch} deploys to dev."
