"""Sign-in through Forgejo (which signs people in through Keycloak), and acting on Forgejo as them.

OAuth2 authorization code with PKCE (S256) against the forge's OAuth2 app. The dashboard keeps
the user's Forgejo token in memory only: a pod that scaled to zero forgets it, and the next page
asks Forgejo again (a redirect, no password: Forgejo and Keycloak still have their session).
Everything the user does through the dashboard is a Forgejo API call with their own token, so the
forge records it as them.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

import httpx
from fastapi import HTTPException, Request
from fastapi.responses import RedirectResponse

SECRET_DIR = Path(os.environ.get("OAUTH_SECRET_DIR", "/var/run/secrets/dashboard-oauth"))


def setting(name: str) -> str:
    """From the environment (local runs), else from the mounted Secret's file of that name."""
    v = os.environ.get(name, "")
    if not v and (SECRET_DIR / name).is_file():
        v = (SECRET_DIR / name).read_text()
    return v.strip()


FORGE = os.environ.get("FORGE_URL", "https://forge.goblincorps.com").rstrip("/")
CLIENT_ID = setting("OAUTH_CLIENT_ID")
CLIENT_SECRET = setting("OAUTH_CLIENT_SECRET")
SESSION_KEY = (setting("SESSION_KEY") or secrets.token_urlsafe(32)).encode()
SCOPES = os.environ.get("OAUTH_SCOPES", "openid profile email read:user write:repository write:issue")
COOKIE = "cicd_dash"
ENABLED = bool(CLIENT_ID and CLIENT_SECRET)


@dataclass
class Session:
    login: str
    name: str
    token: str
    refresh: str | None
    expires: float
    csrf: str


_sessions: dict[str, Session] = {}
_pending: dict[str, tuple[str, str, float]] = {}   # state -> (pkce verifier, next url, created)


def _sign(v: str) -> str:
    return v + "." + hmac.new(SESSION_KEY, v.encode(), hashlib.sha256).hexdigest()[:32]


def _unsign(s: str | None) -> str | None:
    if not s or "." not in s:
        return None
    v, _ = s.rsplit(".", 1)
    return v if hmac.compare_digest(_sign(v), s) else None


def redirect_uri(request: Request) -> str:
    host = request.headers.get("x-forwarded-host") or request.headers.get("host", "")
    return f"https://{host}/auth/callback"   # registered exactly, per host, on the forge's OAuth2 app


def current(request: Request) -> Session | None:
    sid = _unsign(request.cookies.get(COOKIE))
    s = _sessions.get(sid or "")
    if s and s.expires < time.time() + 30 and s.refresh:
        _refresh(s)
    if s and s.expires < time.time():
        _sessions.pop(sid, None)
        return None
    return s


def require(request: Request) -> Session:
    s = current(request)
    if s is None:
        raise HTTPException(401, "sign in first")
    return s


def check_csrf(s: Session, token: str):
    if not hmac.compare_digest(s.csrf, token or ""):
        raise HTTPException(403, "stale form: reload the page and try again")


def login(request: Request, next_url: str = "/") -> RedirectResponse:
    if not ENABLED:
        raise HTTPException(503, "sign-in is not configured in this environment")
    now = time.time()
    for k, (_, _, t) in list(_pending.items()):
        if now - t > 600:
            _pending.pop(k, None)
    state = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    _pending[state] = (verifier, next_url if next_url.startswith("/") else "/", now)
    q = httpx.QueryParams({"client_id": CLIENT_ID, "redirect_uri": redirect_uri(request), "response_type": "code",
                           "scope": SCOPES, "state": state, "code_challenge": challenge,
                           "code_challenge_method": "S256"})
    return RedirectResponse(f"{FORGE}/login/oauth/authorize?{q}", status_code=302)


def callback(request: Request, code: str, state: str) -> RedirectResponse:
    got = _pending.pop(state, None)
    if got is None:
        raise HTTPException(400, "this sign-in link expired: start again")
    verifier, next_url, _ = got
    r = httpx.post(f"{FORGE}/login/oauth/access_token", timeout=20, data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri(request),
        "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "code_verifier": verifier})
    if r.status_code != 200:
        raise HTTPException(502, f"the forge refused the sign-in ({r.status_code})")
    tok = r.json()
    me = httpx.get(f"{FORGE}/api/v1/user", timeout=20, headers={"Authorization": f"token {tok['access_token']}"})
    if me.status_code != 200:
        raise HTTPException(502, f"could not read the signed-in user ({me.status_code})")
    u = me.json()
    sid = secrets.token_urlsafe(32)
    _sessions[sid] = Session(login=u["login"], name=u.get("full_name") or u["login"], token=tok["access_token"],
                             refresh=tok.get("refresh_token"), expires=time.time() + int(tok.get("expires_in", 3600)),
                             csrf=secrets.token_urlsafe(24))
    resp = RedirectResponse(next_url, status_code=302)
    resp.set_cookie(COOKIE, _sign(sid), httponly=True, secure=True, samesite="lax", max_age=12 * 3600)
    return resp


def _refresh(s: Session):
    r = httpx.post(f"{FORGE}/login/oauth/access_token", timeout=20, data={
        "grant_type": "refresh_token", "refresh_token": s.refresh, "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET})
    if r.status_code == 200:
        tok = r.json()
        s.token, s.refresh = tok["access_token"], tok.get("refresh_token", s.refresh)
        s.expires = time.time() + int(tok.get("expires_in", 3600))


def logout(request: Request) -> RedirectResponse:
    sid = _unsign(request.cookies.get(COOKIE))
    _sessions.pop(sid or "", None)
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie(COOKIE)
    return resp


def as_user(s: Session) -> httpx.Client:
    """A Forgejo API client that acts as the signed-in user."""
    return httpx.Client(base_url=f"{FORGE}/api/v1", timeout=20,
                        headers={"Authorization": f"token {s.token}", "Accept": "application/json"})
