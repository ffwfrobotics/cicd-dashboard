"""Sign-in through Forgejo (which signs people in through Keycloak), and acting on Forgejo as them.

OAuth2 authorization code with PKCE (S256) against the forge's OAuth2 app. The dashboard keeps
nothing on its side: the session (the user's Forgejo token among it) and a sign-in in progress
live in cookies encrypted with SESSION_KEY, so a restart, a pod that scaled to zero or a second
replica keeps everyone signed in. SESSION_KEY comes from the Secret; without it (a local run) each
process makes its own and a restart signs everyone out.
Everything the user does through the dashboard is a Forgejo API call with their own token, so the
forge records it as them.
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

import httpx
from cryptography.fernet import Fernet, InvalidToken
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
SCOPES = os.environ.get("OAUTH_SCOPES", "openid profile email read:user read:organization write:repository write:issue")
COOKIE = "cicd_dash"
PENDING_COOKIE = "cicd_dash_login"
MAX_AGE = 12 * 3600
_fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(b"cicd-dashboard session\0" + SESSION_KEY).digest()))
ENABLED = bool(CLIENT_ID and CLIENT_SECRET)


@dataclass
class Session:
    login: str
    name: str
    token: str
    refresh: str | None
    expires: float
    csrf: str


def _seal(d: dict) -> str:
    return _fernet.encrypt(json.dumps(d, separators=(",", ":")).encode()).decode()


def _open(v: str | None, ttl: int) -> dict | None:
    if not v:
        return None
    try:
        return json.loads(_fernet.decrypt(v.encode(), ttl=ttl))
    except (InvalidToken, ValueError):
        return None


def _set_session(resp, s: Session):
    resp.set_cookie(COOKIE, _seal(dataclasses.asdict(s)), httponly=True, secure=True, samesite="lax", max_age=MAX_AGE)


def redirect_uri(request: Request) -> str:
    host = request.headers.get("x-forwarded-host") or request.headers.get("host", "")
    return f"https://{host}/auth/callback"   # registered exactly, per host, on the forge's OAuth2 app


def current(request: Request) -> Session | None:
    """The signed-in user, from the session cookie. A refreshed token is written back by persist()."""
    if hasattr(request.state, "session"):       # read once per request
        return request.state.session
    d = _open(request.cookies.get(COOKIE), MAX_AGE)
    s = None
    try:
        s = Session(**d) if d else None
    except TypeError:
        pass
    if s and s.expires < time.time() + 30 and s.refresh and _refresh(s):
        request.state.session_changed = True
    if s and s.expires < time.time():
        s = None
    request.state.session = s
    return s


async def persist(request: Request, call_next):
    """Middleware: write a session whose token was refreshed during the request back to its cookie."""
    resp = await call_next(request)
    s = getattr(request.state, "session", None)
    if s and getattr(request.state, "session_changed", False) and COOKIE not in resp.headers.get("set-cookie", ""):
        _set_session(resp, s)
    return resp


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
    state = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    q = httpx.QueryParams({"client_id": CLIENT_ID, "redirect_uri": redirect_uri(request), "response_type": "code",
                           "scope": SCOPES, "state": state, "code_challenge": challenge,
                           "code_challenge_method": "S256"})
    resp = RedirectResponse(f"{FORGE}/login/oauth/authorize?{q}", status_code=302)
    pending = {"state": state, "verifier": verifier, "next": next_url if next_url.startswith("/") else "/"}
    resp.set_cookie(PENDING_COOKIE, _seal(pending), httponly=True, secure=True, samesite="lax", max_age=600,
                    path="/auth/callback")
    return resp


def callback(request: Request, code: str, state: str) -> RedirectResponse:
    got = _open(request.cookies.get(PENDING_COOKIE), 600)
    if not got or not hmac.compare_digest(got.get("state", ""), state or ""):
        raise HTTPException(400, "this sign-in link expired: start again")
    verifier, next_url = got["verifier"], got["next"]
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
    s = Session(login=u["login"], name=u.get("full_name") or u["login"], token=tok["access_token"],
                             refresh=tok.get("refresh_token"), expires=time.time() + int(tok.get("expires_in", 3600)),
                             csrf=secrets.token_urlsafe(24))
    resp = RedirectResponse(next_url, status_code=302)
    _set_session(resp, s)
    resp.delete_cookie(PENDING_COOKIE, path="/auth/callback")
    return resp


def _refresh(s: Session) -> bool:
    r = httpx.post(f"{FORGE}/login/oauth/access_token", timeout=20, data={
        "grant_type": "refresh_token", "refresh_token": s.refresh, "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET})
    if r.status_code == 200:
        tok = r.json()
        s.token, s.refresh = tok["access_token"], tok.get("refresh_token", s.refresh)
        s.expires = time.time() + int(tok.get("expires_in", 3600))
        return True
    return False


def logout(request: Request) -> RedirectResponse:
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie(COOKIE)
    return resp


def as_user(s: Session) -> httpx.Client:
    """A Forgejo API client that acts as the signed-in user."""
    return httpx.Client(base_url=f"{FORGE}/api/v1", timeout=20,
                        headers={"Authorization": f"token {s.token}", "Accept": "application/json"})
