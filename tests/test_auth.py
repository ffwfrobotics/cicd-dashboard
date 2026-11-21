"""Sessions live in encrypted cookies: they survive a restart and can't be forged. Run: python -m unittest discover -s tests"""
import importlib
import os
import time
import unittest

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse
from fastapi.testclient import TestClient

os.environ["SESSION_KEY"] = "test-key-for-unit-tests"
from dashboard import auth  # noqa: E402


def session(**kw):
    d = dict(login="ada", name="Ada", token="t1", refresh="r1", expires=time.time() + 3600, csrf="c")
    d.update(kw)
    return auth.Session(**d)


def cookie(s):
    return auth._seal(auth.dataclasses.asdict(s))


def client():
    app = FastAPI()
    app.middleware("http")(auth.persist)

    @app.get("/me")
    def me(request: Request):
        s = auth.current(request)
        return PlainTextResponse(s.login if s else "-")

    @app.get("/auth/callback")
    def cb(request: Request, code: str = "", state: str = ""):
        try:
            auth.callback(request, code, state)
        except HTTPException as e:
            return PlainTextResponse(str(e.status_code))
        return PlainTextResponse("ok")
    return TestClient(app, base_url="https://testserver")


class Sessions(unittest.TestCase):
    def test_signed_in_from_the_cookie(self):
        c = client()
        c.cookies.set(auth.COOKIE, cookie(session()))
        self.assertEqual(c.get("/me").text, "ada")

    def test_survives_a_restart_with_the_same_key(self):
        v = cookie(session())
        importlib.reload(auth)                  # a new process: nothing in memory
        c = client()
        c.cookies.set(auth.COOKIE, v)
        self.assertEqual(c.get("/me").text, "ada")

    def test_tampered_or_foreign_cookie_is_signed_out(self):
        c = client()
        v = cookie(session())
        c.cookies.set(auth.COOKIE, v[:-4] + ("AAAA" if not v.endswith("AAAA") else "BBBB"))
        self.assertEqual(c.get("/me").text, "-")
        other = auth.Fernet(auth.Fernet.generate_key()).encrypt(b'{"login":"mallory"}').decode()
        c.cookies.set(auth.COOKIE, other)
        self.assertEqual(c.get("/me").text, "-")

    def test_expired_token_without_refresh_is_signed_out(self):
        c = client()
        c.cookies.set(auth.COOKIE, cookie(session(expires=time.time() - 10, refresh=None)))
        self.assertEqual(c.get("/me").text, "-")

    def test_refreshed_token_goes_back_into_the_cookie(self):
        orig = auth._refresh
        def fake(s):
            s.token, s.expires = "t2", time.time() + 3600
            return True
        auth._refresh = fake
        try:
            c = client()
            c.cookies.set(auth.COOKIE, cookie(session(expires=time.time() + 5)))
            r = c.get("/me")
        finally:
            auth._refresh = orig
        self.assertEqual(r.text, "ada")
        self.assertEqual(auth._open(r.cookies.get(auth.COOKIE), 60)["token"], "t2")

    def test_callback_needs_the_matching_pending_login(self):
        c = client()
        self.assertEqual(c.get("/auth/callback?code=x&state=s1").text, "400")      # no pending cookie
        c.cookies.set(auth.PENDING_COOKIE, auth._seal({"state": "s1", "verifier": "v", "next": "/"}), path="/auth/callback")
        self.assertEqual(c.get("/auth/callback?code=x&state=s2").text, "400")      # someone else's state


if __name__ == "__main__":
    unittest.main()
