#!/usr/bin/env python3
"""Browser checks of a running dashboard, signed in as a forge user through the forge's own login.

  DASHBOARD=https://dashboard-dev.c-local.k.ffwf.net SSO_USER=... SSO_PASS=... python3 tests/browser/run.py [check...]

Needs Playwright (pip install playwright==1.49.1, with its chromium). The cluster's CA is not in
the browser's store, so certificate errors are ignored. Screenshots go to $OUT (default ./browser-out).
Each check asserts what the page shows as states and fields (classes, links, inputs), never wording.
Not run in CI: it needs a forge user's password (decide where that lives before wiring it in).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE = os.environ.get("DASHBOARD", "https://dashboard-dev.c-local.k.ffwf.net").rstrip("/")
OUT = Path(os.environ.get("OUT", "browser-out"))
CHECKS = {}


def check(fn):
    CHECKS[fn.__name__] = fn
    return fn


def sign_in(ctx):
    pg = ctx.new_page()
    pg.goto(f"{BASE}/auth/login?next=/", wait_until="load", timeout=120000)
    if "/user/login" in pg.url:
        pg.locator("#user_name").fill(os.environ["SSO_USER"])
        pg.locator("#password").fill(os.environ["SSO_PASS"])
        pg.get_by_role("button", name="Sign in", exact=True).click()
        pg.wait_for_load_state("load")
    if "/login/oauth/authorize" in pg.url:
        pg.locator("#authorize-app, button:has-text('Authorize')").first.click()
        pg.wait_for_load_state("load")
    assert pg.url.startswith(BASE), f"sign-in ended at {pg.url.split('?')[0]}"
    assert pg.locator("header").get_by_text(os.environ["SSO_USER"]).count(), "not signed in"
    return pg


@check
def enroll_modes(pg):
    """Add app offers the three modes and the two update policies."""
    pg.goto(f"{BASE}/enroll", wait_until="load")
    modes = pg.locator("select[name=mode] option").all_inner_texts()
    assert modes == ["direct", "wrapped", "monorepo"], modes
    assert pg.locator("select[name=update] option").all_inner_texts() == ["follow", "pin"]


@check
def wrapped_lineage(pg):
    """A wrapped app (fxw, from the e2e fixtures) shows the source commit each environment runs."""
    pg.goto(f"{BASE}/a/fxw", wait_until="load")
    links = pg.locator(".card a[href*='ffwf-fixtures/fx-vibe/commit/']")
    assert links.count() >= 1, "no source link on the environment cards"


@check
def enroll_wrapped_through_the_form(pg):
    """Add app, mode wrapped, on a fixture repo of this forge: the enroll workflow wraps it, and the app appears,
    pending. Needs ENROLL_SOURCE (a repo the signed-in user administers) and ENROLL_NAME; the e2e runner cleans up."""
    src, name = os.environ.get("ENROLL_SOURCE"), os.environ.get("ENROLL_NAME")
    if not (src and name):
        print("  (skipped: ENROLL_SOURCE and ENROLL_NAME not set)")
        return
    pg.goto(f"{BASE}/enroll", wait_until="load")
    pg.locator("input[name=source]").fill(src)
    pg.locator("input[name=name]").fill(name)
    pg.locator("select[name=mode]").select_option("wrapped")
    pg.locator("select[name=update]").select_option("follow")
    pg.locator("form[method=post] button.primary").click()
    pg.wait_for_load_state("load")
    assert pg.locator(".flash").count() and f"ffwf-iac/{name}" in pg.locator(".flash").inner_text(), "no enrolling message"
    import time
    for _ in range(60):                                   # the workflow writes the record in about a minute
        pg.goto(f"{BASE}/a/{name}", wait_until="load")
        if pg.locator("h1").count() and not pg.locator("text=no enrolled application").count():
            break
        time.sleep(10)
    else:
        raise AssertionError(f"{name} did not appear within 10 minutes")


def main():
    names = sys.argv[1:] or list(CHECKS)
    OUT.mkdir(exist_ok=True)
    failed = []
    with sync_playwright() as p:
        b = p.chromium.launch()
        ctx = b.new_context(ignore_https_errors=True, viewport={"width": 1400, "height": 1000})
        pg = sign_in(ctx)
        for n in names:
            try:
                CHECKS[n](pg)
                print(f"PASS {n}")
            except Exception as e:      # noqa: BLE001 - report every check
                print(f"FAIL {n}: {e}")
                failed.append(n)
            pg.screenshot(path=str(OUT / f"{n}.png"), full_page=True)
        b.close()
    print(f"{len(names) - len(failed)}/{len(names)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
