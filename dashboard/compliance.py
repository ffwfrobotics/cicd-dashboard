"""The owner's compliance repo (ffwf/cicd-compliance), read and written as the signed-in person.

It may be private, so nothing here is read anonymously: whoever can see the repo on the forge sees
IT Security's findings in the dashboard, and every change is a commit or pull request by them.

- ledger/<app>.yaml   IT Security's findings, each with a check (cicd-ref-arch tools/external.py)
- advisories/*.yaml   vulnerabilities announced by hand (or picked from OSV)
- releases/<id>/      packages released to IT Security: unaltered records + manifest.json (sha256)
- apps/<app>/app.yaml the release rule (second-person or named approvers)
"""
from __future__ import annotations

import base64
import csv
import datetime as dt
import hashlib
import io
import json
import os
import re
import time

import httpx
import yaml

COMPLIANCE_REPO = os.environ.get("COMPLIANCE_REPO", "ffwf/cicd-compliance")
BRANCH = os.environ.get("COMPLIANCE_BRANCH", "main")
_cache: dict[tuple, tuple[float, object]] = {}


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _get(c: httpx.Client, login: str, path: str, ttl: float = 15, raw: bool = False):
    key = (login, path, raw)
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    r = c.get(path)
    val = None if r.status_code == 404 else (r.content if raw else r.json()) if r.status_code == 200 else False
    now = time.time()
    for k in [k for k, (t, _) in _cache.items() if now - t >= 3600]:
        del _cache[k]
    _cache[key] = (now, val)
    return val


def forget(login: str):
    for k in [k for k in _cache if k[0] == login]:
        _cache.pop(k, None)


def access(c: httpx.Client, login: str) -> dict | None:
    """The person's permissions on the compliance repo, or None if they can't see it."""
    r = _get(c, login, f"/repos/{COMPLIANCE_REPO}", ttl=60)
    return (r or {}).get("permissions") if r else None


def read_yaml(c, login, path: str):
    raw = _get(c, login, f"/repos/{COMPLIANCE_REPO}/raw/{path}?ref={BRANCH}", raw=True)
    return yaml.safe_load(raw) if raw else None


def ledger(c, login, app: str) -> list[dict]:
    return (read_yaml(c, login, f"ledger/{app}.yaml") or {}).get("findings") or []


def app_config(c, login, app: str) -> dict:
    return read_yaml(c, login, f"apps/{app}/app.yaml") or {}


def listing(c, login, d: str) -> list[dict]:
    r = _get(c, login, f"/repos/{COMPLIANCE_REPO}/contents/{d}?ref={BRANCH}")
    return r if isinstance(r, list) else []


def advisories(c, login) -> list[dict]:
    out = []
    for f in listing(c, login, "advisories"):
        if f["name"].endswith(".yaml"):
            a = read_yaml(c, login, f"advisories/{f['name']}")
            if a and a.get("id"):
                out.append(a)
    return sorted(out, key=lambda a: a.get("announced", ""), reverse=True)


def releases(c, login, app: str | None = None) -> list[dict]:
    out = []
    for d in listing(c, login, "releases"):
        if d["type"] != "dir":
            continue
        m = _get(c, login, f"/repos/{COMPLIANCE_REPO}/raw/releases/{d['name']}/manifest.json?ref={BRANCH}", raw=True)
        if m:
            m = json.loads(m)
            if app is None or app in m.get("apps", []):
                out.append(m)
    return sorted(out, key=lambda m: m.get("released", ""), reverse=True)


def release_prs(c, login) -> list[dict]:
    prs = _get(c, login, f"/repos/{COMPLIANCE_REPO}/pulls?state=open&limit=50", ttl=10) or []
    out = []
    for p in prs:
        if not p["head"]["ref"].startswith("release/"):
            continue
        reviews = _get(c, login, f"/repos/{COMPLIANCE_REPO}/pulls/{p['number']}/reviews", ttl=10) or []
        out.append({"number": p["number"], "title": p["title"], "url": p["html_url"], "author": p["user"]["login"],
                    "id": p["head"]["ref"][len("release/"):], "body": p.get("body", ""),
                    "approvers": sorted({r["user"]["login"] for r in reviews if r.get("state") == "APPROVED"})})
    return out


# ---------------------------------------------------------------- writing, as the person


def put_file(c, path: str, text: str, message: str) -> tuple[bool, str]:
    cur = c.get(f"/repos/{COMPLIANCE_REPO}/contents/{path}?ref={BRANCH}")
    body = {"content": base64.b64encode(text.encode()).decode(), "branch": BRANCH, "message": message}
    if cur.status_code == 200:
        r = c.put(f"/repos/{COMPLIANCE_REPO}/contents/{path}", json=dict(body, sha=cur.json()["sha"]))
    else:
        r = c.post(f"/repos/{COMPLIANCE_REPO}/contents/{path}", json=body)
    return r.status_code in (200, 201), _err(r)


def _err(r) -> str:
    try:
        return f"{r.status_code}: {r.json().get('message', '')}"
    except Exception:
        return f"{r.status_code}"


def save_ledger(c, app: str, findings: list[dict], message: str) -> tuple[bool, str]:
    text = ("# IT Security's findings for " + app + ", as tests (cicd-ref-arch docs/oscal.md). Written by\n"
            "# cicd-dashboard as the person who imported, accepted or closed them; edit by hand too.\n"
            + yaml.safe_dump({"app": app, "findings": findings}, sort_keys=False, allow_unicode=True, width=110))
    return put_file(c, f"ledger/{app}.yaml", text, message)


# ---------------------------------------------------------------- importing IT Security's exports

RISK = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "none": "info", "info": "info"}
HEADERS = {"strict-transport-security": "Strict-Transport-Security", "hsts": "Strict-Transport-Security",
           "x-content-type-options": "X-Content-Type-Options", "x-frame-options": "X-Frame-Options",
           "content-security-policy": "Content-Security-Policy", "referrer-policy": "Referrer-Policy"}


def check_for(row: dict) -> dict:
    """Make a Tenable row testable: a package with a fixed version, a missing HTTP header, or manual."""
    text = " ".join(row.get(k, "") for k in ("Name", "Synopsis", "Plugin Output")).lower()
    for needle, header in HEADERS.items():
        if needle in text and ("missing" in text or "not" in text or "absent" in text):
            path = "/"
            m = re.search(r"https?://[^/\s]+(/\S*)", row.get("Plugin Output", ""))
            if m:
                path = m.group(1)
            return {"type": "endpoint", "path": path, "header": header}
    out = row.get("Plugin Output", "")
    fixed = re.search(r"Fixed version\s*:\s*([^\s]+)", out)
    if fixed:
        name = None
        m = re.search(r"site-packages/([A-Za-z0-9_.\-]+)", out) or re.search(r"Package\s*:\s*([A-Za-z0-9_.\-]+)", out)
        if m:
            name = m.group(1)
        else:
            m = re.match(r"\s*([A-Za-z0-9_.\-]+)\s*(<|<=|\d)", row.get("Name", ""))
            name = m.group(1) if m else None
        if name:
            return {"type": "package", "name": name.lower(), "affected": f"<{fixed.group(1)}"}
    return {"type": "manual"}


def parse_tenable(data: bytes, who: str, filename: str) -> list[dict]:
    rows = csv.DictReader(io.StringIO(data.decode("utf-8-sig", errors="replace")))
    out = []
    for row in rows:
        plugin, host = (row.get("Plugin ID") or "").strip(), (row.get("Host") or "").strip()
        risk = RISK.get((row.get("Risk") or "").strip().lower(), "medium")
        if risk == "info" or not plugin:
            continue
        port = (row.get("Port") or "").strip()
        fid = f"TEN-{plugin}-{hashlib.sha1(f'{host}:{port}'.encode()).hexdigest()[:6]}"
        out.append({
            "id": fid, "title": (row.get("Name") or plugin).strip(), "severity": risk,
            "location": f"{host}:{port}" if port and port != "0" else host,
            "check": check_for(row), "status": "open",
            **({"cve": [c.strip() for c in row["CVE"].split(",") if c.strip()]} if (row.get("CVE") or "").strip() else {}),
            "solution": (row.get("Solution") or "").strip()[:300],
            "source": {"kind": "tenable-csv", "plugin": plugin, "file": filename, "imported_by": who, "imported_at": now()}})
    return out


def merge_import(existing: list[dict], new: list[dict]) -> tuple[list[dict], int, int]:
    """New findings are appended; ones already there (same id) keep their status and history."""
    by_id = {f["id"]: f for f in existing}
    added = seen = 0
    for f in new:
        if f["id"] in by_id:
            seen += 1
            old = by_id[f["id"]]
            old.setdefault("source", {})["last_seen"] = f["source"]["imported_at"]
            if old.get("status") == "closed":        # it came back: reopen it
                old["status"], old["reopened"] = "open", f["source"]["imported_at"]
        else:
            existing.append(f)
            added += 1
    return existing, added, seen


# ---------------------------------------------------------------- OSV (public vulnerability data)


def osv_query(packages: list[dict]) -> list[dict]:
    """Ask OSV about the packages of live SBOMs (name, version, ecosystem only). Returns
    [{id, summary, package, version, ecosystem}]. Only PyPI, npm and Go here."""
    eco = {"pypi": "PyPI", "npm": "npm", "golang": "Go"}
    q, keys = [], []
    for p in packages:
        if p["ecosystem"] in eco and p["version"]:
            q.append({"package": {"name": p["name"], "ecosystem": eco[p["ecosystem"]]}, "version": p["version"]})
            keys.append(p)
    if not q:
        return []
    r = httpx.post("https://api.osv.dev/v1/querybatch", json={"queries": q}, timeout=30)
    r.raise_for_status()
    out = []
    for p, res in zip(keys, r.json().get("results", [])):
        for v in res.get("vulns") or []:
            out.append({"id": v["id"], "package": p["name"], "version": p["version"], "ecosystem": p["ecosystem"]})
    for o in out[:40]:   # summaries and fixed versions, for the announce form
        d = httpx.get(f"https://api.osv.dev/v1/vulns/{o['id']}", timeout=20)
        if d.status_code == 200:
            v = d.json()
            o["summary"] = (v.get("summary") or v.get("details", ""))[:160]
            fixed = [e["fixed"] for a in v.get("affected", []) for rg in a.get("ranges", []) for e in rg.get("events", []) if "fixed" in e]
            o["fixed"] = fixed[0] if fixed else ""
            sev = (v.get("database_specific") or {}).get("severity", "")
            sev = {"moderate": "medium"}.get(sev.lower(), sev.lower()) if sev else "high"
            o["severity"] = sev if sev in ("critical", "high", "medium", "low") else "high"
    return out


# ---------------------------------------------------------------- release packages


def release_package(rid: str, app: str, envs: list[str], files: dict[str, bytes], state_head: str, who: str,
                    note: str, cluster: str) -> tuple[list[dict], dict]:
    """(change-files operations, manifest) for releases/<rid>/: the chosen environments' records,
    byte for byte, with their sha256, and where they came from."""
    ops, listed = [], {}
    for env in envs:
        prefix = f"envs/{cluster}/{app}/{env}/"
        for path, data in sorted(files.items()):
            if not path.startswith(prefix):
                continue
            rel = path[len(prefix):]
            if not (rel.startswith(("evidence/", "suppressions/")) or rel in ("security-record.json", "findings-source.json", "app.yaml", "cicd-env.yaml")):
                continue
            dest = f"releases/{rid}/{env}/{rel}"
            ops.append({"operation": "create", "path": dest, "content": base64.b64encode(data).decode()})
            listed[f"{env}/{rel}"] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
                                      "source": f"{path}@{state_head}"}
    manifest = {"schema": "release-package/v1", "id": rid, "apps": [app], "environments": envs, "cluster": cluster,
                "state_commit": state_head, "prepared_by": who, "released": now(), "note": note,
                "files": listed,
                "remarks": "Unaltered records from the state repo at state_commit; the release is the merge of this "
                           "package's pull request by a second person. The owner's self-assessment, not an official one."}
    ops.append({"operation": "create", "path": f"releases/{rid}/manifest.json",
                "content": base64.b64encode((json.dumps(manifest, indent=1) + "\n").encode()).decode()})
    return ops, manifest
