"""Version ranges, the same rules as cicd-ref-arch tools/external.py (kept in step by a test),
so the dashboard can say which live SBOMs an advisory hits before the platform re-scans them."""
from __future__ import annotations

import re

_PART = re.compile(r"(\d+|[a-z]+)")
_PRE = {"dev": -4, "a": -3, "alpha": -3, "b": -2, "beta": -2, "rc": -1, "c": -1, "pre": -1, "preview": -1}
_POST = {"post": 1, "p": 1, "r": 1, "rev": 1, "pl": 1}


def version_parts(v: str) -> list[tuple[int, int]]:
    """Numbers as (1, n); pre-release tags (rc, beta...) as (0, -k), before the release; revision
    and post tags (Alpine/Wolfi -r1, .post1) as (2, k), after it."""
    out = []
    for p in _PART.findall(str(v).lower().lstrip("v").split("+")[0]):
        if p.isdigit():
            out.append((1, int(p)))
        elif p in _POST:
            out.append((2, _POST[p]))
        else:
            out.append((0, _PRE.get(p, -5)))
    return out


def vcmp(a: str, b: str) -> int:
    """-1, 0, 1. Good enough for PyPI, npm, Go and apk versions; missing parts count as 0, so
    1.2 == 1.2.0, and 3.0.0rc1 < 3.0.0 < 3.0.0-r1 < 3.0.1."""
    pa, pb = version_parts(a), version_parts(b)
    for i in range(max(len(pa), len(pb))):
        x = pa[i] if i < len(pa) else (1, 0)
        y = pb[i] if i < len(pb) else (1, 0)
        if x != y:
            return -1 if x < y else 1
    return 0


def affected(version: str, spec: str) -> bool:
    """spec: comma-separated comparisons, all must hold: '<3.1.9', '>=2.0,<2.3', '==1.4.2'."""
    for clause in [c.strip() for c in str(spec).split(",") if c.strip()]:
        m = re.match(r"(<=|>=|==|!=|<|>|=)?\s*(.+)", clause)
        c = vcmp(version, m.group(2))
        op = m.group(1) or "=="
        ok = {"<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0, "==": c == 0, "=": c == 0, "!=": c != 0}[op]
        if not ok:
            return False
    return True


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.lower())


def package_hits(pkgs: list[dict], chk: dict) -> list[dict]:
    want, eco = norm(chk.get("name", "")), chk.get("ecosystem")
    return [p for p in pkgs if norm(p["name"]) == want and (not eco or p["ecosystem"] == eco)
            and affected(p["version"], chk.get("affected", ">=0"))]
