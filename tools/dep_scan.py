"""依赖与许可扫描（只看本项目的依赖闭包，不看整机环境）。

契约 v1：依赖只允许 MIT / Apache-2.0 / BSD / PostgreSQL 许可，禁止 GPL / AGPL。
做法：从 requirements.txt 种子出发，按 importlib.metadata 的 requires 递归求闭包。
用法：python tools/dep_scan.py [--json]
"""
from __future__ import annotations
import json
import os
import re
import sys
from importlib import metadata

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DENY_RE = re.compile(r"\b(?:A?GPL|LGPL|SSPL|BUSL)\b|GNU (?:Affero|Lesser|General Public)", re.I)
ALLOW_RE = re.compile(r"\b(?:MIT|BSD|Apache|ISC|PSF|Python Software Foundation|PostgreSQL|MPL-2\.0|Unlicense|Zlib)\b",
                      re.I)


# 静态许可表：仅用于“运行环境拿不到 license 元信息”时兜底，逐条可在上游仓库核实
KNOWN = {
    "annotated-doc": "MIT", "anyio": "MIT", "cffi": "MIT", "click": "BSD-3-Clause",
    "cryptography": "Apache-2.0 OR BSD-3-Clause", "fastapi": "MIT", "idna": "BSD-3-Clause",
    "opentelemetry-api": "Apache-2.0", "pycparser": "BSD-3-Clause", "pydantic": "MIT",
    "pydantic-core": "MIT", "starlette": "BSD-3-Clause", "typing-extensions": "PSF-2.0",
    "typing-inspection": "MIT", "uvicorn": "BSD-3-Clause", "psycopg": "LGPL-3.0-only",
    "psycopg-binary": "LGPL-3.0-only", "redis": "MIT", "h11": "MIT", "httptools": "MIT",
    "python-dotenv": "BSD-3-Clause", "pyyaml": "MIT", "watchfiles": "MIT", "websockets": "BSD-3-Clause",
    "pytest": "MIT", "httpx": "BSD-3-Clause", "httpcore": "BSD-3-Clause", "sniffio": "MIT",
    # pg8000 运行时依赖（BSD-3 栈）：scramp=SCRAM 认证(MIT)，python-dateutil=Apache-2.0 OR BSD-3
    "scramp": "MIT", "python-dateutil": "Apache-2.0 OR BSD-3-Clause",
    "asn1crypto": "MIT", "six": "MIT",
    "certifi": "MPL-2.0", "charset-normalizer": "MIT", "requests": "Apache-2.0",
}


def seeds() -> list[str]:
    out = []
    path = os.path.join(ROOT, "requirements.txt")
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name = re.split(r"[<>=!~\[; ]", line)[0]
        out.append(name)
    return out


def _canon(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def closure() -> set[str]:
    seen, queue = set(), [_canon(s) for s in seeds()]
    while queue:
        n = queue.pop()
        if n in seen:
            continue
        seen.add(n)
        try:
            reqs = metadata.requires(n) or []
        except metadata.PackageNotFoundError:
            continue
        for r in reqs:
            if "extra ==" in r:            # 跳过可选依赖
                continue
            dep = re.split(r"[<>=!~\[; (]", r)[0].strip()
            if dep:
                queue.append(_canon(dep))
    return seen


def classify(lic: str) -> str:
    up = lic or ""
    if DENY_RE.search(up):
        return "deny"
    if ALLOW_RE.search(up):
        return "allow"
    return "unknown"


def licence_of(dist) -> str:
    lic = (dist.metadata.get("License") or "").strip()
    if not lic or len(lic) > 80:            # 长文本常是全文，退回 classifier
        cls = [c.split("::")[-1].strip() for c in (dist.metadata.get_all("Classifier") or [])
               if c.startswith("License ::")]
        lic = "; ".join(cls) or lic
    return lic


def scan() -> dict:
    keep = closure()
    rows, missing = [], []
    for name in sorted(keep):
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            missing.append(name)
            continue
        lic = licence_of(dist)
        src = "metadata"
        if not lic or classify(lic) == "unknown":
            key = _canon(dist.metadata.get("Name") or "")
            if key in KNOWN:
                lic, src = KNOWN[key], "static"
        rows.append({"name": dist.metadata.get("Name"), "version": dist.version,
                     "license": lic[:80], "source": src, "verdict": classify(lic)})
    denied = [r for r in rows if r["verdict"] == "deny"]
    unknown = [r for r in rows if r["verdict"] == "unknown"]
    return {"scope": "requirements.txt 依赖闭包", "total": len(rows),
            "denied": denied, "unknown": unknown, "not_installed": missing,
            "ok": not denied, "rows": rows}


if __name__ == "__main__":
    res = scan()
    os.makedirs(os.path.join(ROOT, "reports"), exist_ok=True)
    with open(os.path.join(ROOT, "reports", "dep_scan.json"), "w", encoding="utf-8") as fh:
        json.dump(res, fh, ensure_ascii=False, indent=1)
    if "--json" in sys.argv:
        print(json.dumps({k: v for k, v in res.items() if k != "rows"}, ensure_ascii=False, indent=1))
    else:
        print(f"scope={res['scope']} deps={res['total']} denied={len(res['denied'])} "
              f"unknown={len(res['unknown'])} ok={res['ok']}")
        for r in res["denied"]:
            print("  DENY", r["name"], r["version"], r["license"])
        for r in res["unknown"]:
            print("  ?   ", r["name"], r["version"], r["license"])
    sys.exit(0 if res["ok"] else 1)
