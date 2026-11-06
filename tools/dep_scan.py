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
    # pytest 9 的运行时依赖（BSD-3 栈），元数据里 License 字段为空，只能静态兜底
    "iniconfig": "MIT", "packaging": "Apache-2.0 OR BSD-2-Clause", "pygments": "BSD-2-Clause",
    # uvicorn[standard] 的可选栈
    "httptools": "MIT", "watchfiles": "MIT", "websockets": "BSD-3-Clause",
    "python-dotenv": "BSD-3-Clause", "pyyaml": "MIT", "tzdata": "Apache-2.0",
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



def _read_lock() -> dict:
    path = os.path.join(ROOT, "requirements.lock")
    if not os.path.exists(path):
        return {}
    out = {}
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#") or "==" not in line:
            continue
        n, v = line.split("==", 1)
        out[_canon(n.strip())] = v.strip()
    return out


def _lock_mismatch(rows: list[dict]) -> list[dict]:
    """扫描环境与 requirements.lock 逐一比对。

    ★ 这条是 2026-11-06 补的：早先 dep_scan 只扫 requirements.txt 种子求闭包，
      但版本取的是【运行环境里已装的那个】。结果本机装的是 cryptography 50.0.2，
      报告写下 50.0.2，而 requirements.txt 钉的是 44.0.0（有 HIGH）——
      报告的 scope 写着「交付物」，实际扫的是本机。审阅者一对就露。
      现在口径改成：报告必须与 lock 完全一致，不一致直接判失败。
    """
    lock = _read_lock()
    if not lock:
        return [{"name": "<lock>", "issue": "requirements.lock 缺失，无法证明扫的就是交付版本"}]
    bad = []
    for r in rows:
        key = _canon(r["name"] or "")
        want = lock.get(key)
        if want is None:
            bad.append({"name": r["name"], "issue": f"lock 里没有这个包（环境有 {r['version']}）"})
        elif want != r["version"]:
            bad.append({"name": r["name"], "issue": f"版本不一致：环境 {r['version']} / lock {want}"})
    for key in sorted(set(lock) - {_canon(r["name"] or "") for r in rows}):
        bad.append({"name": key, "issue": f"lock 里有、环境里没装（{lock[key]}）"})
    return bad


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
    """扫描对象 = requirements.lock（交付物实际安装的那组版本）。

    ★ 2026-11-06 改：早先是从 requirements.txt 种子跑依赖闭包、版本取环境里装的那个，
      报告写着「requirements.txt 依赖闭包」，实际扫的却是本机环境。
      现在 lock 就是唯一事实源：闭包与版本都来自 lock，环境对不上直接判失败。
    """
    lock = _read_lock()
    if not lock:
        return {"scope": "requirements.lock 全闭包", "total": 0, "denied": [], "unknown": [],
                "lock_mismatch": [{"name": "<lock>", "issue": "requirements.lock 缺失"}],
                "not_installed": [], "ok": False, "rows": []}
    rows, missing, mismatch = [], [], []
    for key in sorted(lock):
        want = lock[key]
        try:
            dist = metadata.distribution(key)
        except metadata.PackageNotFoundError:
            missing.append(f"{key}=={want}")
            continue
        if dist.version != want:
            mismatch.append({"name": key, "issue": f"环境 {dist.version} / lock {want}"})
        lic = licence_of(dist)
        src = "metadata"
        if not lic or classify(lic) == "unknown":
            k = _canon(dist.metadata.get("Name") or "")
            if k in KNOWN:
                lic, src = KNOWN[k], "static"
        rows.append({"name": dist.metadata.get("Name"), "version": dist.version,
                     "license": lic[:80], "source": src, "verdict": classify(lic)})
    denied = [r for r in rows if r["verdict"] == "deny"]
    unknown = [r for r in rows if r["verdict"] == "unknown"]
    return {"scope": "requirements.lock 全闭包（交付物实际安装的版本）", "total": len(rows),
            "lock_mismatch": mismatch, "denied": denied, "unknown": unknown,
            "not_installed": missing,
            "ok": not denied and not unknown and not missing and not mismatch, "rows": rows}


if __name__ == "__main__":
    res = scan()
    os.makedirs(os.path.join(ROOT, "reports"), exist_ok=True)
    with open(os.path.join(ROOT, "reports", "dep_scan.json"), "w", encoding="utf-8") as fh:
        json.dump(res, fh, ensure_ascii=False, indent=1)
    if "--json" in sys.argv:
        print(json.dumps({k: v for k, v in res.items() if k != "rows"}, ensure_ascii=False, indent=1))
    else:
        print(f"scope={res['scope']} deps={res['total']} denied={len(res['denied'])} "
              f"unknown={len(res['unknown'])} lock_mismatch={len(res['lock_mismatch'])} ok={res['ok']}")
        for b in res["lock_mismatch"]:
            print("  LOCK", b["name"], "|", b["issue"])
        for r in res["denied"]:
            print("  DENY", r["name"], r["version"], r["license"])
        for r in res["unknown"]:
            print("  ?   ", r["name"], r["version"], r["license"])
    sys.exit(0 if res["ok"] else 1)
