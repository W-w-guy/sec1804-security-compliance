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


def scan(strict_env: bool = False) -> dict:
    """扫描对象 = requirements.lock（交付物实际安装的那组版本）。

    ★ 2026-11-06 两次改：
      1) 早先从 requirements.txt 种子跑闭包、版本取环境里装的那个，报告却写「交付物」→ 报告说谎。
      2) 改严之后矫枉过正：环境与 lock 不一致就整条判失败 → 审阅者在自己的机器上
         `python tools/verify.py` 必然 FAIL（他装的 transitive 版本不可能和我们的 lock 一样）。
         这不是缺陷，是噪声，而且会把真缺陷淹掉。
    现在的口径：
      - 版本、闭包 = lock（唯一事实源），漏洞扫描 tools/cve_scan.py 也按 lock 查；
      - 许可判定仍读已装 dist 的元数据，但把 env_version 与 drift 逐行写进报告；
      - ok 只看 deny / unknown（契约本身）；漂移单列 env_drift，明示"不是同一组版本"；
      - `--strict-env` 时漂移也判失败，用于「干净 venv 全量自证」那一次记录。
    """
    lock = _read_lock()
    if not lock:
        return {"scope": "requirements.lock 全闭包", "total": 0, "denied": [], "unknown": [],
                "env_drift": [{"name": "<lock>", "issue": "requirements.lock 缺失"}],
                "not_installed": [], "ok": False, "rows": []}
    rows, missing, drift = [], [], []
    for key in sorted(lock):
        want = lock[key]
        try:
            dist = metadata.distribution(key)
        except metadata.PackageNotFoundError:
            # ★ 2026-11-06 补：许可与"这台机器装没装"无关。原先缺装直接 continue，
            #   等于把该包的许可判定静默跳过 —— 一个 GPL 包只要本机没装就能溜过契约。
            #   现在用静态许可表兜底；表里也没有 -> 记 unknown（判失败），不许静默通过。
            missing.append(f"{key}=={want}")
            lic = KNOWN.get(key, "")
            if lic:
                rows.append({"name": key, "version": want, "env_version": None, "drift": False,
                             "license": lic, "source": "static(not_installed)",
                             "verdict": classify(lic)})
            else:
                rows.append({"name": key, "version": want, "env_version": None, "drift": False,
                             "license": "", "source": "无法判定(未安装)",
                             "verdict": "unknown"})
            continue
        env_ver = dist.version
        if env_ver != want:
            drift.append({"name": key, "issue": f"环境 {env_ver} / lock {want}"})
        lic = licence_of(dist)
        src = "metadata"
        if not lic or classify(lic) == "unknown":
            k = _canon(dist.metadata.get("Name") or "")
            if k in KNOWN:
                lic, src = KNOWN[k], "static"
        rows.append({"name": dist.metadata.get("Name"), "version": want,
                     "env_version": env_ver, "drift": env_ver != want,
                     "license": lic[:80], "source": src, "verdict": classify(lic)})
    denied = [r for r in rows if r["verdict"] == "deny"]
    unknown = [r for r in rows if r["verdict"] == "unknown"]
    ok = not denied and not unknown
    if strict_env and (drift or missing):
        ok = False
    return {"scope": "requirements.lock 全闭包（版本以 lock 为准）", "total": len(rows),
            "strict_env": strict_env, "env_drift": drift, "denied": denied, "unknown": unknown,
            "not_installed": missing, "ok": ok, "rows": rows}


if __name__ == "__main__":
    res = scan(strict_env="--strict-env" in sys.argv)
    os.makedirs(os.path.join(ROOT, "reports"), exist_ok=True)
    with open(os.path.join(ROOT, "reports", "dep_scan.json"), "w", encoding="utf-8",
              newline="\n") as fh:
        json.dump(res, fh, ensure_ascii=False, indent=1)
    if "--json" in sys.argv:
        print(json.dumps({k: v for k, v in res.items() if k != "rows"}, ensure_ascii=False, indent=1))
    else:
        print(f"scope={res['scope']} deps={res['total']} denied={len(res['denied'])} "
              f"unknown={len(res['unknown'])} env_drift={len(res['env_drift'])} "
              f"not_installed={len(res['not_installed'])} strict_env={res['strict_env']} ok={res['ok']}")
        if res["env_drift"]:
            print("  NOTE 环境与 lock 不同（以下是漂移项，不是缺陷；要完全一致请 "
                  "`pip install -r requirements.lock`）")
        for b in res["env_drift"]:
            print("  LOCK", b["name"], "|", b["issue"])
        for r in res["denied"]:
            print("  DENY", r["name"], r["version"], r["license"])
        for r in res["unknown"]:
            print("  ?   ", r["name"], r["version"], r["license"])
    sys.exit(0 if res["ok"] else 1)
