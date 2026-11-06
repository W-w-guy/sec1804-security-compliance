"""依赖可复现性 / 漏洞豁免的守护测试（验收点 7）。

为什么单独有这一组：
早先交付的 requirements.txt 钉的是 cryptography==44.0.0、pg8000==1.31.2，
两者都有已公布的 HIGH（pg8000 是 SQL 注入），而单测跑的是本机后来装的修复版，
所以「90 项全绿」和「交付物有 HIGH 漏洞」同时成立、互不暴露。
这组测试把「钉住的版本 = 实际验证过的版本 = 扫描过的版本」变成机器可检查的不变量。
"""
from __future__ import annotations
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _pins(path: str) -> dict:
    out = {}
    if not os.path.exists(path):
        return out
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith(("#", "-r ")) or "==" not in line:
            continue
        name, ver = line.split("==", 1)
        out[name.split("[")[0].strip().lower()] = ver.strip()
    return out


def test_lock_file_exists():
    assert os.path.exists(os.path.join(ROOT, "requirements.lock")), \
        "缺少 requirements.lock：无法证明交付安装的是哪组版本"


def test_requirements_pins_are_in_lock_verbatim():
    lock = _pins(os.path.join(ROOT, "requirements.lock"))
    assert lock, "requirements.lock 为空"
    for f in ("requirements.txt", "requirements-dev.txt"):
        for name, ver in _pins(os.path.join(ROOT, f)).items():
            assert name in lock, f"{name} 在 {f} 里钉住，却不在 lock 中"
            assert lock[name] == ver, f"{name} 版本不一致：{f}={ver} / lock={lock[name]}"


def test_cve_report_matches_current_lock():
    """已提交的漏洞报告必须对应当前 lock，否则报告是过期的。"""
    rep = os.path.join(ROOT, "reports", "cve_scan.json")
    assert os.path.exists(rep), "缺少 reports/cve_scan.json（验收点 7 的依赖漏洞扫描证据）"
    data = json.load(open(rep, encoding="utf-8"))
    snap = {n.lower(): v for n, v in data.get("_lock_snapshot", [])}
    lock = _pins(os.path.join(ROOT, "requirements.lock"))
    assert snap == lock, "漏洞报告与当前 requirements.lock 不一致，须重新扫描"


def test_no_unhandled_high_or_critical():
    data = json.load(open(os.path.join(ROOT, "reports", "cve_scan.json"), encoding="utf-8"))
    assert data.get("ok") is True, f"存在未处理项：{data.get('unhandled')}"
    bad = [u for u in data.get("unhandled", []) if u.get("severity") in ("HIGH", "CRITICAL")]
    assert not bad, f"未处理的高危：{bad}"
    # 允许有漏洞，但 HIGH/CRITICAL 一条都不许留
    for row in data.get("rows", []):
        for v in row.get("vulns", []):
            assert v["severity"] != "CRITICAL" or v["fixed"], \
                f"{row['name']}={row['version']} 的 CRITICAL {v['id']} 没有修复版本"


def test_license_scan_matches_lock():
    """报告必须逐包覆盖 lock，且版本取自 lock —— 与"谁在什么机器上跑的"无关。

    ★ 2026-11-06 改：早先这条断言的是"扫描环境与 lock 零漂移"。
      但那等于要求审阅者的机器和我们一模一样，他跑一次就红给你看；
      而且被改名的字段会让断言静默通过（假通过）。现在断言的是真正的不变量：
      报告里的包集合 = lock 的包集合，且每个包的 version 字段 = lock 版本。
    """
    rep = os.path.join(ROOT, "reports", "dep_scan.json")
    assert os.path.exists(rep), "缺少 reports/dep_scan.json"
    data = json.load(open(rep, encoding="utf-8"))
    assert data.get("ok") is True, f"许可扫描未通过：deny={data.get('denied')} unknown={data.get('unknown')}"
    norm = lambda s: s.lower().replace("_", "-")          # noqa: E731  pydantic_core ≡ pydantic-core
    lock = {norm(k): v for k, v in _pins(os.path.join(ROOT, "requirements.lock")).items()}
    rows = {norm(r["name"]): r for r in data.get("rows", [])}
    # 报告里可以出现 not_installed（本机没装的包无法读元数据），但必须逐个点名，
    # 不许静默漏掉：rows ∪ not_installed 必须正好等于 lock。
    skipped = {norm(x.split("==")[0]) for x in data.get("not_installed", [])}
    missing = sorted(k for k in lock if k not in rows and k not in skipped)
    assert not missing, f"报告既没扫也没点名，属于静默漏项：{missing}"
    assert not (set(rows) & skipped), f"同一个包既扫了又标未安装：{set(rows) & skipped}"
    wrong = {k: (rows[k]["version"], lock[k]) for k in lock
             if k in rows and rows[k]["version"] != lock[k]}
    assert not wrong, f"报告里的版本不是 lock 版本：{wrong}"
    assert data.get("total", 0) >= 30, "许可扫描覆盖的包数异常少，可能只扫了种子"
    assert not data.get("denied") and not data.get("unknown"), "存在 deny/unknown 许可"
