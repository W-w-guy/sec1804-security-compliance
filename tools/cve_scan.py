"""依赖漏洞扫描（CVE/GHSA）：向 OSV.dev 批量查询 requirements.lock 的全闭包。

验收点 7 要求「依赖扫描 … 无未处理的高危项」。本脚本负责其中的【漏洞】部分；
`tools/dep_scan.py` 负责【许可证】部分，两者输出各自独立报告，不互相顶替。

用法：
    python tools/cve_scan.py              # 联网查询，写 reports/cve_scan.json
    python tools/cve_scan.py --offline    # 不联网，只读已提交的报告并复核结论

退出码：0 = 无未处理高危；1 = 存在未处理 HIGH/CRITICAL；2 = 无法得出结论（不判通过）
"""
from __future__ import annotations
import json
import os
import sys
import urllib.request

ECOSYSTEM = "PyPI"
BLOCK = {"HIGH", "CRITICAL"}
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1, "": 0}


def _root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read_lock(path: str) -> list[tuple[str, str]]:
    """读 requirements.lock（pip freeze 形态：name==version）。"""
    out = []
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" not in line:
            continue
        name, ver = line.split("==", 1)
        out.append((name.strip(), ver.strip()))
    return out


def _severity(vuln: dict) -> str:
    ds = (vuln.get("database_specific") or {}).get("severity") or ""
    if ds:
        return str(ds).upper()
    # 无 database_specific 时用 CVSS 向量粗判，避免把未知当安全
    for s in vuln.get("severity") or []:
        score = str(s.get("score", ""))
        if "CRITICAL" in score:
            return "CRITICAL"
        if "HIGH" in score:
            return "HIGH"
    return ""


def query_osv(pkgs: list[tuple[str, str]], timeout: int = 30) -> list[dict]:
    body = {"queries": [{"package": {"name": n, "ecosystem": ECOSYSTEM}, "version": v}
                        for n, v in pkgs]}
    req = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    raw = json.loads(urllib.request.urlopen(req, timeout=timeout).read().decode())
    results = raw.get("results", [])
    if len(results) != len(pkgs):
        raise RuntimeError(f"OSV 返回条数不匹配：{len(results)} != {len(pkgs)}")
    return results


def build(pkgs: list[tuple[str, str]], results: list[dict]) -> dict:
    rows, unhandled = [], []
    for (name, ver), res in zip(pkgs, results):
        ids = []
        for v in res.get("vulns", []) or []:
            sev = _severity(v)
            fixes = set()
            for aff in v.get("affected", []):
                for rg in aff.get("ranges", []):
                    for ev in rg.get("events", []):
                        if "fixed" in ev:
                            fixes.add(ev["fixed"])
            ids.append({"id": v.get("id"), "severity": sev or "UNKNOWN",
                        "summary": (v.get("summary") or "")[:200],
                        "fixed": sorted(fixes)})
            if sev in BLOCK or sev == "" or sev == "UNKNOWN":
                unhandled.append({"package": name, "version": ver, "id": v.get("id"),
                                  "severity": sev or "UNKNOWN", "fixed": sorted(fixes)})
        rows.append({"name": name, "version": ver, "vulns": ids,
                     "max_severity": max([i["severity"] for i in ids],
                                         key=lambda s: SEV_ORDER.get(s, 0), default="")})
    return {
        "tool": "osv.dev querybatch (PyPI)",
        "scope": "requirements.lock 全闭包（交付物实际安装的版本）",
        "packages": len(pkgs),
        "with_vulns": sum(1 for r in rows if r["vulns"]),
        "unhandled": unhandled,
        "ok": len(unhandled) == 0,
        "rows": rows,
    }


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    root = _root()
    lock = os.path.join(root, "requirements.lock")
    rep_path = os.path.join(root, "reports", "cve_scan.json")
    if not os.path.exists(lock):
        print("缺少 requirements.lock，拒绝给出结论", file=sys.stderr)
        return 2
    pkgs = read_lock(lock)
    if "--offline" in argv:
        if not os.path.exists(rep_path):
            print("未提交 reports/cve_scan.json，拒绝给出结论", file=sys.stderr)
            return 2
        rep = json.load(open(rep_path, encoding="utf-8"))
        if [tuple(r) for r in rep.get("_lock_snapshot", [])] != pkgs:
            print("已提交报告与当前 requirements.lock 不一致（依赖已变），须重新联网扫描",
                  file=sys.stderr)
            return 2
        print(f"offline: 复用已提交报告 packages={rep['packages']} "
              f"unhandled={len(rep['unhandled'])} ok={rep['ok']}")
        return 0 if rep["ok"] else 1
    try:
        results = query_osv(pkgs)
    except Exception as e:                     # 网络失败不许当通过
        print(f"扫描失败，无法给出结论：{type(e).__name__}: {e}", file=sys.stderr)
        return 2
    rep = build(pkgs, results)
    rep["_lock_snapshot"] = [list(p) for p in pkgs]
    os.makedirs(os.path.dirname(rep_path), exist_ok=True)
    json.dump(rep, open(rep_path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"packages={rep['packages']} with_vulns={rep['with_vulns']} "
          f"unhandled={len(rep['unhandled'])} ok={rep['ok']}")
    for u in rep["unhandled"]:
        print(f"  UNHANDLED {u['severity']:8s} {u['package']}=={u['version']} {u['id']} "
              f"fixed={u['fixed']}")
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
