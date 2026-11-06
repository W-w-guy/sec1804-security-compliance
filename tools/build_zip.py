"""构建交付 zip：只从 git HEAD 出包，带 `sec1804/` 顶层前缀，并自检与 HEAD 逐字节一致。

★ 为什么要有这个脚本（2026-11-06 踩到的真事故）：
  包体原来是手工 `zip -r` 出来的，于是出现过两个后果：
    1) 工作目录里的 reports/*.json 每跑一次就会变 → 打出来的包与 git HEAD 不一致，
       "我交的"和"买家 clone 的"成了两份不同的东西；
    2) `git archive` 默认不加顶层目录，而 H 组按 `sec1804/...` 取文件 →
       我自己用 git archive 打的包直接被 H 组判 11 项失败（结构不对，不是因为代码错）。
  现在统一入口：`python tools/build_zip.py --out ../sec1804_sec5.zip`

用法：
    python tools/build_zip.py --out <zip 路径> [--manifest reports/zip_manifest.json]
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PREFIX = "sec1804/"


def _git(*args: str) -> bytes:
    return subprocess.run(["git", "-C", ROOT] + list(args), capture_output=True, check=True).stdout


def main() -> int:
    ap = argparse.ArgumentParser(description="从 git HEAD 构建交付 zip")
    ap.add_argument("--out", required=True)
    ap.add_argument("--manifest", default=os.path.join(os.path.dirname(ROOT), "zip_manifest.json"),
                    help="默认写到仓库外的上级目录，避免包体包含描述自己的清单")
    a = ap.parse_args()

    head = _git("rev-parse", "HEAD").decode().strip()
    dirty = _git("status", "--porcelain").decode().strip()
    if dirty:
        print("[WARN] 工作目录不干净，打出来的包仍然只含 HEAD 的内容：")
        for ln in dirty.splitlines()[:8]:
            print("      ", ln)

    outp = os.path.abspath(a.out)
    if os.path.exists(outp):
        os.remove(outp)
    subprocess.run(["git", "-C", ROOT, "archive", "--prefix=" + PREFIX,
                    "--format=zip", "-o", outp, "HEAD"], check=True)

    zf = zipfile.ZipFile(outp)
    names = [n for n in zf.namelist() if not n.endswith("/")]
    sha = hashlib.sha256(open(outp, "rb").read()).hexdigest()

    # 逐文件与 HEAD 比对（换行统一后比，避免 Windows CRLF 噪声）
    def norm(b: bytes) -> bytes:
        return b.replace(b"\r\n", b"\n")

    bad = []
    for n in names:
        rel = n[len(PREFIX):]
        try:
            blob = _git("show", f"HEAD:{rel}")
        except subprocess.CalledProcessError:
            bad.append((rel, "HEAD 里没有"))
            continue
        if norm(zf.read(n)) != norm(blob):
            bad.append((rel, "内容不一致"))

    must = ["README.md", "run.py", "Dockerfile", ".dockerignore", "requirements.txt",
            "requirements.lock", "app/main.py", "tools/verify.py", "data/samples_200.csv"]
    missing = [m for m in must if PREFIX + m not in zf.namelist()]
    junk = [n for n in zf.namelist() if any(k in n for k in
                                            ("__pycache__", ".pyc", ".git/", ".venv", ".kms",
                                             ".pytest_cache", ".db", "_pytest.xml", "_h.xml"))]

    res = {"head": head, "out": os.path.basename(outp), "entries": len(zf.namelist()),
           "files": len(names), "bytes": os.path.getsize(outp), "sha256": sha,
           "prefix": PREFIX, "dirty": bool(dirty), "missing_core": missing,
           "junk": junk, "mismatch": bad[:8], "ok": not (missing or junk or bad)}
    os.makedirs(os.path.dirname(a.manifest), exist_ok=True)
    with open(a.manifest, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(res, fh, ensure_ascii=False, indent=1)
    print(f"entries={res['entries']} files={res['files']} bytes={res['bytes']} sha256={sha[:16]}…")
    print(f"head={head[:8]} prefix={PREFIX} missing={missing} junk={junk} mismatch={bad[:3]}")
    print("RESULT:", "OK" if res["ok"] else "FAILED")
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
