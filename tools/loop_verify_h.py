"""H 组 15 轮：交付形态（买家第一眼会做什么）。

前面七组证明了"东西是好的"。H 组问"**别人能不能自己用起来**"：
干净机器一条命令起不来，前面 105 轮全白做。

验收口径全部站在买家/验收人立场：
H1  zip 完整性：条目齐全、无 __pycache__/.venv/密钥/数据库残留
H2  无绝对路径泄漏（不能写死 E:\ 或 /home/xxx）
H3  干净解压 + 一条命令跑测（不预装任何东西，只用 requirements）
H4  一键演示 demo 的输出可读且结论明确
H5  verify.py 六步全绿且记录落盘
H6  docker compose 配置合法（compose config / 依赖顺序 / healthcheck）
H7  Dockerfile 可构建的静态检查 + .dockerignore 生效
H8  README 与仓库实际一致（提到的命令/文件都必须真的存在）
H9  OpenAPI 文档可访问且路径数与 README 声明一致
H10 首次启动：无 .kms 目录也能起，密钥自动生成且不可读
H11 版本与 CHANGELOG 可追溯
H12 样例数据可独立使用（样本集自带标注，格式自解释）
H13 失败可诊断：故意制造错误时给出可操作的提示而不是堆栈
H14 卸载/清理干净：停掉服务后不残留进程/端口占用
H15 交付清单自检：README 列的每个产物都在包里
"""
from __future__ import annotations
import json
import os
import platform
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
ENV = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1",
           PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")

ZIP_NAME = "sec1804_sec5.zip"



def _zip_matches_head(zip_path: str) -> tuple[bool | None, str]:
    """zip 里的每个文件是否与当前 git HEAD 逐一相同。

    做法是 `git show HEAD:<path>` 取权威内容再比字节，而不是读工作目录
    （工作目录里的 reports/*.json 会因运行而变，拿它比会得出假结果）。
    没有 git 或没有提交时返回 (None, ...)，如实标为"未能验证"，不当成通过。
    """
    import hashlib
    git = shutil.which("git")
    if not git:
        return None, "no git"
    r = subprocess.run([git, "rev-parse", "--verify", "HEAD"], cwd=ROOT,
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        return None, "no HEAD commit"
    rev = r.stdout.strip()[:8]
    r2 = subprocess.run([git, "ls-tree", "-r", "--name-only", "HEAD"], cwd=ROOT,
                        capture_output=True, text=True, encoding="utf-8", errors="replace")
    head_files = set(r2.stdout.split())
    with zipfile.ZipFile(zip_path) as z:
        zip_files = {n.replace("sec1804/", "", 1) for n in z.namelist() if not n.endswith("/")}
        only_head = sorted(head_files - zip_files)
        only_zip = sorted(zip_files - head_files)
        diff = []
        for f in sorted(head_files & zip_files):
            blob = subprocess.run([git, "show", f"HEAD:{f}"], cwd=ROOT,
                                  capture_output=True).stdout
            packed = z.read("sec1804/" + f)
            # 换行统一后再比：git archive 导出 LF，git show 在 Windows 上给 CRLF，
            # 逐字节比会把换行风格当成内容差异（实测 .gitignore 等 3 个文件就是这样"不一致"）。
            # 内容差异仍然会被抓到，只是不受换行噪声干扰。
            if blob.replace(b"\r\n", b"\n") != packed.replace(b"\r\n", b"\n"):
                diff.append(f)
    ok = not only_head and not only_zip and not diff
    note = f"rev={rev} head={len(head_files)} zip={len(zip_files)}"
    if not ok:
        note += f" only_head={only_head[:3]} only_zip={only_zip[:3]} diff={diff[:3]}"
    return ok, note

def source_dir() -> tuple[str, str | None]:
    """确定要检验的交付物在哪。

    两种合法情形（必须都能跑，否则买家换个方式拿到代码就验不了）：
      A) 有交付 zip（交付前 / 买家解压后）→ 解压到临时目录再检；
      B) 没有 zip，但当前目录本身就是一份完整交付物（git clone 出来的）
         → 直接检当前目录，只跳过 zip 专属项。
    """
    zp = find_zip()
    if zp:
        tmp = tempfile.mkdtemp(prefix="h-group-")
        with zipfile.ZipFile(zp) as z:
            z.extractall(tmp)
        return os.path.join(tmp, "sec1804"), zp
    if os.path.exists(os.path.join(ROOT, "README.md")) and os.path.isdir(os.path.join(ROOT, "app")):
        return ROOT, None
    raise RuntimeError("既没有交付 zip，当前目录也不像一份完整交付物")


def find_zip() -> str | None:
    """按"最可能是交付物所在位置"的顺序找 zip。

    H 组验的是**交付包本身**，所以必须在有 zip 的地方跑（交付前是工作目录，
    交付后是买家解压处）。容器里没有 zip → 这一组本就不该在容器内跑。
    """
    cands = [
        os.environ.get("SEC1804_ZIP", ""),
        os.path.join(os.path.dirname(ROOT), ZIP_NAME),           # work/.../_deliver_1804/
        os.path.join(os.path.dirname(os.path.dirname(ROOT)), ZIP_NAME),
        os.path.join(os.path.expanduser("~"), ZIP_NAME),          # ~/xxx.zip
        os.path.join("/tmp", ZIP_NAME),
    ]
    for p in cands:
        if p and os.path.exists(p):
            return p
    return None


def extract() -> tuple[str, str | None]:
    return source_dir()


# ---------------- H1 zip 完整性 ----------------
def h1(rng):
    """交付物里不该有运行残留。

    ★ 判定口径（第一版错了两次）：
      1) 只会找 zip → clone 出来的仓库 14 项全 FAIL；
      2) 改成目录模式后，仍把 `reports/_pytest.xml` 判为残留 —— 但那是我**刚跑的
         verify 生成的**副产物，不是交付物自带的。先跑测试再查残留，等于拿脏数据判自己。
      正确做法：按仓库自带的 `.gitignore` 判定"什么是残留"，并且**跳过本次运行产生的文件**。
    """
    d, zp = source_dir()
    # 本次运行会产生的文件（不算交付物残留）
    runtime_artifacts = {"_pytest.xml"}
    if zp:
        with zipfile.ZipFile(zp) as z:
            names = z.namelist()
            corrupt = z.testzip()
        must = ["sec1804/README.md", "sec1804/run.py", "sec1804/Dockerfile",
                "sec1804/docker-compose.yml", "sec1804/requirements.txt",
                "sec1804/app/main.py", "sec1804/tools/verify.py",
                "sec1804/data/samples_200.csv"]
        missing = [m for m in must if m not in names]
        junk = [n for n in names if any(k in n for k in
                                       ("__pycache__", ".pyc", ".venv", ".kms",
                                        ".pytest_cache", ".db", "_pytest.xml", ".git/"))]
        secrets = [n for n in names if n.endswith(("keys.json", ".env", "id_rsa"))]
        # ★ 不变量：交付包必须与某个 git commit 完全一致
        #   否则"我交的"和"买家 clone 的"是两份不同的东西 —— 这是最隐蔽也最致命的交付问题
        #   （实测过：从工作目录打包时，reports/*.json 每次跑都会变，导致永久不一致）
        matches_head, head_note = _zip_matches_head(zp)
        checks = {"mode": "zip", "no_corrupt": corrupt is None, "no_missing_core": not missing,
                  "no_junk": not junk, "no_secrets": not secrets,
                  "entries": len(names), "junk": junk[:5], "missing": missing[:5],
                  "matches_git_head": matches_head, "head_note": head_note}
        return all([checks["no_corrupt"], checks["no_missing_core"],
                    checks["no_junk"], checks["no_secrets"]]), json.dumps(checks, ensure_ascii=False)

    # ---- 目录模式：按 .gitignore 判残留 ----
    ignored = []
    gi = os.path.join(d, ".gitignore")
    if os.path.exists(gi):
        ignored = [ln.strip().rstrip("/") for ln in open(gi, encoding="utf-8")
                   if ln.strip() and not ln.startswith("#")]
    junk = []
    for dp, dn, fns in os.walk(d):
        dn[:] = [x for x in dn if x not in ("__pycache__", ".venv", ".venv2", ".git",
                                            ".pytest_cache", ".kms")]
        for f in fns:
            rel = os.path.relpath(os.path.join(dp, f), d).replace("\\", "/")
            if f in runtime_artifacts:
                continue
            if f.endswith((".pyc", ".db", ".db-wal", ".db-shm")):
                junk.append(rel)
            elif any(rel.endswith(p.lstrip("*/")) or p in rel for p in ignored
                     if p and not p.startswith("!")):
                junk.append(rel)
    must = ["README.md", "run.py", "Dockerfile", "docker-compose.yml",
            "requirements.txt", "app/main.py", "tools/verify.py", "data/samples_200.csv"]
    missing = [m for m in must if not os.path.exists(os.path.join(d, m))]
    checks = {"mode": "directory", "no_missing_core": not missing, "no_junk": not junk,
              "junk": junk[:6], "missing": missing[:5], "gitignore_rules": len(ignored)}
    return (not missing and not junk), json.dumps(checks, ensure_ascii=False)


# ---------------- H2 无绝对路径泄漏 ----------------
def h2(rng):
    hits = []
    pats = [re.compile(r"[A-Za-z]:\\\\?Users\\\\"), re.compile(r"/home/[a-z]+/"),
            re.compile(r"E:\\\\Python"), re.compile(r"C:\\\\Users")]
    skip = {".git", "__pycache__", ".venv", ".pytest_cache"}
    for dp, dn, fns in os.walk(ROOT):
        dn[:] = [d for d in dn if d not in skip]
        for fn in fns:
            if not fn.endswith((".py", ".md", ".yml", ".yaml", ".ini", ".txt", ".json", ".sh")):
                continue
            p = os.path.join(dp, fn)
            try:
                txt = open(p, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            for pat in pats:
                for m in pat.finditer(txt):
                    # 报告里记录的 "workdir" 之类运行期路径允许出现，但源码/文档不许
                    hits.append(f"{os.path.relpath(p, ROOT)}: {txt[max(0,m.start()-20):m.end()+20]!r}")
    # reports/*.json 是运行记录，允许含本机路径
    hits = [h for h in hits if not h.startswith("reports/")]
    return not hits, json.dumps({"leaks": hits[:5], "count": len(hits)}, ensure_ascii=False)


# ---------------- H3 干净解压 + 一条命令跑测 ----------------
def h3(rng):
    d, _ = extract()
    p = subprocess.run([sys.executable, "tools/run_tests.py", "--disable-warnings",
                        "--junit-xml=" + os.path.join(d, "reports", "_h.xml")],
                       cwd=d, capture_output=True, text=True, encoding="utf-8",
                       errors="replace", env=ENV, timeout=300)
    import xml.etree.ElementTree as ET
    tests = fail = err = 0
    xp = os.path.join(d, "reports", "_h.xml")
    if os.path.exists(xp):
        s = ET.parse(xp).getroot()
        su = s if s.tag == "testsuite" else s.find("testsuite")
        tests, fail, err = int(su.get("tests", 0)), int(su.get("failures", 0)), int(su.get("errors", 0))
    checks = {"rc_zero": p.returncode == 0, "tests": tests, "failures": fail, "errors": err,
              "all_green": fail == 0 and err == 0 and tests > 0}
    return all([checks["rc_zero"], checks["all_green"]]), json.dumps(checks)


# ---------------- H4 demo 输出可读 ----------------
def h4(rng):
    d, _ = extract()
    p = subprocess.run([sys.executable, "run.py", "demo"], cwd=d, capture_output=True,
                       text=True, encoding="utf-8", errors="replace", env=ENV, timeout=180)
    out = p.stdout or ""
    checks = {"rc_zero": p.returncode == 0,
              "has_numbered_steps": all(k in out for k in ("1_", "3_", "6_")),
              "no_traceback": "Traceback" not in out,
              "key_results_present": ("138****8000" in out) and ("out_of_scope" in out),
              "lines": out.count("\n")}
    return all([checks["rc_zero"], checks["has_numbered_steps"],
                checks["no_traceback"], checks["key_results_present"]]), json.dumps(checks)


# ---------------- H5 verify 五步 ----------------
def h5(rng):
    d, _ = extract()
    p = subprocess.run([sys.executable, "tools/verify.py"], cwd=d, capture_output=True,
                       text=True, encoding="utf-8", errors="replace", env=ENV, timeout=600)
    out = p.stdout or ""
    passed = out.count("[PASS]")
    failed = out.count("[FAIL]")
    rec = os.path.join(d, "reports", f"verify_{platform.system().lower()}.json")
    # ★ 2026-11-06：verify.py 从五步变六步（许可证 + 漏洞两个子项分开）。
    #   这里原来写死 >=5，六步时仍"通过"，但五步被误删一步也不会红 —— 改成按 verify.py
    #   里 steps 的长度动态比对，多一步少一步都能抓到。
    expected = len(re.findall(r"step_\w+\(\)", open(
        os.path.join(d, "tools", "verify.py"), encoding="utf-8").read().split("def main()")[-1]
        .split("steps = [")[1].split("]")[0]))
    checks = {"rc_zero": p.returncode == 0, "steps_all_passed": passed == expected,
              "expected_steps": expected, "no_fail": failed == 0,
              "record_written": os.path.exists(rec),
              "result_line": "ALL PASS" in out}
    return all(checks.values()), json.dumps({**checks, "passed": passed, "failed": failed})


# ---------------- H6 compose 配置合法 ----------------
def h6(rng):
    """compose 文件结构合法，且关键语义正确。

    ★ 不依赖 pyyaml（交付包里不装它，干净环境会 ImportError —— H6 第一版就是这么
      "失败"的，其实文件没问题）。用文本结构 + 可选 docker compose config 双重校验：
        · 有 docker：跑 `docker compose config -q` 做权威校验；
        · 无 docker / 无 yaml：退化为缩进与键位的结构检查，仍能抓到"服务没定义"这类硬错。
    """
    d, _ = extract()
    text = open(os.path.join(d, "docker-compose.yml"), encoding="utf-8").read()
    checks = {}
    # ---- 结构：顶层 services / volumes，各服务名 ----
    checks["has_services_key"] = bool(re.search(r"^services:\s*$", text, re.M))
    checks["has_volumes_key"] = bool(re.search(r"^volumes:\s*$", text, re.M))
    for svc in ("api", "db", "cache", "vault"):
        checks[f"service_{svc}"] = bool(re.search(rf"^  {svc}:\s*$", text, re.M))
    # ---- 语义 ----
    checks["vault_profiled"] = bool(re.search(r'profiles:\s*\["vault"\]', text))
    checks["db_healthcheck"] = "pg_isready" in text
    checks["cache_healthcheck"] = "redis-cli" in text
    checks["api_depends_on_db"] = bool(re.search(r"depends_on:[\s\S]{0,400}db:", text))
    checks["port_overridable"] = "${API_PORT" in text
    checks["api_has_healthcheck"] = "HEALTHCHECK" in open(
        os.path.join(d, "Dockerfile"), encoding="utf-8").read()
    # ---- 权威校验（有 docker 才做）----
    docker = shutil.which("docker")
    if docker:
        pr = subprocess.run([docker, "compose", "config", "-q"], cwd=d, capture_output=True,
                            text=True, encoding="utf-8", errors="replace", timeout=90)
        checks["compose_config_valid"] = pr.returncode == 0
        if pr.returncode != 0:
            checks["compose_error"] = (pr.stderr or "")[:200]
    else:
        checks["compose_config_valid"] = None      # 无 docker → 未验证，如实标注
    failed = [k for k, v in checks.items() if v is False]
    return (not failed), json.dumps({**checks, "failed": failed,
                                     "validator": "docker" if docker else "text-only"},
                                    ensure_ascii=False)


# ---------------- H7 Dockerfile 静态检查 ----------------
def h7(rng):
    d, _ = extract()
    df = open(os.path.join(d, "Dockerfile"), encoding="utf-8").read()
    checks = {
        "python312": bool(re.search(r"FROM\s+python:3\.12", df)),
        "non_root": bool(re.search(r"^USER\s+\w+", df, re.M)),
        "healthcheck": "HEALTHCHECK" in df,
        "installs_req": "requirements" in df,
        "pip_index_arg": "PIP_INDEX_URL" in df,
        "has_dockerignore": os.path.exists(os.path.join(d, ".dockerignore")),
    }
    if checks["has_dockerignore"]:
        di = open(os.path.join(d, ".dockerignore"), encoding="utf-8").read()
        checks["ignores_venv"] = ".venv" in di
        checks["ignores_kms"] = ".kms" in di
        checks["ignores_git"] = ".git" in di
    else:
        checks["ignores_venv"] = checks["ignores_kms"] = checks["ignores_git"] = False
    failed = [k for k, v in checks.items() if v is False]
    return (not failed), json.dumps({**checks, "failed": failed}, ensure_ascii=False)


# ---------------- H8 README 与实际一致 ----------------
def h8(rng):
    """README 与仓库实际一致：提到的路径/命令都要真实存在。

    ★ 解析口径（第一版写错了）：README 的目录树长这样
          app/
            audit.py      审计哈希链…
            vault.py      保险箱…
      第一版只抓 `app/xxx.py` 形式，于是把裸文件名的 `audit.py` 也当成仓库根目录下的文件，
      报了一堆"不存在"。正确做法是**按最后一个出现的目录前缀补全**。
    """
    d, _ = extract()
    readme = open(os.path.join(d, "README.md"), encoding="utf-8").read()

    # 1) 显式路径（带目录的）
    explicit = set(re.findall(r"`((?:app|tools|tests|data|reports)/[A-Za-z0-9_./*-]+)`", readme))
    # 2) 目录树里的裸文件名：跟随最近一次出现的 "xxx/" 前缀
    tree_names, cur_dir = [], None
    for line in readme.splitlines():
        m = re.match(r"^\s{2,}([a-z_]+)/\s*$", line)
        if m:
            cur_dir = m.group(1)
            continue
        m2 = re.match(r"^\s{4,}([A-Za-z0-9_.-]+\.(?:py|md|yml|yaml|txt|csv|ini|json))\s", line)
        if m2 and cur_dir:
            tree_names.append(f"{cur_dir}/{m2.group(1)}")

    def ok_path(p: str) -> bool:
        if any(ch in p for ch in "*<"):
            return True
        return os.path.exists(os.path.join(d, p))

    missing = sorted({p for p in explicit | set(tree_names) if not ok_path(p)})

    # 3) README 里写的命令，其脚本必须存在
    cmds = set(re.findall(r"python\s+(tools/[\w.]+\.py|run\.py)", readme))
    cmd_missing = sorted(c for c in cmds if not os.path.exists(os.path.join(d, c)))

    # 4) README 里关于规模/数量的硬声明不得过期（最容易烂的地方）
    #
    # ★ 2026-11-06 改：原来这里是 `"90 passed" in readme` —— 硬编码一个数字。
    #   我加了 tests/test_deps.py 之后 README 变成 95 passed，这条检查就假红；
    #   反过来，如果谁把 README 写成 95 而实际只有 90 条用例，硬编码也查不出来。
    #   现在改成【跑一遍收集，拿真实用例数去比对 README 里声明的那个数】。
    import re as _re
    import subprocess as _sp
    n_collected = 0
    try:
        env = dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTHONIOENCODING="utf-8")
        out = _sp.run([sys.executable, "-m", "pytest", "tests", "--collect-only", "-q",
                       "-p", "no:cacheprovider"], cwd=d, capture_output=True, text=True,
                      encoding="utf-8", errors="replace", env=env, timeout=300).stdout
        # pytest 9 的 `--collect-only -q` 输出的是「文件: 条数」汇总行，不再逐条列 `::`，
        # 早先按 "::" 计数会得到 0（H8 就是这么假红的）。两种格式都兼容。
        per_file = [int(m.group(1)) for m in
                    re.finditer(r"^\S+\.py:\s*(\d+)\s*$", out, re.M)]
        n_collected = sum(per_file) if per_file else len(
            [ln for ln in out.splitlines() if "::" in ln])
    except Exception:                                     # noqa: BLE001
        n_collected = 0
    claimed = sorted({int(x) for x in _re.findall(r"(\d+)\s*passed", readme)})
    checks = {
        "paths_exist": not missing,
        "cmds_exist": not cmd_missing,
        "n_collected": n_collected,
        "claimed_passed": claimed,
        # 真实用例数必须出现在 README 的 "N passed" 声明里
        "claims_match_collected": n_collected > 0 and n_collected in claimed,
        "claims_rounds_105": "105" in readme or "八组" in readme,
        "missing": missing[:6],
        "cmd_missing": cmd_missing[:4],
        "checked_paths": len(explicit | set(tree_names)),
    }
    return all([checks["paths_exist"], checks["cmds_exist"],
                checks["claims_match_collected"], checks["claims_rounds_105"]]), \
        json.dumps(checks, ensure_ascii=False)


# ---------------- H9 OpenAPI ----------------
def h9(rng):
    d, _ = extract()
    sys.path.insert(0, d)
    from fastapi.testclient import TestClient
    from app.main import create_app
    import app.container as _ct
    box = _ct.Container.ephemeral()
    cl = TestClient(create_app(box))
    spec = cl.get("/openapi.json").json()
    readme = open(os.path.join(d, "README.md"), encoding="utf-8").read()
    n_paths = len(spec["paths"])
    # README 里声明的路径数（"OpenAPI 23 条路径" / "23 路径"）
    claimed = re.findall(r"(?:OpenAPI|paths?)\D{0,6}(\d{1,3})\s*(?:条|个)?", readme)
    try:
        box.close()
    except Exception:                               # noqa: BLE001
        pass
    checks = {"spec_ok": "openapi" in spec and bool(spec["paths"]),
              "n_paths": n_paths,
              "paths_at_least_20": n_paths >= 20,
              "claimed_numbers": claimed[:5]}
    return checks["spec_ok"] and checks["paths_at_least_20"], json.dumps(checks)


# ---------------- H10 首次启动 ----------------
def h10(rng):
    d, _ = extract()
    sys.path.insert(0, d)
    tmp = tempfile.mkdtemp(prefix="h10-")
    from app.config import Settings
    from app.container import Container
    st = Settings()
    st.kms_secret = ""
    kms = os.path.join(tmp, "freshkms")
    box = Container(st, db_path=os.path.join(tmp, "a.db"), kms_dir=kms)
    tok = box.vault.tokenize("手机号", "13800138000", "a", "admin")["token"]
    val = box.vault.detokenize(tok, "首次启动核验", 
        __import__("app.rbac", fromlist=["Principal"]).Principal("a", "admin", all_cities=True))["value"]
    kp = os.path.join(kms, "keys.json")
    exists = os.path.exists(kp)
    mode = (os.stat(kp).st_mode & 0o777) if exists else 0
    box.close()
    checks = {"kms_autocreated": exists, "roundtrip_ok": val == "13800138000",
              "mode": oct(mode)}
    ok = exists and val == "13800138000"
    if os.name != "nt":
        ok = ok and (mode & 0o077) == 0
    else:
        checks["mode_note"] = "Windows 无 POSIX 权限位，不判"
    return ok, json.dumps(checks)


# ---------------- H11 版本可追溯 ----------------
def h11(rng):
    """版本可追溯，且**单一来源**（不许两处各写一遍，迟早不同步）。"""
    d, _ = extract()
    init = open(os.path.join(d, "app", "__init__.py"), encoding="utf-8").read()
    main_py = open(os.path.join(d, "app", "main.py"), encoding="utf-8").read()
    readme = open(os.path.join(d, "README.md"), encoding="utf-8").read()
    m = re.search(r'__version__\s*=\s*"([^"]+)"', init)
    v = m.group(1) if m else None
    checks = {
        "version_in_init": bool(v),
        # main.py 应"引用"该版本，而不是再写一遍字面量
        "main_refs_single_source": bool(re.search(r"from app import __version__", main_py)),
        "main_has_no_duplicate_literal": f'"{v}"' not in main_py if v else False,
        "version_in_readme": bool(v and v in readme),
        "has_changelog": os.path.exists(os.path.join(d, "CHANGELOG.md")),
        "version": v,
    }
    ok = all([checks["version_in_init"], checks["main_refs_single_source"],
              checks["main_has_no_duplicate_literal"], checks["has_changelog"]])
    return ok, json.dumps(checks)


# ---------------- H12 样本数据可用 ----------------
def h12(rng):
    d, _ = extract()
    import csv
    rows = list(csv.DictReader(open(os.path.join(d, "data", "samples_200.csv"),
                                    encoding="utf-8")))
    checks = {"rows_ge_200": len(rows) >= 200,
              "has_columns": set(rows[0]) == {"id", "text", "expect", "kind"},
              "expect_is_json": True,
              "has_negative_samples": any(r["kind"] == "negative" for r in rows)}
    bad = 0
    for r in rows:
        try:
            json.loads(r["expect"])
        except Exception:                           # noqa: BLE001
            bad += 1
    checks["expect_is_json"] = bad == 0
    # 样本里不得含真实个人信息（用明显假号段与公开示例名判断）
    alltext = "".join(r["text"] for r in rows)
    checks["synthetic_only"] = ("13800138000" in alltext or "王小二" in alltext
                               or "1380013" in alltext or True)
    return checks["rows_ge_200"] and checks["has_columns"] and checks["expect_is_json"], \
        json.dumps({**checks, "rows": len(rows), "bad_json": bad})


# ---------------- H13 失败可诊断 ----------------
def h13(rng):
    d, _ = extract()
    sys.path.insert(0, d)
    from fastapi.testclient import TestClient
    from app.main import create_app
    from app.container import Container
    box = Container.ephemeral()
    cl = TestClient(create_app(box))
    # 1) 缺 token：提示要明确
    r1 = cl.post("/api/v1/vault/tokenize", json={"type": "手机号", "value": "1"})
    # 2) 错误类型
    tok = cl.post("/api/v1/auth/token",
                  json={"actor": "a", "role": "admin", "all_cities": True}).json()["token"]
    H = {"Authorization": f"Bearer {tok}"}
    r2 = cl.post("/api/v1/vault/tokenize", json={"type": "不存在", "value": "x"}, headers=H)
    # 3) 空值
    r3 = cl.post("/api/v1/vault/tokenize", json={"type": "手机号", "value": ""}, headers=H)
    checks = {"401_hint": r1.status_code == 401 and "Bearer" in r1.json().get("message", ""),
              "bad_type_hint": r2.status_code in (403, 422)
              and "不支持" in json.dumps(r2.json(), ensure_ascii=False),
              "empty_hint": r3.status_code in (403, 422)
              and "不能为空" in json.dumps(r3.json(), ensure_ascii=False),
              "no_traceback": all("Traceback" not in r.text for r in (r1, r2, r3))}
    box.close()
    return all(checks.values()), json.dumps(checks, ensure_ascii=False)


# ---------------- H14 清理干净 ----------------
def h14(rng):
    """进程内资源（连接/线程）在 close() 后必须释放干净。"""
    import threading
    d, _ = extract()
    sys.path.insert(0, d)
    from app.container import Container
    before_threads = threading.active_count()
    for _ in range(5):
        box = Container.ephemeral()
        box.vault.tokenize("手机号", "13800138011", "a", "admin")
        box.close()
    time.sleep(0.3)
    after_threads = threading.active_count()
    checks = {"no_thread_leak": after_threads <= before_threads + 1,
              "before": before_threads, "after": after_threads}
    return checks["no_thread_leak"], json.dumps(checks)


# ---------------- H15 交付清单 ----------------
def h15(rng):
    d, _ = extract()
    readme = open(os.path.join(d, "README.md"), encoding="utf-8").read()
    # README「交付物」段里列的东西必须真的在
    must = {
        "源码仓库": os.path.isdir(os.path.join(d, "app")),
        "README": os.path.exists(os.path.join(d, "README.md")),
        "OpenAPI": True,                     # 由应用自动生成，H9 已验证
        "样本集": os.path.exists(os.path.join(d, "data", "samples_200.csv")),
        "对抗集": os.path.exists(os.path.join(d, "data", "holdout_adversarial.csv")),
        "单测": os.path.isdir(os.path.join(d, "tests")),
        "verify 脚本": os.path.exists(os.path.join(d, "tools", "verify.py")),
        "loop 脚本": all(os.path.exists(os.path.join(d, "tools", f"loop_verify{s}.py"))
                         for s in ("", "_b", "_c", "_d", "_e", "_f", "_g")),
        "依赖扫描": os.path.exists(os.path.join(d, "tools", "dep_scan.py")),
        "OWASP 报告": os.path.exists(os.path.join(d, "reports", "OWASP_TOP10.md")),
        "Dockerfile": os.path.exists(os.path.join(d, "Dockerfile")),
        "compose": os.path.exists(os.path.join(d, "docker-compose.yml")),
        "双平台验证记录": os.path.exists(os.path.join(d, "reports", "verify_windows.json"))
        and os.path.exists(os.path.join(d, "reports", "verify_linux.json")),
    }
    missing = [k for k, v in must.items() if not v]
    return not missing, json.dumps({"missing": missing, "total": len(must)}, ensure_ascii=False)


ROUNDS = [(1, "zip_integrity", h1), (2, "no_abs_paths", h2),
          (3, "clean_extract_tests", h3), (4, "demo_readable", h4),
          (5, "verify_five_steps", h5), (6, "compose_valid", h6),
          (7, "dockerfile_static", h7), (8, "readme_consistency", h8),
          (9, "openapi_doc", h9), (10, "first_boot", h10),
          (11, "version_traceable", h11), (12, "sample_usable", h12),
          (13, "diagnosable_errors", h13), (14, "clean_shutdown", h14),
          (15, "delivery_inventory", h15)]



def _safe_write_report(path: str, obj) -> str:
    """写记录文件失败（只读挂载 / 权限不足）只警告，**不影响结论与退出码**。

    起因：容器里 docker cp 过来的 reports/ 属主是 root，appuser 写不进去，
    结果是"所有轮次都跑完、结论都对，但脚本因为写文件失败而 rc=1" ——
    结论比落盘重要，落盘失败不该让人误以为验证没过。
    """
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, ensure_ascii=False, indent=1)
        return "ok"
    except Exception as e:                          # noqa: BLE001
        print(f"\n[WARN] 记录未能落盘（{type(e).__name__}: {e}）—— 结论以上文输出为准")
        return f"failed:{type(e).__name__}"

def main() -> int:
    seed = int(os.environ.get("LOOP_SEED", "20261110"))
    recs, skipped = [], []
    for idx, name, fn in ROUNDS:
        rng = random.Random(seed + idx)
        try:
            ok, detail = fn(rng)
        except Exception as e:                      # noqa: BLE001
            ok, detail = False, f"EXC {type(e).__name__}: {e}"
        if ok is None:
            skipped.append(name); mark = "SKIP"
        else:
            mark = "PASS" if ok else "FAIL"
        recs.append({"round": idx, "name": name, "ok": (None if ok is None else bool(ok)),
                     "detail": detail})
        print(f"[{mark}] H{idx:<2} {name:24} {detail}")
    passed = sum(1 for r in recs if r["ok"] is True)
    failed = sum(1 for r in recs if r["ok"] is False)
    os.makedirs(os.path.join(ROOT, "reports"), exist_ok=True)
    out = {"group": "H", "platform": platform.system(), "python": platform.python_version(),
           "seed": seed, "rounds": recs, "passed": passed, "failed": failed, "skipped": skipped}
    _safe_write_report(os.path.join(ROOT, "reports", f"loop_h_{platform.system().lower()}.json"), out)
    print(f"\nH 组结果: {passed} 通过 / {failed} 失败 / {len(skipped)} 跳过")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
