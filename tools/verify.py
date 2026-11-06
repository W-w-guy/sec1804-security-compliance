"""一键验收：单测 + 脱敏召回 + 审计篡改定位 + 端到端演示 + 许可扫描 + 漏洞扫描，输出可复跑记录。

用法：
    python tools/verify.py             # 人读摘要（任一失败即非 0 退出）
    python tools/verify.py --json      # 机器可读
记录写入 reports/verify_<platform>.json。
"""
from __future__ import annotations
import hashlib
import json
import os
import platform
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
# PYTEST_DISABLE_PLUGIN_AUTOLOAD：隔离宿主环境里自动加载的第三方 pytest 插件。
# 起因：Ubuntu 上装了 ROS2 Jazzy 时，/opt/ros 的 pytest11 插件 launch_testing 会导入 yaml，
# 干净 venv 里没有 pyyaml → pytest 在收集阶段就退出码 3，一条用例都没跑。
# Windows 上永远看不到这个问题（这正是要求"双平台实跑"的原因）。
ENV = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1",
           PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")


def run(cmd: list[str], timeout: int = 600) -> tuple[int, str]:
    p = subprocess.run(cmd, cwd=HERE, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", env=ENV, timeout=timeout)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def step_tests() -> dict:
    """用例数从 JUnit XML 里读，不从终端文本里猜。

    踩过的坑：pytest 9 在 `-q` 下只打印进度点、**不再打印 "77 passed"**，
    于是用正则解析 "N passed" 会得到 0 个用例——Windows 和 Linux 都是 0，
    这不是平台差异，是我的解析写错了。JUnit XML 是 pytest 内置能力，稳定。
    """
    xml = os.path.join(HERE, "reports", "_pytest.xml")
    os.makedirs(os.path.dirname(xml), exist_ok=True)
    if os.path.exists(xml):
        os.remove(xml)
    rc, out = run([sys.executable, "tools/run_tests.py", "-q", "--no-header",
                   "--disable-warnings", "-p", "no:cacheprovider", f"--junit-xml={xml}"])
    tests = failures = errors = skipped = 0
    if os.path.exists(xml):
        import xml.etree.ElementTree as ET
        root_el = ET.parse(xml).getroot()
        suite = root_el if root_el.tag == "testsuite" else root_el.find("testsuite")
        tests = int(suite.get("tests", 0))
        failures = int(suite.get("failures", 0))
        errors = int(suite.get("errors", 0))
        skipped = int(suite.get("skipped", 0))
    tail = [ln for ln in out.strip().splitlines() if ln.strip()][-1:]
    step = {"name": "unit_tests", "ok": rc == 0 and failures == 0 and errors == 0 and tests > 0,
            "passed": tests - failures - errors - skipped, "failed": failures + errors,
            "collected": tests, "skipped": skipped, "rc": rc,
            "cmd": "python tools/run_tests.py", "tail": tail}
    if not step["ok"]:                     # 失败时必须留下原因，否则报告只有 detail: null
        step["tail"] = out.strip().splitlines()[-25:]
        step["xml_present"] = os.path.exists(xml)
    return step


def step_masking() -> dict:
    from tools.eval_masking import evaluate
    res = {}
    ok = True
    # ★ 三套语料：设计集 / 留出集 / 独立探针集。
    #   只报前两套是"自己测自己"；探针集是 2026-11-06 换买家身份另写的 25 条，
    #   一次就抓出 8 个真缺陷（15位身份证、复姓、T1/2201、路名地址、非ASCII名…）。
    # 四套语料，四种生成方法（换方法才算换轴，换字符串不算）：
    #   设计集（边写边补）/ 留出集（写完再补）/ 独立探针集（换买家身份另写）/
    #   r1（机械变异 + 反向构造负样本：枚举型，不依赖我"想到"什么）
    for fn in ("samples_200.csv", "holdout_adversarial.csv", "probe_20261106.csv",
               "r1_20261106b.csv"):
        rep = evaluate(filename=fn)
        pt = rep["per_type"]
        checks = {
            "no_misses": not rep["misses"],
            "phone_recall": pt["手机号"]["recall"] >= 1.0,
            "idcard_recall": pt["身份证号"]["recall"] >= 1.0,
            "name_recall": pt["姓名"]["recall"] >= 0.95,
            "addr_recall": pt["地址"]["recall"] >= 0.95,
            "fp_rate": all((v["fp_rate"] <= 0.05) for v in pt.values() if v["detected"]),
        }
        ok = ok and all(checks.values())
        res[fn] = {"samples": rep["samples"], "checks": checks,
                   "recall": {k: v["recall"] for k, v in pt.items()},
                   "fp_rate": {k: v["fp_rate"] for k, v in pt.items()}}
    return {"name": "masking_recall", "ok": ok, "detail": res,
            "cmd": "python tools/eval_masking.py [samples_200.csv|holdout_adversarial.csv|probe_20261106.csv|r1_20261106b.csv]"}


def step_audit() -> dict:
    from app.config import Settings
    from app.container import Container
    from app.service import CandidateService
    from app.rbac import Principal
    import tempfile
    tmp = tempfile.mkdtemp(prefix="sec1804-verify-")
    import uuid as _uuid
    st = Settings()
    # 有 PG_DSN 时必须独立 schema：否则会读到上一次运行被篡改过的行，
    # verify 第一步就报 before_ok=false（容器里第一次跑就撞上了）
    schema = "v_" + _uuid.uuid4().hex[:10] if st.pg_dsn else None
    c = Container(st, db_path=os.path.join(tmp, "v.db"),
                  kms_dir=os.path.join(tmp, "kms"), pg_schema=schema)
    svc = CandidateService(c)
    admin = Principal("adm", "admin", all_cities=True)
    for i in range(8):
        svc.create(admin, {"name": f"测试{i}", "phone": f"1380013800{i}",
                           "city": "深圳", "station_id": "S1"})
    base = c.audit.verify()
    c.db.execute("UPDATE audit_log SET detail='{}' WHERE seq=4")
    res = c.audit.verify()
    loc = c.audit.locate(4)
    ok = base["ok"] and (not res["ok"]) and 4 in res["tampered_seq"] and bool(loc["fields"])
    c.close()
    return {"name": "audit_tamper_locate", "ok": ok,
            "detail": {"before_ok": base["ok"], "after_ok": res["ok"],
                       "tampered_seq": res["tampered_seq"], "located_fields": len(loc["fields"])},
            "cmd": "见 README『验证记录 · 篡改定位』"}


def step_demo() -> dict:
    rc, out = run([sys.executable, "run.py", "demo", "--json"])
    ok = False
    detail = {}
    try:
        start = out.index("{")
        detail = json.loads(out[start:])
        ok = (rc == 0
              and detail.get("1_plaintext_leaked_in_db") is False
              and detail.get("1_masked") == "138****8000"
              and detail.get("6_out_of_scope") == "out_of_scope"
              and detail.get("3_denied_codes") == {"recruiter": "missing_permission",
                                                   "admin_no_reason": "reason_required"}
              and detail.get("4_audit_verify", {}).get("ok") is False
              and 3 in detail.get("4_audit_verify", {}).get("tampered_seq", []))
    except Exception as e:  # noqa: BLE001
        detail = {"parse_error": repr(e), "raw_tail": out[-400:]}
    keep = {k: v for k, v in detail.items() if k.startswith(("1_", "3_", "4_", "5_", "6_"))}
    return {"name": "e2e_demo", "ok": ok, "detail": keep, "cmd": "python run.py demo --json"}


def step_license() -> dict:
    rc, out = run([sys.executable, "tools/dep_scan.py", "--json"])
    try:
        detail = json.loads(out[out.index("{"):])
    except Exception:
        detail = {"raw": out[-400:]}
    if isinstance(detail, dict) and detail.get("env_drift"):
        detail["note"] = ("本机环境与 requirements.lock 不同（漂移项仅提示，不判失败）；"
                          "要完全一致请 pip install -r requirements.lock")
    return {"name": "license_scan", "ok": rc == 0, "detail": detail,
            "cmd": "python tools/dep_scan.py --json"}



def step_cve() -> dict:
    """依赖漏洞扫描（验收点 7 的「无未处理高危项」）。

    ★ 这一项 2026-11-06 才补上。此前 verify 只有「许可扫描」，而验收点 7 要的是
      「依赖扫描 … 无未处理的高危项」——许可 MIT/BSD 与 CVE 是两件事。补上后实测：
      原钉的 cryptography==44.0.0 / pg8000==1.31.2 各有 HIGH（pg8000 是 SQL 注入），
      并且 90 项单测跑在本机后来装的修复版上，所以长期没人发现。
    """
    rc, out = run([sys.executable, "tools/cve_scan.py", "--offline"])
    detail = {"tail": [ln for ln in out.strip().splitlines() if ln.strip()][-6:]}
    try:
        rep = json.load(open(os.path.join(HERE, "reports", "cve_scan.json"), encoding="utf-8"))
        detail.update({"packages": rep.get("packages"), "with_vulns": rep.get("with_vulns"),
                       "unhandled": rep.get("unhandled"), "ok": rep.get("ok")})
    except Exception as e:                                   # noqa: BLE001
        detail["parse_error"] = repr(e)
    return {"name": "cve_scan", "ok": rc == 0, "detail": detail,
            "cmd": "python tools/cve_scan.py [--offline]"}


def _safe_write_report(path: str, obj) -> str:
    """写记录文件失败（只读挂载 / 权限不足）只警告，**不影响结论与退出码**。

    起因：容器里 docker cp 过来的 reports/ 属主是 root，appuser 写不进去，
    结果是"所有轮次都跑完、结论都对，但脚本因为写文件失败而 rc=1" ——
    结论比落盘重要，落盘失败不该让人误以为验证没过。
    """
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(obj, fh, ensure_ascii=False, indent=1)
        return "ok"
    except Exception as e:                          # noqa: BLE001
        print(f"\n[WARN] 记录未能落盘（{type(e).__name__}: {e}）—— 结论以上文输出为准")
        return f"failed:{type(e).__name__}"

def main() -> int:
    steps = [step_tests(), step_masking(), step_audit(), step_demo(), step_license(), step_cve()]
    ok = all(s["ok"] for s in steps)
    record = {
        "platform": {"system": platform.system(), "release": platform.release(),
                     "machine": platform.machine(), "python": platform.python_version()},
        "sha256": {p: sha256_of(os.path.join(HERE, p)) for p in
                   ("app/masking.py", "app/vault.py", "app/audit.py", "app/retention.py",
                    "data/samples_200.csv", "data/holdout_adversarial.csv")},
        "steps": steps,
        "ok": ok,
    }
    os.makedirs(os.path.join(HERE, "reports"), exist_ok=True)
    name = f"verify_{platform.system().lower()}.json"
    _safe_write_report(os.path.join(HERE, "reports", name), record)
    if "--json" in sys.argv:
        print(json.dumps(record, ensure_ascii=False, indent=1))
    else:
        for s in steps:
            print(f"[{'PASS' if s['ok'] else 'FAIL'}] {s['name']:22} {s.get('cmd','')}")
            if not s["ok"]:
                print("       detail:", json.dumps(s.get("detail"), ensure_ascii=False)[:600])
        print(f"\nplatform={record['platform']['system']} python={record['platform']['python']}")
        print(f"record -> reports/{name}")
        print("RESULT:", "ALL PASS" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
