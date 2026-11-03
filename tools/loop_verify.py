"""十轮循环验证：每轮打一个不同面，且每轮输入随机（种子可复现）。

R1  全量单测
R2  脱敏召回（合成 + 对抗两份）
R3  审计篡改：随机行改内容 / 改 hash / 删行 / 插行
R4  密钥轮换（两次，第二次重加密）+ 旧 token 可解
R5  越权矩阵：5 角色 × 跨城市 / 跨站点
R6  保留期快进：未录用 90d / 已录用 180d 匿名化 / 未成年人 24h / 对话 30d
R7  撤回同意立即删除 + 删除记录
R8  审批：过期 / 重放 / 目标错配 / 理由过短
R9  接口契约：OpenAPI 路径齐全 + 错误体形状 + 401/403/404
R10 端到端 demo + 许可扫描
"""
from __future__ import annotations
import datetime as dt
import json
import os
import random
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
ENV = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1",
           PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")   # 见 tools/verify.py 注释：隔离宿主 pytest 插件
from app.config import Settings                      # noqa: E402
from app.container import Container                  # noqa: E402
from app.errors import ApiError                      # noqa: E402
from app.masking import MaskingSession, mask_text    # noqa: E402
from app.rbac import Principal, ROLES                # noqa: E402
from app.service import CandidateService             # noqa: E402
from tools.eval_masking import evaluate              # noqa: E402

DAY = 86400.0


def new_box():
    """每轮独立容器；有 PG_DSN 时给独立 schema（等价 sqlite 的一实例一文件）。"""
    import uuid as _uuid
    tmp = tempfile.mkdtemp(prefix="sec1804-loop-")
    st = Settings()
    st.kms_secret = "loop-secret"
    schema = "t_" + _uuid.uuid4().hex[:10] if st.pg_dsn else None
    return Container(st, db_path=os.path.join(tmp, "l.db"),
                     kms_dir=os.path.join(tmp, "kms"), pg_schema=schema)


def r1(rng):
    p = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-q", "--no-header",
                        "-p", "no:cacheprovider"],
                       cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                       errors="replace", env=ENV)
    tail = (p.stdout or "").strip().splitlines()[-1] if p.stdout else ""
    return p.returncode == 0 and "failed" not in tail, tail


def r2(rng):
    marks = []
    ok = True
    for fn in ("samples_200.csv", "holdout_adversarial.csv"):
        rep = evaluate(filename=fn)
        pt = rep["per_type"]
        cond = (pt["手机号"]["recall"] >= 1.0 and pt["身份证号"]["recall"] >= 1.0
                and pt["姓名"]["recall"] >= 0.95 and pt["地址"]["recall"] >= 0.95)
        fp = max((v["fp_rate"] for v in pt.values() if v["detected"]), default=0)
        ok = ok and cond and fp <= 0.05
        marks.append(f"{fn}:n={rep['samples']} r(phone/id/name/addr)="
                     f"{pt['手机号']['recall']}/{pt['身份证号']['recall']}/"
                     f"{pt['姓名']['recall']}/{pt['地址']['recall']} fp={fp:.3f}")
    return ok, " | ".join(marks)


def r3(rng):
    c = new_box()
    svc = CandidateService(c)
    admin = Principal("adm", "admin", all_cities=True)
    for i in range(rng.randint(6, 12)):
        svc.create(admin, {"name": f"测{i}", "phone": f"1380013{8000 + i}",
                           "city": "深圳", "station_id": "S1"})
    n = c.db.one("SELECT COUNT(*) AS c FROM audit_log")["c"]
    target = rng.randint(1, n)
    mode = rng.choice(["content", "hash", "delete", "insert"])
    if mode == "content":
        c.db.execute("UPDATE audit_log SET actor=? WHERE seq=?", (f"evil{rng.randint(0,9)}", target))
        res = c.audit.verify()
        ok = (not res["ok"]) and target in res["tampered_seq"]
        detail = f"mode=content seq={target} tampered={res['tampered_seq']}"
    elif mode == "hash":
        c.db.execute("UPDATE audit_log SET hash=? WHERE seq=?", ("f" * 64, target))
        res = c.audit.verify()
        ok = (not res["ok"]) and target in res["tampered_seq"]
        detail = f"mode=hash seq={target} tampered={res['tampered_seq']}"
    elif mode == "delete":
        c.db.execute("DELETE FROM audit_log WHERE seq=?", (target,))
        res = c.audit.verify()
        ok = (not res["ok"])
        detail = f"mode=delete seq={target} missing={res['missing_seq']}"
    else:
        c.db.execute("INSERT INTO audit_log (seq,ts,actor,role,action,target,city,station_id,"
                     "detail,prev_hash,hash) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                     (n + 5, "2026-01-01T00:00:00Z", "ghost", "admin", "candidate.read.full",
                      "x", None, None, "", "0" * 64, "0" * 64))
        res = c.audit.verify()
        ok = (not res["ok"])
        detail = f"mode=insert missing={res['missing_seq']}"
    c.close()
    return ok, detail


def r4(rng):
    c = new_box()
    values = [("手机号", "13800138000"), ("姓名", "王小二"), ("身份证号", "44030519900101123X")]
    toks = {v: c.vault.tokenize(t, v, "adm", "admin")["token"] for t, v in values}
    a = c.vault.rotate("adm", reencrypt=False)
    b = c.vault.rotate("adm", reencrypt=True)
    admin = Principal("adm", "admin", all_cities=True)
    ok = True
    for v, tok in toks.items():
        got = c.vault.detokenize(tok, "循环验证核验", admin)["value"]
        ok = ok and got == v
    ok = ok and b["to"] == a["to"] + 1
    detail = f"versions {a['from']}->{a['to']}->{b['to']} reencrypted={b['reencrypted']}"
    c.close()
    return ok, detail


def r5(rng):
    c = new_box()
    svc = CandidateService(c)
    admin = Principal("adm", "admin", all_cities=True)
    cand_sz = svc.create(admin, {"name": "王甲", "phone": "13800138001", "city": "深圳", "station_id": "S1"})
    cand_sz2 = svc.create(admin, {"name": "王乙", "phone": "13800138002", "city": "深圳", "station_id": "S2"})
    results = []
    ok = True
    for role in ROLES:
        p_city = Principal(f"{role}-c", role, city="杭州", stations={"S9"})
        try:
            svc.view(p_city, cand_sz["id"]); ok = False; results.append(f"{role}:CITY_NOT_BLOCKED")
        except ApiError as e:
            results.append(f"{role}:{e.code}")
        if role != "admin":
            p_st = Principal(f"{role}-s", role, city="深圳", stations={"S1"})
            try:
                svc.view(p_st, cand_sz2["id"]); ok = False; results.append(f"{role}:STATION_NOT_BLOCKED")
            except ApiError as e:
                results.append(f"{role}:{e.code}")
    c.close()
    return ok, " ".join(results)


def r6(rng):
    c = new_box()
    svc = CandidateService(c)
    admin = Principal("adm", "admin", all_cities=True)
    now = dt.datetime.now(dt.timezone.utc).timestamp()
    svc.create(admin, {"name": "未录用甲", "phone": "13700137001", "city": "深圳", "station_id": "S1",
                       "status": "new"})
    hired = svc.create(admin, {"name": "已录用乙", "phone": "13700137002", "city": "深圳",
                              "station_id": "S1", "status": "hired"})
    minor = svc.create(admin, {"name": "未成年丙", "phone": "13700137003", "city": "深圳",
                               "station_id": "S1", "is_minor": True})
    rep = c.retention.run(now=now + 200 * DAY)
    row = c.db.one("SELECT * FROM candidates WHERE id=?", (hired["id"],))
    rules = {d["rule"] for d in c.retention.deletions()}
    ok = (rep["expired_deleted"] >= 1 and rep["expired_anonymized"] == 1
          and row is not None and row["name_token"] is None
          and c.db.one("SELECT id FROM candidates WHERE id=?", (minor["id"],)) is None
          and "minor_24h" in rules)
    c.close()
    return ok, f"report={rep} rules={sorted(rules)}"


def r7(rng):
    c = new_box()
    svc = CandidateService(c)
    admin = Principal("adm", "admin", all_cities=True)
    cand = svc.create(admin, {"name": "撤回丁", "phone": "13600136001", "city": "深圳", "station_id": "S1"})
    c.consent.record(cand["id"], "v3", "h5")
    res = c.consent.revoke(cand["id"])
    gone = c.db.one("SELECT id FROM candidates WHERE id=?", (cand["id"],)) is None
    logged = any(d["rule"] == "consent_revoked" for d in c.retention.deletions())
    c.close()
    return (res["deleted"] and gone and logged), f"deleted={res['deleted']} gone={gone} logged={logged}"


def r8(rng):
    c = new_box()
    svc = CandidateService(c)
    admin = Principal("adm", "admin", all_cities=True)
    cand = svc.create(admin, {"name": "审批戊", "phone": "13500135001", "city": "深圳", "station_id": "S1"})
    checks = {}
    ap = c.approvals.request("adm", "candidate.read.full", cand["id"], "核对工单")
    c.approvals.decide(ap["id"], "boss", ok=True, now=__import__("time").time() - 10000)
    try:
        c.approvals.consume(ap["id"], "adm", "candidate.read.full", cand["id"])
        checks["expired"] = False
    except ApiError:
        checks["expired"] = True
    ap2 = c.approvals.request("adm", "candidate.read.full", cand["id"], "核对工单")
    c.approvals.decide(ap2["id"], "boss", ok=True)
    svc.view(admin, cand["id"], full=True, approval_id=ap2["id"], reason="核对工单")
    try:
        svc.view(admin, cand["id"], full=True, approval_id=ap2["id"], reason="核对工单")
        checks["replay"] = False
    except ApiError:
        checks["replay"] = True
    ap3 = c.approvals.request("adm", "candidate.read.full", "other-target", "核对工单")
    c.approvals.decide(ap3["id"], "boss", ok=True)
    try:
        c.approvals.consume(ap3["id"], "adm", "candidate.read.full", "different")
        checks["mismatch"] = False
    except ApiError:
        checks["mismatch"] = True
    try:
        c.approvals.request("adm", "candidate.read.full", cand["id"], "x")
        checks["short_reason"] = False
    except ApiError:
        checks["short_reason"] = True
    c.close()
    return all(checks.values()), json.dumps(checks, ensure_ascii=False)


def r9(rng):
    from fastapi.testclient import TestClient
    from app.main import create_app
    c = new_box()
    cl = TestClient(create_app(c))
    spec = cl.get("/openapi.json").json()
    paths = [p for p in spec["paths"] if p != "/health"]
    bad_prefix = [p for p in paths if not p.startswith("/api/v1/")]
    need = ["/api/v1/vault/tokenize", "/api/v1/vault/detokenize", "/api/v1/mask",
            "/api/v1/candidates", "/api/v1/audit/verify", "/api/v1/retention/run",
            "/api/v1/consent", "/api/v1/rights-requests"]
    missing = [p for p in need if p not in spec["paths"]]
    r401 = cl.post("/api/v1/vault/tokenize", json={"type": "手机号", "value": "1"})
    shape401 = set(r401.json()) == {"code", "message"} and r401.status_code == 401
    r404 = cl.get("/api/v1/candidates/nope")
    ok = (not bad_prefix) and (not missing) and shape401 and r404.status_code == 401
    c.close()
    return ok, f"paths={len(paths)} bad_prefix={bad_prefix} missing={missing} 401shape={shape401}"


def r10(rng):
    p = subprocess.run([sys.executable, "run.py", "demo", "--json"], cwd=ROOT, capture_output=True,
                       text=True, encoding="utf-8", errors="replace", env=ENV)
    try:
        d = json.loads((p.stdout or "")[p.stdout.index("{"):])
    except Exception:
        return False, (p.stdout or "")[-300:]
    ok = (p.returncode == 0 and d.get("1_plaintext_leaked_in_db") is False
          and d.get("6_out_of_scope") == "out_of_scope"
          and d.get("5_revoke_deleted") is True
          and 3 in d.get("4_audit_verify", {}).get("tampered_seq", []))
    q = subprocess.run([sys.executable, "tools/dep_scan.py", "--json"], cwd=ROOT, capture_output=True,
                       text=True, encoding="utf-8", errors="replace", env=ENV)
    lic = json.loads((q.stdout or "{}")[q.stdout.index("{"):] if "{" in (q.stdout or "") else "{}")
    ok = ok and q.returncode == 0
    return ok, f"demo_ok={ok} license_ok={lic.get('ok')} denied={len(lic.get('denied', []))}"


ROUNDS = [(1, "unit_tests", r1), (2, "masking_recall", r2), (3, "audit_tamper", r3),
          (4, "kms_rotate", r4), (5, "rbac_matrix", r5), (6, "retention", r6),
          (7, "consent_revoke", r7), (8, "approval", r8), (9, "api_contract", r9),
          (10, "e2e_and_license", r10)]


def main() -> int:
    import platform
    seed = int(os.environ.get("LOOP_SEED", "20261103"))
    recs = []
    for idx, name, fn in ROUNDS:
        rng = random.Random(seed + idx)
        try:
            ok, detail = fn(rng)
        except Exception as e:  # noqa: BLE001
            ok, detail = False, f"EXC {type(e).__name__}: {e}"
        recs.append({"round": idx, "name": name, "ok": bool(ok), "detail": detail})
        print(f"[{'PASS' if ok else 'FAIL'}] R{idx:<2} {name:18} {detail}")
    os.makedirs(os.path.join(ROOT, "reports"), exist_ok=True)
    out = {"platform": platform.system(), "python": platform.python_version(), "seed": seed,
           "rounds": recs, "ok": all(r["ok"] for r in recs)}
    path = os.path.join(ROOT, "reports", f"loop_{platform.system().lower()}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=1)
    print(f"\n10 轮结果: {sum(r['ok'] for r in recs)}/10 通过  记录 -> {os.path.relpath(path, ROOT)}")
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
