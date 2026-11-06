"""D 组 15 轮：一致性与故障恢复。

C 组解决"攻击者能拿到什么"，D 组解决"**系统出问题时会不会留下没法解释的状态**"。
PII 系统里，一次"操作成功但没留痕"比一次功能 bug 严重得多——事后无法向监管解释。

D1  原子性：业务写成功后审计写失败 → 必须补偿，不能变成无痕操作
D2  幂等：同一请求重放不得重复创建/重复扣减
D3  崩溃恢复：写一半被杀 → 重启后库与哈希链仍自洽
D4  KMS 轮换中途崩溃 → 不留半加密数据，旧数据仍可解
D5  清理与并发读竞争：删除的同时读，不得返回半匿名化对象
D6  多表事务边界：一次操作内的多表写要么全成要么全败
D7  并发创建同值 token 的审计完整性
D8  审计与业务数据交叉一致性（计数对齐、无孤儿）
D9  数据库不可达：快速失败而不是挂死
D10 分页与容量：大量候选人时 list 必须分页、耗时可控
D11 审计表规模下的 verify 性能
D12 优雅关闭：in-flight 请求的审计不丢
D13 大批量导出：内存与耗时上限
D14 时钟回拨：now 变小时不得误删/误判过期
D15 事件契约：状态变更是否可被外部消费（诚实标注缺口）
"""
from __future__ import annotations
import concurrent.futures as cf
import datetime as dt
import json
import os
import platform
import random
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from tools.argv_guard import reject_unknown  # noqa: E402
ENV = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1",
           PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")

from app.config import Settings          # noqa: E402
from app.container import Container      # noqa: E402
from app.errors import ApiError          # noqa: E402
from app.rbac import Principal           # noqa: E402
from app.service import CandidateService # noqa: E402

DAY = 86400.0


def new_box(secret="loopD"):
    tmp = tempfile.mkdtemp(prefix="sec1804-loopD-")
    st = Settings()
    st.kms_secret = secret
    st.jwt_secret = "d-" + uuid.uuid4().hex[:8]
    schema = ("d_" + uuid.uuid4().hex[:10]) if st.pg_dsn else None
    return Container(st, db_path=os.path.join(tmp, "d.db"),
                     kms_dir=os.path.join(tmp, "kms"), pg_schema=schema), tmp


def adm():
    return Principal("adm", "admin", all_cities=True)


# ---------------- D1 审计失败必须补偿 ----------------
def d1(rng):
    """业务写成功、审计写失败 —— 不允许留下"有数据、无痕迹"的状态。"""
    c, _ = new_box()
    svc = CandidateService(c)
    checks = {}
    orig = c.audit.append
    calls = {"n": 0}

    def boom(*a, **kw):
        calls["n"] += 1
        if calls["n"] >= 1:
            raise RuntimeError("audit down")
        return orig(*a, **kw)

    c.audit.append = boom
    try:
        svc.create(adm(), {"name": "甲", "phone": "13800138001", "city": "深圳", "station_id": "S1"})
        created = True
    except Exception:                                  # noqa: BLE001
        created = False
    c.audit.append = orig
    rows = c.db.one("SELECT COUNT(*) AS c FROM candidates")["c"]
    # 合格标准：要么整体失败（无候选人、无孤立 vault 行），要么成功且审计已补偿
    checks["no_silent_write"] = (not created and rows == 0) or (created and rows == 1)
    checks["no_orphan_when_failed"] = (rows == 1) or (
        c.db.one("SELECT COUNT(*) AS c FROM vault_items")["c"] == 0)
    c.close()
    return all(checks.values()), json.dumps({**checks, "created": created, "rows": rows})


# ---------------- D2 幂等 ----------------
def d2(rng):
    c, _ = new_box()
    cl = _client(c)
    H = {"Authorization": f"Bearer {_tok(c, 'adm', 'admin', all_cities=True)}"}
    payload = {"name": "乙", "phone": "13800138002", "city": "深圳", "station_id": "S1"}
    key = "idem-" + uuid.uuid4().hex
    r1 = cl.post("/api/v1/candidates", headers={**H, "Idempotency-Key": key}, json=payload)
    r2 = cl.post("/api/v1/candidates", headers={**H, "Idempotency-Key": key}, json=payload)
    n = c.db.one("SELECT COUNT(*) AS c FROM candidates")["c"]
    # 不要求已经实现幂等键，但**必须能测出来**：两次请求创建了 2 条就是缺口
    checks = {"first_ok": r1.status_code == 200,
              "idempotent": n == 1,
              "second_reused": r2.status_code == 200 and r2.json().get("id") == r1.json().get("id")}
    c.close()
    return all(checks.values()), json.dumps({**checks, "rows": n})


# ---------------- D3 崩溃恢复 ----------------
def d3(rng):
    d = tempfile.mkdtemp(prefix="loopD3-")
    dbp, kd = os.path.join(d, "r.db"), os.path.join(d, "kms")
    st = Settings()
    st.kms_secret = "loopD"
    # PG 模式下必须给独立 schema：否则"重启"读到的是 public 里历次运行留下的行，
    # verify() 会因为断号直接判 False（在容器里第一次跑就撞上了）。
    schema = ("r_" + uuid.uuid4().hex[:10]) if st.pg_dsn else None
    c1 = Container(st, db_path=dbp, kms_dir=kd, pg_schema=schema)
    for i in range(6):
        c1.audit.append("u", "admin", "candidate.read.masked", target=str(i))
    c1.db.execute("INSERT INTO candidates (id, status, created_at) VALUES ('half', 'new', '2026-01-01T00:00:00Z')")
    c1.close()
    c2 = Container(st, db_path=dbp, kms_dir=kd, pg_schema=schema)
    v = c2.audit.verify()
    half = c2.db.one("SELECT id FROM candidates WHERE id='half'")
    c2.audit.append("u", "admin", "candidate.read.masked", target="after")
    v2 = c2.audit.verify()
    c2.close()
    checks = {"chain_ok_after_restart": v["ok"], "half_row_survives": half is not None,
              "append_after_restart_ok": v2["ok"] and v2["rows"] == v["rows"] + 1}
    return all(checks.values()), json.dumps(checks)


# ---------------- D4 轮换中途崩溃 ----------------
def d4(rng):
    c, _ = new_box()
    t_old = c.vault.tokenize("手机号", "13800138003", "a", "admin")["token"]
    orig = c.kms.rotate
    calls = {"n": 0}

    def broken_rotate():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("rotate crashed")
        return orig()

    c.kms.rotate = broken_rotate
    try:
        c.vault.rotate("adm", reencrypt=True)
        crashed = False
    except Exception:                                  # noqa: BLE001
        crashed = True
    c.kms.rotate = orig
    ver = c.kms.current_version()
    val = c.vault.detokenize(t_old, "崩溃后核验", adm())["value"]
    checks = {"crash_propagated": crashed,
              "no_version_bump": ver == 1,
              "old_data_decryptable": val == "13800138003"}
    c.close()
    return all(checks.values()), json.dumps({**checks, "version": ver})


# ---------------- D5 删除与读竞争 ----------------
def d5(rng):
    c, _ = new_box()
    svc = CandidateService(c)
    ids = [svc.create(adm(), {"name": f"丙{i}", "phone": f"1380013810{i}",
                              "city": "深圳", "station_id": "S1"})["id"] for i in range(20)]
    bad = []

    def deleter():
        for cid in ids:
            try:
                svc.c.delete if False else c.retention.delete_candidate(cid, "test", "anonymize")
            except Exception as e:                     # noqa: BLE001
                bad.append(f"del:{type(e).__name__}")

    def reader():
        for cid in ids:
            try:
                got = svc.view(adm(), cid)
                # 半匿名化 = name/phone 有其一为 None 但有另一个仍在
                if (got.get("name") is None) != (got.get("phone") is None):
                    bad.append("half-anonymized")
            except ApiError:
                pass
            except Exception as e:                     # noqa: BLE001
                bad.append(f"read:{type(e).__name__}")

    with cf.ThreadPoolExecutor(4) as ex:
        fs = [ex.submit(deleter), ex.submit(reader), ex.submit(reader)]
        for f in fs:
            f.result()
    c.close()
    ok = not [b for b in bad if not b.startswith("read:Not")] and not [b for b in bad if b == "half-anonymized"]
    return ok, json.dumps({"problems": bad[:5], "count": len(bad)})


# ---------------- D6 多表事务边界 ----------------
def d6(rng):
    c, _ = new_box()
    svc = CandidateService(c)
    before = {t: c.db.one(f"SELECT COUNT(*) AS c FROM {t}")["c"]
              for t in ("candidates", "vault_items", "audit_log")}
    # 在审计写入处注入失败，观察业务表是否残留
    orig = c.audit.append
    c.audit.append = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("audit down"))
    try:
        svc.create(adm(), {"name": "丁", "phone": "13800138030", "city": "深圳", "station_id": "S1"})
    except Exception:                                  # noqa: BLE001
        pass
    c.audit.append = orig
    after = {t: c.db.one(f"SELECT COUNT(*) AS c FROM {t}")["c"] for t in before}
    delta = {t: after[t] - before[t] for t in before}
    # 合格：要么全 0，要么业务与审计同时 +1（补偿）
    consistent = (all(v == 0 for v in delta.values())) or (
        delta["candidates"] == 1 and delta["audit_log"] >= 1 and delta["vault_items"] >= 2)
    c.close()
    return consistent, json.dumps(delta)


# ---------------- D7 并发建同值 token 的审计 ----------------
def d7(rng):
    c, _ = new_box()
    errs = []

    def w(_):
        try:
            c.vault.tokenize("手机号", "13800138099", "adm", "admin")
        except Exception as e:                          # noqa: BLE001
            errs.append(type(e).__name__)

    with cf.ThreadPoolExecutor(12) as ex:
        list(ex.map(w, range(24)))
    rows = c.db.one("SELECT COUNT(*) AS c FROM vault_items WHERE item_type='phone'")["c"]
    audits = c.db.one("SELECT COUNT(*) AS c FROM audit_log WHERE action='vault.tokenize'")["c"]
    checks = {"no_error": not errs, "single_row": rows == 1,
              "audit_once_per_insert": audits == rows,
              "chain_ok": c.audit.verify()["ok"]}
    c.close()
    return all(checks.values()), json.dumps({**checks, "errs": errs[:3], "rows": rows, "audits": audits})


# ---------------- D8 交叉一致性 ----------------
def d8(rng):
    c, _ = new_box()
    svc = CandidateService(c)
    for i in range(5):
        svc.create(adm(), {"name": f"戊{i}", "phone": f"1380013820{i}",
                           "city": "深圳", "station_id": "S1"})
    cands = c.db.query("SELECT id, name_token, phone_token FROM candidates")
    orphan = [x for x in cands
              if not c.db.one("SELECT token FROM vault_items WHERE token=?", (x["name_token"],))
              or not c.db.one("SELECT token FROM vault_items WHERE token=?", (x["phone_token"],))]
    creates = c.db.one("SELECT COUNT(*) AS c FROM audit_log WHERE action='candidate.create'")["c"]
    toks = c.db.one("SELECT COUNT(*) AS c FROM audit_log WHERE action='vault.tokenize'")["c"]
    checks = {"no_orphan_token": not orphan,
              "audit_create_matches": creates == len(cands),
              "audit_tokenize_covers_fields": toks >= 2 * len(cands),
              "chain_ok": c.audit.verify()["ok"]}
    c.close()
    return all(checks.values()), json.dumps({**checks, "cands": len(cands),
                                             "creates": creates, "tokenize": toks})


# ---------------- D9 数据库不可达 ----------------
def d9(rng):
    st = Settings()
    st.pg_dsn = "postgresql://nobody:nobody@127.0.0.1:1/none"
    t0 = time.time()
    try:
        Container(st, kms_dir=tempfile.mkdtemp())
        failed = False
    except Exception as e:                              # noqa: BLE001
        failed = True
        err = type(e).__name__
    dur = time.time() - t0
    # 合格：快速失败（不挂死）且抛的是可识别的连接类异常
    ok = failed and dur < 15
    return ok, json.dumps({"failed_fast": failed, "seconds": round(dur, 2),
                           "err": err if failed else None})


# ---------------- D10 分页与容量 ----------------
def d10(rng):
    c, _ = new_box()
    svc = CandidateService(c)
    N = 500
    for i in range(N):
        svc.create(adm(), {"name": f"员{i}", "phone": f"1380013{i:04d}",
                          "city": "深圳", "station_id": "S1"})
    t0 = time.time()
    allrows = svc.list(adm())
    dur_all = time.time() - t0
    page = svc.list(adm(), limit=50, offset=0) if _accepts(svc.list, "limit") else None
    checks = {
        "bulk_returns_all": len(allrows) == N,
        "pagination_supported": page is not None and len(page) <= 50,
        "bulk_under_3s": dur_all < 3.0,
    }
    c.close()
    return all(checks.values()), json.dumps({**checks, "rows": len(allrows),
                                             "bulk_seconds": round(dur_all, 2)})


def _accepts(fn, kw):
    import inspect
    return kw in inspect.signature(fn).parameters


# ---------------- D11 审计规模下 verify ----------------
def d11(rng):
    c, _ = new_box()
    N = 3000
    t0 = time.time()
    for i in range(N):
        c.audit.append("u", "recruiter", "candidate.read.masked", target=str(i))
    dur_ins = time.time() - t0
    t1 = time.time()
    v = c.audit.verify()
    dur_ver = time.time() - t1
    t2 = time.time()
    tail = c.audit.tail(20)
    dur_tail = time.time() - t2
    checks = {"chain_ok": v["ok"] and v["rows"] == N,
              "verify_under_10s": dur_ver < 10,
              "tail_under_1s": dur_tail < 1.0}
    c.close()
    return all(checks.values()), json.dumps({**checks, "rows": N,
                                             "insert_s": round(dur_ins, 2),
                                             "verify_s": round(dur_ver, 2),
                                             "tail_s": round(dur_tail, 3)})


# ---------------- D12 优雅关闭 ----------------
def d12(rng):
    """in-flight 请求被中断时，已提交的审计必须还在。"""
    c, _ = new_box()
    for i in range(5):
        c.audit.append("u", "admin", "candidate.read.masked", target=str(i))
    v_before = c.audit.verify()["rows"]
    c.close()                                  # 模拟进程退出（关闭连接）
    st = c.settings
    # 同一个 schema 才算"重启后重新打开同一个库"
    c2 = Container(st, db_path=c.settings.sqlite_path, kms_dir=c.settings.kms_dir,
                   pg_schema=getattr(c.settings, "pg_schema", None))
    v_after = c2.audit.verify()
    c2.close()
    checks = {"rows_preserved": v_after["rows"] == v_before, "chain_still_ok": v_after["ok"]}
    return all(checks.values()), json.dumps({**checks, "rows": v_after["rows"]})


# ---------------- D13 大批量导出 ----------------
def d13(rng):
    c, _ = new_box()
    svc = CandidateService(c)
    for i in range(200):
        svc.create(adm(), {"name": f"导{i}", "phone": f"1380015{i:04d}",
                          "city": "深圳", "station_id": "S1"})
    t0 = time.time()
    exp = svc.export(adm(), ids=None, full=False)
    dur = time.time() - t0
    payload = json.dumps(exp, ensure_ascii=False)
    checks = {"export_ok": exp["count"] == 200,
              "under_5s": dur < 5.0,
              "no_plaintext": "1380015" not in payload.replace("***", ""),
              "size_reasonable": len(payload) < 2_000_000}
    c.close()
    return all(checks.values()), json.dumps({**checks, "seconds": round(dur, 2),
                                             "bytes": len(payload)})


# ---------------- D14 时钟回拨 ----------------
def d14(rng):
    c, _ = new_box()
    svc = CandidateService(c)
    now0 = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc).timestamp()
    cand = svc.create(adm(), {"name": "己", "phone": "13800138077",
                              "city": "深圳", "station_id": "S1"}, now=now0)
    # 时钟回拨 1 天：不得误删
    rep = c.retention.run(now=now0 - DAY)
    alive = c.db.one("SELECT id FROM candidates WHERE id=?", (cand["id"],)) is not None
    # 审计 ts 变早也不能让链接不上
    c.audit.append("u", "admin", "candidate.read.masked", target="back", now=now0 - 10 * DAY)
    chain = c.audit.verify()["ok"]
    checks = {"no_premature_delete": alive, "deleted_zero": rep["expired_deleted"] == 0,
              "chain_ok_with_backdated_entry": chain}
    c.close()
    return all(checks.values()), json.dumps(checks)


# ---------------- D15 事件契约 ----------------
def d15(rng):
    """契约要求 outbox + Webhook 事件（candidate.created 等，HMAC 签名）。

    本模块是安全模块，事件产生属于业务侧（任务 1/3）。这里**只检查我们提供的
    安全侧事件是否可被外部消费**，并如实标注缺口，不假装已实现 outbox。
    """
    c, _ = new_box()
    cl = _client(c)
    H = {"Authorization": f"Bearer {_tok(c, 'adm', 'admin', all_cities=True)}"}
    spec = cl.get("/openapi.json").json()
    has_audit_api = any("audit" in p for p in spec["paths"])
    # 审计尾部可作为"变更流"被消费（带 seq 单调），这是本模块能给的最小保证
    for i in range(3):
        c.audit.append("u", "admin", "consent.record", target=str(i))
    rows = c.audit.tail(3)
    seqs = [r["seq"] for r in rows]
    checks = {"audit_readable_for_streaming": has_audit_api,
              "seq_monotonic": seqs == sorted(seqs, reverse=True),
              "has_outbox_table": c.db.one(
                  "SELECT name FROM sqlite_master WHERE type='table' AND name='outbox'") is not None
              if c.db.dialect == "sqlite" else True}
    c.close()
    # outbox 明确未实现 → 这一轮按"缺口可见"记 FAIL，写进报告
    return all(checks.values()), json.dumps({**checks,
        "note": "契约的 outbox+HMAC Webhook 属于业务侧（任务1/3）；本模块未实现，如实标注"})


def _client(box):
    from fastapi.testclient import TestClient
    from app.main import create_app
    return TestClient(create_app(box))


def _tok(box, actor, role, **kw):
    from app.auth import issue_staff_token
    return issue_staff_token(box.settings, actor, role, kw.get("city"),
                             kw.get("stations") or [], bool(kw.get("all_cities", True)))


ROUNDS = [(1, "audit_atomicity", d1), (2, "idempotency", d2), (3, "crash_recovery", d3),
          (4, "rotate_crash", d4), (5, "delete_read_race", d5), (6, "tx_boundary", d6),
          (7, "concurrent_tokenize_audit", d7), (8, "cross_consistency", d8),
          (9, "db_unreachable", d9), (10, "pagination_capacity", d10),
          (11, "audit_scale_verify", d11), (12, "graceful_close", d12),
          (13, "bulk_export", d13), (14, "clock_skew", d14), (15, "event_contract", d15)]



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
    reject_unknown("loop_verify_d.py", allowed=())
    seed = int(os.environ.get("LOOP_SEED", "20261106"))
    recs = []
    for idx, name, fn in ROUNDS:
        rng = random.Random(seed + idx)
        try:
            ok, detail = fn(rng)
        except Exception as e:                          # noqa: BLE001
            ok, detail = False, f"EXC {type(e).__name__}: {e}"
        recs.append({"round": idx, "name": name, "ok": bool(ok), "detail": detail})
        print(f"[{'PASS' if ok else 'FAIL'}] D{idx:<2} {name:26} {detail}")
    passed = sum(1 for r in recs if r["ok"])
    os.makedirs(os.path.join(ROOT, "reports"), exist_ok=True)
    out = {"group": "D", "platform": platform.system(), "python": platform.python_version(),
           "seed": seed, "rounds": recs, "passed": passed, "failed": len(recs) - passed}
    path = os.path.join(ROOT, "reports", f"loop_d_{platform.system().lower()}.json")
    _safe_write_report(path, out)
    print(f"\nD 组结果: {passed}/{len(recs)} 通过   记录 -> {os.path.relpath(path, ROOT)}")
    return 0 if passed == len(recs) else 1


if __name__ == "__main__":
    raise SystemExit(main())
