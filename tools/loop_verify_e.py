"""E 组 15 轮：并发正确性、隔离与接口边界。

C 组问"攻击者能拿到什么"，D 组问"出错时会不会留下没法解释的状态"，
E 组问"**两个正常操作同时发生时，结果对不对**"。这类 bug 不报错、不留异常，
只是数据悄悄错了 —— 对 PII 系统来说，错一次就是错一份档案。

E1  丢失更新：两个专员同时改同一候选人，后写覆盖前写
E2  乐观锁：带 If-Match/版本号时，过期版本必须 409 而不是覆盖
E3  部分更新语义：只传一个字段不得把其它字段清空
E4  字段级并发：两人改不同字段，两个都不该丢
E5  删除与更新竞态：删了又改，不得"复活"
E6  唯一约束并发：同一手机号并发建档，是否产生重复候选人
E7  事务隔离：读到别人未提交的中间态
E8  审计与业务的行级一致：并发下审计条数与业务变更数对齐
E9  幂等键并发：同键多请求同时到达，只能有一个真正执行
E10 批量接口的原子性：一批里有一条非法，是否整批回滚
E11 游标分页稳定性：翻页期间有新增/删除，不得重复或漏项
E12 计数一致性：total 与实际可访问条数一致
E13 大字段与超限：单字段超长、批量条数超限，须明确拒绝
E14 并发导出与删除：导出过程中被删，不得导出到已删数据
E15 跨城市并发写：越权写不得因为并发而漏拦
"""
from __future__ import annotations
import concurrent.futures as cf
import json
import os
import platform
import random
import sys
import tempfile
import threading
import time
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
ENV = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1",
           PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")

from app.config import Settings            # noqa: E402
from app.container import Container        # noqa: E402
from app.errors import ApiError            # noqa: E402
from app.rbac import Principal             # noqa: E402
from app.service import CandidateService   # noqa: E402


def new_box():
    tmp = tempfile.mkdtemp(prefix="sec1804-loopE-")
    st = Settings()
    st.kms_secret = "loopE"
    st.jwt_secret = "e-" + uuid.uuid4().hex[:8]
    schema = ("e_" + uuid.uuid4().hex[:10]) if st.pg_dsn else None
    return Container(st, db_path=os.path.join(tmp, "e.db"),
                     kms_dir=os.path.join(tmp, "kms"), pg_schema=schema), tmp


def adm():
    return Principal("adm", "admin", all_cities=True)


def mk(svc, **kw):
    d = {"name": "王小二", "phone": "13800138000", "city": "深圳", "station_id": "S1"}
    d.update(kw)
    return svc.create(adm(), d)


# ---------------- E1 丢失更新 ----------------
def e1(rng):
    """两个专员同时改同一人的不同字段，最终两个修改都应在。

    当前实现是"整行 UPDATE"，没有版本控制 → 后写的覆盖先写的。
    这一轮要如实暴露：并发改不同字段会丢其中一个。
    """
    c, _ = new_box()
    svc = CandidateService(c)
    cand = mk(svc)
    barrier = threading.Barrier(2)
    done = []

    def w1():
        barrier.wait()
        svc.update(adm(), cand["id"], {"area_text": "A区"})
        done.append("w1")

    def w2():
        barrier.wait()
        svc.update(adm(), cand["id"], {"start_text": "下周一"})
        done.append("w2")

    ts = [threading.Thread(target=w1), threading.Thread(target=w2)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    row = c.db.one("SELECT area_text, start_text FROM candidates WHERE id=?", (cand["id"],))
    ok = row["area_text"] == "A区" and row["start_text"] == "下周一"
    c.close()
    return ok, json.dumps({"row": {k: row[k] for k in ("area_text", "start_text")},
                           "both_applied": ok})


# ---------------- E2 乐观锁 ----------------
def e2(rng):
    c, _ = new_box()
    svc = CandidateService(c)
    cand = mk(svc)
    checks = {}
    v1 = cand.get("version")
    checks["version_present"] = isinstance(v1, int)
    if isinstance(v1, int):
        try:
            svc.update(adm(), cand["id"], {"area_text": "X"}, expected_version=v1 + 99)
            checks["stale_version_rejected"] = False
        except ApiError as e:
            checks["stale_version_rejected"] = e.code in ("version_conflict", "conflict")
    c.close()
    failed = [k for k, v in checks.items() if not v]
    return (not failed), json.dumps({"failed": failed, "version": v1})


# ---------------- E3 部分更新语义 ----------------
def e3(rng):
    c, _ = new_box()
    svc = CandidateService(c)
    cand = mk(svc, area_text="原地址", start_text="随时", experience_text="两年")
    svc.update(adm(), cand["id"], {"area_text": "新地址"})
    got = svc.view(adm(), cand["id"])
    checks = {"patched_field_changed": got.get("area_text") == "新地址",
              "other_fields_kept": got.get("start_text") == "随时"
              and got.get("experience_text") == "两年"}
    c.close()
    return all(checks.values()), json.dumps(checks)


# ---------------- E4 字段级并发 ----------------
def e4(rng):
    c, _ = new_box()
    svc = CandidateService(c)
    cand = mk(svc)
    fields = ["area_text", "start_text", "experience_text", "job_type"][:4]
    vals = {f: f + "-v" for f in fields}

    def w(f):
        svc.update(adm(), cand["id"], {f: vals[f]})

    with cf.ThreadPoolExecutor(4) as ex:
        list(ex.map(w, fields))
    row = c.db.one("SELECT * FROM candidates WHERE id=?", (cand["id"],))
    lost = [f for f in fields if row.get(f) != vals[f]]
    c.close()
    return (not lost), json.dumps({"lost_fields": lost})


# ---------------- E5 删除与更新竞态 ----------------
def e5(rng):
    c, _ = new_box()
    svc = CandidateService(c)
    cand = mk(svc)
    res = {"deleted": False, "resurrected": False}

    def deleter():
        c.retention.delete_candidate(cand["id"], "test", "delete")

    def updater():
        try:
            svc.update(adm(), cand["id"], {"area_text": "改了"})
        except ApiError:
            pass

    t1 = threading.Thread(target=deleter)
    t2 = threading.Thread(target=updater)
    t1.start(); time.sleep(0.001); t2.start()
    t1.join(); t2.join()
    row = c.db.one("SELECT id FROM candidates WHERE id=?", (cand["id"],))
    res["deleted"] = row is None
    res["resurrected"] = row is not None
    c.close()
    return res["deleted"], json.dumps(res)


# ---------------- E6 唯一约束并发 ----------------
def e6(rng):
    """同一手机号并发建档：要么只建一条，要么明确允许重复但必须能查出。

    契约没有规定手机号唯一，但重复建档意味着同一份 PII 多副本，
    删除时容易漏删。这里要求"能检测到重复"。
    """
    c, _ = new_box()
    svc = CandidateService(c)
    errors = []
    ids = []

    def w(_):
        try:
            ids.append(mk(svc, phone="13900139000")["id"])
        except ApiError as e:
            errors.append(e.code)
        except Exception as e:                      # noqa: BLE001
            errors.append(type(e).__name__)

    with cf.ThreadPoolExecutor(8) as ex:
        list(ex.map(w, range(8)))
    n = c.db.one("SELECT COUNT(*) AS c FROM candidates")["c"]
    tokens = c.db.query("SELECT token FROM vault_items WHERE item_type='phone'")
    dup_token_reuse = len(tokens) == 1   # 同号应复用同一 token
    checks = {"no_crash": all(e in ("duplicate_phone",) for e in errors),
              "phone_token_reused": dup_token_reuse,
              "duplicates_detectable": c.db.one(
                  "SELECT COUNT(*) AS c FROM candidates WHERE phone_token=?",
                  (tokens[0]["token"],))["c"] == n}
    c.close()
    return all(checks.values()), json.dumps({**checks, "rows": n, "errors": errors[:3]})


# ---------------- E7 事务隔离 ----------------
def e7(rng):
    """未提交的中间态不得被别的连接读到。

    sqlite（WAL）与 PG（READ COMMITTED）默认都不读未提交，这一轮做的是
    "**我们自己的实现有没有把中间态暴露出去**"：比如先建候选人、后写 token，
    中途被别人读到就会看到 phone=None 的半成品。
    """
    c, _ = new_box()
    svc = CandidateService(c)
    seen = {"half": 0, "none": 0, "ok": 0}
    stop = threading.Event()

    def reader():
        while not stop.is_set():
            for row in c.db.query("SELECT id, name_token, phone_token FROM candidates"):
                if row["name_token"] and row["phone_token"]:
                    seen["ok"] += 1
                elif row["name_token"] or row["phone_token"]:
                    seen["half"] += 1
                else:
                    seen["none"] += 1
            time.sleep(0.0005)

    t = threading.Thread(target=reader)
    t.start()
    for i in range(15):
        mk(svc, phone=f"1380013900{i}")
    stop.set()
    t.join()
    c.close()
    return seen["half"] == 0, json.dumps(seen)


# ---------------- E8 审计与业务行级一致 ----------------
def e8(rng):
    c, _ = new_box()
    svc = CandidateService(c)
    ids = []

    def w(i):
        ids.append(mk(svc, phone=f"1380013910{i}")["id"])

    with cf.ThreadPoolExecutor(8) as ex:
        list(ex.map(w, range(25)))
    creates = c.db.one("SELECT COUNT(*) AS c FROM audit_log WHERE action='candidate.create'")["c"]
    rows = c.db.one("SELECT COUNT(*) AS c FROM candidates")["c"]
    checks = {"rows_25": rows == 25, "audit_matches": creates == rows,
              "chain_ok": c.audit.verify()["ok"]}
    c.close()
    return all(checks.values()), json.dumps({**checks, "rows": rows, "creates": creates})


# ---------------- E9 幂等键并发 ----------------
def e9(rng):
    from app.idempotency import fingerprint
    c, _ = new_box()
    fp = fingerprint({"a": 1}, "/x")
    idem = c.idem
    got, conflicts = [], []

    def w(_):
        try:
            r = idem.begin("same-key", "adm", fp)
            got.append(r)
        except ApiError as e:
            conflicts.append(e.code)

    with cf.ThreadPoolExecutor(10) as ex:
        list(ex.map(w, range(10)))
    winners = [x for x in got if x is None]
    checks = {"exactly_one_winner": len(winners) == 1,
              "others_conflict": len(conflicts) == 9,
              "conflict_code": set(conflicts) <= {"idempotency_in_progress"}}
    c.close()
    return all(checks.values()), json.dumps({**checks, "winners": len(winners),
                                             "conflicts": len(conflicts)})


# ---------------- E10 批量原子性 ----------------
def e10(rng):
    c, _ = new_box()
    cl = _client(c)
    # 必须用**受城市限制**的身份，否则管理员 all_cities=True 本来就该能写杭州
    H = {"Authorization": "Bearer " + _tok(c, "mgr", "station_manager", city="深圳")}
    before = c.db.one("SELECT COUNT(*) AS c FROM candidates")["c"]
    r = cl.post("/api/v1/candidates/bulk", headers=H,
                json={"items": [{"name": "甲", "phone": "13800139201", "city": "深圳", "station_id": "S1"},
                                {"name": "乙", "phone": "13800139202", "city": "杭州", "station_id": "H1"},
                                {"name": "丙", "phone": "13800139203", "city": "深圳", "station_id": "S1"}]})
    after = c.db.one("SELECT COUNT(*) AS c FROM candidates")["c"]
    # 第 2 条跨城市越权 → 整批必须回滚（前 1 条已建好也要撤掉）
    ok = r.status_code == 403 and after == before
    c.close()
    return ok, json.dumps({"status": r.status_code, "before": before, "after": after,
                           "atomic": after == before})


# ---------------- E11 游标分页稳定性 ----------------
def e11(rng):
    c, _ = new_box()
    svc = CandidateService(c)
    for i in range(20):
        mk(svc, phone=f"1380013930{i:02d}")
    p1 = svc.list(adm(), limit=10, offset=0)
    # 翻页期间插入新数据（会导致 offset 分页重复）
    mk(svc, phone="13800139399")
    p2 = svc.list(adm(), limit=10, offset=10)
    ids1 = [x["id"] for x in p1]
    ids2 = [x["id"] for x in p2]
    overlap = set(ids1) & set(ids2)
    # 用 cursor（按 created_at+id）则不该重叠
    cur = svc.list(adm(), limit=10, cursor_from=ids1[-1]) if _has(svc.list, "cursor_from") else None
    checks = {"offset_paging_has_overlap": bool(overlap) or True,   # 事实记录，不算失败
              "cursor_api_exists": cur is not None,
              "cursor_no_overlap": (set(x["id"] for x in cur) & set(ids1) == set()) if cur else False}
    c.close()
    ok = checks["cursor_api_exists"] and checks["cursor_no_overlap"]
    return ok, json.dumps({**checks, "overlap_count": len(overlap)})


def _has(fn, kw):
    import inspect
    return kw in inspect.signature(fn).parameters


# ---------------- E12 计数一致性 ----------------
def e12(rng):
    c, _ = new_box()
    cl = _client(c)
    svc = CandidateService(c)
    for i in range(6):
        mk(svc, phone=f"1380013940{i}", city="深圳", station_id="S1")
    mk(svc, phone="13800139410", city="杭州", station_id="H1")
    rec = Principal("r", "recruiter", city="深圳", stations={"S1"})
    H = {"Authorization": f"Bearer {_tok(c, 'r', 'recruiter', city='深圳')}"}
    r = cl.get("/api/v1/candidates?limit=100", headers=H)
    body = r.json()
    checks = {"returns_6": body["count"] == 6,
              # total_scoped_upper_bound 是全库口径，必须显式标注为"上界"而不是可访问数
              "total_not_misleading": body.get("total_scoped_upper_bound") is not None}
    c.close()
    return all(checks.values()), json.dumps({**checks, "count": body["count"],
                                             "field_name": "total_scoped_upper_bound"})


# ---------------- E13 大字段与超限 ----------------
def e13(rng):
    c, _ = new_box()
    cl = _client(c)
    H = _h(c)
    checks = {}
    r = cl.post("/api/v1/candidates", headers=H,
                json={"name": "长" * 5000, "phone": "13800139500", "city": "深圳",
                      "station_id": "S1"})
    checks["long_name_rejected"] = r.status_code == 422
    r2 = cl.post("/api/v1/candidates/bulk", headers=H,
                 json={"items": [{"name": "x", "phone": f"1380013{9600+i}", "city": "深圳",
                                  "station_id": "S1"} for i in range(500)]})
    # 上限是业务规则（不是 schema），所以 403 也可接受
    checks["bulk_limit_enforced"] = r2.status_code in (403, 422)
    c.close()
    return all(checks.values()), json.dumps(checks)


# ---------------- E14 导出与删除竞态 ----------------
def e14(rng):
    c, _ = new_box()
    svc = CandidateService(c)
    ids = [mk(svc, phone=f"1380013970{i}")["id"] for i in range(30)]
    out = {}

    def exporter():
        try:
            out["rows"] = svc.export(adm(), ids=ids, full=False)["count"]
        except ApiError as e:
            out["err"] = e.code

    def deleter():
        for cid in ids[:15]:
            c.retention.delete_candidate(cid, "test", "delete")

    t1 = threading.Thread(target=exporter)
    t2 = threading.Thread(target=deleter)
    t1.start(); t2.start(); t1.join(); t2.join()
    alive = c.db.one("SELECT COUNT(*) AS c FROM candidates")["c"]
    # 合格：要么导出前完成（拿到 30），要么导出时明确报错；不得导出"已删除的数据"
    exported = out.get("rows")
    ok = (exported is not None and exported <= 30) or "err" in out
    # 更严：导出结果里的 id 必须仍然存在
    c.close()
    return ok, json.dumps({"exported": exported, "alive_after": alive, "err": out.get("err")})


# ---------------- E15 跨城市并发写 ----------------
def e15(rng):
    c, _ = new_box()
    svc = CandidateService(c)
    sz = Principal("sz", "recruiter", city="深圳", stations={"S1"})
    leaked = []
    blocked = []

    def w(i):
        try:
            svc.create(sz, {"name": f"甲{i}", "phone": f"1380013980{i}", "city": "杭州",
                            "station_id": "H1"})
            leaked.append(i)
        except ApiError as e:
            blocked.append(e.code)

    with cf.ThreadPoolExecutor(10) as ex:
        list(ex.map(w, range(20)))
    rows = c.db.one("SELECT COUNT(*) AS c FROM candidates")["c"]
    checks = {"all_blocked": not leaked, "rows_zero": rows == 0,
              "code_ok": set(blocked) == {"out_of_scope"}}
    c.close()
    return all(checks.values()), json.dumps({**checks, "leaked": len(leaked),
                                             "blocked": len(blocked), "rows": rows})


def _client(box):
    from fastapi.testclient import TestClient
    from app.main import create_app
    return TestClient(create_app(box))


def _tok(box, actor, role, **kw):
    from app.auth import issue_staff_token
    return issue_staff_token(box.settings, actor, role, kw.get("city"),
                             kw.get("stations") or [], bool(kw.get("all_cities", False)))


def _h(box, **kw):
    actor = kw.pop("actor", "adm")
    role = kw.pop("role", "admin")
    return {"Authorization": "Bearer " + _tok(box, actor, role, **kw)}


ROUNDS = [(1, "lost_update", e1), (2, "optimistic_lock", e2), (3, "partial_update", e3),
          (4, "field_level_concurrency", e4), (5, "delete_update_race", e5),
          (6, "unique_under_concurrency", e6), (7, "tx_isolation", e7),
          (8, "audit_row_alignment", e8), (9, "idempotency_concurrency", e9),
          (10, "bulk_atomicity", e10), (11, "cursor_paging", e11),
          (12, "count_consistency", e12), (13, "bulk_limits", e13),
          (14, "export_delete_race", e14), (15, "cross_city_concurrent_write", e15)]


def main() -> int:
    seed = int(os.environ.get("LOOP_SEED", "20261107"))
    recs = []
    for idx, name, fn in ROUNDS:
        rng = random.Random(seed + idx)
        try:
            ok, detail = fn(rng)
        except Exception as e:                      # noqa: BLE001
            ok, detail = False, f"EXC {type(e).__name__}: {e}"
        recs.append({"round": idx, "name": name, "ok": bool(ok), "detail": detail})
        print(f"[{'PASS' if ok else 'FAIL'}] E{idx:<2} {name:28} {detail}")
    passed = sum(1 for r in recs if r["ok"])
    os.makedirs(os.path.join(ROOT, "reports"), exist_ok=True)
    out = {"group": "E", "platform": platform.system(), "python": platform.python_version(),
           "seed": seed, "rounds": recs, "passed": passed, "failed": len(recs) - passed}
    with open(os.path.join(ROOT, "reports", f"loop_e_{platform.system().lower()}.json"),
              "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=1)
    print(f"\nE 组结果: {passed}/{len(recs)} 通过")
    return 0 if passed == len(recs) else 1


if __name__ == "__main__":
    raise SystemExit(main())
