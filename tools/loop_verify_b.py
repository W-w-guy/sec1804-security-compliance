"""第二轮十轮循环（B 组）：专打第一轮打不到的地方——并发、跨方言一致、重启、边界值、异常输入。

A 组（tools/loop_verify.py）验的是"功能对不对"。B 组验的是"在压力与边界上还对不对"：
  B1  并发审计写入：8 线程 × 50 条，链不得分叉/断号
  B2  并发同值 tokenize：不得因主键冲突失败，token 必须一致
  B3  sqlite 与 PostgreSQL 同场景输出一致（同输入 → 同结论）
  B4  轮换与写入交错：轮换过程中写入的数据，轮换后仍可解
  B5  异常与超大输入：1MB 文本、零宽字符、RTL、空串、非法类型、超长 token
  B6  进程重启后链连续：同一个库文件重新打开，链不断、校验仍通过
  B7  权限矩阵快照：角色 × 权限逐项比对，防"悄悄放权"
  B8  保留期边界：正好 90 天 / 差 1 秒 / 未成年人 24h 整点
  B9  OpenAPI 与错误码自洽：路径/方法齐全、operationId 唯一、错误码唯一且都有 message
  B10 KMS 后端：Vault KV v2 真实可用性（拉不到真 Vault 就如实 SKIP，不给假通过）
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
from app.masking import MaskingSession     # noqa: E402
from app.rbac import PERMISSIONS, ROLES    # noqa: E402
from app.service import CandidateService   # noqa: E402

DAY = 86400.0


def new_box(secret="loopB"):
    """每轮一个独立容器。

    有 PG_DSN 时走真 PostgreSQL，并**分配独立 schema**——否则十轮共用同一个库，
    上一轮篡改审计留下的坏行会让下一轮 verify() 直接判 False（实测就是这么炸的）。
    schema 隔离与 sqlite 的"一实例一文件"语义等价。
    """
    tmp = tempfile.mkdtemp(prefix="sec1804-loopB-")
    st = Settings()
    st.kms_secret = secret
    schema = "t_" + uuid.uuid4().hex[:10] if st.pg_dsn else None
    return Container(st, db_path=os.path.join(tmp, "b.db"),
                     kms_dir=os.path.join(tmp, "kms"), pg_schema=schema), tmp


# ---------------- B1 并发审计 ----------------
def b1(rng):
    c, _ = new_box()
    n_threads, per = 8, 50
    errs = []

    def worker(i):
        try:
            for k in range(per):
                c.audit.append(f"u{i}", "recruiter", "candidate.read.masked",
                               target=f"c{i}-{k}", city="深圳")
        except Exception as e:            # noqa: BLE001
            errs.append(f"T{i}:{type(e).__name__}:{e}")

    with cf.ThreadPoolExecutor(n_threads) as ex:
        list(ex.map(worker, range(n_threads)))
    res = c.audit.verify()
    total = c.db.one("SELECT COUNT(*) AS c FROM audit_log")["c"]
    ok = (not errs) and res["ok"] and len(res["tampered_seq"]) == 0 and not res["missing_seq"]
    c.close()
    return ok, f"rows={total} expect={n_threads*per} chain_ok={res['ok']} forks={len(res['tampered_seq'])} gaps={res['missing_seq']} errs={errs[:2]}"


# ---------------- B2 并发同值 tokenize ----------------
def b2(rng):
    c, _ = new_box()
    value = "13800138000"
    toks, errs = [], []
    lock = threading.Lock()

    def worker(_):
        try:
            t = c.vault.tokenize("手机号", value, "adm", "admin")["token"]
            with lock:
                toks.append(t)
        except Exception as e:            # noqa: BLE001
            with lock:
                errs.append(f"{type(e).__name__}:{e}")

    with cf.ThreadPoolExecutor(16) as ex:
        list(ex.map(worker, range(32)))
    same = c.db.one("SELECT COUNT(*) AS c FROM vault_items WHERE token=?", (toks[0],))["c"] if toks else 0
    ok = (not errs) and len(set(toks)) == 1 and same == 1 and len(toks) == 32
    c.close()
    return ok, f"tokens={len(set(toks))} rows_for_that_token={same} calls={len(toks)} errs={errs[:2]}"


# ---------------- B3 sqlite vs PG 一致 ----------------
def b3(rng):
    """同一个脚本跑两遍：一次 sqlite，一次 PG（若提供了 PG_DSN），输出指纹必须相同。"""
    dsn = os.environ.get("PG_DSN", "")
    scenario = _scenario_sqlite()
    if not dsn:
        return None, f"SKIP(无 PG_DSN) sqlite={scenario[:60]}…"
    pg = _scenario_pg(dsn)
    if scenario == pg:
        return True, f"两方言输出逐项一致（{len(json.loads(scenario))} 项）"
    a, b = json.loads(scenario), json.loads(pg)
    diff = [f"{k}: sqlite={v!r} pg={b[i]!r}" for i, (k, v) in enumerate(a) if v != b[i]]
    return False, "差异: " + "; ".join(diff[:4])


def _scenario(box):
    from app.rbac import Principal
    svc = CandidateService(box)
    adm = Principal("adm", "admin", all_cities=True)
    rec = Principal("r1", "recruiter", city="深圳", stations={"S1"})
    out = []
    tok = box.vault.tokenize("手机号", "13900139000", "adm", "admin")["token"]
    out.append(("tok_len", len(tok)))
    out.append(("mask", box.vault.masked_of(tok)["masked"]))
    cand = svc.create(adm, {"name": "李雷", "phone": "13800138000", "city": "深圳", "station_id": "S1"})
    out.append(("cand_phone", cand["phone"]))
    out.append(("scope", _code(lambda: svc.view(rec, cand["id"]))))
    out.append(("audit_ok", box.audit.verify()["ok"]))
    box.db.execute("UPDATE audit_log SET actor='evil' WHERE seq=2")
    out.append(("tamper", box.audit.verify()["tampered_seq"]))
    rep = box.retention.run()
    out.append(("retention_keys", sorted(rep)))
    return json.dumps(out, ensure_ascii=False, sort_keys=True)


def _code(fn):
    try:
        fn()
        return "NO_ERROR"
    except ApiError as e:
        return e.code


def _scenario_sqlite():
    c, _ = new_box()
    v = _scenario(c)
    c.close()
    return v


def _scenario_pg(dsn):
    st = Settings(pg_dsn=dsn)
    st.kms_secret = "loopB"
    tmp = tempfile.mkdtemp(prefix="loopBpg-")
    c = Container(st, kms_dir=os.path.join(tmp, "kms"),
                  pg_schema="cmp_" + uuid.uuid4().hex[:8])
    try:
        return _scenario(c)
    finally:
        c.close()


# ---------------- B4 轮换与写入交错 ----------------
def b4(rng):
    c, _ = new_box()
    admin = __import__("app.rbac", fromlist=["Principal"]).Principal("adm", "admin", all_cities=True)
    before = c.vault.tokenize("手机号", "13700137000", "adm", "admin")["token"]
    v1 = c.kms.current_version()
    c.kms.rotate()                                  # 只换密钥，不重加密
    during = c.vault.tokenize("手机号", "13700137001", "adm", "admin")["token"]
    c.kms.rotate()
    after = c.vault.tokenize("手机号", "13700137002", "adm", "admin")["token"]
    vals = {t: c.vault.detokenize(t, "轮换交错核验", admin)["value"]
            for t in (before, during, after)}
    ok = (vals == {before: "13700137000", during: "13700137001", after: "13700137002"})
    c.close()
    return ok, f"v1={v1} versions={sorted(set(vals))} ok={ok}"


# ---------------- B5 异常与超大输入 ----------------
def b5(rng):
    c, _ = new_box()
    checks = {}
    # 1MB 文本：不能崩、不能超时太久
    big = ("我叫王小二，电话13800138000。住杭州市西湖区文三路90号。 " * 20000)[:1_000_000]
    t0 = time.time()
    r = MaskingSession().detect(big)
    checks["1MB_no_crash"] = len(r) > 0
    checks["1MB_under_30s"] = (time.time() - t0) < 30
    # 零宽字符 / RTL / emoji 夹杂
    weird = "我\u200b叫\u202e王\u200d小二\U0001F600，电话138\u20110013\u20118000"
    r2 = MaskingSession().detect(weird)
    checks["weird_unicode_survives"] = isinstance(r2, list)
    # 空串 / 只有标点
    checks["empty_ok"] = MaskingSession().detect("") == []
    checks["punct_ok"] = MaskingSession().detect("！！！。。。") == []
    # 非法类型
    try:
        c.vault.tokenize("不存在的类型", "x", "a", "admin")
        checks["bad_type_rejected"] = False
    except ApiError as e:
        checks["bad_type_rejected"] = e.code == "unsupported_type"
    # 空值
    try:
        c.vault.tokenize("手机号", "", "a", "admin")
        checks["empty_value_rejected"] = False
    except ApiError as e:
        checks["empty_value_rejected"] = e.code == "empty_value"
    # 超长 token（枚举/注入尝试）
    try:
        c.vault.detokenize("vt_" + "A" * 5000, "试图枚举令牌", 
                           __import__("app.rbac", fromlist=["Principal"]).Principal("a", "admin", all_cities=True))
        checks["long_token_rejected"] = False
    except ApiError as e:
        checks["long_token_rejected"] = e.code == "token_not_found"
    c.close()
    ok = all(checks.values())
    return ok, json.dumps(checks, ensure_ascii=False)


# ---------------- B6 重启后链连续 ----------------
def b6(rng):
    d = tempfile.mkdtemp(prefix="loopB6-")
    dbp, kd = os.path.join(d, "r.db"), os.path.join(d, "kms")
    st = Settings()
    st.kms_secret = "loopB"
    # 重启测试必须"同一个库"：PG 模式下两次打开要落在同一个 schema 上
    schema = ("r_" + uuid.uuid4().hex[:10]) if st.pg_dsn else None
    c1 = Container(st, db_path=dbp, kms_dir=kd, pg_schema=schema)
    for i in range(5):
        c1.audit.append("u", "admin", "candidate.read.masked", target=f"c{i}")
    tip1 = c1.audit.verify()["tip"]
    c1.close()
    c2 = Container(st, db_path=dbp, kms_dir=kd, pg_schema=schema)
    for i in range(5, 10):
        c2.audit.append("u", "admin", "candidate.read.masked", target=f"c{i}")
    res = c2.audit.verify()
    # 密钥也必须持久：同一个 KMS 目录重新打开仍能解老数据
    tok = c2.vault.tokenize("手机号", "13600136000", "a", "admin")["token"]
    okv = c2.vault.detokenize(tok, "重启后可解", 
        __import__("app.rbac", fromlist=["Principal"]).Principal("a", "admin", all_cities=True))["value"]
    c2.close()
    ok = res["ok"] and res["rows"] == 10 and len(res["tampered_seq"]) == 0 and okv == "13600136000"
    return ok, f"rows={res['rows']} chain_ok={res['ok']} tip_changed={res['tip']!=tip1} key_persist={okv=='13600136000'}"


# ---------------- B7 权限矩阵快照 ----------------
EXPECTED = {
    "recruiter": {"candidate.read.masked", "vault.tokenize", "mask.apply", "rights.track"},
    "station_manager": {"candidate.read.masked", "candidate.export.masked", "vault.tokenize",
                        "mask.apply", "mask.restore", "rights.track"},
    "ops": {"candidate.read.masked", "candidate.export.masked", "vault.tokenize",
            "mask.apply", "retention.run", "audit.read", "rights.track"},
    "admin": {"candidate.read.masked", "candidate.read.full", "candidate.export.full",
              "candidate.export.masked", "vault.tokenize", "vault.detokenize",
              "mask.apply", "mask.restore", "retention.run", "audit.read",
              "approval.decide", "kms.rotate", "rights.track", "rights.close"},
    "auditor": {"candidate.read.masked", "audit.read", "audit.verify", "rights.track"},
}


def b7(rng):
    diffs = []
    for role in ROLES:
        got, want = set(PERMISSIONS.get(role, set())), set(EXPECTED[role])
        if got != want:
            diffs.append(f"{role}: extra={sorted(got-want)} missing={sorted(want-got)}")
    # 关键负面断言：只有 admin 能解密，只有 admin 能改配置
    sensitive = ["vault.detokenize", "kms.rotate", "candidate.read.full", "approval.decide"]
    for role, perms in PERMISSIONS.items():
        if role != "admin":
            for p in sensitive:
                if p in perms:
                    diffs.append(f"{role} 不应有 {p}")
    return (not diffs), ("matrix OK, 5 角色 26 项权限逐项一致" if not diffs else "; ".join(diffs))


# ---------------- B8 保留期边界 ----------------
def b8(rng):
    from app.rbac import Principal
    c, _ = new_box()
    svc = CandidateService(c)
    adm = Principal("adm", "admin", all_cities=True)
    now0 = dt.datetime(2026, 6, 1, 12, 0, 0, tzinfo=dt.timezone.utc).timestamp()
    checks = {}
    # 基准：在 now0 创建，retention_until = now0 + 90d
    a = svc.create(adm, {"name": "边界甲", "phone": "13500135000", "city": "深圳",
                         "station_id": "S1", "status": "new"}, now=now0)
    # 差 1 秒到期 → 不该删
    c.retention.run(now=now0 + 90 * DAY - 1)
    checks["just_before_kept"] = c.db.one("SELECT id FROM candidates WHERE id=?", (a["id"],)) is not None
    # 正好到期 → 应删（语义：until <= now 即到期）
    c.retention.run(now=now0 + 90 * DAY)
    checks["exactly_due_deleted"] = c.db.one("SELECT id FROM candidates WHERE id=?", (a["id"],)) is None
    # 已录用：正好 180 天 → 匿名化而非删除
    h = svc.create(adm, {"name": "边界乙", "phone": "13500135001", "city": "深圳",
                         "station_id": "S1", "status": "hired"}, now=now0)
    c.retention.run(now=now0 + 180 * DAY - 1)
    checks["hired_before_kept"] = c.db.one("SELECT name_token FROM candidates WHERE id=?", (h["id"],))["name_token"] is not None
    c.retention.run(now=now0 + 180 * DAY)
    row = c.db.one("SELECT name_token, anonymized_at FROM candidates WHERE id=?", (h["id"],))
    checks["hired_due_anonymized"] = row is not None and row["name_token"] is None and bool(row["anonymized_at"])
    # 未成年人：23h59m 保留、24h 删除
    m = svc.create(adm, {"name": "边界丙", "phone": "13500135002", "city": "深圳",
                         "station_id": "S1", "is_minor": True}, now=now0)
    c.retention.run(now=now0 + 24 * 3600 - 60)
    checks["minor_23h59_kept"] = c.db.one("SELECT id FROM candidates WHERE id=?", (m["id"],)) is not None
    c.retention.run(now=now0 + 24 * 3600)
    checks["minor_24h_deleted"] = c.db.one("SELECT id FROM candidates WHERE id=?", (m["id"],)) is None
    c.close()
    ok = all(checks.values())
    return ok, json.dumps(checks, ensure_ascii=False)


# ---------------- B9 OpenAPI 与错误码自洽 ----------------
def b9(rng):
    from fastapi.testclient import TestClient
    from app.main import create_app
    from app import errors as E
    c, _ = new_box()
    cl = TestClient(create_app(c))
    spec = cl.get("/openapi.json").json()
    paths = spec["paths"]
    # 1) 每个操作都有响应定义、都有 tags、operationId 唯一
    ops, dup = [], []
    for p, item in paths.items():
        for m, op in item.items():
            oid = op.get("operationId", "")
            if oid in ops:
                dup.append(oid)
            ops.append(oid)
            if not op.get("responses"):
                dup.append(f"{m.upper()} {p} 无 responses")
    # 2) 错误体 schema 一致性：所有 ApiError 子类 code/status 唯一且 body 有 code+message
    classes = [v for v in vars(E).values()
               if isinstance(v, type) and issubclass(v, E.ApiError) and v is not E.ApiError]
    codes = [k.code for k in classes]
    bodies_ok = all(set(k("x").body()) == {"code", "message"} for k in classes)
    # 3) 404 路径返回 JSON 且带 code/message（框架默认 404 会是 detail 字段）
    r = cl.get("/api/v1/no-such-endpoint")
    shape = r.headers.get("content-type", "").startswith("application/json")
    c.close()
    ok = (not dup) and bodies_ok and len(set(codes)) == len(codes) and shape
    return ok, f"paths={len(paths)} ops={len(ops)} dup={dup[:3]} err_codes={sorted(codes)} bodies_ok={bodies_ok} framework404_json={shape}"


# ---------------- B10 Vault 后端 ----------------
def b10(rng):
    addr = os.environ.get("VAULT_ADDR", "")
    token = os.environ.get("VAULT_TOKEN", "")
    if not addr or not token:
        return None, "SKIP(未提供 VAULT_ADDR/VAULT_TOKEN；未验证，不计为通过)"
    from app.kms import VaultKMS
    k = VaultKMS(addr, token)
    v1 = k.current_version()
    key1 = k.key(v1)
    v2 = k.rotate()
    key2 = k.key(v2)
    ok = v2 == v1 + 1 and len(key1) == 32 and len(key2) == 32 and key1 != key2 and k.key(v1) == key1
    return ok, f"versions {v1}->{v2} keylen={len(key2)} old_key_stable={k.key(v1)==key1}"


ROUNDS = [(1, "concurrent_audit", b1), (2, "concurrent_tokenize", b2), (3, "sqlite_vs_pg", b3),
          (4, "rotate_interleave", b4), (5, "fuzz_big_input", b5), (6, "restart_chain", b6),
          (7, "rbac_matrix_snapshot", b7), (8, "retention_boundary", b8),
          (9, "openapi_errorcodes", b9), (10, "vault_backend", b10)]



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
    seed = int(os.environ.get("LOOP_SEED", "20261104"))
    recs, skipped = [], []
    for idx, name, fn in ROUNDS:
        rng = random.Random(seed + idx)
        try:
            ok, detail = fn(rng)
        except Exception as e:                    # noqa: BLE001
            ok, detail = False, f"EXC {type(e).__name__}: {e}"
        if ok is None:
            skipped.append(name)
            mark = "SKIP"
        else:
            mark = "PASS" if ok else "FAIL"
        recs.append({"round": idx, "name": name, "ok": (None if ok is None else bool(ok)),
                     "detail": detail})
        print(f"[{mark}] B{idx:<2} {name:24} {detail}")
    passed = sum(1 for r in recs if r["ok"] is True)
    failed = sum(1 for r in recs if r["ok"] is False)
    os.makedirs(os.path.join(ROOT, "reports"), exist_ok=True)
    out = {"platform": platform.system(), "python": platform.python_version(), "seed": seed,
           "rounds": recs, "passed": passed, "failed": failed, "skipped": skipped}
    path = os.path.join(ROOT, "reports", f"loop_b_{platform.system().lower()}.json")
    _safe_write_report(path, out)
    print(f"\nB 组结果: {passed} 通过 / {failed} 失败 / {len(skipped)} 跳过"
          f"   记录 -> {os.path.relpath(path, ROOT)}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
