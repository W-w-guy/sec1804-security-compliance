"""F 组 15 轮：可运维性与可审计性（出事之后能不能解释清楚）。

E 组解决并发正确性，F 组解决**"证据"**问题：
  · 密钥被人拷走了会怎样？（KMS 目录权限、密钥是否与数据分离）
  · 从备份恢复之后，审计链还能不能验？恢复点之后的数据怎么解释？
  · 保留期到了，怎么**证明**真的删了、而不是嘴上说删了？
  · 监管来要审计导出，导出的东西能不能独立验证？

F1  KMS 目录权限：密钥文件不得 world/group 可读
F2  密钥与数据分离：数据被拷走但没密钥 → 解不出
F3  密钥被拷走 + 数据被拷走 → 能解（这是设计边界，必须如实说明并给出缓解）
F4  KMS 目录缺失/损坏 → 明确报错，不得静默降级成新密钥（否则老数据永久丢失）
F5  备份恢复：库恢复后链仍可验，恢复点之后的空洞可被识别
F6  删除证明：保留期清理后能给出"删了什么、按什么规则、什么时候"
F7  删除证明的完整性：deletion_log 自身被篡改能否被发现
F8  审计导出：导出格式可独立验证（带每行 hash 与链尾）
F9  审计导出不含明文
F10 监管查询：按主体/按时间/按动作可检索，且耗时可控
F11 密钥轮换运维：轮换前后数据可读，轮换可回滚
F12 配置审计：关键配置变更（阈值/保留期/KMS 后端）是否留痕
F13 健康自检：/health 与自检接口能反映真实依赖状态，不得假绿
F14 日志卫生：日志/审计里不得出现密钥、token 值、明文
F15 灾难恢复演练：无密钥、无库、无备份三种情况下系统的行为
"""
from __future__ import annotations
import base64
import json
import os
import platform
import random
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
import datetime as dt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
ENV = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1",
           PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")

from app.config import Settings            # noqa: E402
from app.container import Container        # noqa: E402
from app.errors import ApiError            # noqa: E402
from app.kms import FileKMS                # noqa: E402
from app.rbac import Principal             # noqa: E402
from app.service import CandidateService   # noqa: E402

DAY = 86400.0


def new_box(kms_dir=None, db_path=None, secret="loopF", schema=None):
    tmp = tempfile.mkdtemp(prefix="sec1804-loopF-")
    st = Settings()
    st.kms_secret = secret
    st.jwt_secret = "f-" + uuid.uuid4().hex[:8]
    if schema is None and st.pg_dsn:
        schema = "f_" + uuid.uuid4().hex[:10]
    return Container(st, db_path=db_path or os.path.join(tmp, "f.db"),
                     kms_dir=kms_dir or os.path.join(tmp, "kms"), pg_schema=schema), tmp


def adm():
    return Principal("adm", "admin", all_cities=True)


def mk(svc, **kw):
    d = {"name": "王小二", "phone": "13800138000", "city": "深圳", "station_id": "S1"}
    d.update(kw)
    return svc.create(adm(), d)


# ---------------- F1 KMS 目录权限 ----------------
def f1(rng):
    c, tmp = new_box()
    c.vault.tokenize("手机号", "13800138001", "a", "admin")
    kp = os.path.join(c.settings.kms_dir, "keys.json")
    if not os.path.exists(kp):
        c.close()
        return False, json.dumps({"error": "keys.json 不存在"})
    mode = stat.S_IMODE(os.stat(kp).st_mode)
    world_readable = bool(mode & stat.S_IROTH)
    group_readable = bool(mode & stat.S_IRGRP)
    dirmode = stat.S_IMODE(os.stat(c.settings.kms_dir).st_mode)
    checks = {"key_not_world_readable": not world_readable,
              "key_not_group_readable": not group_readable,
              "mode": oct(mode), "dirmode": oct(dirmode)}
    c.close()
    if os.name == "nt":
        # Windows 没有 POSIX 权限位，os.open 的 0o600 被忽略。
        # 这一段只能在 Linux 上判；在 Windows 上如实 SKIP，不当成通过。
        return None, "SKIP(Windows 无 POSIX 权限位，需在 Linux 上判) " + json.dumps(checks)
    return checks["key_not_world_readable"] and checks["key_not_group_readable"], json.dumps(checks)


# ---------------- F2 密钥与数据分离 ----------------
def f2(rng):
    """只拷走数据库、不拷密钥 → 必须解不出。"""
    c, tmp = new_box()
    tok = c.vault.tokenize("手机号", "13800138002", "a", "admin")["token"]
    row = c.db.one("SELECT * FROM vault_items WHERE token=?", (tok,))
    db_copy = os.path.join(tmp, "stolen.db")
    if c.db.dialect == "sqlite":
        shutil.copy(c.settings.sqlite_path, db_copy)
        c.close()
        # 换一个全新的空 KMS 目录（模拟攻击者只有库）
        c2, _ = new_box(kms_dir=os.path.join(tmp, "empty-kms"), db_path=db_copy)
        try:
            got = c2.vault.detokenize(tok, "模拟攻击者尝试", adm())["value"]
            ok = False
            detail = {"decrypted": got}
        except Exception as e:                      # noqa: BLE001
            ok = True
            detail = {"blocked_by": type(e).__name__}
        c2.close()
        return ok, json.dumps(detail)
    # PG 模式：直接构造一个指向同一 schema 但空 KMS 的容器
    c.close()
    c2, _ = new_box(kms_dir=os.path.join(tmp, "empty-kms"))
    try:
        c2.vault.detokenize(tok, "模拟攻击者尝试", adm())
        ok, detail = False, {"decrypted": True}
    except Exception as e:                          # noqa: BLE001
        ok, detail = True, {"blocked_by": type(e).__name__}
    c2.close()
    return ok, json.dumps(detail)


# ---------------- F3 密钥+数据都被拷走 ----------------
def f3(rng):
    """两者都被拷走能否解密 —— 这是**设计边界**，不遮掩，只验证"有明示风险"。"""
    c, tmp = new_box()
    sch = getattr(c.settings, "pg_schema", None)
    tok = c.vault.tokenize("手机号", "13800138003", "a", "admin")["token"]
    c.close()
    c2, _ = new_box(kms_dir=c.settings.kms_dir, db_path=c.settings.sqlite_path, schema=sch)
    got = c2.vault.detokenize(tok, "拿齐两样的攻击者", adm())["value"]
    c2.close()
    # 验收口径：能解（这是 AES 的必然结果），但必须有文档与缓解措施
    readme = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
    documented = ("密钥与数据分离" in readme or "KMS" in readme) and "已知边界" in readme
    return got == "13800138003" and documented, json.dumps(
        {"decryptable_with_both": got == "13800138003",
         "risk_documented": documented,
         "mitigation": "密钥放 Vault/KMS，不与应用同机同盘；磁盘加密；最小权限"})


# ---------------- F4 KMS 损坏不得静默换钥 ----------------
def f4(rng):
    """keys.json 被破坏时，必须报错；若静默生成新密钥，老数据就永久解不开了。"""
    c, tmp = new_box()
    tok = c.vault.tokenize("手机号", "13800138004", "a", "admin")["token"]
    kp = os.path.join(c.settings.kms_dir, "keys.json")
    c.close()
    open(kp, "w", encoding="utf-8").write("{ this is not json")
    try:
        c2, _ = new_box(kms_dir=c.settings.kms_dir, db_path=c.settings.sqlite_path)
    except Exception as e:                          # noqa: BLE001
        # 启动阶段就拒绝 = 更好（不会带病运行）
        return True, json.dumps({"blocked_at": "startup", "by": type(e).__name__})
    try:
        c2.vault.detokenize(tok, "KMS 损坏后尝试", adm())
        ok, detail = False, "静默解密成功（不可接受：可能用了新密钥）"
    except Exception as e:                          # noqa: BLE001
        ok, detail = True, {"blocked_by": type(e).__name__}
    c2.close()
    return ok, json.dumps({"detail": detail})


# ---------------- F5 备份恢复后链可验 ----------------
def f5(rng):
    """备份 → 备份后继续写 → 从备份恢复 → 链仍可验、且"恢复到哪一点"可说明。

    sqlite：文件级拷贝（最接近真实备份）。
    PG：逻辑备份到独立 schema（CREATE TABLE backup.x AS SELECT * FROM x），
        等价于"把某一时刻的行快照出来"，不需要 pg_dump 也能验证
        "恢复后的数据本身是自洽的"。这比 SKIP 诚实。
    """
    c, tmp = new_box()
    for i in range(6):
        c.audit.append("u", "admin", "candidate.read.masked", target=str(i))
    tip_before = c.audit.verify()
    is_pg = c.db.dialect == "pg"
    bak_schema = None
    bak = os.path.join(tmp, "backup.db")
    if is_pg:
        bak_schema = "bk_" + uuid.uuid4().hex[:10]
        cur = c.db.cursor_exec(f'CREATE SCHEMA IF NOT EXISTS "{bak_schema}"')
        for t in ("audit_log", "candidates", "vault_items", "deletion_log"):
            c.db.cursor_exec(f'CREATE TABLE "{bak_schema}".{t} AS SELECT * FROM {t}')
        c.close()
        c2, _ = new_box(schema=getattr(c.settings, "pg_schema", None))
        for i in range(6, 9):
            c2.audit.append("u", "admin", "candidate.read.masked", target=str(i))
        after = c2.audit.verify()
        c2.close()
        c3, _ = new_box(schema=bak_schema)
        restored = c3.audit.verify()
        c3.close()
    else:
        c.close()
        shutil.copy(tmp + "/f.db", bak)
        c2, _ = new_box(kms_dir=os.path.join(tmp, "kms"), db_path=tmp + "/f.db")
        for i in range(6, 9):
            c2.audit.append("u", "admin", "candidate.read.masked", target=str(i))
        after = c2.audit.verify()
        c2.close()
        c3, _ = new_box(kms_dir=os.path.join(tmp, "kms"), db_path=bak)
        restored = c3.audit.verify()
        c3.close()
    checks = {"backup_chain_ok": restored["ok"],
              "backup_rows": restored["rows"] == tip_before["rows"],
              "gap_detectable": after["rows"] > restored["rows"],
              "tip_matches_backup": restored["tip"] == tip_before["tip"],
              "mode": "pg_logical" if is_pg else "sqlite_file"}
    return all(v for k, v in checks.items() if k != "mode"), json.dumps(checks)


# ---------------- F6 删除证明 ----------------
def f6(rng):
    c, tmp = new_box()
    svc = CandidateService(c)
    now0 = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc).timestamp()
    # 关键：候选人要用 now0 创建，retention_until 才是 now0+90d，
    # 否则（用当前时间建、拿 now0+200d 去清）永远不到期 —— 这是测试写错
    a = svc.create(adm(), {"name": "甲", "phone": "13800138010", "city": "深圳",
                           "station_id": "S1"}, now=now0)
    b = svc.create(adm(), {"name": "乙", "phone": "13800138011", "city": "深圳",
                           "station_id": "S1", "status": "hired"}, now=now0)
    rep = c.retention.run(now=now0 + 200 * DAY)
    logs = c.retention.deletions()
    by_rule = {d["rule"] for d in logs}
    checks = {"has_deletion_records": len(logs) >= 2,
              "records_rule": bool(by_rule & {"not_hired_90d", "transcript_30d", "hired_180d"}),
              "records_mode": all(d["mode"] in ("delete", "anonymize") for d in logs),
              "records_ts": all(d["ts"] for d in logs),
              "evidence_exportable": self_export(c) is not None}
    c.close()
    return all(checks.values()), json.dumps({**checks, "rules": sorted(by_rule),
                                             "count": len(logs)})


def self_export(c):
    """删除证明可导出（给监管方看的清单）。"""
    rows = c.retention.deletions()
    return json.dumps({"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                       "records": rows}, ensure_ascii=False)


# ---------------- F7 删除记录自身被篡改 ----------------
def f7(rng):
    """deletion_log 是"我删过了"的证据，它自己被改却查不出来 = 证据链失效。

    当前实现没有对 deletion_log 做链式保护 → 这一轮如实暴露。
    """
    c, tmp = new_box()
    c.retention._log_deletion("candidate", "c1", "delete", "not_hired_90d")
    c.retention._log_deletion("candidate", "c2", "delete", "consent_revoked")
    before = c.retention.deletions()
    c.db.execute("UPDATE deletion_log SET rule='transcript_30d' WHERE entity_id='c1'")
    after = c.retention.deletions()
    detect = c.retention.deletions_verify() if hasattr(c.retention, "deletions_verify") else None
    c.close()
    ok = detect is not None and detect.get("ok") is False
    return ok, json.dumps({"mutation_detected": ok, "before_rows": len(before),
                           "after_rows": len(after)})


# ---------------- F8 审计导出可独立验证 ----------------
def f8(rng):
    c, tmp = new_box()
    for i in range(5):
        c.audit.append("u", "admin", "candidate.read.masked", target=str(i))
    bundle = c.audit.export_bundle() if hasattr(c.audit, "export_bundle") else None
    ok_shape = bool(bundle) and {"rows", "tip", "generated_at", "algorithm"} <= set(bundle)
    # 独立验证：只拿 bundle，不碰库
    from app.audit import verify_bundle
    res = verify_bundle(bundle) if bundle else {"ok": False}
    c.close()
    return bool(ok_shape and res.get("ok")), json.dumps({"shape_ok": ok_shape, "verify": res.get("ok"),
                                                         "rows": len((bundle or {}).get("rows", []))})


# ---------------- F9 导出不含明文 ----------------
def f9(rng):
    c, tmp = new_box()
    svc = CandidateService(c)
    mk(svc, phone="13800138020")
    c.audit.append("u", "admin", "candidate.read.masked", target="x")
    bundle = c.audit.export_bundle() if hasattr(c.audit, "export_bundle") else {}
    payload = json.dumps(bundle, ensure_ascii=False)
    delrec = self_export(c)
    checks = {"audit_no_phone": "13800138020" not in payload,
              "audit_no_name": "王小二" not in payload,
              "deletion_no_phone": "13800138020" not in delrec}
    c.close()
    return all(checks.values()), json.dumps(checks)


# ---------------- F10 监管查询 ----------------
def f10(rng):
    c, tmp = new_box()
    for i in range(200):
        c.audit.append(f"u{i%5}", "recruiter", "candidate.read.masked" if i % 2 else "vault.detokenize",
                       target=f"c{i}")
    t0 = time.time()
    by_actor = c.audit.by_actor("u1")
    dur1 = time.time() - t0
    t1 = time.time()
    by_action = c.db.query("SELECT * FROM audit_log WHERE action=? ORDER BY seq", ("vault.detokenize",))
    dur2 = time.time() - t1
    checks = {"by_actor_works": len(by_actor) == 40,
              "by_action_works": len(by_action) == 100,
              "fast": dur1 < 1.0 and dur2 < 1.0,
              "indexed_or_fast": dur1 < 0.5}
    c.close()
    return all(checks.values()), json.dumps({**checks, "by_actor_s": round(dur1, 3),
                                             "by_action_s": round(dur2, 3)})


# ---------------- F11 轮换可回滚 ----------------
def f11(rng):
    c, tmp = new_box()
    svc = CandidateService(c)
    mk(svc, phone="13800138030")
    v1 = c.kms.current_version()
    r1 = c.vault.rotate("adm", reencrypt=True)
    got_after = c.db.one("SELECT COUNT(*) AS c FROM vault_items")["c"]
    # 回滚到旧版本：当前版本指针退回
    rolled = c.vault.rollback_to(v1) if hasattr(c.vault, "rollback_to") else None
    ver_now = c.kms.current_version()
    checks = {"rotated": r1["to"] == v1 + 1,
              "rollback_supported": rolled is not None and ver_now == v1,
              "data_still_readable": got_after >= 2}
    cands = svc.list(adm())
    checks["candidates_readable_after_rollback"] = len(cands) == 1
    c.close()
    return all(checks.values()), json.dumps(checks)


# ---------------- F12 配置变更留痕 ----------------
def f12(rng):
    c, tmp = new_box()
    changed = c.config_update("adm", {"retain_not_hired_days": 30, "alert_view_threshold": 5}) \
        if hasattr(c, "config_update") else None
    rows = c.db.query("SELECT * FROM audit_log WHERE action='config.changed'") \
        if changed is not None else []
    checks = {"config_api_exists": changed is not None,
              "audited": len(rows) >= 1,
              "records_old_and_new": bool(rows) and "retain_not_hired_days" in rows[-1]["detail"]}
    c.close()
    return all(checks.values()), json.dumps(checks)


# ---------------- F13 健康自检不得假绿 ----------------
def f13(rng):
    c, tmp = new_box()
    cl = _client(c)
    h = cl.get("/health").json()
    deep = cl.get("/health/deep").json() if _has_path(cl, "/health/deep") else None
    checks = {"health_ok": h.get("status") == "ok",
              "deep_exists": deep is not None,
              "deep_reports_dependencies": bool(deep) and "checks" in deep,
              "deep_all_checks_pass": bool(deep) and deep.get("ok") is True}
    # 断掉 KMS 后，深度自检必须变红（不得假绿）
    if deep:
        kp = os.path.join(c.settings.kms_dir, "keys.json")
        moved = kp + ".bak-" + uuid.uuid4().hex[:6]
        if os.path.exists(kp):
            os.rename(kp, moved)
            try:
                deep2 = cl.get("/health/deep").json()
            finally:
                os.replace(moved, kp)     # 探测过程可能重建 keys.json，用 replace 覆盖
            checks["deep_turns_red_when_kms_broken"] = deep2.get("ok") is False
    c.close()
    return all(checks.values()), json.dumps(checks)


def _has_path(cl, path):
    try:
        return cl.get(path).status_code != 404
    except Exception:                               # noqa: BLE001
        return False


# ---------------- F14 日志卫生 ----------------
def f14(rng):
    c, tmp = new_box()
    svc = CandidateService(c)
    mk(svc, phone="13800138040")
    tok = c.vault.tokenize("手机号", "13800138041", "a", "admin")["token"]
    c.vault.detokenize(tok, "运维演练", adm())
    dump = json.dumps(c.db.query("SELECT * FROM audit_log"), ensure_ascii=False)
    checks = {"no_phone_in_audit": "1380013804" not in dump,
              "no_token_value_in_audit": not any(tok == r.get("detail", "") for r in
                                                c.db.query("SELECT detail FROM audit_log")),
              "no_kms_key_in_audit": "index_key" not in dump}
    # 日志文件（如果应用写文件）
    logdir = os.path.join(ROOT, "logs")
    if os.path.isdir(logdir):
        blob = ""
        for fn in os.listdir(logdir):
            p = os.path.join(logdir, fn)
            if os.path.isfile(p):
                blob += open(p, encoding="utf-8", errors="ignore").read()
        checks["no_phone_in_logs"] = "1380013804" not in blob
    else:
        checks["no_phone_in_logs"] = True
    c.close()
    return all(checks.values()), json.dumps(checks)


# ---------------- F15 灾难恢复三态 ----------------
def f15(rng):
    """无密钥 / 无库 / 无备份，三种情况下的行为必须明确且不误导。"""
    c, tmp = new_box()
    sch = getattr(c.settings, "pg_schema", None)
    tok = c.vault.tokenize("手机号", "13800138050", "a", "admin")["token"]
    tokref = None
    if c.db.dialect == "sqlite":
        tokref = c.settings.sqlite_path
    is_pg = c.db.dialect == "pg"
    c.close()
    results = {}
    # 1) 有库无钥：必须用**不同的 secret** 才算"密钥真的丢了"。
    #    同一个 KMS_SECRET + 空目录会派生出同一把密钥 —— 那叫恢复，不叫丢失。
    try:
        c1, _ = new_box(kms_dir=os.path.join(tmp, "nokey"),
                        db_path=tokref or os.path.join(tmp, "x.db"), schema=sch,
                        secret="".join(["totally", "-different-", "secret"]))
    except Exception as e:                          # noqa: BLE001
        results["no_key"] = "startup_blocked:" + type(e).__name__
        c1 = None
    if c1 is not None:
        try:
            c1.vault.detokenize(tok, "无钥演练", adm())
            results["no_key"] = "DECRYPTED_BAD"
        except Exception as e:                      # noqa: BLE001
            results["no_key"] = type(e).__name__
        c1.close()
    # 2) 有钥无库：应能启动但查询为空/报错，不得崩
    c2, _ = new_box(kms_dir=c.settings.kms_dir)
    try:
        n = c2.db.one("SELECT COUNT(*) AS c FROM candidates")["c"]
        results["no_db"] = f"started_rows={n}"
    except Exception as e:                          # noqa: BLE001
        results["no_db"] = type(e).__name__
    c2.close()
    # 3) 无备份 + 库损坏：必须报错而不是返回空结果（空结果会被误读成"没有数据"）
    if is_pg:
        # PostgreSQL 下没有"库文件损坏"这个概念（由 DB 自己保证），本项不适用
        results["corrupt"] = "SKIP_PG"
    else:
        bad = os.path.join(tmp, "corrupt.db")
        open(bad, "wb").write(b"not a sqlite file")
        try:
            bad_box, _ = new_box(kms_dir=c.settings.kms_dir, db_path=bad)
            results["corrupt"] = "STARTED_BAD"
            bad_box.close()
        except Exception as e:                      # noqa: BLE001
            results["corrupt"] = type(e).__name__
    # no_key 绝不能是 DECRYPTED_BAD（静默换钥）
    # no_db：新部署本来就是空的，允许启动但要能看出来是 0 行
    # corrupt：库文件损坏必须报错，不能当空库
    ok = (results["no_key"] != "DECRYPTED_BAD"
          and not results["no_db"].startswith("DECRYPTED")
          and results["corrupt"] != "STARTED_BAD"
          and results["no_key"] != "NotFound")   # NotFound 说明连库都没连对，不算"防住了"
    return ok, json.dumps(results)


def _client(box):
    from fastapi.testclient import TestClient
    from app.main import create_app
    return TestClient(create_app(box))


ROUNDS = [(1, "kms_dir_permissions", f1), (2, "key_data_separation", f2),
          (3, "both_stolen_boundary", f3), (4, "kms_corrupt_no_silent_newkey", f4),
          (5, "backup_restore_chain", f5), (6, "deletion_evidence", f6),
          (7, "deletion_log_tamper", f7), (8, "audit_export_verifiable", f8),
          (9, "export_no_plaintext", f9), (10, "regulator_query", f10),
          (11, "rotation_rollback", f11), (12, "config_change_audit", f12),
          (13, "health_not_fake_green", f13), (14, "log_hygiene", f14),
          (15, "disaster_recovery", f15)]



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
    seed = int(os.environ.get("LOOP_SEED", "20261108"))
    recs, skipped = [], []
    for idx, name, fn in ROUNDS:
        rng = random.Random(seed + idx)
        try:
            ok, detail = fn(rng)
        except Exception as e:                      # noqa: BLE001
            ok, detail = False, f"EXC {type(e).__name__}: {e}"
        if ok is None:
            skipped.append(name)
            mark = "SKIP"
        else:
            mark = "PASS" if ok else "FAIL"
        recs.append({"round": idx, "name": name, "ok": (None if ok is None else bool(ok)),
                     "detail": detail})
        print(f"[{mark}] F{idx:<2} {name:30} {detail}")
    passed = sum(1 for r in recs if r["ok"] is True)
    failed = sum(1 for r in recs if r["ok"] is False)
    os.makedirs(os.path.join(ROOT, "reports"), exist_ok=True)
    out = {"group": "F", "platform": platform.system(), "python": platform.python_version(),
           "seed": seed, "rounds": recs, "passed": passed, "failed": failed, "skipped": skipped}
    _safe_write_report(os.path.join(ROOT, "reports", f"loop_f_{platform.system().lower()}.json"), out)
    print(f"\nF 组结果: {passed} 通过 / {failed} 失败 / {len(skipped)} 跳过")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
