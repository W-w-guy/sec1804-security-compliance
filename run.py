"""一键演示：不需要数据库、不需要外部服务，直接跑通六条验收链路并打印期望输出。

用法：
    python run.py demo            # 全流程演示（默认 sqlite + 本地文件 KMS）
    python run.py demo --json     # 机器可读输出
"""
from __future__ import annotations
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.config import Settings
from app.container import Container
from app.errors import Forbidden
from app.masking import mask_text
from app.rbac import Principal
from app.service import CandidateService


def demo(tmpdir: str | None = None) -> dict:
    tmp = tmpdir or tempfile.mkdtemp(prefix="sec1804-demo-")
    st = Settings()
    st.kms_secret = "demo"
    c = Container(st, db_path=os.path.join(tmp, "demo.db"), kms_dir=os.path.join(tmp, "kms"))
    svc = CandidateService(c)
    admin = Principal("adm", "admin", city="深圳", all_cities=True)
    recruiter = Principal("rec1", "recruiter", city="深圳", stations={"S1"})
    out: dict = {"workdir": tmp}

    # 1) tokenize / detokenize + 直查库看不到明文
    tok = c.vault.tokenize("手机号", "13800138000", "adm", "admin")["token"]
    row = c.db.one("SELECT * FROM vault_items WHERE token=?", (tok,))
    out["1_plaintext_leaked_in_db"] = "13800138000" in json.dumps(row, ensure_ascii=False)
    out["1_token"] = tok
    out["1_masked"] = c.vault.masked_of(tok)["masked"]
    out["1_detokenized"] = c.vault.detokenize(tok, "客服回访核验", admin)["value"]

    # 2) 脱敏召回
    r = mask_text("我叫王小二，手机138 0013 8000，住深圳市南山区科技园路1号2栋301室")
    out["2_masked_text"] = r["masked"]
    out["2_types"] = sorted(r["found"])

    # 3) 无权限 / 无理由 detokenize 被拒并写审计
    denied = {}
    for who, reason in ((recruiter, "查看客户资料"), (admin, "")):
        try:
            c.vault.detokenize(tok, reason, who)
        except Forbidden as e:
            denied[who.role if reason else "admin_no_reason"] = e.code
    out["3_denied_codes"] = denied
    out["3_denied_audit_rows"] = len(c.db.query(
        "SELECT * FROM audit_log WHERE action='vault.detokenize.denied'"))

    # 4) 篡改审计任意一行后能定位
    cand = svc.create(admin, {"name": "王小二", "phone": "13800138000",
                              "city": "深圳", "station_id": "S1"})
    c.audit.append("x", "admin", "candidate.read.masked", target=cand["id"])
    c.db.execute("UPDATE audit_log SET actor='attacker' WHERE seq=3")
    out["4_audit_verify"] = c.audit.verify()
    out["4_locate_seq3"] = c.audit.locate(3)["fields"]

    # 5) 时间快进清理 + 撤回同意立即删除
    import datetime as dt
    c.db.insert("transcripts", {"id": "t1", "candidate_id": cand["id"], "body": "原文",
                                "is_minor": 0, "created_at": "2026-01-01T00:00:00Z",
                                "deleted_at": None})
    now = dt.datetime(2026, 3, 5, tzinfo=dt.timezone.utc).timestamp()
    out["5_retention_report"] = c.retention.run(now=now)
    out["5_deletion_log"] = [d["rule"] for d in c.retention.deletions()]
    cand3 = svc.create(admin, {"name": "韩梅梅", "phone": "13700137000",
                               "city": "深圳", "station_id": "S1"})
    c.consent.record(cand3["id"], "v1", "qr")
    out["5_revoke_deleted"] = c.consent.revoke(cand3["id"])["deleted"]

    # 6) 越权被拒
    cand2 = svc.create(admin, {"name": "李雷", "phone": "13900139000",
                               "city": "深圳", "station_id": "S1"})
    outsider = Principal("rec2", "recruiter", city="杭州", stations={"S9"})
    try:
        svc.view(outsider, cand2["id"])
        out["6_out_of_scope"] = "NOT_BLOCKED"
    except Forbidden as e:
        out["6_out_of_scope"] = e.code
    c.close()
    return out


if __name__ == "__main__":
    res = demo()
    if "--json" in sys.argv:
        print(json.dumps(res, ensure_ascii=False, indent=1))
    else:
        for k, v in res.items():
            print(f"{k:26} {v}")
