"""PostgreSQL 直连冒烟：设置 PG_DSN 后有库就能跑，验证 PG 方言（%s 占位符、BIGSERIAL、JSON 文本）。

用法：PG_DSN=postgresql://user:pass@host:5432/db python tools/pg_smoke.py
"""
from __future__ import annotations
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import Settings
from app.container import Container
from app.masking import mask_text
from app.rbac import Principal
from app.service import CandidateService


def main() -> int:
    dsn = os.environ.get("PG_DSN", "")
    if not dsn:
        print("SKIP: 未提供 PG_DSN")
        return 2
    st = Settings(pg_dsn=dsn)
    c = Container(st, kms_dir=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".kms"))
    assert c.db.dialect == "pg", c.db.dialect
    svc = CandidateService(c)
    admin = Principal("adm", "admin", city="深圳", all_cities=True)
    checks = {}

    tok = c.vault.tokenize("手机号", "13800138000", "adm", "admin")["token"]
    row = c.db.one("SELECT * FROM vault_items WHERE token=?", (tok,))
    checks["plaintext_not_in_pg"] = "13800138000" not in str(row)
    checks["detokenize"] = c.vault.detokenize(tok, "PG 冒烟核验", admin)["value"] == "13800138000"

    cand = svc.create(admin, {"name": "王小二", "phone": "13900139000",
                              "city": "深圳", "station_id": "S1"})
    checks["candidate_create"] = cand["phone"] == "139****9000"

    c.audit.append("x", "admin", "candidate.read.masked", target=cand["id"])
    checks["audit_chain_ok"] = c.audit.verify()["ok"]
    seq = c.db.query("SELECT seq FROM audit_log ORDER BY seq DESC LIMIT 1")[0]["seq"]
    c.db.execute("UPDATE audit_log SET actor='attacker' WHERE seq=?", (seq,))
    checks["tamper_located"] = seq in c.audit.verify()["tampered_seq"]

    r = mask_text("我叫王小二，手机138 0013 8000")
    checks["masking"] = "〔手机号_1〕" in r["masked"]

    rep = c.retention.run()
    checks["retention_run"] = isinstance(rep, dict)

    for k, v in checks.items():
        print(f"[{'PASS' if v else 'FAIL'}] {k}")
    ok = all(checks.values())
    print("PG_RESULT:", "ALL PASS" if ok else "FAILED")
    c.close()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
