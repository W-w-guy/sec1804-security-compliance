"""AC4：篡改审计日志任意一行后，校验脚本能指出被篡改的位置。"""
import json

from app.audit import Audit


def _seed(c, n=8):
    for i in range(n):
        c.audit.append(f"u{i%2}", "recruiter", "candidate.read.masked", target=f"c{i}", city="深圳")
    return c.audit.verify()


def test_chain_ok_initially(c):
    res = _seed(c)
    assert res["ok"] and res["rows"] == 8 and res["tampered_seq"] == []


def test_tamper_any_row_is_located(c):
    _seed(c, 10)
    for target in (1, 4, 9):
        c.db.execute("UPDATE audit_log SET actor='attacker' WHERE seq=?", (target,))
        res = c.audit.verify()
        assert not res["ok"]
        assert target in res["tampered_seq"], (target, res)
        loc = c.audit.locate(target)
        assert loc["tampered"] and loc["fields"]


def test_tamper_hash_only_is_detected(c):
    _seed(c, 5)
    c.db.execute("UPDATE audit_log SET hash=? WHERE seq=3", ("0" * 64,))
    assert 3 in c.audit.verify()["tampered_seq"]


def test_delete_row_leaves_gap(c):
    _seed(c, 6)
    c.db.execute("DELETE FROM audit_log WHERE seq=4")
    res = c.audit.verify()
    assert not res["ok"] and res["missing_seq"]


def test_append_only_no_update_api(c):
    _seed(c, 3)
    a = c.audit
    assert not hasattr(a, "update")
    assert not hasattr(a, "delete")


def test_bulk_view_triggers_alert(c):
    c.settings.alert_view_threshold = 5
    for i in range(6):
        c.audit.append("rec9", "recruiter", "candidate.read.full", target=f"c{i}")
    alerts = c.audit.alerts()
    assert alerts and alerts[0]["kind"] == "candidate.read.full"
    # 告警本身也入链
    assert any(r["action"] == "alert.raised" for r in c.db.query("SELECT action FROM audit_log"))


def test_export_threshold_alert(c):
    c.settings.alert_export_threshold = 2
    for i in range(3):
        c.audit.append("ops1", "ops", "candidate.export.masked", target="*")
    assert c.audit.alerts()
