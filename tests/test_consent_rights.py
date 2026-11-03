"""同意版本/时间/渠道留痕；查看/更正/删除/副本请求带时限跟踪。"""
import pytest

from app.errors import Forbidden, NotFound
from tests.conftest import make_candidate


def test_consent_records_version_time_channel(c, svc, admin):
    cand = make_candidate(svc, admin)
    c.consent.record(cand["id"], "v2.1", "qr_code")
    row = c.consent.current(cand["id"])
    assert row["version"] == "v2.1" and row["channel"] == "qr_code" and row["at"]
    got = svc.view(admin, cand["id"])
    assert got["consent_version"] == "v2.1"


def test_consent_requires_version_and_channel(c, svc, admin):
    cand = make_candidate(svc, admin)
    with pytest.raises(Forbidden):
        c.consent.record(cand["id"], "", "qr")


@pytest.mark.parametrize("kind", ["view", "correct", "delete", "copy"])
def test_rights_request_kinds(kind, c, svc, admin):
    cand = make_candidate(svc, admin)
    r = c.consent.open_request(cand["id"], kind)
    assert r["status"] == "open" and r["due_at"] > r["created_at"]


def test_unknown_rights_kind_rejected(c):
    with pytest.raises(Forbidden):
        c.consent.open_request("x", "sell")


def test_rights_overdue_tracking(c, svc, admin):
    cand = make_candidate(svc, admin)
    r = c.consent.open_request(cand["id"], "copy", now=1000.0)
    assert c.consent.overdue(now=1000.0 + 1) == []
    overdue = c.consent.overdue(now=1000.0 + c.settings.rights_sla_hours * 3600 + 1)
    assert overdue and overdue[0]["id"] == r["id"]


def test_rights_close_writes_audit(c, svc, admin):
    cand = make_candidate(svc, admin)
    r = c.consent.open_request(cand["id"], "delete")
    c.consent.close_request(r["id"], "已完成删除", actor="adm")
    assert c.consent.requests()[0]["status"] == "done"
    assert any(x["action"] == "rights.close" for x in c.db.query("SELECT action FROM audit_log"))


def test_revoke_without_consent_raises(c):
    with pytest.raises(NotFound):
        c.consent.revoke("no-such-candidate")
