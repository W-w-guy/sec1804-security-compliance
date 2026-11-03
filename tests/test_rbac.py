"""AC6：越权访问其他城市 / 站点的数据被拒，每个角色都有用例。"""
import pytest

from app.errors import Forbidden
from app.rbac import Principal, ROLES, enforce_scope, in_scope, require
from tests.conftest import make_candidate


@pytest.mark.parametrize("role", ROLES)
def test_every_role_out_of_city_denied(role, svc, admin):
    cand = make_candidate(svc, admin, city="深圳", station_id="S1")
    p = Principal(actor=f"{role}-u", role=role, city="杭州", stations={"S9"})
    with pytest.raises(Forbidden) as ei:
        svc.view(p, cand["id"])
    assert ei.value.code == "out_of_scope"


@pytest.mark.parametrize("role", ROLES)
def test_every_role_out_of_station_denied(role, c, svc, admin):
    cand = make_candidate(svc, admin, city="深圳", station_id="S2")
    p = Principal(actor=f"{role}-u", role=role, city="深圳", stations={"S1"})
    if role in ("admin",):
        return
    with pytest.raises(Forbidden):
        svc.view(p, cand["id"])


@pytest.mark.parametrize("role,perm", [
    ("recruiter", "candidate.read.full"),
    ("station_manager", "audit.read"),
    ("ops", "candidate.read.full"),
    ("auditor", "vault.detokenize"),
])
def test_role_missing_permission(role, perm):
    with pytest.raises(Forbidden) as ei:
        require(Principal(actor="x", role=role), perm)
    assert ei.value.code == "missing_permission"


def test_recruiter_can_read_masked(svc, recruiter):
    cand = make_candidate(svc, recruiter)
    got = svc.view(recruiter, cand["id"])
    assert got["phone"] == "138****8000" and got["name"] == "王**"


def test_full_view_requires_approval(svc, admin, recruiter):
    cand = make_candidate(svc, admin)
    with pytest.raises(Forbidden) as ei:
        svc.view(admin, cand["id"], full=True, reason="核对工单")
    assert ei.value.code == "approval_required"


def test_full_view_with_approved_approval(svc, c, admin):
    cand = make_candidate(svc, admin)
    ap = c.approvals.request(admin.actor, "candidate.read.full", cand["id"], "核对工单")
    c.approvals.decide(ap["id"], "boss", ok=True)
    got = svc.view(admin, cand["id"], full=True, approval_id=ap["id"], reason="核对工单")
    assert got["phone"] == "13800138000"


def test_approval_is_single_use(svc, c, admin):
    cand = make_candidate(svc, admin)
    ap = c.approvals.request(admin.actor, "candidate.read.full", cand["id"], "核对工单")
    c.approvals.decide(ap["id"], "boss", ok=True)
    svc.view(admin, cand["id"], full=True, approval_id=ap["id"], reason="核对工单")
    with pytest.raises(Forbidden):
        svc.view(admin, cand["id"], full=True, approval_id=ap["id"], reason="再核一次")


def test_approval_expires(c, admin):
    ap = c.approvals.request(admin.actor, "candidate.read.full", "x", "核对工单", now=1000.0)
    c.approvals.decide(ap["id"], "boss", ok=True, now=1000.0 + 1)
    with pytest.raises(Forbidden) as ei:
        c.approvals.consume(ap["id"], admin.actor, "candidate.read.full", "x", now=1000.0 + 10_000)
    assert ei.value.code == "approval_expired"


def test_scope_helper_semantics():
    p = Principal(actor="a", role="ops", city="深圳", stations={"S1"})
    assert in_scope(p, "深圳", "S1")
    assert not in_scope(p, "杭州", "S1")
    assert not in_scope(p, "深圳", "S2")
    wild = Principal(actor="b", role="admin", all_cities=True)
    assert in_scope(wild, "任何城市", "任意站")
