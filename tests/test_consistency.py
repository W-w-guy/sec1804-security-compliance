"""D 组（一致性与故障恢复）对应的持久化用例：把红队轮次里的关键结论固化成回归测试。"""
import json
import uuid

import pytest
from fastapi.testclient import TestClient

from app.auth import issue_staff_token
from app.errors import ApiError, Conflict
from app.main import create_app
from app.service import CandidateService
from tests.conftest import make_candidate


@pytest.fixture()
def client(c):
    return TestClient(create_app(c))


def _tok(c, actor="adm", role="admin", **kw):
    return issue_staff_token(c.settings, actor, role, kw.get("city"),
                             kw.get("stations") or [], bool(kw.get("all_cities", True)))


def _h(c, **kw):
    return {"Authorization": f"Bearer {_tok(c, **kw)}"}


# ---------- 补偿：不留孤儿 ----------
def test_vault_rollback_when_audit_fails(c, svc, admin, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("audit down")
    monkeypatch.setattr(c.audit, "append", boom)
    with pytest.raises(RuntimeError):
        svc.create(admin, {"name": "甲", "phone": "13800138001", "city": "深圳", "station_id": "S1"})
    monkeypatch.undo()
    assert c.db.one("SELECT COUNT(*) AS c FROM candidates")["c"] == 0
    assert c.db.one("SELECT COUNT(*) AS c FROM vault_items")["c"] == 0     # 关键：没有孤儿密文


def test_no_orphan_tokens_after_normal_create(c, svc, admin):
    make_candidate(svc, admin)
    for row in c.db.query("SELECT name_token, phone_token FROM candidates"):
        for t in (row["name_token"], row["phone_token"]):
            assert c.db.one("SELECT token FROM vault_items WHERE token=?", (t,))


# ---------- 幂等 ----------
def test_idempotency_key_replays_same_response(client, c):
    key = "k-" + uuid.uuid4().hex
    body = {"name": "乙", "phone": "13800138002", "city": "深圳", "station_id": "S1"}
    h = {**_h(c), "Idempotency-Key": key}
    r1 = client.post("/api/v1/candidates", headers=h, json=body)
    r2 = client.post("/api/v1/candidates", headers=h, json=body)
    assert r1.status_code == r2.status_code == 200
    assert r1.json()["id"] == r2.json()["id"]
    assert c.db.one("SELECT COUNT(*) AS c FROM candidates")["c"] == 1


def test_idempotency_same_key_different_body_conflicts(client, c):
    key = "k-" + uuid.uuid4().hex
    h = {**_h(c), "Idempotency-Key": key}
    client.post("/api/v1/candidates", headers=h,
                json={"name": "丙", "phone": "13800138003", "city": "深圳", "station_id": "S1"})
    r = client.post("/api/v1/candidates", headers=h,
                    json={"name": "丁", "phone": "13800138004", "city": "深圳", "station_id": "S1"})
    assert r.status_code == 409 and r.json()["code"] == "idempotency_conflict"


def test_idempotency_in_progress_blocks_concurrent_duplicate(c):
    fp = "same-fp"
    idem = c.idem
    idem.begin("dup", "adm", fp)
    with pytest.raises(Conflict) as ei:
        idem.begin("dup", "adm", fp)
    assert ei.value.code in ("idempotency_in_progress",)


# ---------- 分页 ----------
def test_list_pagination(client, c, svc, admin):
    for i in range(12):
        make_candidate(svc, admin, phone=f"13800138{i:03d}")
    r = client.get("/api/v1/candidates?limit=5&offset=0", headers=_h(c))
    assert r.status_code == 200 and len(r.json()["items"]) == 5
    r2 = client.get("/api/v1/candidates?limit=5&offset=5", headers=_h(c))
    assert len(r2.json()["items"]) == 5
    ids1 = {x["id"] for x in r.json()["items"]}
    ids2 = {x["id"] for x in r2.json()["items"]}
    assert not (ids1 & ids2)


def test_list_rejects_bad_limit(client, c):
    assert client.get("/api/v1/candidates?limit=0", headers=_h(c)).status_code == 422
    assert client.get("/api/v1/candidates?limit=10000", headers=_h(c)).status_code == 422
    assert client.get("/api/v1/candidates?offset=-1", headers=_h(c)).status_code == 422


# ---------- outbox ----------
def test_outbox_emit_and_hmac(client, c):
    from app.outbox import verify
    r = client.post("/api/v1/outbox", headers=_h(c),
                    json={"topic": "candidate.created", "payload": {"candidate_id": "x"}})
    assert r.status_code == 200 and r.json()["signature"]
    items = client.get("/api/v1/outbox", headers=_h(c)).json()["items"]
    env = json.loads(items[0]["payload"])
    assert verify(env, items[0]["signature"], c.settings.webhook_secret)
    # 篡改后签名必须验不过
    env["payload"]["candidate_id"] = "y"
    assert not verify(env, items[0]["signature"], c.settings.webhook_secret)


def test_outbox_rejects_unknown_topic(client, c):
    r = client.post("/api/v1/outbox", headers=_h(c), json={"topic": "made.up", "payload": {}})
    assert r.status_code >= 400


def test_consent_emits_outbox_event(c, svc, admin):
    cand = make_candidate(svc, admin)
    c.consent.record(cand["id"], "v1", "qr")
    rows = c.db.query("SELECT topic FROM outbox ORDER BY id")
    assert any(r["topic"] == "consent.recorded" for r in rows)


def test_outbox_ack_is_single_shot(client, c):
    client.post("/api/v1/outbox", headers=_h(c),
                json={"topic": "candidate.updated", "payload": {"id": "a"}})
    oid = client.get("/api/v1/outbox", headers=_h(c)).json()["items"][0]["id"]
    assert client.post(f"/api/v1/outbox/{oid}/ack", headers=_h(c)).json()["acked"] is True
    assert client.post(f"/api/v1/outbox/{oid}/ack", headers=_h(c)).json()["acked"] is False


# ---------- 审批原子性 ----------
def test_approval_single_use(c, svc, admin):
    cand = make_candidate(svc, admin)
    ap = c.approvals.request(admin.actor, "candidate.read.full", cand["id"], "核对工单")
    c.approvals.decide(ap["id"], "boss", ok=True)
    svc.view(admin, cand["id"], full=True, approval_id=ap["id"], reason="核对工单")
    with pytest.raises(ApiError) as ei:
        svc.view(admin, cand["id"], full=True, approval_id=ap["id"], reason="核对工单")
    assert ei.value.code in ("approval_already_used", "approval_not_granted")


# ---------- 时钟回拨 ----------
def test_clock_backwards_does_not_delete(c, svc, admin):
    import datetime as dt
    now0 = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc).timestamp()
    cand = make_candidate(svc, admin)
    rep = c.retention.run(now=now0 - 86400)
    assert rep["expired_deleted"] == 0
    assert c.db.one("SELECT id FROM candidates WHERE id=?", (cand["id"],))
