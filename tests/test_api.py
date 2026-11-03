"""接口层验收：契约 v1 前缀、错误体 {code,message}、鉴权、主要流程端到端。"""
import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture()
def client(c):
    return TestClient(create_app(c))


def _tok(client, **kw):
    body = {"actor": "adm", "role": "admin", "all_cities": True}
    body.update(kw)
    return client.post("/api/v1/auth/token", json=body).json()["token"]


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_openapi_documents_all_paths(client):
    spec = client.get("/openapi.json").json()
    paths = spec["paths"]
    for p in ("/api/v1/vault/tokenize", "/api/v1/vault/detokenize", "/api/v1/mask",
              "/api/v1/candidates", "/api/v1/audit/verify", "/api/v1/retention/run",
              "/api/v1/consent", "/api/v1/rights-requests"):
        assert p in paths, p


def test_missing_token_error_body_shape(client):
    r = client.post("/api/v1/vault/tokenize", json={"type": "手机号", "value": "13800138000"})
    assert r.status_code == 401
    assert set(r.json()) == {"code", "message"}


def test_tokenize_then_detokenize(client):
    t = _tok(client)
    tok = client.post("/api/v1/vault/tokenize",
                      json={"type": "手机号", "value": "13800138000"}, headers=_h(t)).json()["token"]
    got = client.post("/api/v1/vault/detokenize",
                      json={"token": tok, "reason": "客服回访"}, headers=_h(t)).json()
    assert got["value"] == "13800138000"


def test_detokenize_forbidden_body(client):
    t_admin = _tok(client)
    tok = client.post("/api/v1/vault/tokenize",
                      json={"type": "手机号", "value": "13800138000"}, headers=_h(t_admin)).json()["token"]
    t_rec = _tok(client, actor="r1", role="recruiter", all_cities=False, city="深圳")
    r = client.post("/api/v1/vault/detokenize",
                    json={"token": tok, "reason": "想看"}, headers=_h(t_rec))
    assert r.status_code == 403 and r.json()["code"] == "missing_permission"


def test_candidate_create_and_read(client):
    t = _tok(client)
    cand = client.post("/api/v1/candidates", headers=_h(t),
                       json={"name": "王小二", "phone": "13800138000",
                             "city": "深圳", "station_id": "S1"}).json()
    got = client.get(f"/api/v1/candidates/{cand['id']}", headers=_h(t)).json()
    assert got["phone"] == "138****8000" and got["name"] == "王**"


def test_mask_endpoint(client):
    r = client.post("/api/v1/mask", json={"text": "我叫王小二，手机13800138000"}).json()
    assert "〔姓名_1〕" in r["masked"] and "13800138000" not in r["masked"]


def test_audit_verify_endpoint(client):
    t = _tok(client)
    client.post("/api/v1/candidates", headers=_h(t),
                json={"name": "王小二", "phone": "13800138000", "city": "深圳", "station_id": "S1"})
    res = client.get("/api/v1/audit/verify", headers=_h(t)).json()
    assert res["ok"] is True and res["rows"] > 0


def test_full_view_requires_approval_via_api(client):
    t = _tok(client)
    cand = client.post("/api/v1/candidates", headers=_h(t),
                       json={"name": "王小二", "phone": "13800138000",
                             "city": "深圳", "station_id": "S1"}).json()
    r = client.get(f"/api/v1/candidates/{cand['id']}?full=true", headers=_h(t))
    assert r.status_code == 403 and r.json()["code"] == "approval_required"
    ap = client.post("/api/v1/approvals", headers=_h(t),
                     json={"action": "candidate.read.full", "target": cand["id"],
                           "reason": "核对工单"}).json()
    client.post(f"/api/v1/approvals/{ap['id']}/decide", headers=_h(t), json={"ok": True})
    ok = client.get(f"/api/v1/candidates/{cand['id']}?full=true&approval_id={ap['id']}",
                    headers=_h(t)).json()
    assert ok["phone"] == "13800138000"


def test_consent_and_revoke_via_api(client):
    t = _tok(client)
    cand = client.post("/api/v1/candidates", headers=_h(t),
                       json={"name": "王小二", "phone": "13800138000",
                             "city": "深圳", "station_id": "S1"}).json()
    assert client.post("/api/v1/consent", json={"candidate_id": cand["id"], "version": "v1",
                                               "channel": "qr"}).status_code == 200
    assert client.post(f"/api/v1/consent/{cand['id']}/revoke").json()["deleted"] is True
    assert client.get(f"/api/v1/candidates/{cand['id']}", headers=_h(t)).status_code == 404


def test_error_body_on_unknown_token(client):
    t = _tok(client)
    r = client.post("/api/v1/vault/detokenize", json={"token": "vt_nope", "reason": "查找用户记录"},
                    headers=_h(t))
    assert r.status_code == 404 and set(r.json()) == {"code", "message"}
