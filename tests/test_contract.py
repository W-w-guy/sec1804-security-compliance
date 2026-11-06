"""契约 v1 一致性自检：字段命名、前缀、错误体、掩码格式、事件/接口清单。"""
import json

from fastapi.testclient import TestClient

from app.main import create_app

REQUIRED_PATHS = [
    "/api/v1/vault/tokenize", "/api/v1/vault/detokenize",
    "/api/v1/mask", "/api/v1/candidates", "/api/v1/audit/verify",
    "/api/v1/retention/run", "/api/v1/consent", "/api/v1/rights-requests",
]


def test_all_contract_paths_have_v1_prefix(c):
    spec = TestClient(create_app(c)).get("/openapi.json").json()
    allowed = {"/health", "/health/deep"}      # 运维探针不在 /api/v1 下
    for p in spec["paths"]:
        assert p in allowed or p.startswith("/api/v1/"), p


def test_required_paths_present(c):
    spec = TestClient(create_app(c)).get("/openapi.json").json()
    for p in REQUIRED_PATHS:
        assert p in spec["paths"], p


def test_candidate_fields_match_contract(c, svc, admin):
    cand = __import__("tests.conftest", fromlist=["x"]).make_candidate(svc, admin)
    for f in ("id", "name", "phone", "birth_ym", "area_text", "job_type", "has_ebike",
              "health_cert", "source_channel", "station_id", "status", "consent_version",
              "consent_at", "created_at", "retention_until", "is_minor", "city"):
        assert f in cand, f
    assert cand["status"] in ("new", "collecting", "complete", "booked", "interviewed",
                              "hired", "rejected", "handoff")


def test_mask_format_matches_contract(c):
    tok = c.vault.tokenize("手机号", "13800138000", "t", "admin")["token"]
    assert c.vault.masked_of(tok)["masked"] == "138****8000"
    tok2 = c.vault.tokenize("姓名", "王小二", "t", "admin")["token"]
    assert c.vault.masked_of(tok2)["masked"] == "王**"


def test_error_body_is_code_message(c, svc, admin):
    import pytest
    from app.errors import ApiError
    with pytest.raises(ApiError) as ei:
        svc.view(admin, "not-exist")
    assert list(ei.value.body()) == ["code", "message"]


def test_openapi_is_generated_without_error(c):
    spec = TestClient(create_app(c)).get("/openapi.json")
    assert spec.status_code == 200
    data = spec.json()
    # 版本号的唯一来源是 app/__init__.py 的 __version__，测试里不许再抄一遍字面量
    # （抄了就会出现「改版本要改两处」，H11 正是在查这个）
    from app import __version__ as _v
    assert data["info"]["version"] == _v
    assert len(data["paths"]) >= 20
