"""FastAPI 应用：任务 5/5 数据安全与合规模块（契约 v1，前缀 /api/v1）。

create_app(container) 便于测试注入独立容器；模块级 app 为默认实例。
错误体统一 {code, message}；每个接口都出现在 /openapi.json 里。
"""
from __future__ import annotations

from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.auth import SessionStore, issue_staff_token, principal_from_claims, verify_jwt
from app.config import settings as default_settings
from app.container import Container
from app.errors import ApiError, Unauthorized
from app.masking import MaskingSession, mask_text
from app.rbac import Principal, require
from app.service import CandidateService

VERSION = "0.1.0"
SESSIONS = SessionStore()


# ---------------- 请求模型 ----------------
class TokenIn(BaseModel):
    actor: str = "demo"
    role: str = "admin"
    city: str | None = None
    stations: list[str] = Field(default_factory=list)
    all_cities: bool = False


class TokenizeIn(BaseModel):
    type: str = Field(description="姓名 / 手机号 / 身份证号 / 银行卡号 / 地址")
    value: str


class DetokenizeIn(BaseModel):
    token: str
    reason: str = ""


class MaskIn(BaseModel):
    text: str
    strict_names: bool = True


class UnmaskIn(BaseModel):
    text: str
    mapping: dict[str, str] = Field(default_factory=dict)


class CandidateIn(BaseModel):
    name: str
    phone: str
    city: str | None = None
    station_id: str | None = None
    area_text: str | None = None
    job_type: str | None = "fulltime"
    has_ebike: bool | None = None
    start_text: str | None = None
    experience_text: str | None = None
    health_cert: str | None = "unknown"
    source_channel: str | None = "qr"
    status: str = "new"
    birth_ym: str | None = None
    is_minor: bool = False


class ApprovalIn(BaseModel):
    action: str
    target: str
    reason: str


class DecideIn(BaseModel):
    ok: bool = True


class ExportIn(BaseModel):
    ids: list[str] | None = None
    full: bool = False
    approval_id: str | None = None
    reason: str = ""


class ConsentIn(BaseModel):
    candidate_id: str
    version: str
    channel: str


class RightsIn(BaseModel):
    candidate_id: str
    kind: str
    note: str = ""


def error_handler(_: Request, exc: ApiError) -> JSONResponse:
    return JSONResponse(status_code=exc.status, content=exc.body())


def _register(api: FastAPI, box: Container) -> None:
    api.add_exception_handler(ApiError, error_handler)
    svc = CandidateService(box)

    def principal(authorization: str = Header(default="")) -> Principal:
        if not authorization.startswith("Bearer "):
            raise Unauthorized("缺少 Bearer token")
        return principal_from_claims(verify_jwt(authorization[7:], box.settings.jwt_secret))

    # ---------------- 健康与鉴权 ----------------
    @api.get("/health", tags=["ops"])
    def health():
        return {"status": "ok", "module": "task-5-security-compliance", "version": VERSION}

    @api.post("/api/v1/auth/token", tags=["auth"])
    def auth_token(body: TokenIn):
        """演示/测试签发入口；生产由员工中心用同一 claims 结构签发。"""
        return {"token": issue_staff_token(box.settings, body.actor, body.role, body.city,
                                           body.stations, body.all_cities),
                "token_type": "Bearer"}

    # ---------------- 保险箱 ----------------
    @api.post("/api/v1/vault/tokenize", tags=["vault"])
    def tokenize(body: TokenizeIn, p: Principal = Depends(principal)):
        return box.vault.tokenize(body.type, body.value, p.actor, p.role)

    @api.post("/api/v1/vault/detokenize", tags=["vault"])
    def detokenize(body: DetokenizeIn, p: Principal = Depends(principal)):
        return box.vault.detokenize(body.token, body.reason, p)

    @api.get("/api/v1/vault/stats", tags=["vault"])
    def vault_stats(p: Principal = Depends(principal)):
        require(p, "audit.read")
        return box.vault.stats()

    @api.post("/api/v1/kms/rotate", tags=["vault"])
    def kms_rotate(reencrypt: bool = False, p: Principal = Depends(principal)):
        require(p, "kms.rotate")
        return box.vault.rotate(p.actor, reencrypt=reencrypt)

    # ---------------- 脱敏 ----------------
    @api.post("/api/v1/mask", tags=["masking"])
    def mask(body: MaskIn):
        return mask_text(body.text, strict_names=body.strict_names)

    @api.post("/api/v1/unmask", tags=["masking"])
    def unmask(body: UnmaskIn, p: Principal = Depends(principal)):
        require(p, "mask.restore")
        sess = MaskingSession()
        sess.mapping = body.mapping
        box.audit.append(p.actor, p.role, "mask.restore", target="text",
                         detail={"placeholders": len(body.mapping)})
        return {"text": sess.restore(body.text)}

    # ---------------- 候选人 ----------------
    @api.post("/api/v1/candidates", tags=["candidates"])
    def create_candidate(body: CandidateIn, p: Principal = Depends(principal)):
        return svc.create(p, body.model_dump())

    @api.get("/api/v1/candidates", tags=["candidates"])
    def list_candidates(p: Principal = Depends(principal)):
        items = svc.list(p)
        return {"items": items, "count": len(items)}

    @api.get("/api/v1/candidates/{cid}", tags=["candidates"])
    def get_candidate(cid: str, full: bool = False, approval_id: str | None = None,
                      reason: str = "", p: Principal = Depends(principal)):
        return svc.view(p, cid, full=full, approval_id=approval_id, reason=reason)

    @api.post("/api/v1/candidates/export", tags=["candidates"])
    def export_candidates(body: ExportIn, p: Principal = Depends(principal)):
        return svc.export(p, body.ids, body.full, body.approval_id, body.reason)

    # ---------------- 审批 ----------------
    @api.post("/api/v1/approvals", tags=["approvals"])
    def create_approval(body: ApprovalIn, p: Principal = Depends(principal)):
        return box.approvals.request(p.actor, body.action, body.target, body.reason)

    @api.post("/api/v1/approvals/{aid}/decide", tags=["approvals"])
    def decide_approval(aid: str, body: DecideIn, p: Principal = Depends(principal)):
        require(p, "approval.decide")
        return box.approvals.decide(aid, p.actor, body.ok)

    # ---------------- 审计 ----------------
    @api.get("/api/v1/audit", tags=["audit"])
    def audit_tail(n: int = 20, p: Principal = Depends(principal)):
        require(p, "audit.read")
        return {"items": box.audit.tail(n)}

    @api.get("/api/v1/audit/verify", tags=["audit"])
    def audit_verify(p: Principal = Depends(principal)):
        require(p, "audit.read")
        return box.audit.verify()

    @api.get("/api/v1/audit/verify/{seq}", tags=["audit"])
    def audit_locate(seq: int, p: Principal = Depends(principal)):
        require(p, "audit.read")
        return box.audit.locate(seq)

    @api.get("/api/v1/audit/alerts", tags=["audit"])
    def audit_alerts(p: Principal = Depends(principal)):
        require(p, "audit.read")
        return {"items": box.audit.alerts()}

    # ---------------- 保留与删除 ----------------
    @api.post("/api/v1/retention/run", tags=["retention"])
    def retention_run(p: Principal = Depends(principal)):
        require(p, "retention.run")
        return box.retention.run()

    @api.get("/api/v1/retention/deletions", tags=["retention"])
    def retention_deletions(p: Principal = Depends(principal)):
        require(p, "audit.read")
        return {"items": box.retention.deletions()}

    # ---------------- 同意与权利请求 ----------------
    @api.post("/api/v1/consent", tags=["consent"])
    def record_consent(body: ConsentIn):
        return box.consent.record(body.candidate_id, body.version, body.channel)

    @api.post("/api/v1/consent/{cid}/revoke", tags=["consent"])
    def revoke_consent(cid: str):
        return box.consent.revoke(cid)

    @api.post("/api/v1/rights-requests", tags=["rights"])
    def open_rights(body: RightsIn):
        return box.consent.open_request(body.candidate_id, body.kind, body.note)

    @api.post("/api/v1/rights-requests/{rid}/close", tags=["rights"])
    def close_rights(rid: str, note: str = "", p: Principal = Depends(principal)):
        require(p, "rights.close")
        return box.consent.close_request(rid, note, actor=p.actor)

    @api.get("/api/v1/rights-requests", tags=["rights"])
    def list_rights(p: Principal = Depends(principal)):
        require(p, "rights.track")
        return {"items": box.consent.requests(), "overdue": box.consent.overdue()}


def create_app(container: Container | None = None) -> FastAPI:
    box = container or Container(default_settings)
    api = FastAPI(title="骑手招聘 Agent 化信息收集平台 · 任务 5/5 数据安全与合规",
                  version=VERSION,
                  description="个人信息保险箱 / 脱敏工具库 / RBAC 与数据范围 / 审计哈希链 / 保留与删除 / 同意与权利请求")
    _register(api, box)
    api.state.box = box
    return api


app = create_app()
