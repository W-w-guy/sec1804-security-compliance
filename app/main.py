"""FastAPI 应用：任务 5/5 数据安全与合规模块（契约 v1，前缀 /api/v1）。

create_app(container) 便于测试注入独立容器；模块级 app 为默认实例。
错误体统一 {code, message}；每个接口都出现在 /openapi.json 里。
"""
from __future__ import annotations

import base64
import json
import threading
import time

from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

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
    # 拒绝未知字段：客户端塞 role / actor / all_cities 这类字段应当 422，
    # 而不是被静默忽略（静默忽略会让攻击者以为生效、也让审计看不清意图）
    model_config = ConfigDict(extra="forbid")

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


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "X-Permitted-Cross-Domain-Policies": "none",
}


class RateLimiter:
    """同 actor + 同动作的滑动窗口限流（进程内）。

    为什么需要：C12 轮 60 次失败 detokenize 只用 0.15 秒、全被接受，
    等于给暴力破解开了无限次通道。保险箱是 PII 最集中的地方，必须限速。
    诚实边界：进程内计数，多副本部署时每副本各算一份；要全局精确须换 Redis 计数
    （Redis 已在 compose 里，但本模块不引第三方客户端，故保持零依赖，
     并在 README『已知边界』写明）。
    """

    def __init__(self, window: int, limit: int):
        self.window = max(1, window)
        self.limit = max(0, limit)
        self._hits: dict[tuple[str, str], list[float]] = {}
        self._lock = threading.Lock()

    def check(self, actor: str, action: str, now: float | None = None) -> bool:
        if self.limit == 0:
            return True
        now = time.time() if now is None else now
        key = (actor, action)
        with self._lock:
            hist = [t for t in self._hits.get(key, []) if now - t < self.window]
            if len(hist) >= self.limit:
                self._hits[key] = hist
                return False
            hist.append(now)
            self._hits[key] = hist
            return True


def sanitize_json(obj, depth: int = 0):
    """把 NaN / Infinity 这类非有限浮点替换成字符串，保证响应体一定是合法 JSON。

    C10 轮实测：请求体里写 {"text": NaN} 时，FastAPI 的 422 响应会把原始输入
    （nan）原样回显，序列化直接抛 ValueError → 客户端拿不到响应体。
    这是"恶意输入让服务吐非法 JSON"，属于信息暴露面，必须兜住。
    """
    if isinstance(obj, float):
        if obj != obj or obj in (float("inf"), float("-inf")):
            return str(obj)
        return obj
    if depth >= 20:                      # 深嵌套直接截断，别为了回显错误把自己递归爆栈
        return "…(too deep)"
    if isinstance(obj, dict):
        return {str(k): sanitize_json(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [sanitize_json(v, depth + 1) for v in obj]
    if isinstance(obj, (str, int, bool)) or obj is None:
        return obj
    return str(obj)


def validation_error_handler(request: Request, exc) -> JSONResponse:
    return JSONResponse(status_code=422,
                        content={"code": "validation_error",
                                 "message": "请求参数不合法",
                                 "errors": sanitize_json(exc.errors()[:10])})


def _register(api: FastAPI, box: Container) -> None:
    api.add_exception_handler(ApiError, error_handler)
    from fastapi.exceptions import RequestValidationError
    api.add_exception_handler(RequestValidationError, validation_error_handler)
    limiter = RateLimiter(box.settings.rate_limit_window, box.settings.rate_limit_max)

    @api.middleware("http")
    async def _security(request: Request, call_next):
        # 限流只看"写敏感动作"的失败面，读接口不挡（避免误伤正常浏览）
        if request.url.path in ("/api/v1/vault/detokenize", "/api/v1/candidate/export",
                                 "/api/v1/candidates/export", "/api/v1/unmask"):
            actor = "-"
            auth = request.headers.get("authorization", "")
            if auth.startswith("Bearer "):
                try:
                    actor = json.loads(
                        base64.urlsafe_b64decode(
                            auth[7:].split(".")[1] + "=" * (-len(auth[7:].split(".")[1]) % 4)
                        ).decode()).get("sub", "-")
                except Exception:               # noqa: BLE001
                    actor = "-"
            if not limiter.check(actor, request.url.path):
                box.audit.append(actor, "unknown", "ratelimit.exceeded", target=request.url.path,
                                 detail={"window": box.settings.rate_limit_window,
                                         "limit": box.settings.rate_limit_max})
                resp = JSONResponse(status_code=429,
                                    content={"code": "rate_limited",
                                             "message": "请求过于频繁，请稍后再试"})
                for k, v in SECURITY_HEADERS.items():
                    resp.headers[k] = v
                return resp
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        return response
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
    def create_candidate(body: CandidateIn, p: Principal = Depends(principal),
                         idempotency_key: str | None = Header(default=None,
                                                              alias="Idempotency-Key")):
        from app.idempotency import fingerprint
        fp = fingerprint(body.model_dump(), "/api/v1/candidates")
        replay = box.idem.begin(idempotency_key, p.actor, fp)
        if replay is not None:
            return replay
        result = svc.create(p, body.model_dump())
        box.idem.finish(idempotency_key, 200, result)
        return result

    @api.get("/api/v1/candidates", tags=["candidates"])
    def list_candidates(limit: int | None = None, offset: int = 0,
                        p: Principal = Depends(principal)):
        if limit is not None and (limit < 1 or limit > 500):
            raise ApiError("limit 需在 1..500 之间", code="bad_limit", status=422)
        if offset < 0:
            raise ApiError("offset 不能为负", code="bad_offset", status=422)
        items = svc.list(p, limit=limit, offset=offset)
        total = box.db.one("SELECT COUNT(*) AS c FROM candidates")["c"]
        return {"items": items, "count": len(items), "limit": limit,
                "offset": offset, "total_scoped_upper_bound": int(total)}

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

    # ---------------- outbox 事件 ----------------
    @api.get("/api/v1/outbox", tags=["outbox"])
    def outbox_pending(limit: int = 100, p: Principal = Depends(principal)):
        require(p, "audit.read")
        items = box.outbox.pending(limit)
        return {"items": items, "count": len(items)}

    @api.post("/api/v1/outbox/{oid}/ack", tags=["outbox"])
    def outbox_ack(oid: int, p: Principal = Depends(principal)):
        require(p, "audit.read")
        return {"acked": box.outbox.ack(oid), "id": oid}

    @api.post("/api/v1/outbox", tags=["outbox"])
    def outbox_emit(body: dict, p: Principal = Depends(principal)):
        """业务侧（任务 1/3）发事件用；必须带 topic 与 payload。"""
        require(p, "audit.read")
        topic = body.get("topic")
        payload = body.get("payload") or {}
        if not topic:
            raise ApiError("缺少 topic", code="missing_topic", status=422)
        return box.outbox.emit(topic, payload)

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
