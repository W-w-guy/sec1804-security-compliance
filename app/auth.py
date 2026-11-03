"""员工端 Bearer JWT（HS256，stdlib 实现，无第三方依赖）+ 求职者会话令牌。"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import secrets
import time

from app.errors import Unauthorized
from app.rbac import Principal, check_role


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign_jwt(claims: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    body = dict(claims)
    body.setdefault("iat", int(time.time()))
    seg = f"{_b64e(json.dumps(header, separators=(',', ':')).encode())}." \
          f"{_b64e(json.dumps(body, separators=(',', ':'), ensure_ascii=False).encode())}"
    sig = hmac.new(secret.encode(), seg.encode(), hashlib.sha256).digest()
    return f"{seg}.{_b64e(sig)}"


def verify_jwt(token: str, secret: str, now: float | None = None) -> dict:
    try:
        h, p, s = token.split(".")
    except ValueError:
        raise Unauthorized("token 格式错误")
    expect = _b64e(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(expect, s):
        raise Unauthorized("签名不匹配", code="bad_signature")
    claims = json.loads(_b64d(p))
    now = time.time() if now is None else now
    if claims.get("exp") and now > claims["exp"]:
        raise Unauthorized("token 已过期", code="token_expired")
    return claims


def principal_from_claims(claims: dict) -> Principal:
    return Principal(actor=claims.get("sub", ""), role=check_role(claims.get("role", "")),
                     city=claims.get("city"), stations=set(claims.get("stations") or []),
                     all_cities=bool(claims.get("all_cities", False)))


def issue_staff_token(settings, actor: str, role: str, city: str | None = None,
                      stations: list[str] | None = None, all_cities: bool = False) -> str:
    check_role(role)
    claims = {"sub": actor, "role": role, "city": city, "stations": stations or [],
              "all_cities": all_cities, "exp": int(time.time()) + settings.jwt_ttl}
    return sign_jwt(claims, settings.jwt_secret)


class SessionStore:
    """求职者端会话令牌（契约 v1: /api/v1/agent/sessions 由任务 1 提供，这里给出兼容实现）。"""

    def __init__(self):
        self._data: dict[str, dict] = {}

    def create(self, candidate_id: str | None = None) -> str:
        sid = "sess_" + secrets.token_urlsafe(18)
        self._data[sid] = {"candidate_id": candidate_id, "created_at": time.time()}
        return sid

    def get(self, sid: str) -> dict:
        if sid not in self._data:
            raise Unauthorized("会话不存在", code="session_not_found")
        return self._data[sid]
