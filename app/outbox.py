"""Outbox + Webhook 签名（契约 v1：事件走 outbox + HMAC-SHA256 签名）。

定位：**本模块提供 outbox 基础件与签名校验**；业务事件（candidate.created 等）
由任务 1/3 在各自事务里调用 emit()。安全侧事件（consent.*, retention.delete,
kms.rotate）由本模块自己发。

为什么用 outbox 而不是直接调用 webhook：
  直接发会把"写库成功、推送失败"变成丢事件。outbox 是"先落库、再异步投递"，
  投递失败可重试，且签名可让消费端验证来源与完整性。
"""
from __future__ import annotations
import hashlib
import hmac
import json
import time

TOPICS = {
    "candidate.created", "candidate.updated", "candidate.completed",
    "booking.created", "booking.cancelled", "handoff.requested",
    # 安全侧自有事件
    "consent.recorded", "consent.revoked", "retention.deleted",
    "audit.alert", "kms.rotated",
}


def _canon(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sign(payload: dict, secret: str) -> str:
    return hmac.new(secret.encode(), _canon(payload).encode(), hashlib.sha256).hexdigest()


def verify(payload: dict, signature: str, secret: str) -> bool:
    return hmac.compare_digest(sign(payload, secret), signature or "")


class Outbox:
    def __init__(self, db, secret: str, audit=None):
        self.db = db
        self.secret = secret
        self.audit = audit

    def emit(self, topic: str, payload: dict, now: float | None = None) -> dict:
        if topic not in TOPICS:
            # 走 ApiError（422），不要让它变成 500 —— 这是调用方错误，不是服务故障
            from app.errors import ApiError
            raise ApiError(f"未知事件主题: {topic}", code="unknown_topic", status=422)
        envelope = {"topic": topic, "payload": payload,
                    "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                               time.gmtime(time.time() if now is None else now))}
        sig = sign(envelope, self.secret)
        self.db.insert("outbox", {
            "topic": topic, "payload": json.dumps(envelope, ensure_ascii=False),
            "signature": sig,
            "created_at": envelope["issued_at"], "delivered_at": None})
        return {"topic": topic, "signature": sig}

    def pending(self, limit: int = 100) -> list[dict]:
        return self.db.query(
            f"SELECT * FROM outbox WHERE delivered_at IS NULL ORDER BY id LIMIT {int(limit)}")

    def ack(self, oid: int, now: float | None = None) -> bool:
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() if now is None else now))
        cur = self.db.execute("UPDATE outbox SET delivered_at=? WHERE id=? AND delivered_at IS NULL",
                              (ts, int(oid)))
        return getattr(cur, "rowcount", 0) == 1

    def delivered(self, limit: int = 100) -> list[dict]:
        return self.db.query(
            f"SELECT * FROM outbox WHERE delivered_at IS NOT NULL ORDER BY id DESC LIMIT {int(limit)}")
