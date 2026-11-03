"""RBAC + 城市/站点数据范围 + 敏感操作审批。

角色：recruiter(招聘专员) / station_manager(站长) / ops(运营) / admin(管理员) / auditor(审计员)
原则：默认拒绝；审计员可读审计与掩码数据，但不可看明文；明文查看与导出须管理员审批。
"""
from __future__ import annotations
import time
import uuid
from dataclasses import dataclass, field

from app.errors import Forbidden

ROLES = ("recruiter", "station_manager", "ops", "admin", "auditor")

PERMISSIONS: dict[str, set[str]] = {
    "recruiter":     {"candidate.read.masked", "vault.tokenize", "mask.apply", "rights.track"},
    "station_manager": {"candidate.read.masked", "candidate.export.masked", "vault.tokenize",
                        "mask.apply", "mask.restore", "rights.track"},
    "ops":           {"candidate.read.masked", "candidate.export.masked", "vault.tokenize",
                      "mask.apply", "retention.run", "audit.read", "rights.track"},
    "admin":         {"candidate.read.masked", "candidate.read.full", "candidate.export.full",
                      "candidate.export.masked", "vault.tokenize", "vault.detokenize",
                      "mask.apply", "mask.restore", "retention.run", "audit.read",
                      "approval.decide", "kms.rotate", "rights.track", "rights.close"},
    "auditor":       {"candidate.read.masked", "audit.read", "audit.verify", "rights.track"},
}

# 需要二次审批的动作
NEEDS_APPROVAL = {"candidate.read.full", "candidate.export.full", "vault.detokenize.bulk"}


@dataclass
class Principal:
    actor: str
    role: str
    city: str | None = None
    stations: set[str] = field(default_factory=set)
    all_cities: bool = False

    def perms(self) -> set[str]:
        return PERMISSIONS.get(self.role, set())

    def can(self, perm: str) -> bool:
        return perm in self.perms()

    def scope_repr(self) -> str:
        return "*" if self.all_cities else (self.city or "-")


def check_role(role: str) -> str:
    if role not in ROLES:
        raise Forbidden(f"未知角色: {role}", code="unknown_role")
    return role


def require(principal: Principal, perm: str) -> None:
    check_role(principal.role)
    if not principal.can(perm):
        raise Forbidden(f"角色 {principal.role} 缺少权限 {perm}", code="missing_permission")


def in_scope(principal: Principal, city: str | None, station_id: str | None) -> bool:
    """城市/站点双重范围判定；管理员与运营按 all_cities 标记放行到城市级。"""
    require(principal, "candidate.read.masked")
    if principal.all_cities:
        return True
    if city is not None and principal.city is not None and city != principal.city:
        return False
    if station_id is not None and principal.stations and station_id not in principal.stations:
        return False
    return True


def enforce_scope(principal: Principal, city: str | None, station_id: str | None) -> None:
    if not in_scope(principal, city, station_id):
        raise Forbidden(
            f"越权：{principal.actor}({principal.role}) 范围={principal.scope_repr()} "
            f"不可访问 city={city} station={station_id}",
            code="out_of_scope",
        )


class Approvals:
    """敏感操作审批：request → admin 决定 → 时限内一次性放行。"""

    def __init__(self, db, ttl_seconds: int = 900):
        self.db = db
        self.ttl = ttl_seconds

    def request(self, actor: str, action: str, target: str, reason: str, now: float | None = None) -> dict:
        if action not in NEEDS_APPROVAL:
            raise Forbidden(f"动作 {action} 无需审批", code="no_approval_needed")
        if not reason or len(reason.strip()) < 4:
            raise Forbidden("审批申请必须写明理由", code="reason_required")
        now = time.time() if now is None else now
        row = {
            "id": uuid.uuid4().hex, "actor": actor, "action": action, "target": target,
            "reason": reason.strip(), "status": "pending",
            "created_at": _ts(now), "decided_at": None, "decided_by": None, "expires_at": None,
        }
        self.db.insert("approval", row)
        return row

    def decide(self, approval_id: str, approver: str, ok: bool, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        row = self.db.one("SELECT * FROM approval WHERE id=?", (approval_id,))
        if not row:
            raise Forbidden("审批不存在", code="approval_missing")
        if row["status"] != "pending":
            raise Forbidden(f"审批已是 {row['status']}", code="approval_closed")
        patch = {"status": "approved" if ok else "denied", "decided_at": _ts(now),
                 "decided_by": approver,
                 "expires_at": _ts(now + self.ttl) if ok else None}
        self.db.update("approval", {"id": approval_id}, patch)
        row.update(patch)
        return row

    def consume(self, approval_id: str, actor: str, action: str, target: str,
                now: float | None = None) -> None:
        """校验并**原子地**把审批标记为已用。

        ★ C8 轮实测的双花：8 个并发请求同时用同一个审批，2 次成功。
          原因：原来是"先 SELECT 校验 → 再 UPDATE 标记"，两个线程都读到
          status='approved'，于是都放行。
          改法：用条件 UPDATE ... WHERE status='approved' 抢占，看影响行数，
          只有抢到的那一个能继续；其余按"已用过"拒绝。
        """
        now = time.time() if now is None else now
        row = self.db.one("SELECT * FROM approval WHERE id=?", (approval_id,))
        if not row:
            raise Forbidden("审批不存在", code="approval_missing")
        if row["status"] == "consumed":
            raise Forbidden("审批已使用过", code="approval_already_used")
        if row["status"] != "approved":
            raise Forbidden("审批未通过", code="approval_not_granted")
        if row["actor"] != actor or row["action"] != action or row["target"] != target:
            raise Forbidden("审批与请求不匹配", code="approval_mismatch")
        if row["expires_at"] and _ts(now) > row["expires_at"]:
            raise Forbidden("审批已过期", code="approval_expired")
        cur = self.db.execute(
            "UPDATE approval SET status='consumed' WHERE id=? AND status='approved'",
            (approval_id,))
        if getattr(cur, "rowcount", 0) != 1:
            raise Forbidden("审批已使用过", code="approval_already_used")


def _ts(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
