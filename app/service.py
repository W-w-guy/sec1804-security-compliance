"""候选人服务：创建（明文即 tokenize）、按范围读取、明文/导出需审批。"""
from __future__ import annotations
import time
import uuid
from datetime import datetime, timedelta, timezone

from app.errors import Conflict, Forbidden, NotFound
from app.rbac import Principal, enforce_scope, require

DAY = 86400.0


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# 谁能设置"特权字段"（C4 轮实测：客户端可以自己把 status 设成 hired，
# 于是保留期从 90 天跳到 180 天 —— 这就是用接口绕过数据最小化）。
PRIVILEGED_STATUS = {"hired", "rejected", "handoff"}
INITIAL_STATUS = {"new", "collecting", "complete", "booked", "interviewed"}
SERVER_ONLY_FIELDS = ("consent_version", "consent_at", "consent_channel",
                      "retention_until", "anonymized_at", "name_token", "phone_token")


class CandidateService:
    def __init__(self, c):
        self.c = c

    # ---------- 创建 ----------
    def create(self, p: Principal, data: dict, now: float | None = None) -> dict:
        require(p, "vault.tokenize")
        now = time.time() if now is None else now
        city, station = data.get("city"), data.get("station_id")
        enforce_scope(p, city, station)
        # ---- 批量赋值防护：只接受该由客户端决定的字段 ----
        clean = {k: v for k, v in data.items() if k not in SERVER_ONLY_FIELDS}
        status = clean.get("status", "new")
        if status in PRIVILEGED_STATUS and p.role not in ("admin", "ops"):
            self.c.audit.append(p.actor, p.role, "candidate.create.denied", target="*",
                                city=city, station_id=station,
                                detail={"cause": "privileged_status", "status": status}, now=now)
            raise Forbidden(f"角色 {p.role} 不能把状态直接置为 {status}", code="privilege_required")
        if status not in INITIAL_STATUS | PRIVILEGED_STATUS:
            raise Forbidden(f"非法状态: {status}", code="invalid_status")
        if clean.get("is_minor") and p.role not in ("admin", "ops"):
            self.c.audit.append(p.actor, p.role, "candidate.create.denied", target="*",
                                city=city, station_id=station,
                                detail={"cause": "is_minor_set_by_client"}, now=now)
            raise Forbidden("未成年人标记须由校核流程写入，客户端不可自设", code="privilege_required")
        data = clean
        cid = str(uuid.uuid4())
        # 先记下本次写入的 token：中途失败要能回滚，否则会留下"库里有一行密文、
        # 但没有对应候选人"的孤儿（D6 轮实测：candidates +0，vault_items +1）。
        created_tokens: list[str] = []
        try:
            name_token = self.c.vault.tokenize("name", data["name"], p.actor, p.role, now)["token"]
            created_tokens.append(name_token)
            phone_token = self.c.vault.tokenize("phone", data["phone"], p.actor, p.role, now)["token"]
            created_tokens.append(phone_token)
        except Exception:
            self._rollback_tokens(created_tokens)
            raise
        status = data.get("status", "new")
        days = self.c.settings.retain_hired_days if status == "hired" else self.c.settings.retain_not_hired_days
        row = {
            "id": cid, "name_token": name_token, "phone_token": phone_token,
            "birth_ym": data.get("birth_ym"), "area_text": data.get("area_text"),
            "job_type": data.get("job_type"), "has_ebike": data.get("has_ebike"),
            "start_text": data.get("start_text"), "experience_text": data.get("experience_text"),
            "health_cert": data.get("health_cert"), "source_channel": data.get("source_channel"),
            "station_id": station, "city": city, "status": status,
            "consent_version": None, "consent_at": None, "consent_channel": None,
            "is_minor": 1 if data.get("is_minor") else 0,
            "retention_until": _iso(now + days * DAY),
            "anonymized_at": None, "created_at": _iso(now), "updated_at": _iso(now),
        }
        try:
            self.c.db.insert("candidates", row)
            self.c.audit.append(p.actor, p.role, "candidate.create", target=cid, city=city,
                                station_id=station, detail={"status": status}, now=now)
        except Exception:
            # 业务行写不进 / 审计写不进 → 整笔撤销，绝不留下无痕数据
            try:
                self.c.db.execute("DELETE FROM candidates WHERE id=?", (cid,))
            except Exception:                       # noqa: BLE001
                pass
            self._rollback_tokens(created_tokens)
            raise
        return self.view(p, cid, now=now)

    def _rollback_tokens(self, tokens: list[str]) -> None:
        """补偿删除本次新建的 vault 行（只删本次新增的，不碰别人已经在用的）。"""
        for t in tokens:
            try:
                self.c.db.execute("DELETE FROM vault_items WHERE token=?", (t,))
            except Exception:                       # noqa: BLE001
                pass


    # ---------- 更新（E 组补：乐观锁 + 部分更新） ----------
    UPDATABLE = ("area_text", "job_type", "has_ebike", "start_text", "experience_text",
                 "health_cert", "source_channel", "station_id", "city", "birth_ym",
                 "is_minor", "status")

    def update(self, p: Principal, cid: str, patch: dict,
               expected_version: int | None = None, now: float | None = None) -> dict:
        """部分更新。只改传入的字段，其余保持原值（避免"只传一个字段把别人清空"）。

        ★ 为什么需要 expected_version：E1/E4 轮证明了并发改不同字段会互相覆盖。
          带版本号的调用是"读-改-写"的正确做法：版本不匹配就 409，让调用方重读。
          不带版本号时退回行锁 + 只更新传入列（仍可能覆盖同一字段的并发写，
          但不会把别的字段抹掉）。
        """
        require(p, "vault.tokenize")
        now = time.time() if now is None else now
        unknown = set(patch) - set(self.UPDATABLE)
        if unknown:
            raise Forbidden(f"不可更新的字段: {sorted(unknown)}", code="field_not_updatable")
        if not patch:
            raise Forbidden("patch 为空", code="empty_patch")
        row = self._load(cid)
        enforce_scope(p, row.get("city"), row.get("station_id"))
        if patch.get("city") or patch.get("station_id"):
            enforce_scope(p, patch.get("city", row.get("city")),
                          patch.get("station_id", row.get("station_id")))
        patch = dict(patch)
        patch["updated_at"] = _iso(now)
        patch["version"] = int(row.get("version") or 1) + 1
        if expected_version is not None:
            cur = self.c.db.execute(
                "UPDATE candidates SET " + ",".join(f"{k}=?" for k in patch) +
                " WHERE id=? AND version=?",
                list(patch.values()) + [cid, int(expected_version)])
            if getattr(cur, "rowcount", 0) != 1:
                raise Conflict("版本冲突，请重新读取后再改", code="version_conflict")
        else:
            self.c.db.update("candidates", {"id": cid}, patch)
        self.c.audit.append(p.actor, p.role, "candidate.updated", target=cid,
                            city=row.get("city"), station_id=row.get("station_id"),
                            detail={"fields": sorted(set(patch) - {"updated_at", "version"})},
                            now=now)
        return self.view(p, cid, now=now)

    # ---------- 批量创建（E10：整批原子） ----------
    def create_many(self, p: Principal, items: list[dict],
                    now: float | None = None) -> dict:
        """一批里任何一条非法 → 整批回滚，不留半批数据。"""
        if not items:
            raise Forbidden("items 为空", code="empty_batch")
        if len(items) > self.c.settings.bulk_max_items:
            raise Forbidden(f"单批最多 {self.c.settings.bulk_max_items} 条",
                            code="batch_too_large")
        created: list[str] = []
        try:
            for it in items:
                created.append(self.create(p, it, now=now)["id"])
        except Exception:
            for cid in created:
                try:
                    self.c.db.execute("DELETE FROM candidates WHERE id=?", (cid,))
                except Exception:                   # noqa: BLE001
                    pass
            raise
        return {"created": created, "count": len(created)}

    # ---------- 读取（默认掩码） ----------
    def _load(self, cid: str) -> dict:
        row = self.c.db.one("SELECT * FROM candidates WHERE id=?", (cid,))
        if not row:
            raise NotFound("候选人不存在", code="candidate_not_found")
        return row

    def view(self, p: Principal, cid: str, full: bool = False, approval_id: str | None = None,
             reason: str = "", now: float | None = None) -> dict:
        require(p, "candidate.read.masked")
        row = self._load(cid)
        enforce_scope(p, row.get("city"), row.get("station_id"))
        out = {k: row[k] for k in ("id", "birth_ym", "area_text", "job_type", "has_ebike",
                                   "health_cert", "source_channel", "station_id", "city",
                                   "status", "consent_version", "consent_at", "created_at",
                                   "updated_at", "retention_until", "is_minor", "version",
                                   # 漏了这三个字段 → 客户端拿到 None，会以为"被清空了"
                                   "start_text", "experience_text", "anonymized_at")}
        if not full:
            out["name"] = self._masked(row["name_token"]) if row.get("name_token") else None
            out["phone"] = self._masked(row["phone_token"]) if row.get("phone_token") else None
            self.c.audit.append(p.actor, p.role, "candidate.read.masked", target=cid,
                                city=row.get("city"), station_id=row.get("station_id"), now=now)
            return out
        # 明文：必须权限 + 审批通过
        require(p, "candidate.read.full")
        if not approval_id:
            raise Forbidden("查看完整信息须先申请审批", code="approval_required")
        self.c.approvals.consume(approval_id, p.actor, "candidate.read.full", cid, now=now)
        out["name"] = self._plain(row["name_token"], p, "姓名查看", now)
        out["phone"] = self._plain(row["phone_token"], p, "手机号查看", now)
        self.c.audit.append(p.actor, p.role, "candidate.read.full", target=cid,
                            city=row.get("city"), station_id=row.get("station_id"),
                            detail={"reason": reason, "approval": approval_id}, now=now)
        return out

    def _masked(self, token: str) -> str:
        return self.c.vault.masked_of(token)["masked"]

    def _plain(self, token: str, p: Principal, why: str, now) -> str:
        return self.c.vault.detokenize(token, why, p, now=now)["value"]

    # ---------- 列表 / 导出 ----------
    def list(self, p: Principal, now: float | None = None,
             limit: int | None = None, offset: int = 0,
             cursor_from: str | None = None) -> list[dict]:
        """按范围列出候选人，支持分页。

        为什么要分页：D10 轮实测 500 条时一次全返回 0.4 秒，1 万条就是 8 秒级、
        响应体几十 MB —— 对客户端和内存都是风险，也没法给前端做无限滚动。
        """
        require(p, "candidate.read.masked")
        out = []
        sql = "SELECT id, created_at, city, station_id FROM candidates"
        params: tuple = ()
        if cursor_from:
            # 游标分页：按 (created_at, id) 严格大于上一页最后一条。
            # E11 轮证明 offset 分页在翻页期间有插入时会重复/漏项。
            base = self._load(cursor_from)
            sql += " WHERE (created_at > ? OR (created_at = ? AND id > ?))"
            params = (base["created_at"], base["created_at"], cursor_from)
        sql += " ORDER BY created_at, id"
        if limit is not None:
            sql += " LIMIT ?"
            params = params + (int(limit),)
            if cursor_from is None and offset:
                sql += " OFFSET ?"
                params = params + (int(offset),)
        for row in self.c.db.query(sql, params):
            from app.rbac import in_scope
            if in_scope(p, row.get("city"), row.get("station_id")):
                out.append(self.view(p, row["id"], now=now))
            else:
                self.c.audit.append(p.actor, p.role, "candidate.read.denied", target=row["id"],
                                    city=row.get("city"), station_id=row.get("station_id"),
                                    detail={"cause": "out_of_scope"}, now=now)
        return out

    def export(self, p: Principal, ids: list[str] | None = None, full: bool = False,
               approval_id: str | None = None, reason: str = "", now: float | None = None) -> dict:
        perm = "candidate.export.full" if full else "candidate.export.masked"
        require(p, perm)
        if full and not approval_id:
            raise Forbidden("导出完整信息须先申请审批", code="approval_required")
        rows = []
        for cid in (ids or [r["id"] for r in self.c.db.query("SELECT id FROM candidates")]):
            row = self._load(cid)
            enforce_scope(p, row.get("city"), row.get("station_id"))
            if full:
                self.c.approvals.consume(approval_id, p.actor, "candidate.export.full", "*", now=now)
                rows.append({"id": cid, "name": self._plain(row["name_token"], p, "导出", now),
                             "phone": self._plain(row["phone_token"], p, "导出", now)})
            else:
                rows.append({"id": cid, "name": self._masked(row["name_token"]),
                             "phone": self._masked(row["phone_token"])})
        self.c.audit.append(p.actor, p.role, "candidate.export.full" if full else "candidate.export.masked",
                            target=",".join(ids or ["*"]), detail={"rows": len(rows), "reason": reason},
                            now=now)
        return {"rows": rows, "full": full, "count": len(rows)}
