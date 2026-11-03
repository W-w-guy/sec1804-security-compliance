"""候选人服务：创建（明文即 tokenize）、按范围读取、明文/导出需审批。"""
from __future__ import annotations
import time
import uuid
from datetime import datetime, timedelta, timezone

from app.errors import Forbidden, NotFound
from app.rbac import Principal, enforce_scope, require

DAY = 86400.0


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class CandidateService:
    def __init__(self, c):
        self.c = c

    # ---------- 创建 ----------
    def create(self, p: Principal, data: dict, now: float | None = None) -> dict:
        require(p, "vault.tokenize")
        now = time.time() if now is None else now
        city, station = data.get("city"), data.get("station_id")
        enforce_scope(p, city, station)
        cid = str(uuid.uuid4())
        name_token = self.c.vault.tokenize("name", data["name"], p.actor, p.role, now)["token"]
        phone_token = self.c.vault.tokenize("phone", data["phone"], p.actor, p.role, now)["token"]
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
        self.c.db.insert("candidates", row)
        self.c.audit.append(p.actor, p.role, "candidate.create", target=cid, city=city,
                            station_id=station, detail={"status": status}, now=now)
        return self.view(p, cid, now=now)

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
                                   "retention_until", "is_minor")}
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
    def list(self, p: Principal, now: float | None = None) -> list[dict]:
        require(p, "candidate.read.masked")
        out = []
        for row in self.c.db.query("SELECT id, city, station_id FROM candidates ORDER BY created_at"):
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
