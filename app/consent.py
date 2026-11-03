"""同意与权利请求：同意版本/时间/渠道留痕；查看/更正/删除/副本下载请求带时限跟踪。"""
from __future__ import annotations
import time
import uuid
from datetime import datetime, timedelta, timezone

from app.errors import Forbidden, NotFound

KINDS = ("view", "correct", "delete", "copy")


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Consent:
    def __init__(self, db, audit, settings, retention=None, outbox=None):
        self.db, self.audit, self.s, self.retention = db, audit, settings, retention
        self.outbox = outbox

    def record(self, candidate_id: str, version: str, channel: str,
               now: float | None = None, actor: str = "candidate") -> dict:
        now = time.time() if now is None else now
        if not version or not channel:
            raise Forbidden("同意必须记录版本与渠道", code="consent_incomplete")
        row = {"candidate_id": candidate_id, "version": version, "channel": channel,
               "at": _iso(now), "revoked_at": None}
        self.db.insert("consent_record", row)
        self.db.update("candidates", {"id": candidate_id},
                       {"consent_version": version, "consent_at": _iso(now),
                        "consent_channel": channel})
        self.audit.append(actor, "candidate", "consent.record", target=candidate_id,
                          detail={"version": version, "channel": channel}, now=now)
        outbox = getattr(self, "outbox", None)
        if outbox:
            outbox.emit("consent.recorded", {"candidate_id": candidate_id,
                                             "version": version, "channel": channel}, now=now)
        return row

    def revoke(self, candidate_id: str, now: float | None = None,
               actor: str = "candidate") -> dict:
        now = time.time() if now is None else now
        rows = self.db.query("SELECT * FROM consent_record WHERE candidate_id=? AND revoked_at IS NULL",
                             (candidate_id,))
        if not rows:
            raise NotFound("没有可撤回的同意记录", code="consent_not_found")
        self.db.execute("UPDATE consent_record SET revoked_at=? WHERE candidate_id=? AND revoked_at IS NULL",
                        (_iso(now), candidate_id))
        self.audit.append(actor, "candidate", "consent.revoke", target=candidate_id, now=now)
        outbox = getattr(self, "outbox", None)
        if outbox:
            outbox.emit("consent.revoked", {"candidate_id": candidate_id}, now=now)
        deleted = False
        if self.retention:
            deleted = self.retention.delete_candidate(candidate_id, "consent_revoked",
                                                      mode="delete", now=now)
        return {"candidate_id": candidate_id, "revoked_at": _iso(now), "deleted": deleted}

    def current(self, candidate_id: str) -> dict | None:
        return self.db.one("SELECT * FROM consent_record WHERE candidate_id=? ORDER BY id DESC LIMIT 1",
                           (candidate_id,))

    # ---------- 权利请求 ----------
    def open_request(self, candidate_id: str, kind: str, note: str = "",
                     now: float | None = None) -> dict:
        if kind not in KINDS:
            raise Forbidden(f"不支持的权利请求类型: {kind}", code="unsupported_kind")
        now = time.time() if now is None else now
        row = {"id": uuid.uuid4().hex[:12], "candidate_id": candidate_id, "kind": kind,
               "status": "open", "created_at": _iso(now),
               "due_at": _iso(now + self.s.rights_sla_hours * 3600),
               "closed_at": None, "note": note}
        self.db.insert("rights_request", row)
        self.audit.append(candidate_id, "candidate", f"rights.{kind}", target=candidate_id,
                          detail={"request_id": row["id"]}, now=now)
        return row

    def close_request(self, request_id: str, note: str = "", now: float | None = None,
                      actor: str = "admin") -> dict:
        now = time.time() if now is None else now
        row = self.db.one("SELECT * FROM rights_request WHERE id=?", (request_id,))
        if not row:
            raise NotFound("请求不存在", code="request_not_found")
        self.db.update("rights_request", {"id": request_id},
                       {"status": "done", "closed_at": _iso(now), "note": note or row["note"]})
        self.audit.append(actor, "admin", "rights.close", target=row["candidate_id"],
                          detail={"request_id": request_id}, now=now)
        return self.db.one("SELECT * FROM rights_request WHERE id=?", (request_id,))

    def requests(self) -> list[dict]:
        return self.db.query("SELECT * FROM rights_request ORDER BY created_at")

    def overdue(self, now: float | None = None) -> list[dict]:
        return [r for r in self.requests()
                if r["status"] == "open" and r["due_at"] < _iso(time.time() if now is None else now)]
