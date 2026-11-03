"""保留与删除：按字段保留期到期自动删除/匿名化，撤回同意立即删除，全部留删除记录。

可在用例里“时间快进”：所有入口都接受 now 参数，不读系统时钟以外的隐藏状态。
保留期：未录用 90 天 / 对话原文 30 天 / 未成年人 24 小时 / 已录用 180 天（均可配置）。
"""
from __future__ import annotations
import time
from datetime import datetime, timedelta, timezone

DAY = 86400.0


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(s: str | None) -> float | None:
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


class Retention:
    def __init__(self, db, audit, settings):
        self.db, self.audit, self.s = db, audit, settings

    # ---------- 单条删除 ----------
    def _log_deletion(self, entity: str, entity_id: str, mode: str, rule: str,
                      detail: str = "", now: float | None = None) -> None:
        self.db.insert("deletion_log", {
            "ts": _iso(time.time() if now is None else now), "entity": entity,
            "entity_id": entity_id, "mode": mode, "rule": rule, "detail": detail})

    def delete_candidate(self, candidate_id: str, rule: str, mode: str = "delete",
                         now: float | None = None) -> bool:
        row = self.db.one("SELECT * FROM candidates WHERE id=?", (candidate_id,))
        if not row:
            return False
        if mode == "anonymize":
            self.db.update("candidates", {"id": candidate_id}, {
                "name_token": None, "phone_token": None, "area_text": None,
                "start_text": None, "experience_text": None, "birth_ym": None,
                "anonymized_at": _iso(time.time() if now is None else now),
                "updated_at": _iso(time.time() if now is None else now)})
        else:
            self.db.execute("DELETE FROM candidates WHERE id=?", (candidate_id,))
        self.db.execute("DELETE FROM transcripts WHERE candidate_id=?", (candidate_id,))
        self._log_deletion("candidate", candidate_id, mode, rule, now=now)
        self.audit.append("system", "system", f"retention.{mode}", target=candidate_id,
                          detail={"rule": rule, "mode": mode}, now=now)
        return True

    # ---------- 批量清理 ----------
    def run(self, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        report = {"transcripts_deleted": 0, "minors_deleted": 0,
                  "expired_anonymized": 0, "expired_deleted": 0, "revoked_deleted": 0}

        # 1) 对话原文 30 天
        cutoff = _iso(now - self.s.retain_transcript_days * DAY)
        # 边界语义统一为"到期即触发"：created_at <= cutoff（B8 轮实测：用 < 时，
        # 24h/30d 整点那一刻不触发，差 1 秒才触发 —— 边界上少删一次就是合规缺口）
        for r in self.db.query("SELECT id, candidate_id FROM transcripts WHERE deleted_at IS NULL AND created_at<=?", (cutoff,)):
            self.db.execute("DELETE FROM transcripts WHERE id=?", (r["id"],))
            self._log_deletion("transcript", r["id"], "delete", "transcript_30d",
                               detail=f"candidate={r['candidate_id']}", now=now)
            report["transcripts_deleted"] += 1

        # 2) 未成年人 24 小时内删除
        mcut = _iso(now - self.s.retain_minor_hours * 3600)
        for r in self.db.query("SELECT id FROM candidates WHERE is_minor=1 AND created_at<=?", (mcut,)):
            if self.delete_candidate(r["id"], "minor_24h", mode="delete", now=now):
                report["minors_deleted"] += 1

        # 3) 撤回同意 → 立即删除
        for r in self.db.query("SELECT DISTINCT candidate_id FROM consent_record WHERE revoked_at IS NOT NULL"):
            cid = r["candidate_id"]
            if self.db.one("SELECT id FROM candidates WHERE id=?", (cid,)):
                if self.delete_candidate(cid, "consent_revoked", mode="delete", now=now):
                    report["revoked_deleted"] += 1

        # 4) 到期：未录用 90 天 → 删除；已录用 180 天 → 匿���化
        for r in self.db.query("SELECT * FROM candidates"):
            until = _parse(r.get("retention_until"))
            if until is None or until > now:
                continue
            if r["status"] in ("hired",):
                if self.delete_candidate(r["id"], "hired_180d", mode="anonymize", now=now):
                    report["expired_anonymized"] += 1
            else:
                if self.delete_candidate(r["id"], "not_hired_90d", mode="delete", now=now):
                    report["expired_deleted"] += 1

        self.audit.append("system", "system", "retention.run", target="retention",
                          detail=report, now=now)
        return report

    def deletions(self, limit: int = 100) -> list[dict]:
        return self.db.query(f"SELECT * FROM deletion_log ORDER BY id DESC LIMIT {int(limit)}")
