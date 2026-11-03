"""审计日志：只追加、哈希链防篡改、可定位被改行、异常行为告警。

链式结构：hash = sha256(prev_hash | seq | ts | actor | role | action | target | city | station | detail)
校验：逐行重算；不匹配即定位到该 seq；seq 断号说明有删除；链尾哈希与 tip 不符说明被截断。
"""
from __future__ import annotations
import hashlib
import json
import threading
import time
from datetime import datetime, timedelta, timezone

GENESIS = "0" * 64
WATCH_ACTIONS = {"candidate.read.full", "vault.detokenize", "candidate.export.full", "candidate.export.masked"}


def _canon(*parts) -> str:
    return "|".join("" if p is None else str(p) for p in parts)


class Audit:
    def __init__(self, db, settings=None):
        self.db = db
        self.settings = settings
        self._lock = threading.RLock()

    # ---------- 写入 ----------
    def append(self, actor: str, role: str, action: str, target: str = "",
               city: str | None = None, station_id: str | None = None,
               detail: dict | str | None = None, now: float | None = None) -> int:
        now = time.time() if now is None else now
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
        if isinstance(detail, dict):
            detail_s = json.dumps(detail, ensure_ascii=False, sort_keys=True)
        else:
            detail_s = detail or ""
        # "读上一行 → 算 hash → 写本行" 必须是原子段：
        # 否则并发写会算出同一个 seq / prev_hash，插入撞 UNIQUE，数据直接丢。
        with self._lock, self.db.serialized("audit_log"):
            for attempt in range(6):
                last = self.db.one("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1")
                prev = last["hash"] if last else GENESIS
                seq = (last["seq"] + 1) if last else 1
                h = hashlib.sha256(_canon(prev, seq, ts, actor, role, action, target,
                                          city, station_id, detail_s).encode()).hexdigest()
                try:
                    self.db.insert("audit_log", {
                        "seq": seq, "ts": ts, "actor": actor, "role": role, "action": action,
                        "target": target, "city": city, "station_id": station_id,
                        "detail": detail_s, "prev_hash": prev, "hash": h,
                    })
                    break
                except Exception:
                    if attempt == 5:
                        raise
                    time.sleep(0.002 * (attempt + 1))   # 跨进程竞争时退避重试
        if action in WATCH_ACTIONS:
            self._check_alert(actor, action, now)
        return seq

    # ---------- 校验 ----------
    def verify(self) -> dict:
        rows = self.db.query("SELECT * FROM audit_log ORDER BY seq")
        tampered: list[int] = []
        gaps: list[int] = []
        prev = GENESIS
        expect_seq = 1
        for r in rows:
            if r["seq"] != expect_seq:
                gaps.append(expect_seq)
            expect_seq = r["seq"] + 1
            h = hashlib.sha256(_canon(r["prev_hash"], r["seq"], r["ts"], r["actor"], r["role"],
                                      r["action"], r["target"], r["city"], r["station_id"],
                                      r["detail"]).encode()).hexdigest()
            if h != r["hash"] or r["prev_hash"] != prev:
                tampered.append(r["seq"])
            prev = r["hash"]
        return {
            "ok": not tampered and not gaps,
            "rows": len(rows),
            "tampered_seq": tampered,
            "missing_seq": gaps,
            "tip": prev,
        }

    def locate(self, seq: int) -> dict:
        """说明某一行为何被判为篡改：字段级差异。"""
        res = self.verify()
        r = self.db.one("SELECT * FROM audit_log WHERE seq=?", (seq,))
        if not r:
            return {"seq": seq, "found": False, "tampered": False, "fields": []}
        recomputed = hashlib.sha256(_canon(r["prev_hash"], r["seq"], r["ts"], r["actor"], r["role"],
                                           r["action"], r["target"], r["city"], r["station_id"],
                                           r["detail"]).encode()).hexdigest()
        fields = []
        if recomputed != r["hash"]:
            fields.append({"field": "content_or_hash", "stored_hash": r["hash"], "recomputed": recomputed})
        return {"seq": seq, "found": True, "tampered": seq in res["tampered_seq"],
                "fields": fields, "chain": res}

    # ---------- 查询 ----------
    def tail(self, n: int = 20) -> list[dict]:
        return self.db.query(f"SELECT * FROM audit_log ORDER BY seq DESC LIMIT {int(n)}")

    def by_actor(self, actor: str) -> list[dict]:
        return self.db.query("SELECT * FROM audit_log WHERE actor=? ORDER BY seq", (actor,))

    # ---------- 告警 ----------
    def _check_alert(self, actor: str, action: str, now: float) -> None:
        if not self.settings:
            return
        window = self.settings.alert_window_minutes * 60
        since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - window))
        rows = self.db.query(
            "SELECT COUNT(*) AS c FROM audit_log WHERE actor=? AND action=? AND ts>=?",
            (actor, action, since))
        count = int(rows[0]["c"]) if rows else 0
        if action in ("candidate.export.full", "candidate.export.masked"):
            threshold = self.settings.alert_export_threshold
        else:
            threshold = self.settings.alert_view_threshold
        if count >= threshold:
            dup = self.db.one("SELECT id FROM audit_alert WHERE actor=? AND kind=? AND ts>=?",
                              (actor, action, since))
            if dup:
                return
            self.db.insert("audit_alert", {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                "actor": actor, "kind": action, "observed": count, "threshold": threshold})
            # 告警本身也入链，避免“告警被悄悄删掉”
            self.append("system", "system", "alert.raised", target=actor,
                        detail={"kind": action, "count": count, "threshold": threshold}, now=now)

    def alerts(self) -> list[dict]:
        return self.db.query("SELECT * FROM audit_alert ORDER BY id")
