"""幂等键（D2 轮补）：同一 Idempotency-Key 重放不得重复产生副作用。

做法：key 为主键，存 (actor, 请求指纹, 状态码, 响应体)。重放时：
  - 指纹一致 → 直接回放原响应（不重复写库）；
  - 指纹不一致 → 409，说明同一个键被用于不同请求（调用方 bug，必须报出来）。
进程内先抢占插入，抢不到说明有人正在处理同键请求 → 409，避免并发双写。
"""
from __future__ import annotations
import hashlib
import json
import time

from app.errors import Conflict

MAX_KEY_LEN = 128


def fingerprint(payload, path: str) -> str:
    raw = json.dumps({"path": path, "body": payload}, ensure_ascii=False, sort_keys=True,
                     default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


class Idempotency:
    def __init__(self, db):
        self.db = db

    def begin(self, key: str | None, actor: str, fp: str) -> dict | None:
        """返回已有响应则直接回放；返回 None 表示可以继续处理。"""
        if not key:
            return None
        if len(key) > MAX_KEY_LEN:
            raise Conflict("Idempotency-Key 过长", code="idempotency_key_too_long")
        row = self.db.one("SELECT * FROM idempotency WHERE key=?", (key,))
        if row:
            if row["actor"] != actor or row["fingerprint"] != fp:
                raise Conflict("同一 Idempotency-Key 被用于不同请求", code="idempotency_conflict")
            if row["status"] == 0:
                raise Conflict("相同请求正在处理中", code="idempotency_in_progress")
            return {"status": int(row["status"]), **json.loads(row["body"])}
        try:
            self.db.insert("idempotency", {"key": key, "actor": actor, "fingerprint": fp,
                                          "status": 0, "body": "{}",
                                          "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                                     time.gmtime())})
        except Exception:                       # noqa: BLE001  并发抢同一个键
            raise Conflict("相同请求正在处理中", code="idempotency_in_progress")
        return None

    def finish(self, key: str | None, status: int, body: dict) -> None:
        if not key:
            return
        self.db.execute("UPDATE idempotency SET status=?, body=? WHERE key=?",
                        (int(status), json.dumps(body, ensure_ascii=False, default=str), key))