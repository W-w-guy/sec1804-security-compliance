"""极小存储层：同一套 SQL 跑 sqlite（默认，零依赖）与 PostgreSQL 16（compose）。"""
from __future__ import annotations
import hashlib
import json
import os
import sqlite3
import threading
from typing import Any, Iterable

from contextlib import contextmanager

from app.config import Settings

_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS vault_items (
        token TEXT PRIMARY KEY,
        item_type TEXT NOT NULL,
        key_version INTEGER NOT NULL,
        nonce TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        created_at TEXT NOT NULL,
        rotated_from TEXT)""",
    """CREATE TABLE IF NOT EXISTS candidates (
        id TEXT PRIMARY KEY,
        name_token TEXT, phone_token TEXT,
        birth_ym TEXT, area_text TEXT, job_type TEXT,
        has_ebike INTEGER, start_text TEXT, experience_text TEXT,
        health_cert TEXT, source_channel TEXT,
        station_id TEXT, city TEXT,
        status TEXT, consent_version TEXT, consent_at TEXT,
        consent_channel TEXT, is_minor INTEGER DEFAULT 0,
        retention_until TEXT, anonymized_at TEXT,
        created_at TEXT, updated_at TEXT)""",
    """CREATE TABLE IF NOT EXISTS transcripts (
        id TEXT PRIMARY KEY, candidate_id TEXT NOT NULL,
        body TEXT NOT NULL, is_minor INTEGER DEFAULT 0,
        created_at TEXT NOT NULL, deleted_at TEXT)""",
    """CREATE TABLE IF NOT EXISTS audit_log (
        seq INTEGER PRIMARY KEY,
        ts TEXT NOT NULL, actor TEXT NOT NULL, role TEXT NOT NULL,
        action TEXT NOT NULL, target TEXT, city TEXT, station_id TEXT,
        detail TEXT, prev_hash TEXT NOT NULL, hash TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS audit_alert (
        id INTEGER PRIMARY KEY,
        ts TEXT NOT NULL, actor TEXT NOT NULL, kind TEXT NOT NULL,
        observed INTEGER NOT NULL, threshold INTEGER NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS deletion_log (
        id INTEGER PRIMARY KEY,
        ts TEXT NOT NULL, entity TEXT NOT NULL, entity_id TEXT NOT NULL,
        mode TEXT NOT NULL, rule TEXT NOT NULL, detail TEXT)""",
    """CREATE TABLE IF NOT EXISTS consent_record (
        id INTEGER PRIMARY KEY,
        candidate_id TEXT NOT NULL, version TEXT NOT NULL,
        channel TEXT NOT NULL, at TEXT NOT NULL, revoked_at TEXT)""",
    """CREATE TABLE IF NOT EXISTS rights_request (
        id TEXT PRIMARY KEY,
        candidate_id TEXT NOT NULL, kind TEXT NOT NULL,
        status TEXT NOT NULL, created_at TEXT NOT NULL,
        due_at TEXT NOT NULL, closed_at TEXT, note TEXT)""",
    """CREATE TABLE IF NOT EXISTS idempotency (
        key TEXT PRIMARY KEY, actor TEXT NOT NULL, fingerprint TEXT NOT NULL,
        status INTEGER NOT NULL, body TEXT NOT NULL, created_at TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS outbox (
        id INTEGER PRIMARY KEY,
        topic TEXT NOT NULL, payload TEXT NOT NULL, signature TEXT NOT NULL,
        created_at TEXT NOT NULL, delivered_at TEXT)""",
    """CREATE TABLE IF NOT EXISTS approval (
        id TEXT PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL,
        target TEXT NOT NULL, reason TEXT NOT NULL,
        status TEXT NOT NULL, created_at TEXT NOT NULL,
        decided_at TEXT, decided_by TEXT, expires_at TEXT)""",
]


def _pg_connect(dsn: str):
    """解析 postgresql://user:pass@host:port/db 再逐项传参。

    不能直接 connect(dsn=...)：pg8000 的 dbapi.connect 没有 dsn 关键字参数
    （1.31 实测 TypeError: connect() got an unexpected keyword argument 'dsn'）。
    这个坑只在真连 PG 时才暴露，Windows 上（无 PG）永远看不到。
    """
    from urllib.parse import unquote, urlparse
    import pg8000.dbapi
    u = urlparse(dsn)
    kwargs = {
        "user": unquote(u.username or ""),
        "password": unquote(u.password or ""),
        "host": u.hostname or "127.0.0.1",
        "port": u.port or 5432,
        "database": (u.path or "/postgres").lstrip("/") or "postgres",
    }
    return pg8000.dbapi.connect(**kwargs)


class DB:
    """线程安全、可注入时钟之外的最小封装。占位符统一写 ? ，PG 侧自动转 %s。"""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._lock = threading.RLock()
        self.dialect = "pg" if settings.pg_dsn else "sqlite"
        self.schema = "public"
        if self.dialect == "sqlite":
            self._conn = sqlite3.connect(settings.sqlite_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL" if settings.sqlite_path != ":memory:" else "SELECT 1")
        else:  # pragma: no cover - 需要真实 PG
            # 用 pg8000（BSD-3）而非 psycopg（LGPL-3）：契约 v1 只允许 MIT/Apache/BSD/PostgreSQL
            self._conn = _pg_connect(settings.pg_dsn)
            self._conn.autocommit = True
            self.schema = getattr(settings, "pg_schema", "public") or "public"
            cur = self._conn.cursor()
            cur.execute(f'CREATE SCHEMA IF NOT EXISTS "{self.schema}"')
            cur.execute(f'SET search_path TO "{self.schema}"')
        self._migrate()

    def _migrate(self) -> None:
        for stmt in _SCHEMA:
            if self.dialect == "pg":
                stmt = stmt.replace("INTEGER PRIMARY KEY", "BIGSERIAL PRIMARY KEY")
            self.execute(stmt)
        if self.dialect == "sqlite":
            self._conn.commit()

    def _sql(self, sql: str) -> str:
        if self.dialect == "pg":
            return sql.replace("?", "%s")
        return sql

    def _exec(self, sql: str, params: Iterable[Any] = ()):
        """sqlite 的 Connection 直接有 execute；PG（pg8000/DB-API）必须走 cursor。

        这个差异只在真连 PostgreSQL 时暴露：容器里第一次起 api 就是
        AttributeError: 'Connection' object has no attribute 'execute'。
        """
        sql = self._sql(sql)
        if self.dialect == "sqlite":
            return self._conn.execute(sql, tuple(params))
        cur = self._conn.cursor()
        cur.execute(sql, tuple(params))
        return cur

    def execute(self, sql: str, params: Iterable[Any] = ()) -> Any:
        with self._lock:
            cur = self._exec(sql, params)
            if self.dialect == "sqlite":
                self._conn.commit()
            return cur

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[dict]:
        with self._lock:
            cur = self._exec(sql, params)
            rows = cur.fetchall()
            if self.dialect == "sqlite":
                return [dict(r) for r in rows]
            cols = [d[0] for d in (cur.description or [])]
            return [dict(zip(cols, r)) for r in rows]

    def one(self, sql: str, params: Iterable[Any] = ()) -> dict | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def insert(self, table: str, row: dict) -> None:
        cols = ",".join(row)
        ph = ",".join("?" for _ in row)
        self.execute(f"INSERT INTO {table} ({cols}) VALUES ({ph})", list(row.values()))

    def update(self, table: str, key: dict, patch: dict) -> None:
        sets = ",".join(f"{c}=?" for c in patch)
        self.execute(
            f"UPDATE {table} SET {sets} WHERE " + " AND ".join(f"{c}=?" for c in key),
            list(patch.values()) + list(key.values()),
        )

    @contextmanager
    def serialized(self, name: str = "audit"):
        """跨线程/跨进程的串行区（哈希链"读上一行→写本行"必须原子）。

        sqlite：进程内 RLock 即可（sqlite 自己还有文件锁）。
        PostgreSQL：用 advisory lock，键由表名派生，事务外也生效、释放跟随会话。
        不加这层的后果（B1 轮实测）：8 线程 × 50 条并发 append 时，
        多个线程读到同一个 seq/prev_hash，插入时 UNIQUE constraint failed: audit_log.seq，
        400 条只落 51 条 —— 链没断，但数据丢了。
        """
        if self.dialect == "sqlite":
            with self._lock:
                yield
            return
        key = abs(hash(name)) % (2 ** 31 - 1)
        with self._lock:
            self._conn.cursor().execute("SELECT pg_advisory_lock(%s)", (key,))
            try:
                yield
            finally:
                self._conn.cursor().execute("SELECT pg_advisory_unlock(%s)", (key,))

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass


def db_fingerprint(db: DB) -> str:
    """整表指纹：用于“直查数据库看不到明文”的断言辅助。"""
    h = hashlib.sha256()
    for t in ("vault_items", "candidates", "transcripts"):
        for r in db.query(f"SELECT * FROM {t} ORDER BY 1"):
            h.update(json.dumps(r, ensure_ascii=False, sort_keys=True).encode())
    return h.hexdigest()
