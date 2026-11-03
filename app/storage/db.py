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
        created_at TEXT, updated_at TEXT, version INTEGER DEFAULT 1)""",
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
        mode TEXT NOT NULL, rule TEXT NOT NULL, detail TEXT,
        prev_hash TEXT, hash TEXT)""",
    """CREATE TABLE IF NOT EXISTS consent_record (
        id INTEGER PRIMARY KEY,
        candidate_id TEXT NOT NULL, version TEXT NOT NULL,
        channel TEXT NOT NULL, at TEXT NOT NULL, revoked_at TEXT)""",
    """CREATE TABLE IF NOT EXISTS rights_request (
        id TEXT PRIMARY KEY,
        candidate_id TEXT NOT NULL, kind TEXT NOT NULL,
        status TEXT NOT NULL, created_at TEXT NOT NULL,
        due_at TEXT NOT NULL, closed_at TEXT, note TEXT)""",
    """CREATE TABLE IF NOT EXISTS meta (
        k TEXT PRIMARY KEY, v TEXT NOT NULL)""",
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
    """最小存储层：sqlite（零依赖自验）与 PostgreSQL 16（pg8000，BSD）。

    ★ 连接模型（G11 轮实测后重构）：
      原来全局只有一条连接 + 一把 RLock，所有操作（含读）都被串行化，
      8 线程并发读只跑出 1.18 倍加速 —— 读请求被写锁吃掉了。
      现在改为 **每线程一条连接**：
        · sqlite 开 WAL（多读一写），配 busy_timeout 让写冲突等待而不是立刻报错；
        · PG 每线程一条 pg8000 连接，用信号量限制上限，避免把库连爆。
      哈希链的"读上一行→写本行"仍可能撞唯一约束，由 Audit.append 的
      "重读+退避重试"兜住；这比拿全局锁把并发读一起锁死要好得多。
    """

    MAX_PG_CONNS = 16

    def __init__(self, settings: Settings):
        self.settings = settings
        self._lock = threading.RLock()
        self.dialect = "pg" if settings.pg_dsn else "sqlite"
        self.schema = "public"
        self._local = threading.local()
        self._all_conns: list = []
        self._conns_lock = threading.Lock()
        if self.dialect == "pg":
            self.schema = getattr(settings, "pg_schema", "public") or "public"
            self._pg_slots = threading.BoundedSemaphore(self.MAX_PG_CONNS)
        # 主线程先建一条并做迁移，保证 schema 就绪
        _ = self._conn
        self._migrate()

    # ---------- 连接管理 ----------
    @property
    def _conn(self):
        c = getattr(self._local, "conn", None)
        if c is not None:
            return c
        if self.dialect == "sqlite":
            path = self.settings.sqlite_path
            c = sqlite3.connect(path, check_same_thread=False, timeout=30)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            c.execute("PRAGMA busy_timeout=30000")
        else:  # pragma: no cover
            # 用 pg8000（BSD-3）而非 psycopg（LGPL-3）：契约 v1 只允许 MIT/Apache/BSD/PostgreSQL
            self._pg_slots.acquire()
            c = _pg_connect(self.settings.pg_dsn)
            c.autocommit = True
            cur = c.cursor()
            cur.execute(f'CREATE SCHEMA IF NOT EXISTS "{self.schema}"')
            cur.execute(f'SET search_path TO "{self.schema}"')
        self._local.conn = c
        with self._conns_lock:
            self._all_conns.append(c)
        return c

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
        # 不加进程级锁：读并发靠每线程独立连接；写冲突靠 sqlite busy_timeout /
        # PG 唯一约束 + 上层重试（G11 轮：加锁会让 8 线程读退化成串行）
        cur = self._exec(sql, params)
        if self.dialect == "sqlite":
            self._conn.commit()
        return cur

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[dict]:
        cur = self._exec(sql, params)
        rows = cur.fetchall()
        if self.dialect == "sqlite":
            return [dict(r) for r in rows]
        cols = [d[0] for d in (cur.description or [])]
        return [dict(zip(cols, r)) for r in rows]

    def one(self, sql: str, params: Iterable[Any] = ()) -> dict | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def cursor_exec(self, sql: str, params: Iterable[Any] = ()):
        """执行 DDL / 非标准语句（备份、schema 操作）。走同一个连接，保持 search_path 一致。"""
        return self.execute(sql, params)

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
            # sqlite 的写操作本身由文件锁串行化；这里不再加进程级 RLock，
            # 否则会把"所有读请求"也串起来（G11 轮实测并发读加速只有 1.18 倍）。
            # 链式 append 的竞态由 Audit.append 的"插入失败→重读上一行→重试"解决。
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
        with self._conns_lock:
            conns, self._all_conns = list(self._all_conns), []
        for c in conns:
            try:
                c.close()
            except Exception:                       # noqa: BLE001
                pass
        self._local = threading.local()


def db_fingerprint(db: DB) -> str:
    """整表指纹：用于“直查数据库看不到明文”的断言辅助。"""
    h = hashlib.sha256()
    for t in ("vault_items", "candidates", "transcripts"):
        for r in db.query(f"SELECT * FROM {t} ORDER BY 1"):
            h.update(json.dumps(r, ensure_ascii=False, sort_keys=True).encode())
    return h.hexdigest()
