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
        # sqlite 只允许一个写者。**只串行化写**（不是所有语句）：
        # 早先试过"全局锁"，8 线程并发读退化成 1.18 倍加速（G11 因此重写过一次）。
        # 现在读走各自连接并行，写在这里排队——这正是 sqlite WAL 的设计意图。
        self._write_lock = threading.Lock()
        self._wal_done = False
        # sqlite 的写连接只有这一条，只在 _write_lock 内使用。
        # 这样"多个连接同时持写事务互相等"这种情况在结构上就不存在。
        self._wconn: sqlite3.Connection | None = None
        # ★ :memory: 不能用"另一条写连接"：sqlite 的 :memory: 库是**每个连接一份**，
        #   另开一条连接去看就是一个空库（实测表现：pytest 收集阶段 no such table: meta）。
        #   所以内存库走"本线程连接 + 写锁"，落盘库走"唯一写连接"。
        _p = getattr(settings, "sqlite_path", "") or ""
        self._mem_sqlite = (":memory:" in _p) or ("mode=memory" in _p) or _p == ""
        if self.dialect == "pg":
            self.schema = getattr(settings, "pg_schema", "public") or "public"
            self._pg_slots = threading.BoundedSemaphore(self.MAX_PG_CONNS)
        # 主线程先建一条并做迁移，保证 schema 就绪
        _ = self._conn
        self._wal_done = True
        self._migrate()

    # ---------- 连接管理 ----------
    @property
    def _conn(self):
        c = getattr(self._local, "conn", None)
        if c is not None:
            return c
        if self.dialect == "sqlite":
            path = self.settings.sqlite_path
            c = sqlite3.connect(path, check_same_thread=False, timeout=5)
            c.row_factory = sqlite3.Row
            # ★ journal_mode 只在**第一条连接**（__init__ 里主线程那条）上设一次。
            #   原来每条新连接都执行 PRAGMA journal_mode=WAL：库里已是 WAL 时它是空操作，
            #   但首次并发建立连接时该 pragma 需要短暂排他锁，16 个线程同时抢，
            #   和"握住写锁等锁"的那条线程互相等 —— B2 表现为整体卡死不返回。
            #   busy_timeout / synchronous 是"每连接"设置，不需要锁，可以每条连接都设。
            if not self._wal_done:
                c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            c.execute("PRAGMA busy_timeout=5000")
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

    # sqlite 只读事务升级成写事务时，busy_timeout **不生效**（立刻返回 SQLITE_BUSY），
    # 表现为 OperationalError: database is locked。这是 sqlite 的已知语义，不是配置问题：
    # PRAGMA busy_timeout=30000 只能让"一开始就拿写锁"的语句等待，救不了锁升级。
    # B 组并发 tokenize 实测：32 线程同号并发，偶发 1 次 locked → B2 红。
    # 所以在这一层做有界重试（退避 5ms 起、上限 200ms），保证并发写不因时序差异假失败。
    _LOCK_RETRY = 8

    def _retrying(self, fn):
        if self.dialect != "sqlite":
            return fn()
        import time as _t
        delay = 0.005
        for attempt in range(self._LOCK_RETRY):
            try:
                return fn()
            except sqlite3.OperationalError as e:
                msg = str(e).lower()
                if "locked" not in msg and "busy" not in msg:
                    raise
                try:
                    self._conn.rollback()
                except Exception:                   # noqa: BLE001
                    pass
                if attempt == self._LOCK_RETRY - 1:
                    raise
                _t.sleep(delay)
                delay = min(delay * 2, 0.2)
        raise AssertionError("unreachable")

    def execute(self, sql: str, params: Iterable[Any] = ()) -> Any:
        """写路径（DDL/DML 都走这里）。

        ★ 2026-11-06 第三次改连接模型，原因要写清楚：
          第一版：全局 RLock 覆盖所有语句 → 读也被串行，G11 只有 1.18 倍加速。
          第二版：完全不加锁 + busy_timeout=30s → 16 线程并发写同一行时，
                  多个连接都卡在 sqlite3 C 调用里等锁，30 秒的等待互相叠加，
                  B2 从"偶发 database is locked"变成"整体卡死不返回"（faulthandler 抓到
                  16 个 worker 全停在 _exec 的 C 调用里）。这比直接报错更糟：不报错、也不结束。
          现在：**只锁写**。sqlite 本身只允许一个写者，排队是事实而不是妥协；
                读仍走各自连接并行（G11 复测见 README）。
        """
        if self.dialect == "sqlite":
            with self._write_lock:
                return self._retrying(lambda: self._write_exec(sql, params))
        cur = self._conn.cursor()
        cur.execute(self._sql(sql), tuple(params))
        return cur

    def _write_exec(self, sql: str, params: Iterable[Any] = ()):
        """sqlite 专用：**唯一一条写连接**上的写操作（调用方必须已持 _write_lock）。

        为什么必须是"唯一一条写连接"（第三次踩坑后的结论）：
          每条线程各用各的连接去写，等于让 sqlite 的文件锁去仲裁 16 个写事务。
          一旦某个连接在 C 层等锁（busy handler 最多等 5 秒），而它又握着进程内的
          _write_lock，其它线程就只能干等 —— faulthandler 抓到的现场是
          「1 个线程卡在 cur.execute，3 个线程卡在 with self._write_lock」，
          整体不报错、也不结束。这比直接报错更难查。
          改成单写连接后：进程内锁 + 单连接，写路径只有一层排队，没有锁升级问题。
        """
        if self._mem_sqlite:                    # 内存库：只能复用本线程的连接
            cur = self._conn.execute(sql, tuple(params))
            self._conn.commit()
            return cur
        if self._wconn is None:
            c = sqlite3.connect(self.settings.sqlite_path, check_same_thread=False, timeout=5)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA synchronous=NORMAL")
            c.execute("PRAGMA busy_timeout=5000")
            self._wconn = c
        cur = self._wconn.execute(sql, tuple(params))
        self._wconn.commit()
        return cur

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[dict]:
        cur = self._retrying(lambda: self._exec(sql, params))
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
        with self._write_lock:
            if self._wconn is not None:
                try:
                    self._wconn.close()
                except Exception:                   # noqa: BLE001
                    pass
                self._wconn = None
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
