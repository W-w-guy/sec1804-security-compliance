"""依赖容器：一处装配，测试可注入临时库 / 临时 KMS 目录 / 固定时钟。"""
from __future__ import annotations
import os
import tempfile

from app.audit import Audit
from app.config import Settings
from app.consent import Consent
from app.idempotency import Idempotency
from app.kms import FieldCipher, build_kms
from app.outbox import Outbox
from app.masking import MaskingSession  # noqa: F401  (对外暴露)
from app.rbac import Approvals
from app.retention import Retention
from app.storage.db import DB
from app.vault import Vault


class Container:
    def __init__(self, settings: Settings | None = None, db_path: str | None = None,
                 kms_dir: str | None = None, pg_schema: str | None = None):
        self.settings = settings or Settings()
        if pg_schema:
            self.settings.pg_schema = pg_schema
        if db_path:
            self.settings.sqlite_path = db_path
        if kms_dir:
            self.settings.kms_dir = kms_dir
        self.db = DB(self.settings)
        self.kms = build_kms(self.settings)
        self.cipher = FieldCipher(self.kms)
        self.audit = Audit(self.db, self.settings)
        # 顺序有依赖：outbox 先于 consent（consent 要发事件）
        self.outbox = Outbox(self.db, self.settings.webhook_secret, self.audit)
        self.retention = Retention(self.db, self.audit, self.settings)
        self.vault = Vault(self.db, self.cipher, self.kms, self.audit, self.settings)
        self.consent = Consent(self.db, self.audit, self.settings, self.retention, self.outbox)
        self.approvals = Approvals(self.db)
        self.idem = Idempotency(self.db)
        self._verify_kms_binding()

    CONFIG_KEYS = ("retain_not_hired_days", "retain_transcript_days", "retain_minor_hours",
                   "retain_hired_days", "alert_view_threshold", "alert_export_threshold",
                   "alert_window_minutes", "rights_sla_hours", "reason_min_len",
                   "max_value_len", "bulk_max_items", "rate_limit_window", "rate_limit_max")

    def config_update(self, actor: str, patch: dict, now: float | None = None) -> dict:
        """改运行期配置并留痕。

        F12 轮暴露的口径问题：保留期、告警阈值这些直接影响合规的配置，
        原来只能改环境变量重启，**没有任何痕迹**说不清"谁在什么时候把 90 天改成 30 天"。
        """
        unknown = set(patch) - set(self.CONFIG_KEYS)
        if unknown:
            raise ValueError(f"不可改的配置项: {sorted(unknown)}")
        changes = {}
        for k, v in patch.items():
            old = getattr(self.settings, k)
            if old != v:
                changes[k] = {"old": old, "new": v}
                setattr(self.settings, k, v)
        if changes:
            self.audit.append(actor, "admin", "config.changed", target="settings",
                              detail=changes, now=now)
        return {"changed": changes, "effective": {k: getattr(self.settings, k) for k in patch}}

    def _verify_kms_binding(self) -> None:
        """把"这份数据是用哪套密钥加密的"固化下来，防静默换钥。

        首次启动：写入当前密钥指纹。
        之后启动：指纹不一致 → 抛错（宁可起不来，也不要拿错密钥去读别人的 PII）。
        """
        from app.kms import key_fingerprint
        fp = key_fingerprint(self.kms)
        row = self.db.one("SELECT v FROM meta WHERE k='kms_fingerprint'")
        used = self.db.one("SELECT COUNT(*) AS c FROM vault_items")["c"]
        if row is None:
            # 有数据却没指纹 = 老库升级：以当前密钥为准补写，但必须留痕
            self.db.insert("meta", {"k": "kms_fingerprint", "v": fp})
            if used:
                self.audit.append("system", "system", "kms.fingerprint.adopted",
                                  target="kms", detail={"fingerprint": fp[:16], "rows": used})
            return
        if row["v"] != fp:
            raise RuntimeError(
                "KMS 与数据不匹配：库里的密钥指纹与当前 KMS 不一致。"
                "常见原因=密钥文件丢失/被替换/挂载错了。拒绝启动以免用错密钥读 PII。"
                f" (db={row['v'][:16]} current={fp[:16]} rows={used})")

    @classmethod
    def ephemeral(cls) -> "Container":
        d = tempfile.mkdtemp(prefix="sec1804-")
        return cls(db_path=os.path.join(d, "test.db"), kms_dir=os.path.join(d, "kms"))

    def close(self):
        self.db.close()
