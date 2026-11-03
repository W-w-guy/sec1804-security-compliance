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

    @classmethod
    def ephemeral(cls) -> "Container":
        d = tempfile.mkdtemp(prefix="sec1804-")
        return cls(db_path=os.path.join(d, "test.db"), kms_dir=os.path.join(d, "kms"))

    def close(self):
        self.db.close()
