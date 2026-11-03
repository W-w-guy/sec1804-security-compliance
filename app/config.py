"""集中配置：全部可用环境变量覆盖，便于 compose / 测试注入。"""
from __future__ import annotations
import os
from dataclasses import dataclass, field


def _int(name: str, dflt: int) -> int:
    try:
        return int(os.environ.get(name, dflt))
    except (TypeError, ValueError):
        return dflt


@dataclass
class Settings:
    # 存储：未设置 PG_DSN 时用内置 sqlite（零依赖，便于干净机器自验）
    pg_dsn: str = os.environ.get("PG_DSN", "")
    sqlite_path: str = os.environ.get("SQLITE_PATH", ":memory:")
    # KMS：file（默认）| vault（HashiCorp Vault KV v2 适配层，可替换）
    kms_backend: str = os.environ.get("KMS_BACKEND", "file")
    kms_dir: str = os.environ.get("KMS_DIR", "./.kms")
    kms_secret: str = os.environ.get("KMS_SECRET", "")   # 测试注入；生产由 KMS 提供
    # JWT
    jwt_secret: str = os.environ.get("JWT_SECRET", "dev-only-change-me")
    jwt_ttl: int = _int("JWT_TTL", 3600)
    # 保留期（天）：按字段配置，到期删除或匿名化
    retain_not_hired_days: int = _int("RETAIN_NOT_HIRED_DAYS", 90)
    retain_transcript_days: int = _int("RETAIN_TRANSCRIPT_DAYS", 30)
    retain_minor_hours: int = _int("RETAIN_MINOR_HOURS", 24)
    retain_hired_days: int = _int("RETAIN_HIRED_DAYS", 180)
    # 审计告警阈值
    alert_view_threshold: int = _int("ALERT_VIEW_THRESHOLD", 20)
    alert_export_threshold: int = _int("ALERT_EXPORT_THRESHOLD", 3)
    alert_window_minutes: int = _int("ALERT_WINDOW_MINUTES", 10)
    # 权利请求时限（小时）
    rights_sla_hours: int = _int("RIGHTS_SLA_HOURS", 360)
    # detokenize 理由最小长度
    reason_min_len: int = _int("REASON_MIN_LEN", 4)
    extra: dict = field(default_factory=dict)


settings = Settings()
