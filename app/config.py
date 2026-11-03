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
    # PG 模式下用独立 schema 隔离（等价于 sqlite 的"每个实例一个文件"）。
    # 默认 public；测试/多租同时可指定，避免互串数据把哈希链搞脏。
    pg_schema: str = os.environ.get("PG_SCHEMA", "public")
    sqlite_path: str = os.environ.get("SQLITE_PATH", ":memory:")
    # KMS：file（默认）| vault（HashiCorp Vault KV v2 适配层，可替换）
    kms_backend: str = os.environ.get("KMS_BACKEND", "file")
    kms_dir: str = os.environ.get("KMS_DIR", "./.kms")
    kms_secret: str = os.environ.get("KMS_SECRET", "")   # 测试注入；生产由 KMS 提供
    # Webhook 签名密钥（契约 v1：事件 HMAC-SHA256）
    webhook_secret: str = os.environ.get("WEBHOOK_SECRET", "dev-webhook-secret-change-me")
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
    # 保险箱单字段值上限（防超长值撑爆密文/审计）
    max_value_len: int = _int("MAX_VALUE_LEN", 256)
    # 限流：同 actor 同动作在窗口内的最大失败次数（0 = 关闭）
    rate_limit_window: int = _int("RATE_LIMIT_WINDOW", 60)
    rate_limit_max: int = _int("RATE_LIMIT_MAX", 30)
    extra: dict = field(default_factory=dict)


settings = Settings()
