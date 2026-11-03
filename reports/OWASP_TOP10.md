# OWASP Top 10 (2021) 自测清单与结果

范围：本模块（任务 5/5 数据安全与合规）。方法：代码走查 + 用例验证 + 依赖扫描。
结论：**无未处理的高危项**；剩余项为设计边界，已列明。

| # | 风险 | 本模块控制 | 证据 | 结论 |
|---|---|---|---|---|
| A01 | 越权访问 | RBAC 5 角色 + 城市/站点双重范围；明文与导出须单次限时审批 | `tests/test_rbac.py` 对 5 角色参数化越权；`approval_is_single_use` / `approval_expires` | 已控制 |
| A02 | 加密失效 | 字段级 AES-256-GCM，AAD 绑定字段类型；密钥与数据分离；支持轮换与重加密 | `test_rotation_old_data_still_decrypts`、`test_aad_binds_type_ciphertext_not_cross_decryptable`、`test_plaintext_never_in_db` | 已控制 |
| A03 | 注入 | 所有 SQL 走参数化（sqlite `?` / PG `%s`，无字符串拼接用户输入）；无 shell 调用 | `app/storage/db.py` 全部 `execute(sql, params)`；`grep` 无 f-string 拼接 WHERE | 已控制 |
| A04 | 不安全设计 | 默认拒绝；审批与理由强制；脱敏先于一切外发；保留期默认最短 | `errors.py` 401/403 默认拒绝；`reason_min_len`；`RETAIN_*` 默认 90/30/24 | 已控制 |
| A05 | 安全配置错误 | CORS 未开启、无默认口令、容器非 root（uid 10001）、健康检查 | `Dockerfile` `USER appuser`；`JWT_SECRET` 必须由环境注入 | 已控制（部署需改 JWT_SECRET） |
| A06 | 易受攻击/过时组件 | 依赖闭包扫描 + 许可白名单；非白名单许可直接判失败 | `tools/dep_scan.py`、`reports/dep_scan.json`（**22 个依赖，0 deny，0 unknown**） | 已控制 |
| A07 | 身份认证失效 | HS256 JWT（stdlib hmac，常量时间比较）、exp 校验、角色枚举校验 | `app/auth.py` `hmac.compare_digest`；`test_role_missing_permission` | 已控制 |
| A08 | 数据完整性失效 | 审计哈希链只追加；篡改可逐行定位；告警本身入链 | `tests/test_audit.py` 7 项 | 已控制 |
| A09 | 日志与监控失效 | 查看/导出/配置变更全量入审计；单人短时大量查看/导出触发告警 | `test_bulk_view_triggers_alert`、`test_export_threshold_alert` | 已控制 |
| A10 | SSRF | 本模块不发起任何外部 HTTP；KMS Vault 后端地址来自环境变量白名单式配置 | `grep -r "urlopen\|requests\." app/` 仅 `VaultKMS` 一处且地址可配 | 已控制（接入外部模型时由任务 1/3 负责） |

## 依赖与许可（A06 明细）

扫描范围：`requirements.txt` 依赖闭包（非整机环境），共 **22** 个。

```
$ python tools/dep_scan.py
scope=requirements.txt 依赖闭包 deps=22 denied=0 unknown=0 ok=True
```

许可分布（全部落在契约白名单内）：
MIT（fastapi / pydantic / pydantic-core / starlette 用 BSD / anyio / sniffio / sniffio /
click 用 BSD / h11 / typing-extensions 用 PSF / scramp / asn1crypto / six）、
Apache-2.0（cryptography 双许可 / opentelemetry-api / python-dateutil 双许可）、
BSD-3-Clause（uvicorn / starlette / click / idna / pycparser / pg8000 / httpcore / httpx / pytest）、
PSF-2.0（typing-extensions）、MPL-2.0（certifi，未在本闭包）。**无 GPL / AGPL / LGPL / SSPL。**

**过程中修掉的一个真实问题**：初版用 `psycopg[binary]` 连 PostgreSQL，其许可为
**LGPL-3.0**，不在契约允许的 MIT / Apache-2.0 / BSD / PostgreSQL 之列。已换成
`pg8000`（BSD-3），`app/storage/db.py` 的 PG 分支随之改为 DB-API 调用（`%s` 占位符、
`cursor.description` 取列名）。同时删掉了从未使用的 `redis` 客户端依赖（Redis 7.2
仍由 compose 提供，供平台其它任务使用；本模块不需要客户端即可满足验收）。

换库连带踩的两个坑（都只在真连 PostgreSQL 时暴露，Windows 上无 PG 永远看不到）：

1. `pg8000.dbapi.connect(dsn=...)` → `TypeError: connect() got an unexpected keyword
   argument 'dsn'`。pg8000 没有 dsn 参数，必须自己 `urlparse` 拆成
   user/password/host/port/database 逐项传。已封装 `_pg_connect()`。
2. `sqlite3.Connection` 有 `execute()`，`pg8000` 的 `Connection` **没有**，必须
   `cursor().execute()`。容器第一次起 api 就直接
   `AttributeError: 'Connection' object has no attribute 'execute'` 退出。
   已改 `DB._exec()` 按方言分流。

## 渗透自测要点（自测，非第三方）

| 用例 | 输入 | 期望 | 结果 |
|---|---|---|---|
| 伪造签名 | 改 JWT payload 一位 | 401 `bad_signature` | 通过 |
| 过期令牌 | `exp` 早于当前 | 401 `token_expired` | 通过 |
| 跨城市直取 | 杭州专员读深圳候选人 | 403 `out_of_scope` | 通过 |
| 明文直取 | 管理员不带审批 `full=true` | 403 `approval_required` | 通过 |
| 审批重放 | 同一审批用两次 | 第二次 403 | 通过 |
| 审计删行 | `DELETE FROM audit_log WHERE seq=4` | `missing_seq=[4]` | 通过 |
| 密文跨字段重放 | 手机号密文按 name 类型解 | `InvalidTag` | 通过 |
| token 枚举 | 猜 26 位 base64 token | 404 `token_not_found` | 通过（token 为 HMAC 派生，不可枚举） |
