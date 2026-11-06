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
| A06 | 易受攻击/过时组件 | **两件事分开做**：许可白名单（`dep_scan.py`）+ CVE/GHSA 漏洞扫描（`cve_scan.py`，查 OSV.dev）。版本由 `requirements.lock` 单一事实源锁定，扫描对象 = lock 全闭包（与跑在谁的机器上无关） | `reports/dep_scan.json`（36 个依赖，0 deny / 0 unknown，clean venv 内 0 漂移 / 0 缺装）、`reports/cve_scan.json`（36 个依赖，**0 条未处理，0 条 HIGH/CRITICAL**）、`tests/test_deps.py` 5 项不变量守护（含「报告覆盖率 = lock 全量」） | 已控制 |
| A07 | 身份认证失效 | HS256 JWT（stdlib hmac，常量时间比较）、exp 校验、角色枚举校验 | `app/auth.py` `hmac.compare_digest`；`test_role_missing_permission` | 已控制 |
| A08 | 数据完整性失效 | 审计哈希链只追加；篡改可逐行定位；告警本身入链 | `tests/test_audit.py` 7 项 | 已控制 |
| A09 | 日志与监控失效 | 查看/导出/配置变更全量入审计；单人短时大量查看/导出触发告警 | `test_bulk_view_triggers_alert`、`test_export_threshold_alert` | 已控制 |
| A10 | SSRF | 本模块不发起任何外部 HTTP；KMS Vault 后端地址来自环境变量白名单式配置 | `grep -r "urlopen\|requests\." app/` 仅 `VaultKMS` 一处且地址可配 | 已控制（接入外部模型时由任务 1/3 负责） |

## 依赖：许可与漏洞（A06 明细）

扫描对象是 **`requirements.lock` 全闭包 36 个包**——即交付物 `pip install` 后实际安装的那组版本。
锁文件由干净 venv 里 `pip freeze` 生成，`90+5` 项单测就是在这组版本上跑通的。

### 1) 许可证（`tools/dep_scan.py` -> `reports/dep_scan.json`）

```
$ python tools/dep_scan.py
scope=requirements.lock 全闭包（版本以 lock 为准） deps=36 denied=0 unknown=0 env_drift=0 not_installed=0 strict_env=False ok=True
```

全部落在契约白名单内：MIT / Apache-2.0 / BSD-2-Clause / BSD-3-Clause / PSF-2.0 / MPL-2.0（certifi，仅 httpx 测试依赖）。
**无 GPL / AGPL / LGPL / SSPL。**

过程中修掉的一个真实问题：初版用 `psycopg[binary]` 连 PostgreSQL，其许可为 **LGPL-3.0**，
不在契约允许范围内。已换成 `pg8000`（BSD-3）。

### 2) 漏洞（`tools/cve_scan.py` -> `reports/cve_scan.json`，数据源 OSV.dev）

```
$ python tools/cve_scan.py
packages=36 with_vulns=0 unhandled=0 ok=True
```

**这一项是 2026-11-06 补的，补的过程本身就是一个应该被记录的缺陷。**

初版只做了许可扫描，却把 OWASP A06 写成「已控制」，标书里也只能写「CVE 比对未做」——
而验收点 7 要求的是「依赖扫描 … **无未处理的高危项**」。按 OSV 对当时钉住的版本实测：

| 依赖 | 当时钉的版本 | 公告 | 等级 | 修复版本 |
|---|---|---|---|---|
| `pg8000` | 1.31.2 | GHSA-wq2g-r956-j8cc（SQL 注入） | **HIGH** | 1.31.5 |
| `cryptography` | 44.0.0 | 6 条（OpenSSL / PKCS#7 / 子群攻击） | **4×HIGH** | 48.0.1 ~ 50.0.0 |
| `fastapi` -> `starlette` | 0.115.6 -> 0.41.3 | 11 条 | 含 HIGH | 随 fastapi 升级 |

**为什么一直没发现**：单测跑的是本机后来装的 `cryptography 50.0.2 / pg8000 1.31.6`，
而 `requirements.txt` 钉的是有漏洞的旧版——「测试全绿」和「交付物有 HIGH」同时成立。

现在的做法（三道机器可检查的不变量，见 `tests/test_deps.py`）：

1. `requirements.txt` / `requirements-dev.txt` 里每一个钉住的版本，必须在 `requirements.lock` 里逐字一致；
2. 已提交的 `reports/cve_scan.json` 的版本快照必须等于当前 `requirements.lock`（报告不能过期）；
3. 报告里不许有 `HIGH` / `CRITICAL` 未处理项；有 CRITICAL 的必须有修复版本。

`tools/verify.py` 的 `cve_scan` 步与 `license_scan` 步分别对应这两件事，任一不过即 `RESULT: FAILED`。
`cve_scan.py --offline` 不联网，只复核已提交报告与 lock 是否一致——验收人没有外网也能验真。

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
