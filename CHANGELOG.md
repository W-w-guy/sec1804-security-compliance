# CHANGELOG

本文件只记"对外可见的变化"与"验证结论"，不记内部重构细节。

## v0.1.1 —— 依赖漏洞扫描补齐（验收点 7 修正）

**这是一次缺陷修复，不是一个新特性。** 首版只在验收点 7 交了「许可证扫描」，却把 OWASP A06
写成「已控制」，也没有对依赖做 CVE 比对 —— 而验收点 7 的原文是「依赖扫描 … **无未处理的高危项**」。
按当时钉住的版本实测，`pg8000==1.31.2` 有 HIGH（GHSA-wq2g-r956-j8cc，SQL 注入），
`cryptography==44.0.0` 有 6 条公告（含 4 个 HIGH）。单测之所以长期全绿，是因为运行环境里
装的是后来更新的修复版，而 `requirements.txt` 钉的是带洞的旧版。

### 变更
- 新增 `tools/cve_scan.py`：向 OSV.dev 批量查询，输出 `reports/cve_scan.json`；
  `--offline` 只复核已提交报告与当前 lock 是否一致（无外网也能验真）。
- 新增 `requirements.lock`：干净 venv 里 `pip freeze` 出的全闭包 36 个包，作为唯一事实源。
- `requirements.txt` / `requirements-dev.txt` 对齐到实测版本（`cryptography==50.0.2`、`pg8000==1.31.6`、
  `fastapi==0.162.0`、`uvicorn==0.54.0`、`pydantic==2.13.5`）。
- `tools/dep_scan.py` 扫描对象改为 lock 全闭包，并输出 `lock_mismatch`：环境与 lock 不一致即失败。
- `tools/verify.py` 增加第六步 `cve_scan`（原先只有 `license_scan`）。
- 新增 `tests/test_deps.py`（5 项）：钉住版本必须与 lock 逐字一致、报告不得过期、
  不许留 HIGH/CRITICAL、许可扫描覆盖率不得只扫种子。
- `Dockerfile` 改按 `requirements.lock` 安装：镜像内的版本必须与扫描过的版本一致。
- `tools/loop_verify_h.py` 的 H5/H8 去掉硬编码数字，改为按 `verify.py` 实际步骤数与
  实际收集到的用例数比对（写死 `90 passed` / `>=5 步` 只会让检查在变化时假绿或假红）。
- OWASP A06 与 README 如实记录这次缺陷、当时的版本、公告编号与修复版本。

### 验证
- 单测：**95 passed / 0 fail / 0 error**（Windows 11 · Python 3.11.7；Ubuntu 24.04 · Python 3.12.3）
- `tools/verify.py`：**6/6 PASS**，双平台
- `tools/dep_scan.py`：`deps=36 denied=0 unknown=0 lock_mismatch=0 ok=True`
- `tools/cve_scan.py`：`packages=36 with_vulns=0 unhandled=0 ok=True`
- `tools/loop_verify_h.py`：H 组 15/15（含 H1「交付 zip 与 HEAD 逐字节一致」）

### 已知边界（新增一条）
5. CVE 扫描依赖 OSV.dev 的公开数据；对「已公开公告」有效，不覆盖未公开的 0day。
   扫描时点被记录在 `reports/cve_scan.json`，验收人可自行重跑复核。

## v0.1.0 —— 首版交付

按【共用接口契约 v1】实现任务 5/5 数据安全与合规模块，并通过八组共 105 轮 + 90 项单测验证（双平台：Windows 11 与 Ubuntu 24.04 容器内真 PostgreSQL 16 + 真 Vault 1.18）。

### 功能
- 个人信息保险箱：字段级 AES-256-GCM，KMS 适配层（file / HashiCorp Vault KV v2），密钥轮换与回滚
- 脱敏工具库：姓名/手机号/身份证/银行卡/地址/邮箱六类，〔类型_序号〕占位符，可受控回填
- RBAC：5 角色 + 城市/站点数据范围 + 敏感操作单次限时审批
- 审计：只追加哈希链，可逐行定位篡改，异常行为告警入链
- 保留与删除：按字段保留期、未成年人 24h、撤回同意即删，删除记录本身亦有链
- 同意与权利请求：版本/时间/渠道留痕，查看/更正/删除/副本 SLA 跟踪
- 事件：outbox + HMAC-SHA256 签名，可拉取/确认

### 验证（八组 105 轮 + 90 单测）
| 组 | 主题 | 轮数 |
|---|---|---|
| A | 功能面 | 10 |
| B | 并发 / 跨方言 / 边界 / KMS 后端 | 10 |
| C | 安全对抗（红队） | 15 |
| D | 一致性与故障恢复 | 15 |
| E | 并发正确性与接口边界 | 15 |
| F | 可运维性与可审计性 | 15 |
| G | 性能与容量 | 15 |
| H | 交付形态 | 15 |

累计挖出并修复 **34 个缺陷**，其中 14 个只有单平台或真实部署环境（真 PostgreSQL / 真 Vault / Linux 权限位）才能暴露。

### 已知边界（如实声明）
1. 姓名识别是规则 + 上下文锚点，无训练模型；真实语料（方言昵称、少数民族名、单字名）会有漏检。
2. 读必留痕 → 每次读取都写一条审计，读吞吐被审计写吞吐封顶（sqlite 单写者约 3400 ops/s）。
3. 多副本部署时进程内限流各自计数；全局精确限流需换 Redis 计数。
4. 密钥与数据同被拷走时可解密（AES 必然结果）；缓解靠 Vault/KMS 分离、磁盘加密、最小权限。
