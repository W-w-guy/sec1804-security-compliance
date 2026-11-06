# CHANGELOG

本文件只记"对外可见的变化"与"验证结论"，不记内部重构细节。

## v0.1.2 —— 修正 v0.1.1 里「环境漂移即失败」的过度矫正

v0.1.1 把 `lock_mismatch` 做成了硬失败，本意是防「报告扫的是本机、不是交付物」。
但它把判据从「报告的内容」挪到了「跑报告的那台机器」：审阅者 `pip install -r requirements.txt`
之后跑 `python tools/verify.py`，他的 transitive 版本不可能和我们的 lock 逐字相同，
于是 `license_scan` 必红 —— 这不是缺陷，是把真缺陷淹掉的噪声。（我自己两次在本机换
解释器复跑就复现了：换到系统 Python，同一条命令红了 10 个包。）

### 变更
- `tools/dep_scan.py`：版本与包集合一律取自 `requirements.lock`，报告内容因此与运行环境无关；
  环境不一致改列 `env_drift`（提示），缺装列 `not_installed`（逐个点名，不静默跳过）；
  `ok` 只看 `deny` / `unknown` 这两个契约项。
- 新增 `--strict-env`：漂移与缺装也算失败，用于「干净 venv 全量自证」那一次记录。
- `tests/test_deps.py`：`test_license_scan_matches_lock` 改为断言真正的不变量 ——
  「已扫 + 点名 = lock 全量」且每个包的 `version` 等于 lock 版本（原来断言环境零漂移，
  等于要求审阅者的机器和我们一模一样）。顺带修掉字段改名后**断言静默通过**的假绿。
- `tools/verify.py`：`unit_tests` 失败时记录 `rc` 与末 25 行输出（原先只有 `detail: null`，
  红了不知道为什么红）；`license_scan` 在有漂移时附 `note`。
- README / OWASP A06 同步口径，并说明漂移是提示而非缺陷。

- `tools/dep_scan.py`：**本机未装的包不再静默跳过** —— 许可与「这台机器装没装」无关，
  原先 `continue` 等于把该包从契约里漏掉（一个 GPL 包只要没装就能溜过去）。现在用静态
  许可表兜底，兜不底记 `unknown` 判失败；报告因此对 lock 全量 36 个包逐一有结论。
- 所有写报告的地方显式 `newline="\n"`：Windows 与 Linux 生成的 `reports/*.json` 现在逐字节一致，
  「复跑同结论」不再受 git 换行归一化影响。
- **新增 `tools/argv_guard.py`：验收脚本不再静默忽略参数。** 起因是实测踩到：
  `loop_verify_h.py --zip ~/ship_x.zip` 当时根本不支持 `--zip`，也不读 `sys.argv`，
  于是它退回去在 `~/` 里命中了一个**旧的** `sec1804_sec5.zip`，把另一份包体验成 PASS。
  验收工具最危险的失败不是报错，是「验错了东西还打勾」。现在 8 个 `loop_verify*.py`
  遇到不认识的参数一律非 0 退出并回显命令行。
- `loop_verify_h.py`：真正支持 `--zip <包>` / `--dir <目录>`，启动时打印
  `[artifact] zip=... `，声明后续检查只针对这一个交付物；`--zip` 指向不存在的文件直接报错。
- `loop_verify_h.py::h8`：README 数字一致性改口径 —— 只要求「当前用例数」被声明，
  README 里标注为历史（当轮记录 / 77 → 90 → 95）的数字不再判红；同时新增
  `stale_current_claims`：未标历史却写着旧数字的，仍然判失败。
- `app/__init__.py` / README 的版本号与 CHANGELOG 对齐到 `0.1.2`（此前代码还停在 0.1.1）。
- `tests/test_deps.py::test_license_scan_matches_lock`：断言收紧为「rows 必须覆盖 lock 全量」，
  并做过变异测试验证它真的会红（见下）。

### 变异测试（验证断言不是摆设）
| 人为注入的缺陷 | 结果 |
|---|---|
| 报告写环境版本而非 lock 版本 | `test_deps` **红** |
| 把「缺装静默跳过」放回去 | `test_deps` **红** |
| 改了 lock 但不重新生成报告（报告过期） | `test_deps` **红** |

### 验证
- 干净 venv（`pip install -r requirements.lock`）：`dep_scan.py --strict-env` → 36 包，
  0 deny / 0 unknown / **0 漂移 / 0 缺装**，`ok=True`。
- 系统 Python（有 10 个包漂移、1 个缺装）：`verify.py` 仍 **6/6 ALL PASS**，漂移如实列在报告里。
- 单测：**95 passed / 0 fail / 0 error**。

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
