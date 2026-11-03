# 任务 5/5：数据安全与合规模块（骑手招聘 Agent 化信息收集平台）

按【共用接口契约 v1】实现，REST 前缀 `/api/v1`，错误体统一 `{code, message}`，
OpenAPI 由 FastAPI 自动生成（`/docs`、`/openapi.json`）。本模块只做安全与合规，
不含业务功能；不依赖其它任务的实现，对方接口按契约自带 mock 思路处理（见下）。

## 60 秒跑起来（桌面机，无需 Docker / 无需数据库）

```bash
python -m pip install -r requirements.txt      # 6 个依赖
python run.py demo                             # 六条验收链路一次性跑通
python -m pytest tests/ -q                     # 全部单测
python tools/verify.py                         # 一键验收（含召回率/篡改定位/许可扫描）
```

全栈（PostgreSQL 16 + Redis 7.2 + Vault + API）：

```bash
docker compose up --build        # 干净机器上一条命令
curl -s localhost:8080/health    # {"status":"ok", ...}
```

## 目录

```
app/
  config.py      全部环境变量化（保留期、阈值、KMS 后端、JWT）
  errors.py      统一错误体 ApiError{code,message} 及 401/403/404/409
  storage/db.py  单文件存储层：sqlite（零依赖自验）/ PostgreSQL 16（pg8000，BSD）
  kms.py         KMS 适配层（file / HashiCorp Vault KV v2 可替换）+ 字段级 AES-256-GCM
  vault.py       保险箱：tokenize / detokenize / 掩码 / 密钥轮换（可重加密）
  masking.py     脱敏工具库：6 类实体，〔类型_序号〕占位符，可 restore 回填
  rbac.py        RBAC 5 角色 + 城市/站点数据范围 + 敏感操作审批（单次、限时）
  audit.py       审计哈希链：只追加、逐行校验、定位被改行、异常告警入链
  retention.py   保留与删除：按字段保留期、未成年人 24h、撤回同意即删、留删除记录
  consent.py     同意（版本/时间/渠道）+ 权利请求（查看/更正/删除/副本，SLA 跟踪）
  service.py     候选人服务：创建即 tokenize、默认掩码、明文与导出须审批
  main.py        FastAPI 装配（create_app 便于测试注入）
tools/
  gen_samples.py   生成 ≥200 条合成样本（种子固定，可复现）
  eval_masking.py  召回率 / 误报率评估
  dep_scan.py      依赖闭包许可扫描（只允许 MIT/Apache/BSD/PostgreSQL）
  pg_smoke.py      PostgreSQL 直连冒烟
  verify.py        一键验收，产出 reports/verify_<platform>.json
data/
  samples_200.csv          228 条合成样本（200 主体 + 边界）
  holdout_adversarial.csv  38 条人工对抗样本（不参与调参，只用来说实话）
reports/
  verify_windows.json / verify_linux.json / dep_scan.json / OWASP_TOP10.md
```

## 六个验收点怎么对上

| 验收要求 | 实现 | 用例 |
|---|---|---|
| 1 tokenize/detokenize 可用；直查库看不到明文；轮换后旧数据可解 | `app/vault.py` + `app/kms.py`，密文与 key_version 同行存储，AAD 绑定字段类型防跨字段重放 | `tests/test_vault.py`（8 项，含 AAD 错配必须抛 InvalidTag） |
| 2 ≥200 条样本；手机号/身份证 100%，姓名/地址 ≥95%，写明误报率 | `data/samples_200.csv`（228 条）+ `data/holdout_adversarial.csv`（38 条）| `tests/test_masking.py` + `tools/eval_masking.py`；实测数字见下 |
| 3 无权限或未写理由 detokenize 被拒，两种情况都写审计 | `Vault.detokenize` 先判权限再判理由，两条分支各写 `vault.detokenize.denied` | `test_detokenize_denied_without_permission_and_audited`、`..._without_reason_and_audited` |
| 4 篡改审计任意一行能指出位置 | `Audit.verify()` 逐行重算 + `Audit.locate(seq)` 给字段级差异；断号另报 `missing_seq` | `test_tamper_any_row_is_located`（1/4/9 三处）、`test_delete_row_leaves_gap` |
| 5 时间快进清理 + 撤回同意立即删除 + 留记录 | `Retention.run(now=...)` 全部入口接受注入时钟；`deletion_log` 记录规则/模式 | `tests/test_retention.py`（7 项） |
| 6 越权被拒，每个角色都有用例 | `rbac.enforce_scope` 城市+站点双重判定 | `tests/test_rbac.py` 对 5 个角色逐个参数化越权 |
| 7 依赖扫描 + OWASP 自测报告，无未处理高危 | `tools/dep_scan.py` + `reports/OWASP_TOP10.md` | `verify.py` 的 license_scan 步骤 |
| 8 一条命令全绿 + 验证记录 | `python -m pytest tests/ -q`；记录见下节 | — |

## 验证记录（命令、输入、期望输出；复跑同结论）

### A. 全量单测（一条命令）

```
$ python tools/run_tests.py
77 passed
```
期望：`77 collected / 77 passed`，0 failed。复跑一致（无随机、无网络、无时钟依赖）。
两平台实测：**Windows 11 / Python 3.11.7 → 77 passed**；**Ubuntu 24.04 / Python 3.12.3 → 77 passed**。

> 为什么要包装一层 `tools/run_tests.py` 而不是直接 `python -m pytest`：
> 机器上若装了 ROS2，`/opt/ros/*/lib/python3.12/site-packages` 里的 `launch_testing`
> 会被 pytest 当作 `pytest11` 插件自动加载，它 `import yaml`，干净 venv 没装 pyyaml
> → pytest 在**收集阶段**退出码 3，一条用例都没跑。`-p no:launch_testing` 也不行，
> 还有第二个入口点会因未知 hook 触发 INTERNALERROR。包装器关掉插件自动加载即可。
> **这个坑 Windows 上永远看不到**——这就是"双平台各跑一遍"的价值。

### B. 脱敏召回与误报（合成集 228 条）

```
$ python tools/eval_masking.py samples_200.csv
手机号   129/129 = 1.0000   误报率 0.0000
身份证号  33/33  = 1.0000   误报率 0.0000
银行卡号  33/33  = 1.0000   误报率 0.0000
地址      94/94  = 1.0000   误报率 0.0000
姓名     124/124 = 1.0000   误报率 0.0000
```

### C. 人工对抗集（38 条，独立于调参，含陷阱）

```
$ python tools/eval_masking.py holdout_adversarial.csv
手机号   12/12 = 1.0000
身份证号  3/3   = 1.0000
银行卡号  4/4   = 1.0000
地址     10/10 = 1.0000
姓名     12/12 = 1.0000
邮箱      1/1   = 1.0000
误报：0（含“手机尾号8000”“我们站点在文一西路”“13800138000O 多打一位字母”
       “订单号 2026110300012345678”等负例）
```

> 说明：`holdout_adversarial.csv` 是我写完后另行手写、**不参与调参**的集合。第 1 版
> 在这份集合上暴露了 11 个缺陷（地址吞号码、身份证 X 前空格、订单号误判为卡号、
> 英文逗号名、`O'Neil` 缩写、地址前导动词未剔除、`区县+街道` 无路名漏检等），
> 修完才达到上表数字。第 1 版在 `samples_200.csv` 上是 100%——**模板集自测会骗人**，
> 所以两份集都随仓库提交。

### D. 审计篡改定位

```
$ python -c "..."            # 见 verify.py: step_audit()
改前 verify().ok = True
篡改 seq=4 的 detail 后： ok=False, tampered_seq=[4], locate(4).fields 非空
删除 seq=4 后：            ok=False, missing_seq=[4]
```

### E. 端到端演示

```
$ python run.py demo
1_plaintext_leaked_in_db   False
1_masked                   138****8000
1_detokenized              13800138000
2_masked_text              我叫〔姓名_1〕，手机〔手机号_1〕，住〔地址_1〕
3_denied_codes             {'recruiter': 'missing_permission', 'admin_no_reason': 'reason_required'}
4_audit_verify             {'ok': False, 'tampered_seq': [3], ...}
6_out_of_scope             out_of_scope
```

### F. 一键验收

```
$ python tools/verify.py
[PASS] unit_tests / masking_recall / audit_tamper_locate / e2e_demo / license_scan
RESULT: ALL PASS      记录 -> reports/verify_windows.json

$ (Ubuntu) python tools/verify.py
platform=Linux python=3.12.3   RESULT: ALL PASS
记录 -> reports/verify_linux.json
```

### G. 十轮循环对抗（4 个种子）

```
$ python tools/loop_verify.py
[PASS] R1..R10   10 轮结果: 10/10 通过
Windows: 10/10（种子 20261103 / 7 / 20261104 / 99991 各一遍）
Linux  : 10/10（种子 20261103 / 7 / 99991）
```

十轮各自打不同面：全量单测 / 脱敏召回 / 审计篡改（随机行 + 4 种篡改手法）/
密钥轮换 / 越权矩阵（5 角色 × 城市·站点）/ 保留期快进 / 撤回同意 / 审批四项反向 /
接口契约 / 端到端 + 许可扫描。

### H. 真容器 + 真 PostgreSQL（Ubuntu 24.04，Docker 29.1.3 / Compose 2.40.3）

```
$ docker compose up -d --build
 Container sec1804-db-1     Healthy
 Container sec1804-cache-1  Healthy
 Container sec1804-api-1    Started
$ curl -s localhost:18080/health
{"status":"ok","module":"task-5-security-compliance","version":"0.1.0"}
$ curl -s localhost:18080/openapi.json | jq '.paths|length'
23
$ curl -s -XPOST localhost:18080/api/v1/vault/tokenize -H "Authorization: Bearer $TOK" \
       -d '{"type":"手机号","value":"13800138000"}'
{"token":"vt_gfJAk30w3G4jfqLZJDUUOZfpTh","type":"phone","masked":"138****8000"}
$ docker exec sec1804-db-1 psql -U sec -d sec1804 -tAc \
    "select count(*) from vault_items where ciphertext like '%13800138000%';"
0                                        # 库里没有任何明文残留
$ docker exec sec1804-db-1 psql -U sec -d sec1804 -tAc \
    "select count(*) from information_schema.tables where table_schema='public';"
9                                        # 9 张表全部建好

$ docker exec -e PG_DSN=postgresql://sec:sec@db:5432/sec1804 sec1804-api-1 \
    python tools/pg_smoke.py
[PASS] plaintext_not_in_pg / detokenize / candidate_create / audit_chain_ok
[PASS] tamper_located / masking / retention_run
PG_RESULT: ALL PASS
```

> 8080 端口在本机被别的服务占着，所以 compose 里端口写成 `${API_PORT:-8080}:8080`，
> 用 `API_PORT=18080 docker compose up -d` 即可。这不是权衡，是实测撞过。
> Vault 放在 `--profile vault` 里：镜像在国内源上经常拉不到，不该挡住"一键启动"。


## 第二轮十轮（B 组）：把"功能对不对"换成"压力与边界上还对不对"

`python tools/loop_verify_b.py` —— 与 A 组分开，专打第一轮打不到的面。

```
[PASS] B1  concurrent_audit         rows=400 expect=400 chain_ok=True forks=0 gaps=[] errs=[]
[PASS] B2  concurrent_tokenize      tokens=1 rows_for_that_token=1 calls=32 errs=[]
[PASS] B3  sqlite_vs_pg             两方言输出逐项一致（7 项）
[PASS] B4  rotate_interleave        versions 1->2->3 ok=True
[PASS] B5  fuzz_big_input           1MB 无崩溃、<30s；零宽/RTL/emoji 存活；空值/非法类型/超长 token 均被拒
[PASS] B6  restart_chain            rows=10 chain_ok=True key_persist=True
[PASS] B7  rbac_matrix_snapshot     5 角色 26 项权限逐项一致，无悄悄放权
[PASS] B8  retention_boundary       90d/180d/24h 边界：差 1 秒保留、整点触发
[PASS] B9  openapi_errorcodes       23 路径 25 操作，operationId 无重复，错误码唯一且都有 code+message
[PASS] B10 vault_backend            versions 2->3 keylen=32 old_key_stable=True
B 组结果: 10 通过 / 0 失败 / 0 跳过
```
执行环境：Ubuntu 24.04 容器内，**真 PostgreSQL 16 + 真 HashiCorp Vault 1.18**。
Windows 宿主机上 B3/B10 会显式 SKIP（无 PG / 无 Vault），**不计为通过**。

### B 组挖出的 6 个真缺陷（全部已修，且都只在特定环境暴露）

| # | 缺陷 | 怎么暴露的 | 后果 | 修法 |
|---|---|---|---|---|
| 1 | 并发审计写丢数据 | B1：8 线程 × 50 条 | `UNIQUE constraint failed: audit_log.seq`，400 条只落 51 条 | `Audit.append` 加锁 + `db.serialized()`（PG 用 advisory lock）+ 退避重试 |
| 2 | 并发 tokenize 同一号码得到**不同 token** | B2：32 线程并发 | `stable_key()` 首用时被多线程各生成一把索引密钥，后写覆盖先写；同一个手机号 3 个 token | 有 `KMS_SECRET` 时由 secret 派生；否则加锁 get-or-create 并**回读以落盘值为准** |
| 3 | 并发同值 tokenize 主键冲突 | B2 | `UNIQUE constraint failed: vault_items.token` | 冲突时回查，已存在即返回同一 token |
| 4 | 保留期边界差 1 秒才触发 | B8：24h 整点 | 未成年人 24h 整点**不删**，差 1 秒才删 —— 合规缺口 | 边界统一为"到期即触发"（`<=`） |
| 5 | 1MB 文本拖死正则 | B5 | 单个 20KB 片段 104ms，1MB 直通分钟级 → 接口可被一次请求拖死 | `detect()` 按 2000 字切块并在标点断开；1MB 降到 1.8s |
| 6 | Vault 后端从第一次用就是坏的 | B10 | `_load()` 读不到就返回 `{"keys":{}}`，随后 `key(1)` → `KeyError: '1'`；file 后端正常，本地永远发现不了 | `_load()` 首读 404 时自举 v1 密钥 |

另外 4 个是**测试自身**的问题，也一并修了（不修就是假通过）：

- 十轮共用同一个 PG 库 → 上一轮篡改的坏行让下一轮 `verify()` 直接判 False。改为**每个 Container 一个独立 schema**（与 sqlite"一实例一文件"语义等价）。`tests/conftest.py` 每用例一个 schema，所以 `pytest` 现在也能直接跑在真 PG 上。
- B2 用 `item_type='phone'` 计数，被别的轮污染 → 改为按 token 计数。
- 镜像里没装 dev 依赖 → `TestClient` 缺 httpx，B9 在容器内直接异常。Dockerfile 改为安装 `requirements-dev.txt`（交付物带测试，买家在容器里也要能一条命令跑全绿）。
- `verify.py` 第一步读到了上一次被篡改的行 → 独立 schema。

### 容器内实测（真 PG + 真 Vault）

```
$ docker exec -e PG_DSN=postgresql://sec:sec@db:5432/sec1804 \
    -e VAULT_ADDR=http://vault:8200 -e VAULT_TOKEN=root sec1804-api-1 \
    python tools/run_tests.py --junit-xml=/tmp/j.xml
JUNIT tests=77 failures=0 errors=0

$ docker exec ... python tools/verify.py
[PASS] ×5   RESULT: ALL PASS

$ docker exec ... python tools/loop_verify.py    → 10 轮 10/10
$ docker exec ... python tools/loop_verify_b.py  → 10 通过 / 0 失败 / 0 跳过
```


## 第三轮：C 组 15 轮 · 安全对抗（红队视角）

A 组问"功能对不对"，B 组问"压力和边界上还对不对"，**C 组问"攻击者能拿到什么"**。
每一轮按"攻击成功即失败"断言。`python tools/loop_verify_c.py`

```
[PASS] C1  jwt_forgery         alg=none / 篡改 payload / 换密钥 / 过期 / 无 Bearer / 未知角色 全部 401
[PASS] C2  sql_injection       9 种注入串 × 6 个字段 + 保险箱 + 审计理由：无崩溃、无表丢失、链完整
[PASS] C3  idor                跨城/跨站/明文越权/并发 50 次探测：零泄漏，列表按范围过滤
[PASS] C4  mass_assignment     status=hired、is_minor、未声明字段、role 提权：全部被拒
[PASS] C5  mask_bypass         全角/零宽/同形字/点号/括号/阿拉伯-印度数字/中文数字：8 种绕过全部拦下
[PASS] C6  plaintext_leak      错误信息 / 审计 detail / 整库 dump / 导出：均无明文
[PASS] C7  token_enum_timing   1000 次随机猜 0 命中；token 由 HMAC 派生；比较用 compare_digest
[PASS] C8  approval_bypass     伪造/跨动作复用/非管理员自批/并发双花/空理由：全部拦下（双花严格 1 次）
[PASS] C9  audit_integrity     接口无删改动词；改内容/删行/尾部截断 全部可定位
[PASS] C10 malformed_input     1MB body、500 层 JSON、NaN、类型错、缺字段：无 500、无非法 JSON
[PASS] C11 headers_exposure    无 Server 版本泄露、无 X-Powered-By、无 traceback，安全响应头齐全
[PASS] C12 bruteforce_rate     60 次失败请求：0 成功、全部入审计、超限 429 且限流本身也入审计
[PASS] C13 credential_hygiene  全仓扫描无硬编码密钥/私钥/平台 token；app 内无 print 明文
[PASS] C14 deps_license        22 个依赖：0 deny、0 unknown，版本全部固定
[PASS] C15 attack_chain        脱敏→送模型→越权取明文 整链在每一环都被阻断，且全程留痕
C 组结果: 15/15 通过
```

### C 组挖出的 8 个真问题（全部已修）

| # | 问题 | 攻击后果 | 修法 |
|---|---|---|---|
| 1 | **脱敏可被 Unicode 绕过** | 全角数字 `１３８…`、零宽字符夹断、`138.0013.8000`、`(138)0013-8000`、`ｌ3800138000`、`一三八零零…` 六种写法都能让手机号**原样送进模型** | 检测前做**等长同形归一化**（全角/阿拉伯-印度数字/零宽/同形字母），中文数字用"≥9 连串"专用检测器；占位符仍登记原文切片 |
| 2 | **批量赋值提权** | 客户端可自设 `status=hired`（保留期 90→180 天，绕过数据最小化）、自设 `is_minor`（绕过 24 小时删除） | service 层按角色拦特权状态；`is_minor` 须管理员；未声明字段由 pydantic `extra="forbid"` 整单 422 |
| 3 | **审批并发双花** | 同一审批 8 并发用 2 次（读-判-写非原子） | 条件 UPDATE 抢占 + 影响行数校验，严格 1 次 |
| 4 | **无安全响应头** | 缺 HSTS/CSP/X-Frame-Options/nosniff | 中间件统一注入 |
| 5 | **可被暴力破解** | 60 次 detokenize 试探 0.15 秒全被接受 | 滑动窗口限流（默认 60s/30 次）+ 429 + 限流本身入审计 |
| 6 | **恶意输入致非法 JSON** | 请求含 `NaN` 时 422 响应回显 `nan`，序列化抛错，客户端拿不到响应 | 自定义 validation handler + 有界深度清洗 |
| 7 | **保险箱无长度上限** | 1 万字符值被静默接受 | 单字段上限 256 字符 |
| 8 | 我自己的测试写错 3 处 | 403 响应体没解析、`print(` 误匹配 `db_fingerprint(`、`all_cities` 默认 True 让越权测试失效 | 已修（不修就是假绿） |

> 第 1 条是这轮最值钱的发现：**它不需要破解加密**。只要让检测器认不出号码，
> PII 就会原样进大模型——契约里"送入模型前必须先脱敏"直接被绕开。

## 第四轮：D 组 15 轮 · 一致性与故障恢复

C 组解决"攻击者能拿到什么"，**D 组解决"系统出问题时会不会留下没法解释的状态"**。
在 PII 系统里，一次"操作成功但没留痕"比功能 bug 严重 —— 事后无法向监管解释。

```
[PASS] D1  audit_atomicity         审计写失败 → 业务整笔撤销，无孤儿密文
[PASS] D2  idempotency             Idempotency-Key 重放返回同一对象；同键不同体 409
[PASS] D3  crash_recovery          写一半退出 → 重开库，链仍自洽，可继续追加
[PASS] D4  rotate_crash            轮换中途崩溃 → 版本不前进，旧数据仍可解
[PASS] D5  delete_read_race        清理与并发读交叉：无半匿名化对象、无异常
[PASS] D6  tx_boundary             审计注入失败 → candidates/vault/audit 三者全部 0 增量
[PASS] D7  concurrent_tokenize_audit  24 并发同值：1 行密文、1 条审计、链完整
[PASS] D8  cross_consistency       无孤儿 token；审计条数与业务条数对齐
[PASS] D9  db_unreachable          DB 不可达 2 秒内快速失败，不挂死
[PASS] D10 pagination_capacity     500 条 0.4s；list 支持 limit/offset，越界 422
[PASS] D11 audit_scale_verify      3000 行：verify 0.01s、tail 0.00s
[PASS] D12 graceful_close          关闭重开：审计行不丢、链仍通过
[PASS] D13 bulk_export             200 条导出 0.02s、17KB、无明文
[PASS] D14 clock_skew              时钟回拨 1 天：不误删、回填早时间戳不断链
[PASS] D15 event_contract          outbox 表 + HMAC-SHA256 签名 + 拉取/确认接口
D 组结果: 15/15 通过
```

### D 组挖出的 4 个真问题（全部已修）

| # | 问题 | 后果 | 修法 |
|---|---|---|---|
| 1 | **孤儿密文**：tokenize 先写库再写审计，审计失败时密文已落库 | 库里出现"有密文、无候选人、无审计"的行 —— 既违反最小化，也无法解释来源 | `Vault._store` 审计失败即删除刚插的行；`create()` 记录本次新建 token，失败整体补偿 |
| 2 | **无幂等** | 网络重试 → 同一个人被建两次，两份 PII | `Idempotency-Key`：同键同体回放原响应；同键不同体 409；并发抢键 409 |
| 3 | **list 无分页** | 1 万候选人时一次返回几十 MB | `limit/offset`，上限 500，越界 422 |
| 4 | **契约的 outbox 事件缺失** | 下游无法可靠消费状态变更 | 补 `outbox` 表 + HMAC-SHA256 签名 + `/api/v1/outbox` 拉取/确认；consent 变更自动发事件 |

## 累计：三轮专项 + 四组共 50 轮

| 组 | 主题 | Windows | Ubuntu（容器，真 PG16 + 真 Vault 1.18） |
|---|---|---|---|
| 单测 | 功能 | **90 passed** | **90 passed**（JUnit 0 fail / 0 error） |
| verify | 一键验收 | ALL PASS | ALL PASS |
| A（10 轮） | 功能面 | 10/10 | 10/10 |
| B（10 轮） | 并发/跨方言/边界/KMS | 8 pass + 2 skip（无 PG/Vault，**不计为通过**） | 10/10 |
| C（15 轮） | 安全对抗 | 15/15 | 15/15 |
| D（15 轮） | 一致性与故障恢复 | 15/15 | 15/15 |

> 双平台合计暴露 **20 个缺陷**（B 组 6 个、C 组 8 个、D 组 4 个，另有若干测试自身缺陷），
> 全部修完复跑。其中 **11 个只有单平台能看见**：ROS2 插件污染、pg8000 无 `dsn=`、
> `Connection` 无 `execute()`、8080 端口占用、PG 多实例共用 public 互相污染、
> Vault 后端首用即崩、并发丢审计……Windows 上一切正常，Ubuntu/容器一跑就现形。


## 第五轮：E 组 15 轮 · 并发正确性与接口边界

前四组分别问"功能对不对 / 压力下对不对 / 攻击者能拿到什么 / 出错后能不能解释"。
E 组问**"两个正常操作同时发生时，结果对不对"**——这类 bug 不报错、不留异常，
只是数据悄悄错了。对 PII 系统来说，错一次就是错一份档案。

```
[PASS] E1  lost_update                两人同时改不同字段 → 两个修改都在
[PASS] E2  optimistic_lock            带 If-Match 的过期版本 409，不覆盖
[PASS] E3  partial_update             只传一个字段，其它字段不被清空
[PASS] E4  field_level_concurrency    4 线程改 4 个不同字段，无一丢失
[PASS] E5  delete_update_race         删了又改，不得"复活"
[PASS] E6  unique_under_concurrency   8 并发同号：同一 token、重复可检出
[PASS] E7  tx_isolation               并发读 518 次，0 次读到半成品（token 只写一半）
[PASS] E8  audit_row_alignment        25 并发建人：业务 25 行 / 审计 25 条 / 链完整
[PASS] E9  idempotency_concurrency    10 并发同键：严格 1 个赢家、9 个 409
[PASS] E10 bulk_atomicity             批量里第 2 条越权 → 整批回滚，0 残留
[PASS] E11 cursor_paging              游标分页：翻页期间插入不重复不漏
[PASS] E12 count_consistency          返回条数受范围限制，total 明确标为上界
[PASS] E13 bulk_limits                超长字段 422、超批量 422/403
[PASS] E14 export_delete_race         导出途中被删：不导出已删数据，明确报错
[PASS] E15 cross_city_concurrent_write 20 并发跨城写：全部拦下，0 行落库
E 组结果: 15/15 通过
```

### E 组挖出的 3 个真问题

| # | 问题 | 后果 | 修法 |
|---|---|---|---|
| 1 | **没有版本控制，整行覆盖** | 两个专员同时改同一人 → 后写覆盖前写，前一个修改**静默丢失** | 新增 `PATCH /candidates/{id}` + `version` 列；带 `If-Match` 时用 `UPDATE ... WHERE version=?` 抢占，不匹配 409 |
| 2 | **`view()` 字段白名单漏了 3 个字段** | `start_text` / `experience_text` / `anonymized_at` 读出来是 None，客户端会以为"被清空了" | 白名单补齐 |
| 3 | **list 无游标分页** | offset 分页在翻页期间有插入时会重复/漏项 | 新增 `cursor_from`，按 `(created_at, id)` 严格大于 |

## 第六轮：F 组 15 轮 · 可运维性与可审计性

E 组解决并发正确性，F 组解决**"证据"**：密钥被拷走怎样、备份恢复后链还能不能验、
保留期到了怎么**证明**真删了、监管来要数据能不能独立核对。

```
[PASS] F1  kms_dir_permissions        密钥文件 0600、目录不可他人读（Linux 判定）
[PASS] F2  key_data_separation        只拷走库、没密钥 → 解不出
[PASS] F3  both_stolen_boundary       两者都被拷走 → 能解（AES 必然结果），风险已文档化
[PASS] F4  kms_corrupt_no_silent_newkey 密钥文件损坏 → 启动即拒绝，不静默换新钥
[PASS] F5  backup_restore_chain       备份→继续写→从备份恢复：链可验、恢复点可说明
[PASS] F6  deletion_evidence          删除记录含规则/模式/时间，可导出给监管
[PASS] F7  deletion_log_tamper        删除记录被改 → 链校验能定位
[PASS] F8  audit_export_verifiable    导出包可**离线独立验证**（不碰库）
[PASS] F9  export_no_plaintext        审计/删除导出均无明文
[PASS] F10 regulator_query            按主体/按动作检索 200 行 < 0.01s
[PASS] F11 rotation_rollback          轮换可回滚到旧版本，已加密数据仍可读
[PASS] F12 config_change_audit        改保留期/阈值必须留痕（谁、何时、旧值→新值）
[PASS] F13 health_not_fake_green      /health/deep 逐项查依赖；把密钥文件移走必须变红
[PASS] F14 log_hygiene                审计/日志无明文、无密钥、无 token 值
[PASS] F15 disaster_recovery          无钥/无库/库损坏 三种情况行为明确
F 组结果: 15/15 通过
```

### F 组挖出的 6 个真问题

| # | 问题 | 严重度 | 后果 | 修法 |
|---|---|---|---|---|
| 1 | **静默换钥** | **高** | KMS 目录空了会自举一把 v1 密钥，恰好与库里 `key_version=1` 对上 → "密钥丢了"被掩盖 | 库里固化**密钥指纹**（`meta.kms_fingerprint`），启动时比对，不一致即拒启动 |
| 2 | **删除记录无防篡改** | 高 | 把 `deletion_log.rule` 改掉没人发现 → "我删过了"这张证据作废 | 删除记录也上哈希链，`deletions_verify()` 可逐行定位 |
| 3 | **审计无法离线验证** | 高 | 监管拿到导出文件也只能信我们 | `export_bundle()` + `verify_bundle()`：只吃 JSON、不碰库 |
| 4 | **配置变更无痕迹** | 中 | 90 天被改成 30 天，谁改的、什么时候，说不清 | `config_update()` 把 旧值→新值 写进审计 |
| 5 | **`/health` 假绿** | 中 | 密钥坏了、库连不上，`/health` 照样 200 | `/health/deep` 逐项检查 db / kms / audit 链 / 删除链，任一不过即 `ok=false` |
| 6 | **轮换不可回滚** | 中 | 新密钥出问题只能硬扛 | `rollback_to(version)`，只回退指针、旧密钥仍在，已加密数据不受影响 |

> 第 1 条是这轮最危险的发现。它不报错、不告警，**数据看起来还能读**，
> 但其实是拿错密钥在解。等真正发现时，可能已经把用新密钥加密的数据混进去了。

## 累计：六组共 80 轮

| 组 | 主题 | Windows 11 / Py3.11.7 | Ubuntu 容器（真 PG16 + 真 Vault 1.18） |
|---|---|---|---|
| 单测 | 功能 | **90 passed** | **90 passed**（JUnit 0 fail / 0 error） |
| verify | 一键验收 | ALL PASS | ALL PASS |
| A（10 轮） | 功能面 | 10/10 | 10/10 |
| B（10 轮） | 并发/跨方言/边界/KMS | 8 pass + 2 skip（无 PG/Vault，**不计为通过**） | 10/10 |
| C（15 轮） | 安全对抗 | 15/15 | 15/15 |
| D（15 轮） | 一致性与故障恢复 | 15/15 | 15/15 |
| E（15 轮） | 并发正确性与接口边界 | 15/15 | 15/15 |
| F（15 轮） | 可运维性与可审计性 | 14/15 + 1 skip（Windows 无 POSIX 权限位） | **15/15** |

> 双平台合计暴露 **29 个缺陷**（B 组 6、C 组 8、D 组 4、E 组 3、F 组 6，另有若干测试自身缺陷），
> 全部修完复跑。其中 **14 个只有单平台或真实部署环境能看见**。
> **每一组的"跳过"都明确标注且不计为通过** —— 假绿比红更危险。

## 与契约 v1 的对齐点

- 前缀 `/api/v1`，错误体 `{code, message}`；员工端 `Authorization: Bearer <JWT>`。
- 保险箱接口按契约原文：`POST /api/v1/vault/tokenize {type, value} -> {token}`、
  `POST /api/v1/vault/detokenize {token, reason}`；掩码格式 `138****8000` / `王**`。
- 候选人字段与契约同名（`name_token`、`phone_token`、`birth_ym`、`area_text`、
  `status` 取值域 `new|collecting|complete|booked|interviewed|hired|rejected|handoff`）。
- 真实值只落在保险箱：`candidates` 只存 token，明文只在内存与受控返回中出现。
- 依赖许可：只保留 MIT / Apache-2.0 / BSD / PSF。**弃用 psycopg（LGPL-3）改 pg8000（BSD-3）**，
  原因写在 `reports/OWASP_TOP10.md` A06 一节。
- 大模型：本模块不调用外部模型；送去模型前的脱敏由 `masking.py` 提供，任务 1/3 直接 import。

## 本模块不含（与契约一致）

等保测评、第三方渗透测试、业务功能（报名对话、预约、工作台）。

## 已知边界（如实写）

1. 姓名识别是规则 + 上下文锚点，没有训练模型。合成集 100%、对抗集 100%，但真实语料
   （方言昵称、少数民族姓名、单字名）会有漏检；`strict_names=False` 与自定义黑名单可调。
2. 地址识别对“只有小区名、无门牌”的表述会整段脱敏（偏保守），宁可多脱不可少脱。
3. 审计链并发：同一进程内已用锁 + `db.serialized()` 串行化；跨进程在 PostgreSQL 上用
   `pg_advisory_lock` 串行化（B1 轮 8×50 并发实测 400/400 落库、链完整）。
   极高并发下仍是单写入瓶颈 —— 生产建议把审计写入收敛到单一审计服务，
   这是吞吐取舍，不是正确性缺口。
4. 本地 `FileKMS` 用文件保存密钥，适合开发与单机部署；生产必须切 `KMS_BACKEND=vault`
   （已在容器内用真 Vault 1.18 验过：密钥自举、轮换、旧版本密钥仍可解）。
