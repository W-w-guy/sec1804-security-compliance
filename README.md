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
3. 审计链是“单写入者顺序链”。多进程并发写同一张表时，`seq` 由数据库序列保证唯一，
   但 `prev_hash` 需串行化；生产建议把审计写入收敛到单一审计服务（本模块已这样设计）。
4. 本地 `FileKMS` 用文件保存密钥，适合开发与单机部署；生产必须切 `KMS_BACKEND=vault`。
