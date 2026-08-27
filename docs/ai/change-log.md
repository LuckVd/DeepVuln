# Change Log

## 2026-08-27

### 第二轮 mini 实测基线 — P1+P3+P4 修复后全链路（Recall 100%，safe 零 FP）✅

- **环境**: 重启 celery worker + uvicorn 加载新代码；LLM = deepseek-v4-flash（迁移后）；9 case 全跑
- **结果**（`benchmarks/results/run3_mini/report.json`）:
  | conf>= | TP | FP | FN | P | R | F1 |
  |---|---|---|---|---|---|---|
  | 0.0 | 9 | 21 | 0 | 0.300 | **1.000** | 0.462 |
  | 0.7 | 9 | 15 | 0 | 0.375 | **1.000** | 0.545 |
  | 0.8 | 9 | 8 | 0 | 0.529 | **1.000** | 0.692 |
- **对比首轮（同 conf>=0 口径）**: TP 8→9（FN 清零，java-cmdi 恢复）、safe-FP 26→0（P3 生效）、R 0.889→1.0、P 0.235→0.300、F1 0.372→0.462
- **Token**: 135,273（27 次 chat、0 http_error、平均 5K/次）——低于首轮 38 次（含 6 次失败重试）且无浪费
- **残余 21 FP 全部是 vuln 文件上的其他类型误报**（agent 跨类型高置信 + semgrep 通用规则如 use-tls/no-direct-write）；safe 文件零 FP；conf>=0.8 时 P=0.529/F1=0.692 → 下一次优化方向：类型校准/阈值策略或 semgrep 规则裁剪
- **Commit**: 未提交（遵循不自动提交规则）

## 2026-08-27

### P4 修复 — java-cmdi 漏报根因定位与 LLM 模型迁移（ox-alpha-free → deepseek-v4-flash）✅

- **根因 1（run1 的 FN 直接原因）**: trace 显示 java-cmdi vuln 的 agent 调用（17:23:21）遇 provider 503 "Endpoint is unavailable"，两次重试后放弃 → 该文件 0 findings → FN=1。不是 prompt/规则缺陷，是上游瞬时故障。
- **根因 2（当前复现的阻断）**: 直扫复现时发现 `ox-alpha-free` 已被 opencode.ai/zen/go 网关下线——实测 401 `"Model ox-alpha-free is not supported"`；同端点 `deepseek-v4-flash`（DSH settings.yaml 的 agent-default-model）实测 200 OK。
- **另发现（环境）**: 未 `-u ALL_PROXY` 时 agent 引擎的 httpx 调用因 `ALL_PROXY=socks5h` + 缺 `socksio` 直接 ImportError（worker 启动要求已在 change-log 记录，引擎层未内化）。
- **修复** `benchmarks/eval/seed_llm_config.py`: TARGET_MODEL `ox-alpha-free` → `deepseek-v4-flash`（CONFIG_NAME 同步）；重跑 seed 幂等更新 DB llm_configs id=1，agent_scan + verification 两条消费链路验证通过。
- **验证**: agent 直扫 `benchmarks/mini/java/cmdi/vuln` → `command_injection` confidence 1.0（"命令注入漏洞 - Runtime.exec拼接用户输入"）；叠加 P1 后 semgrep 的 `tainted-cmd-from-http-request`，java-cmdi 双引擎覆盖。
- **Commit**: 未提交（遵循不自动提交规则）

## 2026-08-26

### P3 修复 — agent `is_suspicious` 低置信条目抽离为审查队列（FP 主源切除）✅

- **根因**: agent 引擎把 LLM 响应中 `suspicious_code` 段（模型自己也拿不准的"待审查"条目）转成 `Finding`（`metadata.is_suspicious=True`、confidence ≤ 0.5、severity LOW），随后进入多轮裁决却只停在 `conditional`，最终落库为正式 findings。DB 实测 run1 落库 53 条 findings 中 **28 条（53%）是 suspicious_***，全 conditional、无一条贡献 TP；26 个 FP 中绝大多数即此类。
- **修复** `src/web/services/scan_orchestrator.py` + `src/web/models/schemas.py`:
  - `_run_adjudication` 聚合处新增 `_split_review_queue()`：默认把 `is_suspicious` 条目从待裁决/落库集合抽离，存入 `self._suspicious_review_queue`（dict 化，供人工审查），不进最终 findings
  - `ScanConfig` 新增逃生阀 `include_suspicious_findings: bool=False`——True 时恢复旧行为（全进报告）
- **量化**（run1 DB 落库数据模拟，P1 前快照）: 过滤前 TP=8/FP=42/P=0.160/F1=0.271 → 过滤后 TP=8/FP=16/**P=0.333/F1=0.485**；**被过滤条目贡献 0 TP**（Precision +108%，F1 +79%，Recall 不变 0.889）
- **验证**: 新增 3 项测试（划分逻辑/逃生阀/裁决链路不含 suspicious）——test_final_score_wiring 5 passed；test_web 基线 34F/31E 零回归（194 passed）
- **Commit**: 未提交（遵循不自动提交规则）

### P1 修复 — Semgrep `--config auto` 零 findings 根因定位（HOME 不可写 + 相对路径双解析）✅

- **根因 1（主因）**: `SemgrepEngine` 以 `env=None` 继承父进程环境跑 semgrep；semgrep 启动时打开 `~/.semgrep/semgrep.log`（`env.py:157` 可用 `SEMGREP_LOG_FILE` 重定向）。沙箱/root 环境 `HOME=/root` 不可写 → `PermissionError` 在产 JSON 前崩溃 → `json.loads` 失败 → 引擎静默 success=False，findings=0（benchmark 首轮 semgrep 全空）。实测复现：`HOME=/root` 跑 `--config auto` 直接崩；`HOME=/tmp/fakehome` 同命令出 5 条。
- **根因 2（隐患）**: `scan()` 把相对 `source_path` 同时传给 command target 和 `run_command(cwd=source_path)` → semgrep 在 cwd 内二次解析 target → "Invalid scanning root"，而 `_parse_results` 只读 `results` 不看 `errors` → 又一个静默 0 findings 路径（web 栈传绝对路径未触发，防御性修复）。
- **修复** `src/layers/l3_analysis/engines/semgrep.py`:
  - 新增 `_spawn_env()`：未显式设置 `SEMGREP_LOG_FILE` 时注入 `<tmpdir>/deepvuln-semgrep/semgrep-<pid>.log`（父目录 mkdir）；`get_version()` 与 `scan()` 的 `run_command` 均传该 env
  - `scan()` 开头 `source_path = source_path.resolve()`，杜绝相对路径双解析
- **验证**:
  - 新增 4 项测试：3 项 env 注入行为（注入/尊重显式配置/可写）+ 1 项相对路径 resolve 回归；`test_semgrep_engine` + `test_semgrep_integration` **44 passed**
  - 真实引擎 `HOME=/root` 全链路扫 mini：python/sqli 5 条、go/sqli 6 条（含 tainted-sql-string）、java/cmdi 2 条（含 tainted-cmd-from-http-request——顺带补上 P4 关心的 java-cmdi 检出面）
- **Commit**: 未提交（遵循不自动提交规则）

### 可观测性 — LLM 调用追踪（opt-in JSONL）+ 首轮 mini 基线 ✅

- **背景**: benchmark 实跑排查误报/漏报需要"模型当时看到什么、答了什么"；现有 token 聚合（scan.token_usage → `/token-usage` 端点）与会话存档（agent-conversation / adversarial-debate / events）都不含逐次原始报文
- **改动** `src/layers/l3_analysis/llm/openai_client.py`: 新增 `_llm_trace_dir/_write_llm_trace`——env `DEEPVULN_LLM_TRACE=<目录>` 时，chat 每次调用以 JSONL 追加 `{ts, event(chat|rate_limited|http_error), model, base_url, attempt, duration_ms, request:{messages,max_tokens,temperature,json_mode}, response:{content,reasoning_content,finish_reason,usage}}` 到 `<目录>/llm_trace.jsonl`；env 逐次读取（进程内生效即可）、trace 异常静默不打断主流程、不落 api_key
- **文档**: `.env.web.example` 增 DEEPVULN_LLM_TRACE / DEEPVULN_LOGGING_FILE 示例；benchmarks/README 增「可观测性」表
- **验证**: py_compile OK；helper 开/关 env 行为正确；test_l3 LLM 相关 **72 passed**

### 首轮 mini 实测基线（ox-alpha-free 全链路）✅

- **环境**: 本机 sqlite DB + redis(apt) + celery solo pool + uvicorn；LLM = opencode-go / ox-alpha-free（DB seed）；DEEPVULN_LLM_TRACE 开启（38 条 JSONL）
- **修复**: ① `run_benchmark.py` findings 端点 key `items`→`findings` ② worker 启动需 `-u ALL_PROXY`（环境 socks5h 代理 + httpx 缺 socksio 致 agent 引擎全挂）③ celery 需 `--pool=solo`（沙箱禁 /dev/shm Semaphore，prefork PermissionError）
- **结果**（9 case，vuln/safe 成对）:
  | conf>= | TP | FP(safe) | FN | P | R | F1 |
  |---|---|---|---|---|---|---|
  | 0.0 | 8 | 26 | 1 | 0.235 | 0.889 | 0.372 |
  | 0.5 | 8 | 11 | 1 | 0.421 | 0.889 | 0.571 |
  | 0.7 | 7 | 6 | 2 | 0.538 | 0.778 | 0.636 |
- **总 token: 112,503**（~12.5K/case）；38 次 LLM 调用（含推理 reasoning_content）
- **发现的问题**:
  1. **Semgrep 0 findings**：`--config auto` 走了但产出空——需单独排查（可能 registry 拉取失败或规则包不匹配 mini 场景）
  2. **java-cmdi FN**：agent 对 `Runtime.exec` 未产出 cmd_injection 类 finding，只给了 info_disclosure/resource_mgmt 两个 low conf suspicious
  3. **safe 文件 FP 多**：agent 在参数化查询/ProcessBuilder 等 safe 文件上仍产大量低置信度 "suspicious_" 条目（26 个 FP 中绝大多数是这类）→ 提阈值或按 is_suspicious 标签过滤可显著提升 Precision
  4. **CPG 可达性全标 not_exploitable**：exploitability_verification 的 reasoning 均为 "Code is not reachable from external entry points"（reachability=0.10）——Flask/Spring/net-http 入口未被 CPG 识别为可达入口，与 Phase 18 已知的入口识别问题一致，mini 基准精确暴露了此缺口
  5. AST 引擎仅出 2 条（py-cmdi/py-eval 各 1），go/java 的 dangerous_api/framework 规则未命中 mini 场景（规则覆盖面问题非 bug）

## 2026-08-26

### AST 规则修复 — 7 条 tree-sitter 查询编译失败清零 + TS 语言加载 ✅

- **发现**: benchmark mini 集离线预检（AST 引擎直扫）暴露大量 `Failed to create query` ERROR；诊断脚本枚举全部 27 条规则查询，**10 处失败**：6 条 S-expression 语法坏（括号错位/谓词嵌套过深）、4 条 TypeScript 规则因语言模块无 `.language` 属性加载失败
- **修复 1 — 规则查询**（6 文件，全部按可用的 `dangerous_eval` 同款「顶层组+谓词」idiom 重写）:
  - `django/python_extra_raw_sql.yaml` / `flask/python_render_string_template.yaml`: `(call function: (attribute attribute: (identifier) @method))` + `#match?`
  - `java/java_jni_register_natives.yaml`: 补 `name:` field
  - `go/go_context_without_deadline.yaml`: 删多余右括号
  - `go/go_defer_close_file.yaml`: **根因是 go 语法树 block 下有 statement_list 包裹层**（"Impossible pattern"）；改为 `(block (statement_list (defer_statement ...)))` 双模式（裸 identifier + selector_expression）
  - `dangerous_api/python_subprocess_shell.yaml`: argument_list 挂到 `call.arguments:` field 下
- **修复 2 — TS 加载**: `tree_sitter_manager.py` 新增 `_LANGUAGE_ENTRYPOINTS` 回退表——多语法包（tree_sitter_typescript≥0.23）暴露 `language_typescript/language_tsx` 而非 `.language`；get_language 按 `.language → 已知工厂函数` 顺序解析
- **验证**: 27/27 查询编译通过、mini 重扫零 ERROR；test_l3 ast/detector/rule 相关 **246 passed**；（全量回归见下方补记）
- **影响**: 此前 TS 的 AST+CPG 全链路静默失效（A2 补了依赖声明但加载器用不了）；go/java 各有规则从未生效
- **全量回归补记**: test_l3 **2075 passed / 4 failed**，4 个失败全部是 `test_semgrep_integration` 的**沙箱环境问题**（semgrep 需写 `~/.semgrep/semgrep.log`，本沙箱拒绝写 /root）——`HOME=<可写目录>` 重定向后 10/10 全过，与本次改动无关。沙箱内跑全量的姿势：`HOME=/tmp/fakehome pytest tests/unit/test_l3 -q`

### LLM 接线 — opencode-go / ox-alpha-free ✅

- **背景**: 用户指定 DeepVuln 用 DSH 当前默认模型 ox-alpha-free。链路坐实：DeepVuln LLM 客户端**只从 DB `llm_configs` 表构建**（scan_tasks→get_agent_scan_config / adversarial_service→get_verification_config），provider=custom 走 OpenAI 兼容分支
- **新增 `benchmarks/eval/seed_llm_config.py`**: 幂等 upsert `{name:"opencode-go / ox-alpha-free (DSH)", provider:"custom", base_url:"https://opencode.ai/zen/go/v1", model:"ox-alpha-free", config_type:"both", is_default:true, context_size:1000000, max_tokens:131072}`；key 从 env `OPENCODE_GO_API_KEY` 或 DSH 凭据库 `~/.dsh/.credentials.yaml` refs 解析；写后回读验证 agent_scan + verification 两条消费链路
- **模型元数据来源**: dsh pi-ai `providers/data/opencode-go.json`（openai-completions API, ctx 1M, maxTokens 131072）
- **验证**: 临时 sqlite 三连跑（新增→更新→更新）幂等通过，两链路均取到配置；web 栈起后在真实库执行一次即生效

### 基准建设 — py/go/java 检测基准落地 + mini 集 ✅

- **背景**: Phase 18 关闭后"下一步建议①"（建检测基准出 P/R 数字，旧 /tmp/vuln_test 已丢失）。调研选定现成基准组合（见对话记录）：SecurityEval（Python 片段级）/ go-test-bench（Go 项目级，Contrast 官方）/ django.nV（Python 项目级）/ OWASP BenchmarkJava（Java 金标准）/ findsecbugs 用例（Java 补充）
- **新增 `benchmarks/`**:
  - `fetch.sh`: 一键下载第三方源到 `third_party/`（gitignore，27MB，已验证全部拉通；OWASP 只取 testcode 2740 文件 + expectedresults-1.2.csv）
  - **mini 集**: 每语言 3 例共 9 例（py: sqli/cmdi/eval，go: cmdi/sqli/ssrf，java: cmdi/sqli/crypto），模式取自三大基准同型 taint 流，**vuln/safe 成对**（safe 文件无 SINK 注释，作 FP 对照）；`truth.json` 含 CWE + sink_comment 自检标记 + cwe_keywords 匹配词
  - `owasp_subset_manifest.json`: BenchmarkJava 分层子集 **150 例（75 正/75 负，覆盖全部 11 类），seed=42 可复现**
  - `eval/make_owasp_subset.py`: 确定性分层抽样
  - `eval/run_benchmark.py`: 评测入口——`--mode selfcheck`（离线真值↔文件一致性）+ `--mode api`（Web API 提交扫描→轮询→分页拉 findings→TP/FP/FN→P/R/F1，mini 按 case 目录归属+关键词匹配，owasp-subset 先暂存再整体扫防噪声；另有 4 个探索性目标只报计数）；报告写 `results/<tag>_<target>/report.json`
  - `README.md`: 结构/用法/指标口径/注意事项
- **验证**: mini selfcheck 9/9 PASS；owasp manifest 150 例源文件齐全 PASS；两脚本 py_compile OK
- **待办（下次会话可直接做）**: 起 docker-compose-web 后实跑 `--target mini` 与 `--target owasp-subset` 出首批 P/R 基线数字；探索性目标人工定性
- **Commit**: 未提交（遵循不自动提交规则）

## 2026-08-25

### 全量体检修复 — A 类检测失效 + 部署三连 + 死代码清理 ✅

- **依据**: `docs/ai/audit-2026-08-25-findings.md`（5 路并行审计）；本批按"先检测失效 → 部署 → 死代码"顺序修复
- **A 类·检测能力**:
  - **A1** `detectors/base_detector.py`：规则加载按 `id:language` 做 key（此前同 id 跨语言文件相互覆盖，Python eval/exec 检测静默丢失）；finding 的 rule_id 仍用干净 id。新增 `test_rule_id_collision.py` 5 测试；2 个既有 eval 失败翻绿
  - **A2** `pyproject.toml`：补 `tree-sitter-javascript/typescript>=0.23.0`（venv 手工装过、声明缺失，干净安装 JS/TS AST+CPG 静默失效）。⚠️ uv.lock 待有网时 `uv lock` 同步（本机 PyPI 不可达）
  - **A3** `engines/base.py`：新增 `resolve_binary_path()`（PATH → 解释器同目录探测），`semgrep.py` 执行与版本检查改用解析后的绝对路径 —— venv 未上 PATH 时 semgrep 不再静默跳过；顺带修 `--lang` 过滤在无显式 config 时被丢弃。9 个既有 semgrep 失败翻绿
  - **A4** `scan_orchestrator._run_adjudication`：裁决前统一调 `assign_scores_to_findings`（该入口此前零生产调用，dedup "keep highest final_score" 恒比较 None）。新增 `test_final_score_wiring.py`
  - **A5** `scan_executor.create_scan`：ScanConfig 先 `model_dump(mode="json")` 再入库（修复 REST POST /scans 必 500）。新增回归测试
  - **A6** 引擎默认值收敛为 `schemas.DEFAULT_SCAN_ENGINES` 单一来源（orchestrator 兜底 / zip 端点 / schema 三处不一致，AST 引擎多数路径默认不跑）
- **部署与数据完整性**:
  - **B2** Dockerfile/Dockerfile.lite：删指向已删除 CLI 的 ENTRYPOINT，CMD 改 web API 入口，安装加 `web` extra（此前镜像根本没有 fastapi/celery，web 栈无法启动）；compose `command:` 现可完整生效
  - **B3** compose×2 / start-web.sh / .env.web.example：`DATABASE_URL` → `DEEPVULN_DB_URL`（代码只读后者，此前全部无效）；config.py env_file/upload_dir 去硬编码他人机器路径；start-web.sh PYTHONPATH 改脚本相对
  - **B17** 删除三个活文件里不存在的 config.local.toml 挂载；CLI 时代三个 compose（yml/china/tun）加废弃声明指向 docker-compose-web.yml
  - **B1** `pause_scan` 复用 scan 行已带的 checkpoint 合并 resume_data（此前手工最小 payload 整体覆盖，恢复丢全部引擎结果强制重跑）
- **死代码清理（约 8000+ 行，同步删测试）**:
  - B6 删 `l3_analysis/incremental/`（3423 行双实现之一）+ test_incremental.py + __init__ 再导出
  - B10 删 `l3_analysis/pre_filter/`（1416 行零生产引用）+ 4 个测试文件；`test_verification_gatekeeper.py` 是活代码测试，移至 `tests/unit/test_l3/`
  - B7 删 `phase_manager.py`（590 行，唯一引用是赋值后从未读的属性）+ test_phase_manager.py + executor 引用
  - B8 删 checkpoint write-only 的 /tmp 文件备份（方法 + 调用点 + 相关测试）
  - B12 删根目录 celery_worker.py + 死任务 check_scan_progress（含孤立 helper 与路由项）
  - B18 删 `auto_security_scan.py` + `security_analyzer/` + 连带测试与再导出
- **既有失败测试修复（体检 C 节定性落地）**: test_deduplicator×5 / test_adjudication×3 改为正确 await async API（MockFinding 补 confidence 字段）；test_opencode_agent 默认并发断言对齐 P5-05 语义（2→5）
- **Tests**: test_l3 基线 2203 passed/18 failed → 预期全绿（详见当次运行结果）；ruff F 错误 183 → 175（零新增，净减 8）；ast OK
- **Security**: 无新增密钥；删除代码无安全影响
- **Commit**: 未提交（遵循不自动提交规则）

### 体检修复第四批 — B16 配置岔路 + B14 模型归位 + README 对齐 ✅

- **B16** `adjudication.py`：删 llm_client=None 时从 TOML/env 现建 LLM client 的兜底（第四条配置岔路，timeout=30 与主链路不一致）。**连带揭出并修复潜在 bug**：ASTDeduplicator.deduplicate 是同步方法，调用处无条件 await —— 此前测试能过恰因兜底从环境变量悄悄建出异步 client；现按 iscoroutine 分派
- **B14** 模型职责归位：`core/models/` 补 `__init__.py` 导出；21 处引用从 `l1_intelligence.attack_surface.models` 垫片直连 `core.models.attack_surface`；删除垫片。顺带补 `AttackSurfaceReport.get_summary()`（测试契约存在但实现缺失的既有失败，test_attack_surface 首次被跑到）
- **B11** 定性为保留：engine_registry 有测试覆盖 + 引擎自注册是有意机制，代码已有 NOTE 注明生产流未用（体检"留注释"选项）
- **README** 对齐 web-only 现实：删 CLI 快速开始/参数表（CLI 已移除）、语言收敛为核心 py/go/java（AST 另覆盖 js/ts）、删已清理死代码（pre_filter 五件套）的特性宣称、项目结构更新（src/web、pipeline）、配置节改为 DEEPVULN_* 环境变量
- **Tests**: test_l3+test_l1+test_attack_surface 全量 **2258 passed / 0 failed**；ruff F 保持 175（零新增）；ast OK
- **Commit**: 未提交



## 2026-06-19

### Phase 17 — E5 AI 补漏逻辑漏洞（LogicVulnDetector）✅

- **Goal ID**: phase17-ai-static-deepening（E5）
- **Summary**: 新增 limited-scope、证据锚定的 AI 补漏检测器，补静态引擎漏掉的逻辑漏洞（缺失授权/认证绕过/IDOR/业务逻辑/复杂注入）。反误报四重护栏：入口可达 limited-scope + 三要素硬证据（missing_check/entry_point/attack_path）+ 置信度封顶 0.6 + `evidence_strength=SPECULATIVE`
- **Impact**:
  - 新增 `src/layers/l3_analysis/prompts/logic_vuln.py`（`build_logic_vuln_prompt` + `parse_logic_vuln_response`，全量 5 类 + JSON 容错 + 三要素强制）
  - 新增 `src/layers/l3_analysis/engines/logic_vuln_detector.py`（`LogicVulnerabilityDetector`：入口筛选→LLM→Finding）
  - `models.py`：`Finding.source` Literal 增 `"logic_vuln"`
  - `phases.py`：`ScanPhase.LOGIC_VULN_DISCOVERY`（插 EXPLOIT 后/ADJUDICATION 前）
  - `scan_orchestrator.py`：`_run_logic_vuln_discovery` + PhaseSpec（`skip_when = not logic_vuln`，默认关）
  - `schemas.py`：`ScanConfig.logic_vuln=False`
- **Tests**: 27 passed（prompt 19 + detector 8）；GLM(glm-4.5-air) 端到端检出 IDOR、不误报受保护入口
- **Dead Code**: 无（新公开函数全部被引用）
- **Security**: 无硬编码密钥；flag 默认关，不影响存量扫描
- **Commit**: cb348cb

### Phase 17 — D3 断点续扫 findings 持久化与恢复 ✅

- **Goal ID**: phase17-ai-static-deepening（D3）
- **Summary**: 续扫时已完成 phase 被跳过但 findings 未恢复 → 后续无数据。新增 serialize→checkpoint resume_data→restore 链路。摸排暴露并修复 `checkpoint_service` 两个既有阻塞 bug（此前 checkpoint 根本没存进过 DB）
- **Impact**:
  - `scan_orchestrator.py`：`_serialize_scan_results`（`model_dump(mode="json")` 逐引擎）+ `_restore_scan_results` + `_restore_state_from_checkpoint`；`execute_scan` resume 恢复 findings
  - `scan_pipeline_adapters.py`：`WebCheckpointSink.save` 注入 `resume_data`（不污染 progress summary）
  - `checkpoint_service.py` bug 1：`async with get_session_local() as db` 缺 `()`（maker 非 context manager）→ `()()`
  - `checkpoint_service.py` bug 2：`model_dump()` 保留 datetime → DB JSON 列 TypeError → `mode="json"`
- **Tests**: 10 passed；真实 sqlite DB 往返（hash 验证通过）；真实 Celery（docker redis broker）跨任务 save→resume 全 PASS
- **Dead Code**: 无
- **Security**: 无硬编码密钥；findings 只进 checkpoint（resume_data），不进前端 progress 事件
- **Commit**: 2a0e568

### Phase 17 — phase_manager session bug 修复 ✅

- **Goal ID**: phase17-ai-static-deepening（D3 附带）
- **Summary**: 与 D3 的 checkpoint_service 同一根因：`phase_manager.py` 7 处 `async with get_session_local() as db` 缺 `()` → phase 状态读写全部抛 TypeError
- **Impact**: `src/web/services/phase_manager.py` 7 处改 `()()`
- **Tests**: ast/ruff OK；真实 sqlite 跑 `PhaseManager().get_phase_status()` 修前抛错、修后正常
- **Dead Code**: 无
- **Security**: 无
- **Commit**: 8cb6277

### Phase 17 — D6 CPG CFG 可达性接地 + P9-01/Go bug 修复 ✅

- **Goal ID**: phase17-ai-static-deepening（D6；含 P9-01 连接、Go 裂块修复）
- **Summary**: 把已实现却从未接入的 CFG 子系统（~2000 行死代码）接通，`reaches_sink`/`condition_paths` 从硬编码变为真实值；接通过程暴露并修复 5 个既有 bug，其中 P9-01 使整个 CPG 攻击路径特性首次端到端可用。四语言（py/js/java/go）均裂块 + 死代码检测
- **Impact**:
  - `cpg/models.py`：`function_cfgs` 字段 + `merge_cfg()`（建 `cfg_block` 节点+`cfg` 边）+ `get_successors(edge_types=)` + `get_cfgs_for_file()`
  - `cpg/builder.py`：`FUNCTION_TYPES` 常量；`_fuse_graphs(language=)`；`_build_and_merge_cfgs()`；`_link_call_to_definition()`+`_files_match()`（P9-01）
  - `path_finder/finder.py`：`_verify_cfg_reachability`/`_locate_block`/`_extract_condition_paths`/`_find_cfg_edge`；`_find_sinks` 回落 `ast_node.name`（bug 3）；`_build_attack_path` 接真实值
  - `cfg/base.py`：通用化 `_extract_function_body`（下钻 `block`/`statement_block`）——**根因 bug，修前全语言 0 块**
  - `cfg/builders/go_cfg.py`：`_extract_function_body` 解包 `statement_list`（Go 单块 bug）
- **Bug 修复（5，全是死代码接通才暴露）**：①CFG 体提取返回空（根因）②P9-01 入口/体节点未连通（`get_paths` 恒 `[]`）③sink 读未设置的 `ast_name` ④`method_declaration` 缺失（Java）⑤Go `statement_list` 未解包
- **Tests**: `test_path_finder`+`test_cpg`+`test_cfg` = 109 passed；四语言参数化裂块 + provider e2e（可达→`True`/死代码→`False`）；全 `test_l3` 2177 passed / 24 既有失败（零回归，+10 通过）
- **Dead Code**: `get_cfgs_for_file` 初为未用 → 已接入 `_locate_block`；`get_successors(edge_types)` 为预留 API（按设计 BFS 不消费 cfg 边，CFG 作独立校验），已单测覆盖
- **Security**: 无硬编码密钥（扫描通过）；无新增对外接口/鉴权变更
- **Commit**: 待提交（pending）

## 2026-04-25

### Phase 16 — 全面质量修复（深度审视 40 项问题） ✅

- **Goal ID**: phase16-quality-fix
- **Summary**: 对全项目深度审视发现 40 个问题，按优先级分 6 批次全部修复。涵盖致命崩溃、核心功能空壳、声明未实现、实现偏差、负优化消除和前端 i18n 杂项清理
- **影响范围**: 后端 3 层核心（L1 情报、L3 分析）、Web 服务全链路（API/任务/仓库）、前端所有页面
- **核心变更**:
  1. **Batch 1 — 致命崩溃**: 创建 go/javascript/php Sink/Source 定义文件，修复 registry.py 导入不存在模块导致的 ImportError
  2. **Batch 2 — 核心空壳**: 实现增量扫描 _scan_single_file()、SHA256 项目哈希、Java/Go/JS 完整 CFG 构建器、Java CPG Provider、Java+JS 调用图构建器、FrameworkDetector 注册、SmartScanner 添加 ast_engine 调度
  3. **Batch 3 — 声明补全**: 实现 Cargo/Composer/Gem/NuGet 4 个依赖扫描器、JS/TS 代码结构解析器、HTML 报告导出修复、威胁情报版本匹配、CPG Provider 集成、对抗验证规则持久化
  4. **Batch 4 — 实现偏差**: Agent Semaphore 并发控制、CodeQL 内容哈希缓存、登录返回 user_id、401 React Router、WebSocket JWT、服务端搜索、Vulnerabilities 跳转修复、对抗性验证并行化、证据强度无条件计算
  5. **Batch 5 — 负优化消除**: 引擎注册表清理、死缓存移除、多套件 SARIF 合并、Dashboard memo、粒子 useMemo、单条 finding API、staleTime 配置、时区 Context 共享、AST 上下文缓存、404 路由 + lazy loading
  6. **Batch 6 — i18n 杂项**: Login/Findings 中文 i18n、版本号注入、as any 消除、ScanProgress 标记 deprecated、Rounds 死代码清理
- **新增文件**: 12 个（go/js/php sink-source、java/js call graph builder、java cpg provider、4 个依赖扫描器、js_ts parser、useSystemSettings hook）
- **修改文件**: ~45 个（后端 ~20 + 前端 ~15 + 工作流文件）
- **测试**: 后端 Python 导入验证全部通过（6 批次），前端 TypeScript 有 4 个预存错误（非 Phase 16 引入），Scans.tsx readonly 类型已修复
- **安全**: 3 个 BLOCKER（硬编码 JWT 密钥、默认 admin 密码、DB 凭据在跟踪文件中）均为 Phase 15 及之前的预存问题，Phase 16 新增了 WS JWT 认证改进。无新增安全问题
- **死代码**: 8 项发现 — 5 项可立即清理（_detect_tech_stack 包装、_deduplicate_findings 死方法、ScanProgress 未用组件、exportPdf 死函数、PathlibPath 冗余导入），2 项转为路线图（HybridHTTPDetector、engine_registry），1 项功能 Bug（exportHtml 调用错误端点）

---

## 2026-04-17

### Web 安全与体验增强 — JWT 登录认证 + HTML 报告重设计 + UI 修复 ✅

- **Goal ID**: feat-jwt-auth
- **Summary**: 实现 JWT 登录认证系统（默认账户 admin/deepvuln + 首次登录强制改密），重设计 HTML 报告为赛博深色主题，修复多个 UI 问题
- **影响范围**: 后端认证全链路、前端登录/路由守卫、报告导出服务、扫描列表和仪表盘 UI
- **核心变更**:
  1. **JWT 登录认证**: 新增 User 模型 + auth_service + auth API（login/change-password/me），bcrypt 哈希，JWT HS256 24h 过期
  2. **启动种子**: 应用启动时自动创建 admin/deepvuln 默认用户（must_change_password=True）
  3. **前端登录系统**: Login 页面 + AuthContext + AuthGuard 路由守卫 + ChangePasswordModal 强制改密弹窗
  4. **axios 拦截器**: 自动注入 Bearer token，401 自动跳转 /login
  5. **HTML 报告重设计**: 白底平铺 → 深色赛博风，ASCII Art Logo、横向条形图 severity 分布、卡片式 findings、description CSS 折叠可展开
  6. **API Key 并行**: JWT 为主认证，保留 API Key 供 CI/CD 调用
  7. **UI 修复**: Reports 页下拉框被遮挡（Card overflow-hidden → overflow-visible）；扫描列表列宽和换行；仪表盘最近扫描对齐+创建时间+漏洞标签
- **新增文件**: 9 个（后端 3 + 前端 5 + 测试 1）
- **修改文件**: 11 个（后端 6 + 前端 5）
- **测试**: 37/37 通过（18 auth + 19 report），零回归
- **安全**: 无新增安全问题，XSS 转义正常

---

### LLM 稳定性增强 — 动态并发自适应 + 429限频修复 + JSON解析增强 + 前端排序分页 ✅

- **Goal ID**: feat-llm-stability
- **Summary**: 全面增强 LLM 调用链路稳定性：429 限频即时回调、JSON 解析容错增强、验证器 JSON 提取修复、对抗性验证超时保护、漏洞列表服务端排序分页
- **影响范围**: LLM 客户端、并发管理器、JSON 解析器、三个验证器、对抗性服务、扫描 API、前端 Findings 页面
- **核心变更**:
  1. **429 即时回调**: OpenAI 客户端收到 429 时立即通知并发管理器（不再等 `__aexit__`），实现更快的自适应降速
  2. **JSON 解析增强**: `fix_chinese_punctuation` 安全处理字符串内中文引号；新增 `fix_missing_commas` 修复 LLM 输出遗漏逗号（+23 测试）
  3. **验证器提取修复**: attacker/defender/arbiter 移除手写 `split("```json")` 代码块提取（会因嵌套 ``` 截断），统一用 `robust_json_loads`
  4. **截断响应处理**: `finish_reason="length"` 抛出 `LLMTruncatedResponseError`（截断 JSON 不再静默传递给解析器）
  5. **超时保护**: 对抗性验证每个 finding 300s 超时（`asyncio.wait_for`），防止单个卡死
  6. **扫描 API 增强**: severity counts 实时计算（修复旧缓存不准确）、并发状态暴露、服务端排序
  7. **前端排序分页**: Findings 列表改为服务端排序（severity 权重/confidence/engine），数字分页
  8. **模型参数调整**: max_tokens 4096→16384, context_size 4096→8192, 新增 json_mode 支持
- **新增测试**: json_parser 23 个（总计 61/61 通过）
- **修改文件**: 25 个（后端 16 + 前端 8 + 测试 1）
- **测试结果**: 零新增失败 ✅（预存 14 失败 + 3 收集错误均非本次引入）
- **安全**: 无新增安全问题（12 个预存发现不变）
- **变更统计**: +1018/-149 行

---

## 2026-04-15

### 报告导出能力完成 ✅

- **Goal ID**: web-ui-polish-batch (feat: 报告导出)
- **Summary**: 完成报告导出能力。原 PDF 导出是占位实现，JSON 只返回摘要，CSV 缺少关键字段。新建 report_service 服务层，重构三种格式的报告生成
- **影响范围**: 后端报告 API、前端报告页面
- **核心变更**:
  1. **report_service.py**: 新建服务层，封装 JSON/CSV/HTML 三种报告生成逻辑
  2. **JSON 报告增强**: 补充完整 findings 列表（含 extra_metadata、evidence、remediation、cpg_path），新增 severity summary 统计
  3. **CSV 报告增强**: 新增 Title、Evidence、Remediation 列，移除 description 200 字符截断，正确处理 None 和特殊字符
  4. **HTML 报告（替代 PDF 占位）**: 生成自包含 HTML 报告，含扫描元数据、严重性分布、完整发现列表和修复建议，支持浏览器打印为 PDF
  5. **前端 Reports.tsx**: PDF 格式选项改为 HTML，更新翻译
- **新增文件**:
  - `src/web/services/report_service.py` — 报告生成服务（build_json_report / build_csv_report / build_html_report）
  - `tests/unit/test_web/test_report_service.py` — 19 个单元测试覆盖三种格式
- **修改文件**:
  - `src/web/api/v1/scans.py` — 重写 3 个报告端点，使用 report_service
  - `src/web/frontend/src/pages/Reports.tsx` — PDF→HTML 格式选项
  - `src/web/frontend/src/i18n/translations.ts` — 翻译更新
- **测试结果**: 19/19 report_service 单元测试通过 ✅
- **安全**: HTML 报告所有用户输入经 html.escape 处理，无 XSS 风险

---

## 2026-04-14

### Web UI 打磨与功能增强批次 ✅

- **Goal ID**: web-ui-polish-batch
- **Summary**: Web 前端 UI 打磨与功能增强，涵盖漏洞详情增强、导航修复、全屏终端、扫描队列增强等 10 项改进
- **影响范围**: 前端 UI、后端 API、扫描列表、扫描详情、漏洞页面
- **核心变更**:
  1. **FindingDrawer 漏洞详情增强**: 从 3 Tab 扩展为 5 Tab（概览/代码证据/利用链/LLM 辩论/元数据）
  2. **Findings 返回按钮修复**: 返回到扫描详情页而非扫描列表
  3. **LiveTerminal 全屏按钮**: 使用浏览器 Fullscreen API，全屏时自动扩展高度
  4. **Findings 工具栏修复**: 下拉框溢出裁剪修复 + 控件底部对齐
  5. **扫描队列移除已分析列**: 移除容易混淆的 analyzed_files 统计
  6. **扫描详情信息优化**: 扫描对象（原始文件名）与任务名分离显示
  7. **扫描详情布局调整**: Agent 模型和辩论模型各占一行，"验证模型"改名为"辩论模型"
  8. **扫描队列删除功能**: 新增后端 DELETE API + 前端删除按钮 + 确认对话框
  9. **扫描队列耗时列**: 基于 started_at/completed_at 计算并格式化显示
  10. **扫描队列漏洞分等级显示**: 替换单数字为 Critical/High/Medium/Low/Info 彩色标签
- **新增 API**:
  - `DELETE /api/v1/scans/{scan_id}` — 删除已完成/失败/取消的扫描
- **测试结果**: TypeScript 编译通过，浏览器交互验证
- **安全扫描**: 无新增安全问题（预存问题不变）
  - BLOCKER: config.py 硬编码 DB 凭据（预存）
  - HIGH: WebSocket 无认证（预存）
  - HIGH: API Key 认证默认禁用（预存）
- **死代码检测**: 7 项高置信度发现（unused imports/variables/methods）
  - `event.py`: unused FindingStatus import
  - `incremental_scan.py`: unused datetime/timezone import
  - `adversarial_service.py`: unused TriggerConditions/VerificationSession import
  - `scan_orchestrator.py`: unused VerificationService/AdjudicationService/create_adversarial_service import
  - `scans.py`: unused completed_engines/running_engines/pending_engines variables
  - `scan_orchestrator.py`: unused _deduplicate_findings method
  - `scan_orchestrator.py`: unused _detect_tech_stack method
- **变更统计**: 29 文件修改, +1868/-306 行

---

## 2026-04-13 (续)

### 项目审视问题修复 - 25 个修复点全部完成 ✅

- **Goal ID**: bugfix-comprehensive-review
- **Summary**: 修复项目代码审视中发现的 25 个问题，涵盖运行时崩溃、安全漏洞、后端逻辑、前端 Bug、代码质量和低优先级清理
- **影响范围**: 后端 API、前端 UI、安全模块、扫描引擎、验证器
- **核心变更**:
  1. **批次 1 - Critical 运行时崩溃修复** (`6506f39`):
     - 3 个验证器中 `self.logger` → `logger` 修正
     - `adjudication.py` 添加缺失的 `await`
     - `scan_executor.py` 添加 `self.project_repo` 初始化
     - `codeql.py` `dir()` → `locals()` 修正
     - `codeql.py` 删除重复 `shutil.rmtree()`
  2. **批次 2 - 安全漏洞修复** (`efd9dc4`):
     - 4 个扫描控制端点添加认证
     - API Key 比较改用 `hmac.compare_digest` 恒定时间
     - 删除重复 `SecurityDepends` 类定义
     - 移除 `verify_api_key` 无用参数
  3. **批次 3 - 后端逻辑修复** (`e6f21af`):
     - 工厂函数参数修正
     - Redis 订阅者添加重连逻辑
     - 移除双重去重
     - bare `except:` → `except Exception:`
     - SIGKILL → SIGTERM
     - Celery 任务幂等性保护
  4. **批次 4 - 前端 Bug 修复** (`127a8ee`):
     - Token Usage 条件修正
     - ZIP 上传使用配置的 client
     - 移除 `window.location.reload()`
     - 翻页 filter 重置
  5. **批次 5 - 代码质量改进** (`9dfdeb7`):
     - `main.py` print → logging
     - `progress_broadcaster.py` 合并 DB 查询
     - `adversarial_service.py` 删除死代码
     - `scan_tasks.py` 进度检查复用 DB engine
  6. **批次 6 - 低优先级清理** (`57a858a`):
     - `Settings.tsx` 修复 uptime 实际运行时间
     - 版本号从构建时注入
- **测试结果**: tests 目录不在仓库中，各批次通过独立语法检查和功能验证
- **安全扫描**: 4 个发现，均为预存问题（非本次引入）
  - BLOCKER: `config.py` 硬编码 DB 凭据
  - HIGH: `main.py` 日志输出 DB URL 明文
  - MEDIUM: WebSocket 端点无认证
  - LOW: API Key 认证默认禁用
- **死代码检测**: 10 项高置信度发现
  - 5 项可安全清理（建议下一轮处理）
  - 4 项延后
  - 1 项 Bug（websocket.py `_running` 属性未初始化）
- **变更统计**: 6 个独立 commit，跨 20+ 文件

---

## 2026-04-13

### Web 前端增强 + 安全修复 - 批量同步 ✅

- **Summary**: 扫描详情页面增强、终端风格实时进度、WebSocket 修复、安全加固
- **影响范围**: 前端 UI、WebSocket、后端 API 安全
- **核心变更**:
  1. **扫描详情页面增强**:
     - 新增 Collapsible 组件（基于 @radix-ui/react-collapsible）
     - ScanDetail: 添加扫描目标卡片、可折叠配置卡片、修复主进度条
     - ScanProgress: 引擎状态改为可展开卡片列表
  2. **终端风格实时进度窗口 (LiveTerminal)**:
     - 新建 LiveTerminal 组件（终端 UI + 扫描线 + 闪烁光标）
     - 复用全局 WS 单例、性能优化（React.memo、300ms 节流、200 条上限）
     - 后端增强 WS 事件数据（阶段详情、引擎进度、对抗辩论、漏洞发现）
  3. **WebSocket 跨进程修复**:
     - Redis Pub/Sub 桥接（Celery Worker → FastAPI）
     - Vite 代理添加 `ws: true`
     - useWebSocket 循环断连修复（useRef 存 options）
  4. **安全修复**:
     - `llm_configs.py`: create/update 响应遮蔽 API Key（与 get 一致）
     - `llm_configs.py`: 写操作端点添加 `Depends(require_api_key)`
     - `system_settings.py`: update 端点添加 `Depends(require_api_key)`
  5. **其他增强**:
     - 对抗性辩论数据推送（attacker/defender/judge 详情）
     - 规则翻译工具增强（ruleTranslations.ts）
     - 前端国际化完善（translations.ts）
     - GeneralSettingsCard、Checkbox 组件
     - CodeQL config/rules 更新
     - Token 统计修复
- **新增文件** (7 个):
  - `src/web/frontend/src/components/scan/LiveTerminal.tsx`
  - `src/web/frontend/src/components/settings/GeneralSettingsCard.tsx`
  - `src/web/frontend/src/components/ui/checkbox.tsx`
  - `src/web/frontend/src/components/ui/collapsible.tsx`
  - `src/web/frontend/src/utils/format.ts`
  - `tests/unit/test_web/test_timezone_awareness.py`
  - `.claude/commands/ai-feat.md`
- **修改文件**: 39 个
- **测试结果**: CodeQL 63/63 通过, Web 85 passed (18 failed 为已有问题，与本次无关)
- **安全检查**: ✅ API Key 遮蔽修复 + 端点认证修复
- **变更统计**: +2079/-528 行

---

## 2026-04-11

### P18: 配置系统迁移 - 完成 ✅

- **Goal ID**: P18-config-migration
- **Summary**: 移除 config.local.toml 依赖，所有配置迁移到数据库和前端设置
- **影响范围**: 配置系统、后端 API、前端 UI、扫描任务
- **核心变更**:
  1. **数据库模型** (P18-01):
     - `system_settings` 表：扫描配置、威胁情报 API Key
     - `llm_configs` 表：LLM 配置管理（支持按类型获取默认配置）
     - Alembic 迁移：004~007
  2. **后端 API** (P18-02):
     - `/api/v1/system-settings`：系统配置 CRUD
     - `/api/v1/llm-configs/type/{config_type}`：按类型获取默认配置
     - LLM 配置验证服务：支持连接测试
  3. **扫描任务集成** (P18-03):
     - `scan_tasks.py`：从数据库获取 LLM 配置
     - `opencode_agent.py`：支持传入 LLM 客户端
     - `adjudication.py`：对抗性验证使用正确的配置类型
  4. **前端 UI** (P18-04):
     - LLM 配置管理组件：添加/编辑/删除/测试连接
     - 系统设置页面：扫描参数、API Key 配置
     - 高级配置：max_retries, max_concurrent_requests, batch_size
  5. **清理旧代码** (P18-05):
     - 移除 `get_llm_config()` 中的 config.local.toml 读取
     - 配置完全从数据库加载
- **新增文件** (11 个):
  - `migrations/versions/004_add_task_id_to_scans.py`
  - `migrations/versions/005_add_llm_configs.py`
  - `migrations/versions/006_add_llm_advanced_fields.py`
  - `migrations/versions/007_create_system_settings.py`
  - `src/web/api/v1/llm_configs.py`
  - `src/web/api/v1/system_settings.py`
  - `src/web/models/llm_config.py`
  - `src/web/models/system_setting.py`
  - `src/web/repositories/llm_config.py`
  - `src/web/repositories/system_setting.py`
  - `src/web/services/llm_config_service.py`
  - `src/web/services/llm_validation.py`
- **测试结果**: passed ✅
- **安全检查**: ✅ config.local.toml 密钥已清理，API Key 迁移到数据库/环境变量
- **死代码检测**: Settings.from_yaml() 方法未使用；ConfigLoader 类仅用于废弃功能

---

## 2026-04-09 (续 3)

### P15: 代码质量改进 - 完成 ✅

- **Goal ID**: P15-code-quality-improvement
- **Summary**: 修复跨层依赖、清理死代码、修复假测试，并通过完整扫描验证
- **影响范围**: 架构层、测试层、代码质量
- **核心修复**:
  1. **跨层依赖修复**:
     - 创建 `src/core/models/attack_surface.py` 共享模型
     - 移动 `EntryPoint`, `AttackSurfaceReport`, `EntryPointType` 到 Core
     - 更新 L1/L3 层导入路径
     - 解决 L3 ↔ L1 循环依赖问题
  2. **死代码清理** (~1700 行):
     - 删除 `src/web/services/cli_adapter.py` (672 行)
     - 删除 `src/web/services/scan/` 子目录 (~800 行)
     - 删除 `src/web/api/v1/scans_v2.py` (221 行)
     - 更新 `src/web/services/__init__.py` 移除 CLIAdapter 导出
  3. **假测试修复**:
     - `tests/unit/test_l3/test_scan_order.py:187`: 修复 `assert True` 假测试
     - `tests/unit/test_l1/test_llm_detector.py:302`: 修复 `assert True` 假测试
  4. **Bug 修复** (验证扫描中发现):
     - `progress_broadcaster.py`: 阶段时间记录保留小数 (round(duration, 2))
     - `progress_broadcaster.py`: 修复多阶段记录重复问题
     - `adversarial_service.py`: 修复 API 签名不匹配 (code_context 参数)
     - `scan_tasks.py`: 修复模型配置优先级 (始终使用 config.local.toml)
     - `openai_client.py`: 增强 token 追踪 (支持非标准 API 格式)
- **测试结果**:
  - 单元测试: 69 passed, 2 warnings
  - 完整扫描: 成功 (4 findings, 114116 tokens, 581.89s)
  - 各阶段耗时: L1(42s) + Engines(155s) + Adversarial(381s)
- **安全扫描**: 无安全风险 (config.local.toml 已在 .gitignore)
- **死代码检测**: 无新的死代码发现
- **架构改进**:
  ```
  修复前: L3 → L1 → Core (循环依赖)
  修复后: L3 → Core ← L1 (单向依赖)
  ```
- **Commit ID**: 待提交

---

## 2026-04-09 (续)

### 同步: P14 完成 → 开始 P15

- **P14 状态**: 已完成并同步 ✅
- **P15 目标**: 代码质量改进 - 架构优化与死代码清理
- **待修复问题**:
  1. 跨层依赖 (L3 ↔ L1)
  2. 假测试 (assert True)
  3. 死代码 (CLIAdapter, scan/ 子目录, scans_v2.py)

---

### P14: Web 服务完整能力迁移 ✅

- **Goal ID**: P14-web-capability-migration
- **Summary**: 将 CLI 的所有高级功能迁移到 Web 服务，实现攻击面检测、可利用性验证、去重仲裁、对抗性验证、Token 统计、增量扫描增强
- **Impact**:
  - **新增服务** (4 个):
    - `src/web/services/attack_surface_service.py`: 攻击面检测服务 (P14-01)
    - `src/web/services/verification_service.py`: 可利用性验证服务 (P14-02)
    - `src/web/services/adjudication_service.py`: 仲裁和去重服务 (P14-03)
    - `src/web/services/adversarial_service.py`: 对抗性验证服务 (P14-04)
  - **核心修改**:
    - `src/web/services/scan_orchestrator.py`: 重构扫描流程，新增 7 个 Phase
    - `src/web/services/incremental_scan.py`: 增强增量扫描功能
    - `src/web/models/schemas.py`: 配置参数扩展 (llm_detect, llm_verify, adversarial, incremental 等)
    - `src/web/api/v1/scans.py`: 新增 3 个 API 端点
  - **数据库迁移**:
    - `migrations/versions/002_add_p14_verification_fields.py`: 添加 P14 字段
- **新增功能**:
  - **Phase 0 - L1_Preparation**: 攻击面检测 (静态 + LLM 模式)
  - **Phase 3.5 - Exploitability Verification**: 可利用性验证 (CodeQL 数据流 + 攻击面集成)
  - **Phase 4 - Deduplication + Adjudication**: 语义去重 + 仲裁决策
  - **Phase 5 - Adversarial Verification**: 多轮辩论 (Attacker vs Defender)
  - **Phase 7 - Token Statistics**: Token 使用统计 + 成本计算
  - **增量扫描增强**: Git diff 分析 + 失败时报错终止
- **新增 API**:
  ```
  GET /api/v1/scans/{id}/adversarial-debate      # 对抗性辩论内容
  GET /api/v1/scans/{id}/token-usage           # Token 统计
  GET /api/v1/scans/{id}/incremental-stats      # 增量扫描统计
  ```
- **配置参数**:
  ```json
  {
    "llm_detect": true,              // LLM 攻击面检测
    "static_only": false,            // 仅静态检测
    "llm_verify": true,              // 可利用性验证
    "adversarial": true,             // 对抗性验证
    "adversarial_max_rounds": 5,     // 最大对抗轮数
    "adversarial_round_timeout": 180, // 每轮超时(秒)
    "incremental": false,            // 增量扫描模式
    "base_ref": "HEAD~1",            // 增量扫描基准引用
    "head_ref": "HEAD"               // 增量扫描目标引用
  }
  ```
- **Tests**: 15 个单元测试全部通过 + 端到端测试成功 ✅
- **E2E Test**:
  - Web API + Celery Worker 启动成功
  - 扫描创建和执行正常 (0.72秒完成)
  - TechStackDetection 和 Semgrep 引擎工作正常
  - API 响应包含所有 P14 新字段
- **Security**: 无安全风险
- **Milestone**: v1.1 完成
- **Next**: 集成测试 (P14-09) 或开始下一个里程碑

---

## 2026-04-07 (续 2)

### P12-06: 漏洞结果界面完成 ✅

- **Goal ID**: P12-06
- **Summary**: 实现漏洞结果展示界面，包括列表/详情/代码高亮/状态管理
- **Impact**:
  - `src/web/api/v1/scans.py`: 新增 PATCH 状态更新 API
  - `src/web/frontend/src/pages/Findings.tsx`: 漏洞列表主页面
  - `src/web/frontend/src/components/finding/`: 3 个组件（List/Drawer/Highlight）
  - `src/web/frontend/src/hooks/useFindings.ts`: 数据获取 Hook
  - `src/web/frontend/package.json`: 添加 react-syntax-highlighter
- **Features**:
  - **漏洞列表**: 分页、排序、严重程度筛选、状态筛选、关键字搜索
  - **详情抽屉**: 3 个 Tab（概览/代码/元数据）
  - **代码高亮**: 多语言语法高亮、目标行高亮显示
  - **状态管理**: 已确认/误报/有条件状态切换
  - **统计卡片**: 总数/已确认/误报/严重/高危统计
  - **导航链接**: 从扫描详情页跳转到漏洞列表
- **API**:
  ```
  PATCH /api/v1/scans/{scan_id}/findings/{finding_id}/status
  Body: { "status": "confirmed" | "false_positive" | "conditional" }
  ```
- **Route**:
  ```
  /scans/:scanId/findings
  ```
- **Tests**: 待用户运行 npm install 后测试
- **Security**: 无安全风险
- **Milestone**: v0.98 完成
- **Next**: P12-07 报告生成、P13 企业级功能 或自定义新目标

---

## 2026-04-07 (续)

### P12-00: 前端界面 MVP 完成 ✅

- **Goal ID**: P12-00
- **Summary**: 完成 React + TypeScript + Ant Design 前端 MVP，实现项目管理和扫描管理界面，支持 WebSocket 实时进度更新
- **Impact**:
  - `src/web/frontend/`: 新增前端项目目录（25 个文件）
  - 配置文件: package.json, tsconfig.json, vite.config.ts, tailwind.config.js, .eslintrc.cjs, .gitignore
  - API 层: client.ts, projects.ts, scans.ts, websocket.ts
  - 类型定义: models.ts, websocket.ts
  - Hooks: useWebSocket.ts, useScanProgress.ts, useApi.ts (React Query)
  - 页面: Projects.tsx, Scans.tsx, ScanDetail.tsx
  - 布局: AppLayout.tsx (Ant Design 侧边栏布局)
- **Features**:
  - **项目管理**: 项目列表（分页、筛选）、创建项目（表单验证）、删除项目（确认提示）、查看扫描历史
  - **扫描管理**: 扫描列表（分页、状态筛选）、扫描详情（进度、统计、阶段时间线）
  - **扫描控制**: 暂停/继续/取消按钮，根据状态动态显示
  - **实时进度**: WebSocket 客户端封装，自动重连（指数退避），心跳机制（30 秒）
  - **降级策略**: WebSocket 失败时自动降级到轮询（5 秒间隔）
  - **React Query**: 数据获取与缓存，自动重新验证（扫描中每 5 秒）
  - **TypeScript**: 严格类型安全，完整的 API 类型定义
- **Tech Stack**:
  - React 18.3 + TypeScript 5.3
  - Vite 5.0 (构建工具)
  - Ant Design 5.12+ (UI 组件库)
  - React Router 6.20 (路由管理)
  - React Query 5.0 (数据获取)
  - Axios 1.6 (HTTP 客户端)
- **Tests**: 待用户运行 `npm install` 后测试
- **Security**: 无安全风险，API Key 通过 localStorage 读取
- **Milestone**: v0.97 完成
- **Next**: P12-06 漏洞结果界面、P13 企业级功能 或自定义新目标

---

### P11-00: 暂停/续扫机制完成 ✅

- **Goal ID**: P11-00
- **Summary**: 完成暂停/续扫机制，支持检查点保存/恢复、阶段状态管理、控制接口 API、WebSocket 实时推送和增量扫描
- **Impact**:
  - `src/web/services/checkpoint_service.py`: 检查点服务 (~400 行)
  - `src/web/services/phase_manager.py`: 阶段管理器 (~500 行)
  - `src/web/services/incremental_scan.py`: 增量扫描服务 (~400 行)
  - `src/web/api/websocket.py`: WebSocket 连接管理器 (~300 行)
  - `src/web/services/scan_executor.py`: 添加 pause/resume/cancel 方法
  - `src/web/tasks/scan_tasks.py`: 添加 resume_from 参数支持
  - `src/web/services/cli_adapter.py`: 集成增量扫描预分析
  - `src/web/api/v1/scans.py`: 添加 4 个控制端点 + WebSocket 端点
  - `src/web/models/schemas.py`: 添加 4 个控制响应模型
  - `tests/unit/test_web/test_pause_resume.py`: pause/resume 测试 (15 测试)
  - `tests/unit/test_web/api/test_control.py`: 控制 API 测试 (17 测试)
  - `tests/unit/test_web/test_incremental_scan.py`: 增量扫描测试 (25 测试)
  - `tests/unit/test_web/test_websocket.py`: WebSocket 测试 (20 测试)
- **Features**:
  - **检查点服务**: CheckpointData/PhaseCheckpoint 模型，数据库+文件双备份，完整性验证，续扫策略计算
  - **阶段管理**: VALID_TRANSITIONS 状态转换规则，start/complete/fail/skip 阶段方法
  - **暂停扫描**: 保存检查点，更新状态为 PAUSED，终止 Celery 任务
  - **恢复扫描**: 加载检查点，验证完整性，启动新 Celery 任务，跳过已完成阶段
  - **取消扫描**: 清理资源，更新状态为 CANCELLED
  - **状态查询**: 动态计算 available_actions, can_pause, can_resume, can_cancel
  - **增量扫描**: Git 差异分析，文件哈希计算，变更分类 (added/modified/deleted/renamed)
  - **WebSocket**: ConnectionManager 连接管理，ScanEventBroadcaster 事件广播，心跳机制
  - **事件类型**: phase_start/complete, finding_new, progress, scan_complete, scan_failed, scan_paused
- **API Endpoints**:
  ```
  POST /api/v1/scans/{id}/pause    # 暂停扫描
  POST /api/v1/scans/{id}/resume   # 继续扫描
  POST /api/v1/scans/{id}/cancel   # 取消扫描
  GET  /api/v1/scans/{id}/status   # 查询状态
  WS   /api/v1/ws/{scan_id}       # WebSocket 实时推送
  ```
- **Tests**: 77/77 单元测试通过 ✅
  - Pause/resume 服务: 15/15 (2 skipped)
  - 控制 API: 17/17
  - 增量扫描: 25/25
  - WebSocket: 20/20
- **Security**: 无安全风险，API 认证通过 require_api_key 保护
- **Dead Code**: 未检测到死代码
- **Milestone**: v0.96 完成
- **Next**: Phase 12 前端界面 或自定义新目标

---

## 2026-04-07

### P10-07: CLI 集成服务完成

- **Goal ID**: P10-00
- **Summary**: 完成 CLI 集成服务，实现 Celery 后台任务和实时进度追踪
- **Impact**:
  - `pyproject.toml`: 添加 celery>=5.3.0, redis>=5.0.0
  - `src/web/core/celery_app.py`: Celery 应用配置 (122 行)
  - `src/web/tasks/scan_tasks.py`: Celery 扫描任务 (176 行)
  - `src/web/services/cli_adapter.py`: CLI 适配器 (494 行)
  - `src/web/services/scan_executor.py`: 扫描执行器 (482 行)
  - `src/web/services/__init__.py`: 服务模块导出
  - `tests/unit/test_web/test_services.py`: 服务层单元测试 (14 测试)
- **Features**:
  - **Celery 集成**: Redis broker，异步任务执行，任务状态追踪
  - **CLIAdapter**: 子进程调用 deepvuln CLI，解析 JSONL 输出
  - **实时进度**: 文件级、引擎级、Token 级进度追踪
  - **事件处理**: 18+ 种事件类型 (phase_start/complete, file_start/complete, finding_new/verified, agent_thinking, adversarial_start/round)
  - **ScanExecutor**: 扫描生命周期管理（创建/启动/查询/取消/重试）
  - **asyncio.run()**: Celery 同步任务包装异步实现
- **Event Types Supported**:
  ```
  phase_start, phase_complete, engine_start, engine_complete
  file_start, file_complete
  agent_thinking, agent_action, agent_observation
  adversarial_start, adversarial_round, adversarial_complete
  finding_new, finding_verified, finding_false_positive
  progress, error, warning, info
  scan_complete, scan_failed
  ```
- **Tests**: 14/14 服务层测试通过 ✅
  - test_scan_executor_initialization: 初始化验证
  - test_get_scan_executor_singleton: 单例模式验证
  - test_create_scan: 创建扫描验证
  - test_get_scan_status: 状态查询验证
  - test_get_scan_progress: 详细进度查询验证
  - test_cancel_scan: 取消扫描验证
  - test_retry_scan: 重试扫描验证
  - test_extract_adversarial_status: 对抗状态提取
  - test_extract_current_file_info: 当前文件提取
- **Total Tests**: 78/78 (64 原有 + 14 新增)
- **Security**: No hardcoded secrets, Redis URL from environment
- **Dead Code**: 未检测到死代码
- **Next**: P10-00 完成 / v0.95 里程碑 / 或开始 P11 暂停续扫功能

---

## 2026-04-07 (续)

### P10-04/05/08: API 端点与测试完成

- **Goal ID**: P10-00
- **Summary**: 完成 Web 服务 API 端点和单元测试，实现 15 个 RESTful 接口
- **Impact**:
  - `src/web/api/v1/projects.py`: 265 行，6 个项目管理端点
  - `src/web/api/v1/scans.py`: 697 行，9 个扫描管理端点
  - `src/web/api/deps.py`: 依赖注入提供者
  - `tests/unit/test_web/api/`: 新增 API 测试目录
  - `tests/unit/test_web/api/test_projects.py`: 13 个单元测试
  - `tests/unit/test_web/api/test_scans.py`: 9 个单元测试
  - `tests/unit/test_web/test_main.py`: 更新路由测试
- **Features**:
  - **项目管理 API**: 创建/列出/获取/更新/删除项目，查询扫描历史
  - **扫描管理 API**: 创建/列出/获取扫描，查询进度/阶段/事件
  - **Agent 对话 API**: 获取 Agent 对话历史（含对抗辩论）
  - **进度追踪 API**: 详细进度（引擎状态、Token 消耗、发现统计）
  - **文件追踪 API**: 获取当前处理文件详情
  - **认证分层**: 写操作需 API Key，读操作可选认证
  - **分页支持**: 所有列表端点支持分页（page/page_size）
  - **过滤支持**: 按状态、项目、严重程度过滤
- **API 端点清单**:
  ```
  项目管理:
    POST   /api/v1/projects          创建项目
    GET    /api/v1/projects          列出项目 (分页/过滤)
    GET    /api/v1/projects/{id}     获取详情
    PUT    /api/v1/projects/{id}     更新项目
    DELETE /api/v1/projects/{id}     删除项目
    GET    /api/v1/projects/{id}/scans 扫描历史

  扫描管理:
    POST   /api/v1/scans                        创建扫描
    GET    /api/v1/scans                        列出扫描 (分页/过滤)
    GET    /api/v1/scans/{id}                   获取详情
    GET    /api/v1/scans/{id}/progress          详细进度
    GET    /api/v1/scans/{id}/phases            阶段详情
    GET    /api/v1/scans/{id}/events            事件流
    GET    /api/v1/scans/{id}/agent-conversation Agent 对话
    GET    /api/v1/scans/{id}/current-file      当前文件
    GET    /api/v1/scans/{id}/findings          漏洞结果
    GET    /api/v1/scans/{id}/report            扫描报告
  ```
- **Tests**: 64/64 单元测试通过 ✅
  - 数据模型: 10/10
  - Schema 验证: 15/15
  - Repository: 7/7
  - Main 应用: 9/9
  - **Projects API: 13/13** (路由 + 请求验证 + 分页)
  - **Scans API: 9/9** (路由 + 请求验证 + 分页)
  - **新增: 23 API 测试**
- **Security**: No hardcoded secrets, API authentication from environment
- **Dead Code**: not run
- **Next**: P10-07 CLI 集成服务 (当前 in_progress)

---

## 2026-04-07

### P10-01~P10-06: Web 服务基础架构

- **Goal ID**: P10-00
- **Summary**: 实现 FastAPI 后端基础架构，包括 PostgreSQL 数据库、Pydantic 模型、Repository 层
- **Impact**:
  - `migrations/`: Alembic 迁移框架 + 初始 schema (001_init_schema.py)
  - `src/web/models/`: 7 个数据模型文件 (project/scan/finding/checkpoint/schemas/database)
  - `src/web/core/`: 配置管理 (config.py)、数据库连接 (database.py)、API Key 认证 (security.py)
  - `src/web/repositories/`: 6 个 Repository 类 (base/project/scan/finding/event)
  - `src/web/main.py`: FastAPI 应用入口
  - `pyproject.toml`: 添加 web 依赖 (fastapi, uvicorn, sqlalchemy, alembic, asyncpg)
- **Features**:
  - **数据库设计**: 7 张核心表 (projects/scans/scan_phases/scan_events/findings/scan_files/api_keys)
  - **细粒度进度追踪**: 引擎级、步骤级、Token 消耗、发现统计 (参考 DeepAudit)
  - **Agent 对话支持**: scan_events 表存储 agent_turn/agent_role/agent_message
  - **Phase 9 集成**: findings.cpg_path JSONB 字段
  - **异步支持**: SQLAlchemy 2.0 Async + AsyncSession
  - **API Key 认证**: 基于头部的简单认证 (X-API-Key)
- **Tests**: 41/41 单元测试通过 ✅
  - 数据模型: 10/10
  - Schema 验证: 15/15
  - Repository: 7/7
  - Main 应用: 9/9
- **Security**: No hardcoded secrets, API keys from environment
- **Dead Code**: not run
- **Next**: P10-04 项目管理 API (当前 in_progress)

### P9-01: CPG 与 Agent 标准集成

- **Goal ID**: P9-01
- **Summary**: 实现 CPG 与 Agent 的标准集成，为 AI 分析提供攻击路径信息
- **Impact**:
  - `src/layers/l3_analysis/engines/ast_engine/cpg/path_provider.py`: CPGPathProvider 语言无关接口
  - `src/layers/l3_analysis/engines/ast_engine/cpg/base.py`: LanguageCPGProvider 抽象基类
  - `src/layers/l3_analysis/engines/ast_engine/cpg/providers/python_provider.py`: Python 实现
  - `src/layers/l3_analysis/engines/ast_engine/cpg/providers/js_provider.py`: JavaScript 实现
  - `src/layers/l3_analysis/engines/opencode_agent.py`: Agent 集成 CPGPathProvider
  - `src/layers/l3_analysis/models.py`: Finding 添加 `cpg_path` 字段
  - `src/layers/l3_analysis/prompts/security_audit.py`: Prompt 集成 CPG 路径信息
- **Features**:
  - **CPGPathProvider**: 语言无关接口，自动路由到语言特定 Provider
  - **语言检测**: 基于文件扩展名的自动语言检测
  - **降级策略**: CPG 失败时 Agent 继续正常工作
  - **Finding 扩展**: `cpg_path` 字段存储攻击路径元数据 (entry_point, sink, path, confidence, sanitizers, reaches_sink)
  - **路径匹配**: 自动将 Finding 匹配到最相关的 CPG 路径
  - **多语言支持**: Python (完整) + JavaScript/TypeScript
- **Tests**: 61/61 测试通过 (100%)
  - test_path_provider.py: 11 单元测试
  - test_python_provider.py: 11 单元测试
  - test_js_provider.py: 14 单元测试
  - test_e2e.py: 8 集成测试
- **Security**: No secrets exposed
- **Design**: 分层集成，可选降级，不影响现有 Agent 功能

### P8-09: CPG 基础实现

### P8-09: CPG 基础实现

- **Goal ID**: P8-09
- **Summary**: 实现 Code Property Graph 基础，融合 AST Graph + Call Graph + CFG，支持攻击路径搜索
- **Impact**:
  - `src/layers/l3_analysis/engines/ast_engine/cpg/`: 新增 CPG 统一代码图模块
    - `models.py`: CPGNode, CPGEdge, CodePropertyGraph 数据结构
    - `builder.py`: CPGBuilder 融合 AST + Call Graph
  - `src/layers/l3_analysis/engines/ast_engine/cfg/`: 新增控制流图模块
    - `models.py`: CFGNode, CFGEdge, ControlFlowGraph, BasicBlock
    - `base.py`: LanguageCFGBuilder 抽象基类
    - `factory.py`: CFGBuilderFactory 语言路由
    - `builders/python_cfg.py`: Python CFG 构建器（完整支持）
    - `builders/js_cfg.py`: JavaScript/TypeScript CFG 构建器
    - `builders/java_cfg.py`: Java CFG 构建器
    - `builders/go_cfg.py`: Go CFG 构建器
  - `src/layers/l3_analysis/engines/ast_engine/path_finder/`: 新增攻击路径搜索模块
    - `models.py`: AttackPath, PathFinderConfig, PathType
    - `finder.py`: AttackPathFinder BFS 路径搜索算法
- **Features**:
  - **CPG 统一视图**: 融合 AST Graph（语句级）+ Call Graph（函数级）到统一代码图
  - **多语言 CFG 支持**: Python（完整）+ JavaScript + Java + Go（基础）
    - Python: if/while/for/try/match/async/break/continue/return
    - JavaScript: if/while/for/try/switch/break/continue
    - Java: if/while/for/try/switch/break/continue
    - Go: if/while/for/switch/break/continue
  - **语言抽象接口**: `LanguageCFGBuilder` 基类，支持扩展到其他语言
  - **攻击路径搜索**: BFS 算法从入口点到危险函数
  - **Sanitizer 检测**: 自动识别清洗函数（sanitize/escape/validate/filter）
  - **路径属性**: confidence 计算、可达性验证、条件分支记录
- **Tests**: 47 单元测试通过 (CPG: 15, CFG: 18, PathFinder: 14)
- **Multi-language**: Python (完整) + JavaScript + Java + Go (框架支持)
- **Next**: v0.9 里程碑完整验证 / CPG 与 Agent 集成

## 2026-04-05

### P8-08: 前置防误报架构

- **Goal ID**: P8-08
- **Summary**: 实现前置防误报架构，在源头防止误报，节省 ~40% LLM 调用
- **Impact**:
  - `src/layers/l3_analysis/pre_filter/`: 新增预过滤器模块目录
    - `file_pre_filter.py`: FilePreFilter 文件级预过滤 (P8-08a)
    - `streaming_validator.py`: StreamingValidator 流式验证 (P8-08c)
    - `in_memory_deduplicator.py`: InMemoryDeduplicator 前置去重 (P8-08e)
    - `codeql_pre_filter.py`: CodeQLPreFilter CodeQL 预过滤 (P8-08d)
  - `src/layers/l3_analysis/prompts/enhanced_audit_prompt.py`: 防幻觉规则 (P8-08b)
  - `src/layers/l3_analysis/verification/verification_gatekeeper.py`: 对抗验证门槛 (P8-08f)
  - `src/layers/l3_analysis/prompts/security_audit.py`: 集成增强 prompt
  - `src/layers/l3_analysis/deduplicator.py`: 支持 GLM-5 reasoning_content (P8-08h)
- **Features**:
  - **FilePreFilter**: 扫描前判断文件是否值得分析
    - 跳过配置文件、生成代码、无可执行代码的文件
    - 攻击面可达性检查
  - **EnhancedPrompt**: 集成 code-audit skill 防幻觉规则
    - 执行证据要求：必须有用户可控输入 + 危险操作 + 实际执行
    - Few-Shot 示例：正反例对比
    - 置信度校准规则
  - **StreamingValidator**: Finding 流式验证
    - 检查执行证据（危险调用 vs 仅构造）
    - 置信度合理性校准
    - XSS + JSON 响应自动降级
  - **InMemoryDeduplicator**: 前端内存去重
    - 文件级去重（同文件同行号保留最高分）
    - 调用链去重（同漏洞不同层级只保留一个）
  - **CodeQLPreFilter**: CodeQL 预过滤
    - 规则置信度调整（XSS 默认降低 0.2）
    - 响应类型检测（JSON vs HTML）
    - 通配符规则匹配
  - **VerificationGatekeeper**: 对抗验证准入门槛
    - 明显误报 → 自动拒绝
    - 强证据 + 高置信 → 自动确认
    - 低置信 + 低严重 → needs_review
  - **GLM-5 支持**: 去重器支持 reasoning_content 字段解析
- **Tests**: 109 单元测试 + 16 集成测试通过
- **Security**: No secrets exposed
- **Dead Code**: 未检测到死代码
- **Expected Effects**:
  - ~50% 减少 Agent 误报（防幻觉规则 + 流式验证）
  - ~50% 减少 CodeQL 误报（JSON 响应检测 + 规则调整）
  - ~56% 减少重复检测（前端内存去重）
  - ~40% 减少对抗验证调用（智能准入门槛）
- **Next**: P8-09 CPG 基础 (可选)

## 2026-04-04

### P8-07: 规则库扩展

- **Goal ID**: P8-07
- **Summary**: 扩展 AST Query 规则库，增加框架特定漏洞检测规则
- **Impact**:
  - `src/layers/l3_analysis/engines/ast_engine/detectors/framework_detector.py`: FrameworkDetector 实现
  - `rules/ast_query/framework/`: 13 个框架规则 YAML 文件
    - `flask/`: 4 个 Flask 规则
    - `django/`: 2 个 Django 规则
    - `fastapi/`: 1 个 FastAPI 规则
    - `express/`: 2 个 Express 规则
    - `java/`: 2 个 Java 规则
    - `go/`: 2 个 Go 规则
  - `tests/unit/test_l3/test_ast_engine/test_framework_detector.py`: 19 个单元测试
- **Features**:
  - **FrameworkDetector**: 框架专用检测器
    - 从 `rules/ast_query/framework/` 目录加载规则
    - 支持框架特定上下文验证
  - **框架规则覆盖**:
    - **Flask**: render_template_string (SSTI), secret_key_hardcoded, allow_all_hosts, redirect_user_input (开放重定向)
    - **Django**: render_xss, extra_raw_sql (SQL 注入)
    - **FastAPI**: corp_auto_origin (CORS 配置错误)
    - **Express**: prototype_pollution_merge, template_injection_ejs (SSTI)
    - **Java**: reflection_class_forname (代码注入), jni_register_natives
    - **Go**: context_without_deadline (DoS), defer_close_file (资源泄漏)
- **Tests**: 19/19 单元测试通过，覆盖所有框架检测场景
- **Security**: No secrets exposed
- **Dead Code**: 未检测到死代码
- **Next**: P8-08 CPG 基础 (Phase 2) 或其他 Phase 8 任务

### P8-06: AI Agent 结构化上下文

- **Goal ID**: P8-06
- **Summary**: 为 AI Agent 提供 AST 结构化上下文，提升推理精度
- **Impact**:
  - `src/layers/l3_analysis/engines/ast_engine/context/extractor.py`: ASTContextExtractor 实现 (~260 行)
  - `src/layers/l3_analysis/prompts/security_audit.py`: 添加 `ast_context` 参数
  - `src/layers/l3_analysis/engines/opencode_agent.py`: 集成 ASTContextExtractor
  - `tests/unit/test_l3/test_ast_context/test_extractor.py`: 11 个单元测试
- **Features**:
  - **ASTContextExtractor**: 提取 AST 结构化上下文
    - `extract_for_location()`: 提取特定位置的 AST 上下文
    - `extract_for_sinks()`: 批量提取 sink 上下文
    - `extract_for_code()`: 从代码直接提取 AST 上下文
  - **ASTContext**: 上下文数据结构（code_snippet, ast_structure, parent_context, risk_analysis）
  - **风险分析**: 支持 6 类危险函数检测（code_injection, command_injection, sql_injection, path_traversal, deserialization, weak_crypto）
  - **Prompt 增强**: AST Structure Analysis 自动添加到 AI prompt
- **Design**:
  - 降级策略：AST Graph 不可用时降级到不使用 AST 上下文
  - 风险映射：危险函数 → 漏洞类型（eval → code_injection）
- **Tests**: 11/11 单元测试通过
- **Security**: No secrets exposed
- **Dead Code**: 未检测到死代码
- **Next**: P8-07 规则库扩展（可选）

### P8-05: 与 Call Graph 桥接

- **Goal ID**: P8-05
- **Summary**: 实现 AST Graph 与 Call Graph 的桥接，提供统一查询接口
- **Impact**:
  - `src/layers/l3_analysis/engines/ast_engine/graph/bridge.py`: GraphBridge 实现 (~370 行)
  - `src/layers/l3_analysis/engines/ast_engine/graph/unified.py`: UnifiedGraphQuery 实现 (~500 行)
  - `src/layers/l3_analysis/engines/ast_engine/graph/__init__.py`: 导出新类
  - `tests/unit/test_l3/test_ast_graph/test_bridge.py`: 14 个单元测试
  - `tests/unit/test_l3/test_ast_graph/test_unified.py`: 18 个单元测试
  - `tests/integration/test_graph_bridge_e2e.py`: 3 个端到端集成测试
- **Features**:
  - **GraphBridge**: 跨图导航核心
    - `find_containing_function()`: AST 节点 → 包含它的 CallNode（向上遍历 parent_id）
    - `find_ast_nodes_in_function()`: CallNode → 函数体内的所有 ASTNode（向下遍历子树）
    - `trace_to_sink()`: 从入口点到 sink 的完整路径追踪
  - **UnifiedGraphQuery**: 高层统一查询接口
    - `find_all_sinks()`: 查找所有危险 sink（eval、system、open、pickle.load 等）
    - `find_reachable_sinks()`: 从入口点找到所有可达的危险 sink
    - `get_function_context()`: 获取某个位置的完整上下文（函数、调用者、被调用者、sinks）
    - `get_attack_paths()`: 获取到目标位置的完整攻击路径
  - **TracedPath**: 完整攻击路径数据结构（entry_point → call_chain → sink）
  - **SinkMatch**: 危险 sink 匹配结果（含 sink_type、confidence）
  - **FunctionContext**: 函数上下文（call_node、ast_nodes、callers、callees、sinks）
- **Design Decision**:
  - 选项 A (保持简单): 基于坐标匹配 + 父子关系，无需修改已有代码
  - 完全准确：利用 tree-sitter 的真实 AST 结构，向上遍历 parent_id
  - 升级触发条件记录在 roadmap 中
- **Tests**: 58/58 测试通过（14 bridge + 18 unified + 23 models + 3 builder）
- **Security**: No secrets exposed
- **Dead Code**: 未检测到死代码
- **Next**: P8-06 AI Agent 结构化上下文（可选）

### P8-04: AST Graph Builder (选项 A)

- **Goal ID**: P8-04
- **Summary**: 实现简单的 AST 代码图构建器，支持基础遍历和查询
- **Impact**:
  - `src/layers/l3_analysis/engines/ast_engine/graph/`: 新增图模块目录
  - `src/layers/l3_analysis/engines/ast_engine/graph/models.py`: ASTNode, ASTGraph 数据结构
  - `src/layers/l3_analysis/engines/ast_engine/graph/builder.py`: ASTGraphBuilder 实现
  - `tests/unit/test_l3/test_ast_graph/`: 新增 23 个单元测试
- **Features**:
  - **ASTNode**: 节点数据结构 (id, type, name, file, line, parent_id, children)
  - **ASTGraph**: 图容器，支持文件索引、类型索引
  - **ASTGraphBuilder**: 遍历 tree-sitter AST，构建代码图
  - **查询 API**: get_node, get_children, get_nodes_by_type, get_nodes_by_file, find_by_name
  - **序列化**: to_dict() 支持导出为 JSON
- **Design Decision**:
  - 选项 A (简单图构建): 基础节点/边 + 父子关系
  - P8-05 时评估是否需要升级到选项 B (完整图系统)
- **Tests**: 23/23 单元测试通过
- **Security**: No secrets exposed
- **Next**: P8-05 与 Call Graph 桥接（需先评估升级需求）

### P8-03: 结构型漏洞检测器实现

- **Goal ID**: P8-03
- **Summary**: 实现检测器框架和 YAML 规则系统，支持可扩展的结构化漏洞检测
- **Impact**:
  - `src/layers/l3_analysis/engines/ast_engine/detectors/`: 新增检测器框架目录
  - `src/layers/l3_analysis/engines/ast_engine/ast_engine.py`: 重构为检测器架构，移除硬编码规则
  - `rules/ast_query/`: 新增 YAML 规则目录，10 条规则文件
  - `tests/unit/test_l3/test_detectors/`: 新增 16 个检测器单元测试
- **Features**:
  - **BaseDetector**: 抽象基类，提供 YAML 规则加载和 `_post_validate` hook
  - **DangerousAPIDetector**: 检测 eval/exec/os.system/subprocess，支持常量字面量过滤
  - **CryptoMisuseDetector**: 检测 md5/sha1，支持测试代码过滤
  - **DeserializationDetector**: 检测 pickle/yaml unsafe load
  - **YAML 规则系统**: 规则外部化，支持多语言，易于扩展
- **Rules Added**:
  - Python: eval, exec, os.system, subprocess shell=True, md5, sha1, pickle.load, yaml.load
  - JavaScript: eval, md5
- **Tests**: 16/16 单元测试通过 + 14/14 AST Engine 测试通过
- **Security**: No secrets exposed
- **Next**: P8-04 AST Graph Builder

### P8-02a: AST Engine 基础设施

- **Goal ID**: P8-02a
- **Summary**: 实现 AST Engine 核心架构，提供语句级别的代码结构分析能力
- **Impact**:
  - `src/layers/l3_analysis/engines/ast_engine/`: 新增 AST Engine 完整模块
  - `src/layers/l3_analysis/models.py`: 添加 `ast_engine` 到 Finding.source 允许值
  - `tests/unit/test_l3/test_ast_engine/`: 新增 14 个单元测试
- **Features**:
  - **TreeSitterManager**: 动态加载多语言 tree-sitter 解析器
  - **QueryEngine**: 封装 tree-sitter 查询 API，支持结构化查询
  - **ASTEngine**: 主引擎类，继承 BaseEngine，集成到引擎注册表
  - **内置规则**: eval/exec/os.system/md5/pickle 检测
- **Supported Languages**: Python, JavaScript, TypeScript, Java, Go, C/C++, Ruby, PHP, Rust
- **Tests**: 14/14 单元测试通过
- **Security**: No secrets exposed
- **Next**: P8-03 结构型漏洞检测器扩展

## 2026-04-02

### P7-01: 报告导出增强 - LLM 分析详情选项

- **Goal ID**: P7-01
- **Summary**: 添加 `--include-llm-details` 选项，允许在导出报告中包含 LLM 评估详情
- **Impact**:
  - `src/cli/main.py`: 新增 `--include-llm-details` 参数，增强 `_export_full_scan_result` 函数
- **Features**:
  - 去重分析详情：显示合并的漏洞组及 LLM 推理原因
  - 对抗验证详情：每个漏洞的 verdict (CONFIRMED/REJECTED)、confidence、reasoning
- **Usage**:
  ```bash
  # 基本导出（不含 LLM 详情）
  deepvuln scan -p /target --full --export report.txt

  # 带 LLM 详情的导出
  deepvuln scan -p /target --full --export report.txt --include-llm-details
  ```
- **Tests**: Docker 集成测试通过 (java-simple-vuln: 4 CONFIRMED, 完整 reasoning 导出)
- **Security**: No secrets exposed

### P5-01e: 扫描顺序优化完成

### P5-01e: 扫描顺序优化完成

- **Goal ID**: P5-01e
- **Summary**: 将去重阶段移到对抗性验证之前，减少 LLM API 调用量约 25%
- **Impact**:
  - `src/cli/main.py`: 新增 Phase 4.25 (Deduplication)，移动去重逻辑到对抗验证之前
  - `tests/unit/test_l3/test_scan_order.py`: 新文件（12 个单元测试）
  - `tests/unit/test_l3/test_deduplicator.py`: 修复 `llm_timeout` 期望值 (30→180)
- **Flow Change**:
  ```
  旧: Phase 4 (Verify) → Phase 4.5 (Adversarial) → Deduplication
  新: Phase 4 (Verify) → Phase 4.25 (Deduplication) → Phase 4.5 (Adversarial)
  ```
- **Key Changes**:
  - 在 Phase 4 结束后立即调用 `adjudicate_findings()` 进行去重
  - 更新 `result["verified_findings"]` 为去重后的结果
  - Phase 4.5 现在接收去重后的 findings（191 → ~150）
- **Expected Impact**:
  - 对抗验证数量减少约 22% (191 → 150)
  - API 调用减少约 25%
  - Token 使用量减少约 30%
  - 扫描时间减少约 25%
- **Tests**: 12/12 单元测试通过
- **Commit**: 2a87275

### Bug 修复: 扫描日志问题修复

- **Goal ID**: bugfix-scan-log-issues
- **Summary**: 修复扫描日志中发现的 4 个系统问题
- **Impact**:
  - `src/layers/l3_analysis/readiness_gate.py`: 修复 RuntimeType 导入路径
  - `src/layers/l3_analysis/verification/*.py`: 集成 `robust_json_loads` 增强解析容错
  - `src/layers/l3_analysis/deduplicator.py`: 使用 `robust_json_loads`
  - `src/layers/l3_analysis/engines/codeql.py`: 修复 Java 构建命令检测逻辑
  - `src/cli/main.py`: 添加报告导出前目录创建和权限错误处理
- **Issues Fixed**:
  1. Readiness Gate 导入错误：`types.py` → `models.py`
  2. LLM 响应解析失败：多次 JSON 解析错误（GLM API 格式问题）
  3. CodeQL Java 构建失败：`build_command` 优先级逻辑错误
  4. 报告导出权限错误：缺少目录创建和错误处理
- **Tests**: 31/31 readiness_gate + 45/45 json_parser 通过
- **Commit**: 73d4c32

## 2026-04-01

### Bug 修复: LLM 去重服务集成问题

- **Goal ID**: bugfix-llm-dedup-integration
- **Summary**: 修复 P6-17 LLM 去重功能的多个集成问题，确保跨引擎去重正常工作
- **Impact**:
  - `src/layers/l3_analysis/adjudication.py`: 添加 `api_key` 和 `base_url` 参数传递
  - `src/layers/l3_analysis/llm/openai_client.py`: 处理 GLM-5 的 `content`/`reasoning_content` 字段，添加请求超时参数支持
  - `src/layers/l3_analysis/deduplicator.py`: 使用子进程方式调用 LLM 避免异步冲突，超时增加到 180 秒
  - `src/layers/l3_analysis/models.py`: 添加 `merged_findings` 字段用于存储合并的漏洞详情
- **Root Cause**:
  - `adjudication.py` 创建 `OpenAIClient` 时未传递认证信息
  - GLM-5 推理模型使用 `reasoning_content` 字段存储推理过程，`content` 字段存储最终答案
  - 扫描框架在异步上下文中运行，`asyncio.run()` 无法嵌套调用
  - 默认超时 30 秒不足以支持 GLM-5 推理（需要 60-90 秒）
- **Fix**:
  - 从 `get_openai_config()` 获取并传递 `api_key` 和 `base_url`
  - 优先读取 `content` 字段，为空时回退到 `reasoning_content`
  - 使用子进程 + base64 编码方式调用 LLM，避免事件循环冲突
  - 默认超时从 30 秒增加到 180 秒
  - 添加 `merged_findings: list[dict[str, Any]]` 字段记录合并的漏洞详情
- **Tests**: 本地验证通过 (3 findings → 2 findings, 1 removed)
- **Security**: No secrets exposed

### Bug 修复: Readiness Gate 属性访问安全

- **Goal ID**: bugfix-readiness-gate-attr
- **Summary**: 修复 readiness_gate.py 中直接访问可能不存在的属性导致的崩溃
- **Impact**:
  - `src/layers/l3_analysis/readiness_gate.py`: 异常处理中使用安全属性访问 (getattr + fallback)
- **Root Cause**:
  - `_analyze_build_readiness` 接收 `list[BuildRecommendation]`，但异常处理假设 target 有 `name` 和 `language` 属性
  - `BuildRecommendation` 没有 `name`/`language` 属性，导致 `AttributeError`
- **Fix**:
  - 使用 `getattr(target, 'name', default_value)` 安全访问属性
  - 当 `name` 不存在时，使用 `path` 或对象的字符串表示
  - 当 `language` 不存在时，默认为 `'unknown'`
- **Tests**: 本地验证通过
- **Security**: No secrets exposed

### P6-17: 两阶段混合去重策略完成

- **Goal ID**: P6-17
- **Summary**: 实现基于位置聚类 + LLM 判断的两阶段混合去重，解决跨引擎去重失效问题
- **Impact**:
  - `src/layers/l3_analysis/deduplicator.py`: +280 行（ClusterBasedDeduplicator, LocationCluster, cluster_findings_by_location）
  - `src/layers/l3_analysis/adjudication.py`: +50 行（集成 LLM 客户端，降级到 ASTDeduplicator）
  - `tests/unit/test_l3/test_deduplicator.py`: +240 行（18 个新测试用例）
  - `tests/integration/test_deduplication.py`: 新文件（7 个集成测试）
- **Features**:
  - 位置聚类：按 file_path + line_range (容差 10 行) 分组
  - LLM 判断：对聚类内 findings 进行语义级去重判断
  - 保留策略：重复的保留 final_score 最高的，更新 related_engines
  - 降级机制：LLM 不可用时降级到 ASTDeduplicator
- **Tests**: 101 passed (deduplicator) + 54 passed (adjudication)
- **Dead Code**: not run
- **Security**: No secrets exposed

### P6-16: Readiness Gate 自动修复机制完成

- **Goal ID**: P6-16
- **Summary**: 实现 Readiness Gate 自动修复机制，尽量构建环境而非跳过检测
- **Impact**:
  - `src/layers/l3_analysis/readiness_gate.py`: Query Pack 自动下载 + RuntimeVersionManager 集成
  - `docker-compose-tun.yml`: TUN 透明代理配置（空代理变量保留用于明确禁用代理）
  - `docker-compose-china.yml`: 国内网络优化配置
  - `.env.docker.build`: Docker 构建环境变量模板
  - `Dockerfile`: 更新构建参数支持
  - `docs/docker-china-setup.md`: 国内网络环境设置指南
  - `README.md`: 新增 Docker 扫描使用指南
- **Acceptance Criteria**:
  - ✅ Readiness Gate 检测到 Query Pack 未安装时，自动尝试下载
  - ✅ Readiness Gate 检测到构建工具缺失时，尝试使用 RuntimeVersionManager 安装
  - ✅ Semgrep 在 TUN 模式下正常工作
  - ✅ 增强日志输出（`[P6-16a Auto-fix]`, `[P6-16b Auto-fix]` 标记）
- **Tests**: 31 passed (test_readiness_gate)
- **Dead Code**: not run
- **Security**: No secrets exposed (`.env` in `.gitignore`)
- **Commit**: 51f58a6

## 2026-03-30

### Bug 修复: Semgrep CLI 兼容性与类型安全

- **Goal ID**: bugfix-semgrep-cli-compat
- **Summary**: 修复 Semgrep 引擎 CLI 参数冲突和 FailedEngineInfo 类型处理问题
- **Impact**:
  - `Dockerfile`: CodeQL 版本升级 `2.24.2` → `2.25.1`
  - `src/cli/main.py`: 修复 `FailedEngineInfo` 对象/字典兼容性（3 处）
  - `src/layers/l3_analysis/engines/semgrep.py`: 修复 `--lang` 与 `--config auto` 冲突 + 添加调试日志
- **Issues Fixed**:
  - Semgrep 使用 `--config auto` 时加 `--lang` 参数导致命令失败
  - CLI 导出时 `FailedEngineInfo` dataclass 与 dict 混用导致属性访问错误
- **Tests**: 47 passed, 9 skipped (Docker 集成测试验证无回归)
- **Dead Code**: not run
- **Security**: No secrets exposed
- **Commit**: 6c32401
