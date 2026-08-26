# 全量体检问题清单（2026-08-25，架构/检测能力/合理性）

> 审计方式：5 路并行子审计（L3 检测链路 / 架构 / 裁决评分 / L1+Web / 测试真实性）+ 主线逐条读码验证。
> 状态标记：✅ 已确认（读码+实验证实）｜❓ 待其余审计返回后确认

## A. 检测能力（真实失效）

### A1 ✅ Python eval 检测丢失 — 规则 id 冲突相互覆盖
- `rules/ast_query/dangerous_api/python_eval.yaml` 与 `javascript_eval.yaml` 同 `id: dangerous_eval`；`base_detector.py:198` 按 id 做 dict key，rglob 顺序 javascript 在前 → **python 版被覆盖，Python eval/exec 检测静默丢失**（js 反而保留）。
- 同款：`crypto/javascript_md5.yaml` vs `python_md5.yaml` 同 `id: weak_crypto_md5`（python 版后加载侥幸存活，但加载顺序依赖文件名排序，脆弱）。
- 实测：对 `eval(r)` 的 Python 文件扫描 findings=0；query 本身执行正常（手动执行命中 eval@line3）。
- 修复：合并多语言规则到单文件（queries 已按语言分键），或 key 改为 `id:language`。

### A2 ✅ pyproject 缺 tree-sitter-javascript/typescript 依赖
- `ast_engine.py:39-43` 声明支持 javascript/typescript，`pyproject.toml:38-41` 只装 py/java/go 语法包。干净安装下 JS/TS AST 检测与 CPG CFG 构建静默失效（装上后 test_path_finder 35 全过）。
- 修复：补依赖声明。

### A3 ✅ semgrep 引擎在 venv 内不可用（PATH 探测 vs 模块安装）
- semgrep 以 pip 包安装于 `.venv/bin/semgrep`，`is_available()` 用 `shutil.which("semgrep")`（`base.py:204`）→ venv 激活但 PATH 未含 `.venv/bin` 时恒 False，引擎静默跳过。Docker 镜像若以 `uv pip install` 装进非 PATH 前缀同样中招。
- 修复：is_available 增加 `sys.executable` 同目录探测 + `python -m semgrep` 兜底。

### A4 ✅ final_score 全链路从未生效（死评分器，活代码引用其输出）
- `core/final_score.py:429` 是全仓库唯一给 `finding.final_score` 赋值处，其入口 `assign_scores_to_findings` **零生产调用**（仅测试）。
- 但 `core/finding_budget.py:259`（预算截断排序首选 final_score）与 `deduplicator.py:427/575/1181`（保留最高分）都读它 → 恒 None，退化为 confidence 排序/任意保留。
- 修复：真正接线（多轮裁决后统一打分）或让 budget/dedup 改读已生效的 confidence_score。

### A5 ✅ ScanConfig(pydantic) 塞 JSON 列 — API 创建扫描即 500
- `ScanCreate.config` 是 `ScanConfig` 对象（`schemas.py:278`），`scan_executor.py:85` 直接 `config=scan_create.config` → SQLAlchemy JSON 序列化 `TypeError: Object of type ScanConfig is not JSON serializable`（实测复现，sqlite；asyncpg 同样会炸）。
- 前端正常路径传 dict 不炸（zip 端点先 json.loads），但 REST `POST /scans`（body 走 pydantic 默认）必炸。
- 修复：入库前 `model_dump()`（含排除 None）。

### A6 ✅ 引擎默认值三处不一致
- orchestrator 默认 `["semgrep","codeql","agent"]`（`scan_orchestrator.py:887`）/ schemas `["semgrep","codeql","agent","ast"]`（`schemas.py:82`）/ zip 端点 `["semgrep","codeql","agent"]`（`scans.py:146`）→ 前端默认带 ast，API 默认不带；AST 引擎在多数路径默认不跑。
- 修复：单一默认值来源。

### A7 ❓（裁决评分审计返回后补充）

## B. 架构（分层/重复/部署）

### B1 ✅ pause 覆盖 orchestrator 的 resume_data → 恢复丢全部引擎结果
- `scan_executor.py:441-455` pause 手工构造 `resume_data={total_files,...}`（不含 scan_results/completed_engines），经 `checkpoint_service.py:182` 整体替换 checkpoint → 恢复时 `_restore_state_from_checkpoint` 读不到 scan_results，引擎全重跑、findings 丢失。
- 附带：`scan_executor.py:448` 把 `scan.engines_completed`（Integer 列）当列表塞进 global_state。
- 修复：pause 复用 `_serialize_resume_data()`；save 侧 resume_data 合并。

### B2 ✅ Dockerfile ENTRYPOINT 指向已删除的 src.cli.main — web compose 启动即崩
- `Dockerfile:242` / `Dockerfile.lite:58` `ENTRYPOINT ["python","-m","src.cli.main"]`；`src/cli` 不存在。`docker-compose-web.yml:63,101` 只覆盖 command（CMD）→ 容器执行 `python -m src.cli.main python -m celery ...` → No module named src.cli。仅 `docker-compose-web-host.yml` 用 entrypoint 覆盖幸免。
- `docker-compose.yml` 整体还是 CLI 时代文件。
- 修复：Dockerfile 改 web 入口；compose 面同步。

### B3 ✅ DATABASE_URL 环境变量全部无效 + env_file/upload_dir 硬编码错误路径
- 代码只读 `DEEPVULN_DB_*`（`web/core/config.py:12`），而 compose/start-web.sh/.env.web.example 全设 `DATABASE_URL` → 容器连默认 localhost 库（密码也不对）。
- `config.py:13,44,137` `env_file="/opt/projects/DeepVuln/.env"`（本仓库在 /opt/pro/DeepVuln，路径不存在）；`upload_dir` 默认 `/opt/projects/deepvuln/uploads` 同病。
- 修复：compose 改 `DEEPVULN_DB_URL`；env_file 相对路径；upload_dir 修正。

### B4 ✅ core 反向依赖上层（分层倒置）
- `core/llm/concurrency.py:578,713,746` import `src.web.services.llm_config_service`；`:685` import `src.layers.l3_analysis.llm.openai_client`。core 被所有层依赖，却拖起 web/l3。
- 修复：依赖倒置——web 侧把配置值传入 core（callback/参数），或把 concurrency manager 挪到 web。

### B5 ✅ scan_orchestrator 上帝类（2245 行 / 55 方法 / ≥12 职责）
- 源准备/解 zip/增量/技术栈/引擎选择/并发调度/checkpoint/四轮审计/adjudication/adversarial/落库/token 全在一个类。pipeline 适配器还直接调其私有方法成环（`scan_pipeline_adapters.py:77-90`）。
- 修复方向（大重构，本目标内做最小纠偏：抽出引擎选择与选项装配两块，其余登记 roadmap）。

### B6 ✅ l3/incremental 3423 行无生产调用者（与 web/incremental_scan.py 双实现）
- 生产走 `scan_orchestrator.py:814` 用 web 那套；l3 那套仅 `__init__` re-export + 测试。
- 修复：删除或明示 deprecated（倾向删除，保 web 单实现）。

### B7 ✅ PhaseManager 590 行死代码 + phase 状态四处分裂
- 唯一引用 `scan_executor.py:62` 赋值后从未使用。真实写 scan_phases 的是 progress_broadcaster + executor 预插行。
- 修复：删 PhaseManager，phase 状态机收敛到 pipeline/phases.py。

### B8 ✅ checkpoint /tmp 文件备份 write-only
- `checkpoint_service.py:214` 每次落盘 /tmp，无人读。浪费 IO 且无恢复路径。
- 修复：删文件备份。

### B9 ✅ CodeQL 双实现（engines/codeql.py 2510 行 vs codeql/ 子包 548 行 SARIF 解析两套）
- 互不引用。同目录 semgrep.py/opencode_agent.py 平铺，ast_engine/ 深包，logic_vuln_detector 非 BaseEngine 却在 engines/。
- 修复（本目标最小）：SARIF 解析收敛到一处；结构问题登记 roadmap。

### B10 ✅ pre_filter 1416 行死代码（含陈旧失败测试）
- FilePreFilter/StreamingValidator/CodeQLPreFilter/InMemoryDeduplicator 无生产 import；其 3 个失败测试在维护死代码假象。
- 修复：删包+删测试。

### B11 ✅ engine_registry/SmartScanner 死路径
- `base.py:260` 自注释 unused。SmartScanner registry 分支无人走。
- 修复：SmartScanner 保留（还有直接调用价值？验证后定），registry 删或留注释。

### B12 ✅ 双 Celery 入口 + 死任务
- 根目录 celery_worker.py 零引用；`check_scan_progress_task` 无调用者且 worker 进程直接 get_session_local 会 RuntimeError。
- 修复：删。

### B13 ✅ 配置三体系互不读取；config.example.toml 唯一活段整链断裂
- TOML(config/core) / YAML(settings.py) / pydantic env(web)。`[directory_classification]` 段从 TOML→config 函数→classify→finding.directory_class 四级零接线（`get_directory_classification_config` 等零调用）。`get_scan_timeout` 等仅 scripts 用。
- 修复（最小）：删断链条目或接线；登记 roadmap 做配置收敛。

### B14 ✅ models 三处职责错位 + l1 垫片让 l3→l1 依赖复活
- core/models 无 __init__.py；l1/attack_surface/models.py 纯 re-export 被 16 处引用（含 l3/web，可直连 core）；web/models/checkpoint.py 名不符实。
- 修复：import 直连 core；删垫片。

### B15 ✅ 同名异构模型（SeverityLevel×4 / ScanResult×3 / FindingStatus×2 + 两套 status 映射）
- 修复（最小）：不动枚举定义，登记 roadmap。

### B16 ✅ adjudication.py:500 环境变量兜底建 LLM client（第四条配置岔路）
- llm_client=None 时走 env 建 client（timeout=30s，与主链路 DB 配置不一致）。
- 修复：删兜底，None 就用 ASTDeduplicator（现注释也是这么说的）。

### B17 ✅ docker-compose 挂载不存在的 config.local.toml
- 新版 compose 直接报错。修复：删挂载。

### B18 ✅ l1/workflow/auto_security_scan.py 289 行死代码（连带 security_analyzer）
- 修复：删。

## C. 测试真实性（既有 18 失败的定性）

- ✅ test_deduplicator×5 / test_adjudication×3：测试同步调用 async 方法（coroutine never awaited）——**测试错**，生产正确 await。
- ✅ test_semgrep_engine×4 / test_semgrep_integration×5：PATH 探测问题（见 A3）——环境错，但暴露 A3 真缺陷。
- ✅ test_path_finder×2：缺 JS 语法包（见 A2）——环境错，暴露 A2 真缺陷。
- ✅ test_in_memory_deduplicator×3：死代码包的陈旧测试（见 B10）。
- ✅ test_ast_engine×2：A1 所致（python_eval 规则被覆盖）——**代码错**。
- ✅ test_framework_detector×1：断言相对路径 vs 实现返回绝对路径——测试过时（实现是对的，绝对路径才能工作）。
- ✅ test_opencode_agent×1：断言 max_concurrent==2 vs 代码默认 5——待定性（历史默认 2→5 改了代码没改测试；LLM_MAX_CONCURRENT_REQUESTS 默认也是 5，代码对）。
- 修复：按定性逐个修（修代码或修测试）。

## D. 合理性（阈值/状态机）— ❓ 待裁决评分审计返回

## 修复策略
1. 先修 A 类（检测能力真实失效）+ B1/B2/B3（部署与数据丢失）
2. 再修死代码类（B6/B7/B8/B10/B12/B18 —— 删除时同步删测试，基线数学会变，如实记录）
3. 测试修正类（C）随各根因修复
4. B5/B9/B13/B15 大重构登记 roadmap，本目标只做无风险最小纠偏
