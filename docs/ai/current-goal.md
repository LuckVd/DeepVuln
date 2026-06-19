# Current Goal

> **状态**: 进行中 🔧（创建于 2026-06-19）
> **目标**: Phase 17 — AI 与静态最优结合的深化（剩余架构/能力项）
> **Goal ID**: phase17-ai-static-deepening
> **创建日期**: 2026-06-19

---

## 需求背景

承接 2026-06-19 的深度改造会话。该会话完成了"AI 与静态最优结合"的**核心闭环**（静态产出 source→sink 证据 → 落库 → 注入 LLM prompt → AI grounded 裁决），修复了所有已发现的 bug，并端到端验证了多引擎（除 CodeQL）能力。

剩余 6 项是**架构统一 + 能力深化**，每项都需独立的"设计→实现→运行时验证"循环（且会互相暴露下一层问题，如 D4 修了崩溃又暴露 0 candidates），故**分会话推进**。

---

## 本次会话已完成（4 commit，分支 `feat/static-evidence-grounding`，未 push）

| commit | 内容 |
|---|---|
| ec15c12 | 安全加固 + P0 bug + 文档：统一 require_auth 鉴权/JWT 启动校验/上传 zip-slip/slowapi 限流；system_setting_service 语法错误/concurrency 借还许可/去重两阶段/shell→exec/5xx 重试 |
| 95178ae | 证据引擎 + 函数内数据流 + AI grounding：调用图缓存/reachability 统一 CallGraphAnalyzer/证据落库 Finding.taint_analysis+cpg_path/函数内 taint(_trace_intra_function)/证据注入 prompt/证据把关(EXPLOITABLE 须硬证据)/pipeline 模块+断点续扫接通+四轮开关 |
| 4700adf | taint 误报修复 + 多语言框架 + 性能：_find_intra_taint 按 language 路由(消除跨语言误报)/_extract_python_function 嵌套 stop/JS source-sink patterns+提取/大函数体跳过/python_builder func_name 合法性校验 |
| 87c7083 | 四轮启动崩溃修复：_group_targets 跳过 SKIP 级(SKIP 的 max_concurrent=0 违反 ge=1) |

**已验证**（本机 sqlite + GLM）：
- 多引擎端到端：Semgrep 10 + Agent 3 findings → 聚合 → 裁决（证据把关生效，无误报 exploitable）
- pipeline 模块单测 6/6
- 3 个 Python 漏洞函数内数据流：eval→exploitable、SQL/cmd→conditional
- D4 四轮 RoundController 流程跑通（不再 fallback Round4）

**环境**：分支 `feat/static-evidence-grounding`（**未 push**，作者 qac）；LLM 用 GLM Coding Plan 端点 `https://open.bigmodel.cn/api/coding/paas/v4`（token=`$ANTHROPIC_AUTH_TOKEN`，glm-4.5-air 快）；本机 1.9GB 内存，CodeQL 跑不了；已装 semgrep/web 依赖/sqlite。

---

## 剩余目标（6 项，按优先级，分会话推进）

### D4 — 四轮 Round1-3 候选产出（P0，最兑现宣传）✅ 已修复（本会话）

**真实根因（实证修正，推翻原假设）**：并非 Round1 不产出候选，而是 `TerminationDecider.should_continue`（`termination.py`）在 **0 个 round 已完成**时就停机。启动时 `benefit=0`、`cost=elapsed_time·ε>0` → `net_benefit<0` → check #6（`net_benefit_score<0`，termination.py:340）触发 `diminishing_returns` 停机 → `RoundController._should_continue()` 首次即返回 False → 循环体一次都不进 → **Round1 从未运行** → 0 candidates。Round1 的 Semgrep 本身能产 10 findings（插桩实测 `rule_sets=["security"]`→`--config auto` 命中 eval/SQLi/cmd），只是没机会跑。
- 插桩证据：`benefit=0.0 / cost=1e-8 / net=-1e-8 / should_continue=False reason=diminishing_returns`；修复后 audit probe 显示 `RoundOneExecutor.execute -> total_candidates=10`、`RESULT(verified)=10`（从 0→10）。
- 原 A（种子注入）/B（修独立 semgrep）方案均打错层，已废弃。

**修复**：`termination.py` 的 `should_continue` 在 max_rounds 检查（check #1）之后加「首轮必跑」护栏——`rounds_completed==0` 时强制 `should_continue=True`（零数据时收益/成本/边际递减启发式无意义，首轮必须执行才能拿到候选供后续判定）。

**TDD**：`tests/unit/test_l3/test_rounds.py::TestTerminationDecider` 新增 `test_should_continue_first_round_always_runs`（红→绿，精确复现 DIMINISHING_RETURNS 早停）+ `test_should_continue_respects_max_rounds_before_first_round`（护栏不覆盖 max_rounds）；TestTerminationDecider + controller 集成共 22 测试全绿；ruff/ast 无新增问题。

**遗留观察（部分已闭合）**：
- ✅ **Round1 agent findings 已接通（本会话，种子注入）**：`_run_full_rounds_audit` 把主扫描 `scan_results["agent"].findings` 作为 `seed_findings` 传给 `RoundOneExecutor`；Round1 把它们注入为候选（`_add_seeded_candidates`），四轮现纳入 agent findings 而**不重跑 agent**（避免 2x token）。TDD `test_execute_seeds_findings_as_candidates` 绿；test_rounds 147 全绿。
- ⏳ **Round2 agent 深度审仍 skip**（无 agent_executor，且与 Round4 可利用性验证重叠）——低价值，Round4 已覆盖裁决，暂不接。

### 附加修复 — Web 主路径 semgrep 0 findings（本会话发现并修复）✅

**背景**：为 D1 建基线时发现 Web orchestrator 的 semgrep 对 `/tmp/vuln_proj`（eval/SQLi/命令注入）返回 **0 findings**，而独立 `rule_sets=["security"]` 与 CLI 都能找到 10。Web 主扫描对漏洞致盲——web-only 方向的关键 bug（之前只验证过 CLI 路径）。

**根因（两层，均已修）**：
1. **`RuleGatingEngine` 不认 dict tech_stack**（`src/core/rule_gating.py:_extract_tech_stack_info`）：用 `hasattr(dict, ...)` 属性访问，但 orchestrator 传的是 dict → `primary_language` 恒 None → 关掉所有语言包。**修**：加 `_field()` 辅助同时支持 dict（`.get`）与对象（`getattr`），enum 取 `.value` 兜底 `str`。TDD `tests/unit/test_core/test_rule_gating.py` 4 用例。
2. **orchestrator semgrep 无 `--config`**（`scan_orchestrator.py:_build_engine_options`，主因）：既没设 `rule_sets` 也没 `use_auto_config` → semgrep 用 minimal default 规则 → 0 findings。**修**：semgrep 分支加 `options["use_auto_config"] = True`。

**验证**：`/tmp/d1_baseline.py`（semgrep-only，`/tmp/vuln_proj`）改前 `success:false/0 findings` → 改后 `engine_execution: semgrep 10 findings → dedup 3 → success:true, findings_count:3`。ruff/ast 改动区间零新增问题；test_pause_resume 的 17 ERROR 为既有（`scan_executor.AsyncSessionLocal` 缺失，无关）。

**行为变化（生产需知）**：Web semgrep 现跑 `--config auto`（全量 registry），单次变慢（~142s）、耗 token（~10k）、依赖网络——"能找漏洞"的必要代价；如需更可控可改 `rule_sets=["security"]` 显式配置。

**遗留（非阻塞）**：file_filtering 的 `--exclude test` 会误伤路径含 "test" 的目录（如夹具 `/tmp/vuln_test`）；属既有 semgrep exclude 语义，D1 基线改用 `/tmp/vuln_proj` 规避。

---

### D5 — 三套打分统一（P1，精度核心）

**现状**：confidence_scorer（0-100）/ final_score.py（加权）/ multi_dim_scorer（0-1）三套并存，round_four 同时产出两个 confidence。
**卡点**：动 confidence 计算回归风险高（影响所有 finding 最终分），**必须先建 confidence 端到端测试**。
**步骤**：
1. 先加测试：对一组 fixture finding，断言 round_four 产出的最终 confidence（固化当前行为）。
2. 让 round_four 的最终 confidence 以 `multi_dim_scorer.final_confidence` 为准（confidence_scorer 降为辅助/审计）。
3. 跑测试确认无回归。
**验证**：现有 `tests/unit/test_l3/test_scoring/`（40 用例）+ 新增 confidence 端到端测试通过。
**风险**：中（回归）。

### D1 — Web 接入 ScanPipeline（P1，架构统一）✅ 已完成（本会话，Web-only）

> CLI 已弃用（web-only 决策），D1 收窄为 **Web 单边**：`ScanOrchestrator.execute_scan` 改用 ScanPipeline 编排；CLI 不再接入（也不再维护）。

**改动**：
- `scan_orchestrator.py`：`execute_scan` 的 9-phase 硬编码循环 → `_build_scan_phases(ctx)` 构造 `PhaseSpec` 列表（runner 复用现有 `_run_*`，summary 复刻原 progress payload，条件 phase 用 `skip_when`，checkpoint phase 设 `checkpoint_key`）→ `ScanPipeline.execute(resume_from)`。并发管理器初始化/on_scan_complete/token 拆分/错误契约（try/except→`{success:False}`）保持不变。
- `src/web/services/scan_pipeline_adapters.py`（新）：`WebProgressSink`（映射 pipeline 事件→`ProgressCallback`，`on_phase_complete` 的 `**data`→位置 dict；skipped/failed/progress no-op 保现状）+ `WebCheckpointSink`（包 `_save_checkpoint_phase`/`_clean_checkpoint`，`skip_phases` 取自 `_completed_phases`）。
- `phases.py`：`ScanPhase` 枚举的 `ROUNDS_AUDIT` → `EXPLOITABILITY_VERIFICATION`（保留前端在用旧名，避免 i18n/progress_broadcaster 回归）。

**验证**：改前/改后基线（`/tmp/vuln_proj` semgrep-only）phase 事件序列 + 各 payload **逐字段一致**，`semgrep 10→dedup 3→success:true findings:3`；pipeline 6 + rule_gating 4 = 10 测试绿；ruff/ast 我的新代码零问题。

**遗留（非 D1）**：~~CLI `run_full_security_scan` 仍硬编码……~~ → **本会话已彻底移除 CLI**（`src/cli/` + `tests/unit/test_cli/` + `pyproject` 的 `deepvuln` 入口 + `test_semgrep_integration.py::TestCLIIntegration`），web-only 落地。历史文档（roadmap/change-log/docker*.md）保留过往记录未改。

### D3 — 断点续扫完整 skip（P2）

**现状**：execute_scan 接了 checkpoint save/clean/resume_from（机制通），但 findings 中间状态没持久化，resume 实际仍重跑。
**卡点**：完整 skip 需序列化 Finding 列表 + 恢复引擎状态，**必须用真实 Celery 中断→resume 场景验证**。
**步骤**：
1. engine_execution phase 后，把 scan_results 的 findings 投影（可序列化部分）存 checkpoint output_data。
2. resume 时 load + 反序列化恢复 self.scan_results，skip engine_execution。
3. Celery 环境：pause→resume 测试跳过已跑 phase。
**验证**：中断后 resume 不重跑 engine_execution，findings 从 checkpoint 恢复。
**风险**：需 Celery+Redis 环境。

### E5 — AI 补漏逻辑漏洞（P2，新能力）

**现状**：无。当前是"静态产证→AI 验证"，缺"AI 补漏静态没覆盖的（认证绕过/业务逻辑/复杂注入）"。
**步骤**：
1. 设计 `prompts/logic_vuln.py`（逻辑漏洞检测 prompt，limited scope：只审入口点可达的高风险区，防误报）。
2. 实现 `LogicVulnerabilityDetector`（复用 `_llm_assisted_assessment` 基础设施）。
3. 接入：独立 phase 或 agent 增强。
4. 验证不误报（对正常代码不报）。
**验证**：对已知逻辑漏洞（如缺失授权检查）能检出，正常代码不误报。
**风险**：新功能，需防误报。

### D6 — CPG CFG 可达性实现（P3，大工程）

**现状**：`path_finder/finder.py` 有 `TODO: CFG reachability`；`reaches_sink` 固定 True；GoCPGProvider 未实现（`cpg/path_provider.py:50`）。
**卡点**：CFG 可达性是大工程（每语言 CFG 构建 + 路径验证）。
**步骤**：见 roadmap P8-09（CPG 基础已 done，CFG 可达性是增强）。
**验证**：path_finder 用真实验证（非固定 True）。
**优先级**：低（CPG 是增强，非核心链路）。

---

## 实施顺序建议（分会话）

1. **D4**（四轮候选）— 最兑现宣传，本会话已定位卡点。
2. **D5**（打分统一）— 精度核心，先建测试再统一。
3. **D1**（pipeline 接入）— 架构统一，需测试环境。
4. **D3 / E5**（断点续扫 / AI 补漏）— 中等。
5. **D6**（CPG）— 增强，最低优先。

---

## 验证环境（每次会话复用）

```bash
cd /opt/pro/deepvuln
export OPENAI_API_KEY="$ANTHROPIC_AUTH_TOKEN"
export OPENAI_BASE_URL="https://open.bigmodel.cn/api/coding/paas/v4"

# 多引擎端到端验证（除 CodeQL）
deepvuln scan -p /tmp/vuln_test --engines semgrep --engines agent --model glm-4.5-air --llm-verify

# 四轮验证（构造 orchestrator，参考本会话脚本，enable_full_rounds=True）
# pipeline 单测
python3 -m pytest tests/unit/test_pipeline/ --noconftest -o asyncio_mode=auto

# 全量语法/ruff（防回归）
python3 -c "import ast,pathlib;[ast.parse(f.read_text()) for f in pathlib.Path('src').rglob('*.py')];print('OK')"
ruff check src/ --select F
```

**测试项目** `/tmp/vuln_test/app.py`（如不存在，用以下内容创建——本次所有验证的基准）：
```python
import os, sqlite3
from flask import Flask, request
app = Flask(__name__)

@app.route("/run")
def run_code():
    code = request.args.get("code", "")
    return str(eval(code))          # RCE: eval 用户输入

@app.route("/user")
def get_user():
    uid = request.args.get("id", "")
    cur = sqlite3.connect("db.sqlite").cursor()
    cur.execute("SELECT * FROM users WHERE id = " + uid)   # SQL 注入
    return str(cur.fetchall())

@app.route("/file")
def cat_file():
    name = request.args.get("f", "")
    os.system("cat " + name)        # 命令注入
    return "ok"
```

---

## 新 agent 接力指南（冷启动必读）

### 1. 先读这些建立上下文（按顺序）
1. **本文件**（current-goal.md）—— 当前 goal + 6 项拆解 + 本指南。
2. `/root/.claude/projects/-opt-pro/memory/deepvuln-refactor-progress.md` —— 跨会话记忆（愿景 + 已完成阶段 + 环境）。
3. `git log --oneline -6` + 各 commit diff —— 本次改了什么。
4. `git branch --show-current` → 应是 `feat/static-evidence-grounding`（未 push）。

### 2. 环境与已踩的坑（避免重复踩）
- **LLM**：`export OPENAI_API_KEY="$ANTHROPIC_AUTH_TOKEN"; export OPENAI_BASE_URL="https://open.bigmodel.cn/api/coding/paas/v4"`；**用 glm-4.5-air（快）**；glm-4.6/4.5 是 reasoning 模型，慢且 max_tokens 要给够、易超时。
- **内存**：本机 1.9GB，**CodeQL 跑不了**（Java OOM）；用 sqlite（`sqlite+aiosqlite:///:memory:`）替代 postgres 测试。已装 semgrep/web 依赖/tree-sitter-javascript。
- **enable_full_rounds（D4 关键坑）**：CLI 和 scan_tasks **都不传它**（已 grep 确认），**只能**构造 `ScanOrchestrator(scan_config={"enable_full_rounds": True, ...})` 传入。**不能用 CLI 测 D4**。
- **构造 ScanOrchestrator 测试的坑**：
  - `progress_callback` 必须用 `__getattr__` 兜底（接口方法多：on_phase_start/complete/progress/on_engine_*/on_scan_*/broadcast_event/set_scan_config/on_phase_skipped 等），否则缺方法报错。
  - 建表：`async with engine.begin() as conn: await conn.run_sync(Base.metadata.create_all)`。
  - concurrency 从 sqlite 读 llm_config 表会失败（warning）→ 自动 fallback default，**可忽略**。

### 3. D4 调试脚本（可直接复跑，定位 0 candidates）
保存为 `/tmp/d4_debug.py`，`python3 /tmp/d4_debug.py`（先 export OPENAI_* 两个变量）：
```python
import asyncio, os, traceback
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from src.web.services.scan_orchestrator import ScanOrchestrator
from src.layers.l3_analysis.llm.openai_client import OpenAIClient
from src.web.models.database import Base

# 关键：patch _run_full_rounds_audit 打印真实异常（默认被 _run_exploitability_verification 的 try/except 吞掉）
orig = ScanOrchestrator._run_full_rounds_audit
async def patched(self):
    try:
        r = await orig(self)
        print("Multi-round OK, verified:", r); return r
    except Exception as e:
        print("FULL_ROUNDS_EXCEPTION:", repr(e)); traceback.print_exc(); raise
ScanOrchestrator._run_full_rounds_audit = patched

class FakeProgress:
    async def on_phase_start(self, *a, **k): pass
    async def on_scan_failed(self, e): print("scan failed:", e)
    async def broadcast_event(self, *a, **k): pass
    def set_scan_config(self, c): pass
    def __getattr__(self, n):           # 兜底所有未实现方法（必需）
        async def _noop(*a, **k): pass
        return _noop

async def main():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    sm = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    llm = OpenAIClient(model="glm-4.5-air", api_key=os.environ["OPENAI_API_KEY"], base_url=os.environ["OPENAI_BASE_URL"])
    orch = ScanOrchestrator(scan_id=1, source_path="/tmp/vuln_test",
        scan_config={"enable_full_rounds": True, "engines": ["agent"], "llm_verify": True},
        progress_callback=FakeProgress(), db_session_factory=sm, llm_client=llm, source_type="local")
    print("RESULT:", await orch.execute_scan())

asyncio.run(main())
```
**当前症状**：`Audit session completed: 0 candidates`（RoundController 流程通，但 Round1-3 产出空）。
**下一步排查**：① `_run_full_rounds_audit` 里 `strategy.total_targets` 是否 0（→ 查 `strategy/engine.py:211 _convert_entry_points` 是否把 entry_points 转成 targets）；② 若 targets>0，在 `round_one.py:84 execute` 内打印 candidate 构造点，看为什么没产出 VulnerabilityCandidate。

### 4. 关键文件:行号锚点
| 项 | 文件:行 | 说明 |
|---|---|---|
| D4 | `scan_orchestrator.py:1048` `_run_exploitability_verification`、`:1071` enable_full_rounds 检查、`:1155` `_run_full_rounds_audit` | 四轮接通点 |
| D4 | `round_one.py:84` `execute`（round_two/three 同结构） | Round1-3 候选产出（0 candidates 源头） |
| D4 | `strategy/engine.py:125` `create_strategy`、`:211` `_convert_entry_points` | targets 生成 |
| D1 | `scan_orchestrator.py:140` `execute_scan`、`cli/main.py:739` `run_full_security_scan` | pipeline 待接入的两处编排（均未 import ScanPipeline） |
| D5 | `round_four.py:~909` `_calculate_confidence_score` + `scoring/multi_dim_scorer.py` + `core/final_score.py` | 三套打分 |
| D3 | `scan_orchestrator.py` `_save_checkpoint_phase`/`_clean_checkpoint` + `checkpoint_service.py` | 断点续扫（机制通，缺 findings 持久化） |
