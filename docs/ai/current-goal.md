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

### D4 — 四轮 Round1-3 候选产出（P0，最兑现宣传）

**现状**：RoundController 流程跑通（87c7083 修了 SKIP 崩溃），但 Round1-3 **产出 0 candidates**（`Audit session completed: 0 candidates`）。
**卡点**：Round1 execute（Semgrep+Agent）对 strategy targets 不产出 VulnerabilityCandidate。
**步骤**：
1. 在 `_run_full_rounds_audit`（`scan_orchestrator.py:1100-1180`）调试：打印 `strategy.total_targets` + Round1 execute 返回的 `RoundResult.total_candidates`。
2. 若 targets=0：查 `StrategyEngine.create_strategy(attack_surface=...)` 的 `_convert_entry_points`（attack_surface_report_obj 是否传入 + entry_points→targets 转换）。
3. 若 targets>0 但 candidates=0：查 `RoundOneExecutor.execute`（round_one.py）内部（SemgrepEngine/Agent 调用 + VulnerabilityCandidate 构造）。
4. 修复产出，重跑确认 candidates>0。
**验证**：`enable_full_rounds=True` 跑 /tmp/vuln_test，`session.all_candidates` 非空。
**复用**：RoundOne/Two/ThreeExecutor 已有完整代码 + `tests/unit/test_l3/test_rounds.py` 单测。

### D5 — 三套打分统一（P1，精度核心）

**现状**：confidence_scorer（0-100）/ final_score.py（加权）/ multi_dim_scorer（0-1）三套并存，round_four 同时产出两个 confidence。
**卡点**：动 confidence 计算回归风险高（影响所有 finding 最终分），**必须先建 confidence 端到端测试**。
**步骤**：
1. 先加测试：对一组 fixture finding，断言 round_four 产出的最终 confidence（固化当前行为）。
2. 让 round_four 的最终 confidence 以 `multi_dim_scorer.final_confidence` 为准（confidence_scorer 降为辅助/审计）。
3. 跑测试确认无回归。
**验证**：现有 `tests/unit/test_l3/test_scoring/`（40 用例）+ 新增 confidence 端到端测试通过。
**风险**：中（回归）。

### D1 — CLI/Web 接入 ScanPipeline（P1，架构统一）

**现状**：ScanPipeline 模块（`src/layers/pipeline/`）建好+6 单测，但 `cli/main.py`(4751 行) 和 `scan_orchestrator.py` 都**没用它**（grep `ScanPipeline` 无匹配），仍各自硬编码 phase。
**卡点**：重写两个大函数用 pipeline 编排，高风险，**必须跑完整扫描回归对比**（改前 vs 改后 findings 一致）。
**步骤**（渐进，Web 先 CLI 后）：
1. Web：`ScanOrchestrator.execute_scan` 收缩为构造 ScanContext + phase 列表（runner 复用现有 `_run_*`）+ WebProgressSink（包装 progress_callback）+ CheckpointHook → `ScanPipeline.execute(resume_from)`。
2. 跑 Web 扫描回归（sqlite+GLM，对比 findings）。
3. CLI：`run_full_security_scan` 同样收缩 + RichProgressSink。
4. 跑 CLI 扫描回归。
**验证**：改前/改后扫同一项目 findings 一致；pipeline 单测仍 6/6。
**风险**：高（重写主路径）。建议有完整测试环境时做。

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
