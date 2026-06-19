# Current Goal

> **状态**: 已完成 ✅（创建于 2026-06-19；D6 收尾 2026-06-19）
> **目标**: Phase 17 — AI 与静态最优结合的深化（剩余架构/能力项）
> **Goal ID**: phase17-ai-static-deepening
> **创建日期**: 2026-06-19
>
> **🧭 冷启动 TL;DR（2026-06-19 全部完成）**：Phase 17 **全部项已完成** — D4 / Web-semgrep(0→10) / D1(ScanPipeline) / D5(打分统一) / D4 遗留(agent 种子) / CLI 移除(web-only) / E5(AI 补漏逻辑漏洞) / D3(断点续扫 findings 持久化) / **D6(CPG CFG 可达性接地)**。D6 接通了 ~2000 行死代码 CFG 子系统，`reaches_sink`/`condition_paths` 变真实值，四语言(py/js/java/go)裂块；暴露并修 **5 个既有 bug**，其中 **P9-01**（入口/体节点未连通）使**整个 CPG 攻击路径特性首次端到端可用**（此前 `get_paths` 恒返回 `[]`）。D3 顺带修了 `checkpoint_service`/`phase_manager` session bug。**待提交**（HEAD 仍 `098cb4d`，本次改动未 commit）。**环境**：web-only；`export OPENAI_API_KEY="$ANTHROPIC_AUTH_TOKEN"; export OPENAI_BASE_URL="https://open.bigmodel.cn/api/coding/paas/v4"`；glm-4.5-air；本机 1.9GB（**无 CodeQL**）；测试用 sqlite。分支 `feat/static-evidence-grounding`。

---

## 需求背景

承接 2026-06-19 的深度改造会话。该会话完成了"AI 与静态最优结合"的**核心闭环**（静态产出 source→sink 证据 → 落库 → 注入 LLM prompt → AI grounded 裁决），修复了所有已发现的 bug，并端到端验证了多引擎（除 CodeQL）能力。

剩余 6 项是**架构统一 + 能力深化**，每项都需独立的"设计→实现→运行时验证"循环（且会互相暴露下一层问题，如 D4 修了崩溃又暴露 0 candidates），故**分会话推进**。

---

## 已完成基线（上一轮 4 commit + 本轮 3 commit，分支 `feat/static-evidence-grounding`，已 push 到 origin）

> 上一轮：安全+P0bug / 证据引擎+数据流+AI grounding / taint 修复 / 四轮 SKIP 崩溃修复。
> **本轮（2026-06-19 第二轮，3 commit `b372071`/`0787683`/`2f7624a`）**：D4 终止护栏 · Web semgrep 0→10 · D1 ScanPipeline · CLI 移除(web-only) · D4 遗留 agent 种子注入 · D5 打分统一。详见下方各节。

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

## 剩余目标（3 项待办：E5 / D3 / D6；D4 / D5 / D1 + Web semgrep 修复 已完成 ✅）

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

### D5 — 三套打分统一（P1，精度核心）✅ 已完成（本会话）

**根因**：`round_four._apply_verification_result` 把 `finding.confidence_score` 设为 **ConfidenceScorer**（`confidence_report.score`，0-100 int），而状态判定用 `result.confidence`（multi_dim，0-1）——两套分裂、会不一致。

**修复**（round_four.py:1422）：`confidence_score = round(result.confidence * 100)`——以 **multi_dim 为唯一来源**，×100 保持 0-100 量纲（reporting 阈值 50 / int 类型 / 前端不破）；ConfidenceScorer 降级为 `confidence_scorer_audit` 审计证据。
- 量纲确认：`final_score.calculate_finding_score` 不直接读 `confidence_score`（从 `confidence` 推导），唯一直接消费者 `reporting.py:558` 阈值 `<50` 仍按 0-100 成立。

**TDD**：`test_rounds.py::TestRoundFourConfidenceUnification` 2 用例（multi_dim×100 主导 + 无 report 时仍设值）。
**验证**：test_scoring 40 + test_rounds/round_four_llm/round_four_codeql 共 **200 绿**，无回归；AST/ruff 我的新代码零问题。

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
1. **本文件顶部 TL;DR + 各节状态** —— 当前 goal 全景（已完成 ✅ / 待办 3 项）。
2. 跨会话记忆：`/root/.claude/projects/-opt-pro-deepvuln/memory/`（本项目；含 `deepvuln-web-only-no-cli.md` 等决策）。
3. `git log --oneline -8` + 各 commit diff —— 本会话改了什么（4 笔：b372071/0787683/2f7624a/1ff6fa0）。
4. `git branch --show-current` → 应是 `feat/static-evidence-grounding`（**已 push origin**，与远端同步）。

### 2. 环境与已踩的坑（避免重复踩）
- **LLM**：`export OPENAI_API_KEY="$ANTHROPIC_AUTH_TOKEN"; export OPENAI_BASE_URL="https://open.bigmodel.cn/api/coding/paas/v4"`；**用 glm-4.5-air（快）**；glm-4.6/4.5 是 reasoning 模型，慢且 max_tokens 要给够、易超时。
- **内存**：本机 1.9GB，**CodeQL 跑不了**（Java OOM）；用 sqlite（`sqlite+aiosqlite:///:memory:`）替代 postgres 测试。已装 semgrep/web 依赖/tree-sitter-javascript。
- **enable_full_rounds（四轮开关）**：`scan_tasks` 默认不传它，需构造 `ScanOrchestrator(scan_config={"enable_full_rounds": True, ...})` 传入（CLI 已移除，web-only）。
- **构造 ScanOrchestrator 测试的坑**：
  - `progress_callback` 必须用 `__getattr__` 兜底（接口方法多：on_phase_start/complete/progress/on_engine_*/on_scan_*/broadcast_event/set_scan_config/on_phase_skipped 等），否则缺方法报错。
  - 建表：`async with engine.begin() as conn: await conn.run_sync(Base.metadata.create_all)`。
  - concurrency 从 sqlite 读 llm_config 表会失败（warning）→ 自动 fallback default，**可忽略**。

### 3. 四轮审计验证探针（D4 已修复 ✅，此为复用回归工具）
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
**状态**：D4 已修复（`termination.py` 首轮必跑护栏 + Round1 agent 种子注入）。此脚本现作四轮回归探针——期望 `RESULT(verified) > 0`（Round1 产 semgrep 候选 + 注入的 agent 种子候选）。若回退到 0，先查 `termination.py` 的 `rounds_completed==0` 护栏是否被改掉。

### 4. 关键文件:行号锚点
| 项 | 文件:锚点 | 说明 | 状态 |
|---|---|---|---|
| D4 | `termination.py` 首轮必跑护栏；`round_one.py` `_add_seeded_candidates` | 四轮候选产出 + agent 种子注入 | ✅ |
| Web semgrep | `core/rule_gating.py` `_extract_tech_stack_info`(dict 兼容)；`scan_orchestrator.py` `_build_engine_options`(`use_auto_config`) | 0→10 findings 修复 | ✅ |
| D1 | `scan_orchestrator.py` `execute_scan`/`_build_scan_phases`；`web/services/scan_pipeline_adapters.py` | ScanPipeline 编排（Web-only） | ✅ |
| D5 | `round_four.py` `_apply_verification_result`(`confidence_score=round(confidence*100)`) | 打分统一到 multi_dim | ✅ |
| **E5** | `prompts/logic_vuln.py` + `engines/logic_vuln_detector.py`（入口可达 limited-scope + 三要素硬证据 + 置信度封顶0.6）+ `ScanPhase.LOGIC_VULN_DISCOVERY` + flag `logic_vuln`（默认关） | AI 补漏逻辑漏洞 | ✅ `cb348cb` |
| **D3** | `scan_orchestrator._serialize/_restore_scan_results` + `WebCheckpointSink.save` 注入 `resume_data` + execute_scan resume 恢复；修 `checkpoint_service` session/datetime 两 bug | 断点续扫 findings 持久化与恢复 | ✅ `2a0e568` |
| **D6** | `cpg/models.py`(function_cfgs/merge_cfg) + `cpg/builder.py`(_build_and_merge_cfgs/_link_call_to_definition) + `path_finder/finder.py`(_verify_cfg_reachability/_extract_condition_paths) + `cfg/base.py`(_extract_function_body 通用化) + `go_cfg.py`(解包 statement_list) | CPG CFG 可达性接地（reaches_sink/condition_paths 真实值）+ 修 5 既有 bug（P9-01/体提取/sink/Java/Go） | ✅ 待提交 |

---

## Feat Record: 2026-06-19 E5 — AI 补漏逻辑漏洞（LogicVulnerabilityDetector）

### 需求描述
E5（Phase 17 待办）：补静态引擎（semgrep/AST/taint）和现有 agent 全量审计都容易漏掉的**逻辑漏洞**——缺失授权/认证绕过/IDOR/业务逻辑/复杂注入。核心诉求：AI 生成型补漏，但**防误报**是硬约束。用户确认维度：v1 **全量范围** + **独立 pipeline phase** + **独立 flag 默认关**。

### 实现方案
新增 `LogicVulnerabilityDetector`——一个 limited-scope、证据锚定的 AI 补漏 pass。反误报四重护栏：① 只把**入口点可达**的源码区喂 LLM（复用 `attack_surface_report` 入口索引）② 强制**三要素硬证据** `missing_check` + `entry_point` + `attack_path`，缺一丢弃（prompt 层 + 解析层双重强制）③ 置信度**封顶 0.6** + `evidence_strength=SPECULATIVE` ④ 正常代码 0 误报为验收门槛。复用 `RoundFourExecutor._llm_assisted_assessment` 同款 LLM client + prompt build/parse 基础设施。接入为独立 `ScanPhase.LOGIC_VULN_DISCOVERY`（插在 `EXPLOITABILITY_VERIFICATION` 之后、`ADJUDICATION` 之前），逻辑漏洞自带证据、无 source→sink taint，故跳过 taint 验证直接进去重/裁决。

### 修改文件
- `src/layers/l3_analysis/prompts/logic_vuln.py`（新增）：`build_logic_vuln_prompt(regions)` → `(system, user)` + `parse_logic_vuln_response(text)` → `list[dict]`；全量 5 类 + 三要素 schema + JSON 容错（裸 list/单对象/code fence/正则兜底）+ 置信度 clamp。
- `src/layers/l3_analysis/engines/logic_vuln_detector.py`（新增）：`LogicVulnerabilityDetector`；`select_entry_regions()`（按文件分组去重 + cap）、`discover()`（入口筛选→LLM→解析→Finding）、`_to_finding()`（source=logic_vuln、SPECULATIVE、置信度封顶、CWE 映射）。
- `src/layers/l3_analysis/models.py`：`Finding.source` Literal 增 `"logic_vuln"`。
- `src/layers/pipeline/phases.py`：`ScanPhase` 增 `LOGIC_VULN_DISCOVERY = "logic_vuln_discovery"`。
- `src/web/services/scan_orchestrator.py`：`_run_logic_vuln_discovery()`（构造 detector、产 ScanResult 桶、异常不中断扫描）+ `_build_scan_phases` 注册 PhaseSpec（`skip_when = not config.get("logic_vuln", False)`，默认关）。
- `src/web/models/schemas.py`：`ScanConfig` 增 `logic_vuln: bool = False`。
- `tests/unit/test_l3/test_logic_vuln_prompt.py`（新增，19 测试）：prompt 构建 + 解析（多条/缺三要素丢弃/裸对象/裸列表/code fence/畸形→空/clamp/全 5 类）。
- `tests/unit/test_l3/test_logic_vuln_detector.py`（新增，8 测试）：无攻击面/无 LLM 不调、入口筛选按文件去重、不可读文件跳过、source/evidence_strength 标记、置信度封顶、缺证据丢弃、cap。

### 验证结果
- 单测：`test_logic_vuln_prompt.py`（19）+ `test_logic_vuln_detector.py`（8）= **27 passed**。
- 静态：6 个改动/新增文件 `ast.parse` OK；新文件 `ruff --select F` All checks passed（orchestrator 的 3 个 F 警告为既有，非本次引入）。
- 回归：`tests/unit/test_pipeline/` + `test_l3/test_consistency.py` 全绿；`test_deduplicator.py` 5 个失败经 `git stash` 验证为**既有** async 未 await 问题（与本次无关）。
- **端到端（本机 sqlite 无需，直连 GLM glm-4.5-air）**：构造 IDOR 入口 `get_user` + 受保护入口 `get_profile`（有 ownership check）。实测检出 1 条 `[high] IDOR in user lookup`（CWE-639, conf=0.6），三要素证据完整（attack_path 具体到「认证用户改 /api/users/2 取回他人记录」）；**未误报**受保护的 `get_profile`。RESULT: **PASS ✅**。
- 临时 e2e 脚本（/tmp）验证后已删除；2 个单测文件为契约测试，保留。

---

## Feat Record: 2026-06-19 D3 — 断点续扫 findings 持久化与恢复

### 需求描述
D3（Phase 17 待办）：续扫时已完成 phase（`engine_execution`）被 skip，但其产出的 findings 没持久化/恢复 → 后续 exploitability/adjudication 无数据。原状态「save/clean/resume_from 机制已通，findings 持久化恢复待续」。验证要求：真实 Celery 中断→resume 场景（用户授权 docker 装 redis）。

### 实现方案 + 暴露的既有 bug
实现 findings 序列化→checkpoint `resume_data`→恢复链路。**摸排中暴露 checkpoint DB 持久化根本没工作过**（两个既有 bug，D3 的真前置）：
- **Bug 1（阻塞）**：`checkpoint_service.py` 用 `async with get_session_local() as db:`——`get_session_local()` 返回的是 `async_sessionmaker`（不支持 async context manager），必须 `get_session_local()() `。修 3 处。（代码库不一致：orchestrator/adversarial/concurrency 用 `factory()` 带括号=对；checkpoint_service/phase_manager 缺括号=错，本次只修 checkpoint_service。）
- **Bug 2（阻塞）**：`checkpoint.model_dump()` 保留 datetime 对象 → 存 DB JSON 列 `TypeError: datetime not JSON serializable`。改 `model_dump(mode="json")`（与 `get_hash()` 的 `model_dump_json` 一致）。

D3 核心改动：
- `scan_orchestrator.py`：`_serialize_scan_results()`（`ScanResult.model_dump(mode="json")` 逐引擎，容错）+ `_restore_scan_results()`（`model_validate` 逐引擎，容错）+ `_restore_state_from_checkpoint(ckpt)`；`execute_scan` resume 块加载 checkpoint 后调恢复。
- `scan_pipeline_adapters.py`：`WebCheckpointSink.save` 注入 `resume_data={"scan_results": ...}`——**不**污染 progress summary（summary 仍只进前端），findings 只进 checkpoint。

### 修改文件
- `src/web/services/checkpoint_service.py`：修 session context manager（3 处 `()()`) + datetime 序列化（`mode="json"`) + 清未用导入（json/Scan/ScanPhase/ScanStatus）。
- `src/web/services/scan_orchestrator.py`：+`_serialize_scan_results`/`_restore_scan_results`/`_restore_state_from_checkpoint`；execute_scan resume 调恢复 + 日志恢复 findings 数。
- `src/web/services/scan_pipeline_adapters.py`：`WebCheckpointSink.save` 注入 resume_data。
- `tests/unit/test_web/test_scan_resume_findings.py`（新增，10 测试）：往返保真（severity/source/location/cwe/evidence_strength/metadata/logic_vuln 源）、JSON 兼容、垃圾容错、WebCheckpointSink 注入且不污染 summary、`_restore_state_from_checkpoint` 从 CheckpointData 恢复。

### 验证结果
- 单测：10 passed（往返 + 注入 + 恢复）。
- **Tier-1 真实 DB 往返**：真 CheckpointService + sqlite，scan_results(semgrep+logic_vuln) → `save_checkpoint`(DB JSON 列 + hash) → `load_checkpoint` → **hash 验证通过** → 恢复 2 findings 字段保真（含 metadata/evidence_strength/location）。RESULT: **PASS ✅**（修 bug 前 save_checkpoint 直接 False）。
- **Tier-2 真实 Celery 跨进程**：docker redis + 真 celery worker（redis broker）。Task A（独立 worker 进程）存 2 findings → Task B（**独立 worker 调用**）load + **hash_verified=True** + 恢复双引擎 2 findings + metadata 跨进程保真。RESULT: **PASS ✅**。
- 静态：改动文件 `ast.parse` OK；`checkpoint_service.py` ruff F 全清；orchestrator 的 2 个 F 警告为既有（非本次）。
- 回归：`test_pause_resume.py`/`test_checkpoint_service.py` 既有 errors 不变（同源 fixture/环境问题，与本次无关）；E5 的 27 测试仍绿。
- 临时脚本/docker redis 验证后已清理。

---

## Feat Record: 2026-06-19 D6 CPG CFG 可达性接地（完整版）

### 需求描述
用户原描述：`/ai-feat D6`。范围经确认选「完整 D6（原描述）」：把已实现却从未接入的 CFG 子系统接通，让 `AttackPath.reaches_sink` 与 `condition_paths` 从硬编码变为真实值，并跨 python/js/java/go 验证。

### 实现方案
CFG 作为**独立的可达性后置校验**，不并入 BFS 路径搜索（保持现有路径语义/测试不破）。分 5 阶段 TDD：
1. **CPG 模型**：`CodePropertyGraph` 携带 `function_cfgs`，`merge_cfg()` 建 `cfg_block` 节点+`cfg` 边并登记 CFG，`get_successors(edge_types=)` 可选过滤，`get_cfgs_for_file()`。
2. **可达性**：`_verify_cfg_reachability` 按行号把路径节点映射到 CFG 基本块（`_locate_block`），要求每个块从其函数入口可达；死块（如 `return` 后）→ `reaches_sink=False`；无 CFG 回落 `True`（零回归）。
3. **条件**：`_extract_condition_paths` 沿路径块查 `CFGEdge.condition`+edge_type，记 `{cond: True/False}`（仅 conditional 边）。
4. **builder 接通**：`_fuse_graphs` 末尾 `_build_and_merge_cfgs`（按扩展名定语言→`CFGBuilderFactory`→遍历函数节点→`build_cfg`→`merge_cfg`，每函数 try/except 容错）；`build_from_code` 传显式 language。
5. **多语言**：通用化 base `_extract_function_body` 处理 `block`/`statement_block` 体包装；加 `method_declaration`(Java)。

### 暴露并修复的既有 bug（CFG 子系统从未被调用，全是死代码）
- **Bug 1（根因，致全语言 CFG 空）**：`cfg/base.py _extract_function_body` 只找函数的直接 `*_statement` 子节点，但 tree-sitter 里函数体包在 `block`/`statement_block` 下 → 返回空 → 0 基本块。通用化为下钻 `block`/`statement_block`。
- **Bug 2**：`cpg/builder.py` `function_types` 缺 `method_declaration`（Java 方法不被识别）。收敛为 `FUNCTION_TYPES` 类常量并补齐。
- **Bug 3**：`path_finder/finder.py _find_sinks` 读 `metadata["ast_name"]`（从未被 `merge_ast_graph` 设置）→ sink 永远找不到。回落到 `metadata["ast_node"].name`。

### 修改文件
- `src/layers/l3_analysis/engines/ast_engine/cpg/models.py`：+`function_cfgs` 字段、`merge_cfg()`、`get_successors(edge_types=)`、`get_cfgs_for_file()`；导入 `ControlFlowGraph`。
- `src/layers/l3_analysis/engines/ast_engine/cpg/builder.py`：+`FUNCTION_TYPES` 常量；`_fuse_graphs(language=)`；`_build_and_merge_cfgs()`；`_create_function_body_edges`/`_build_and_merge_cfgs` 改用常量；`build_from_code` 传 language。
- `src/layers/l3_analysis/engines/ast_engine/path_finder/finder.py`：`_build_attack_path` 调真实 `_verify_cfg_reachability`/`_extract_condition_paths`；实现 `_verify_cfg_reachability`/`_locate_block`/`_extract_condition_paths`/`_find_cfg_edge`；`_find_sinks` 回落 `ast_node.name`。
- `src/layers/l3_analysis/engines/ast_engine/cfg/base.py`：通用化 `_extract_function_body`（下钻 block/statement_block）。
- `tests/unit/test_l3/test_cpg/test_models.py`：+`TestCFGFusion`（7 测试：function_cfgs/merge_cfg 节点边/get_successors 过滤/get_cfgs_for_file）。
- `tests/unit/test_l3/test_path_finder/test_finder.py`：+`TestCFGReachability`（3）、`TestConditionPaths`（3）、`TestPythonEndToEnd`（3，含 1 xfail 记录 P9-01）、`TestMultiLanguageCFGBuild`（5，含 4 语言参数化）。

### 验证结果
- **D6 全绿**：`test_path_finder` + `test_cpg/test_models` + `test_cfg` = **68 passed, 1 xfailed**（xfailed 是有意记录的 P9-01 provider 缺口）。
- **集成层实证（真源码）**：python `eval` 可达 → `_verify_cfg_reachability=True`；`return` 后死 `eval` → `False`（真 CFG，非桩）。多语言 function_cfgs 均产出：python/js 在 `if` 处正确裂块（≥2 block、≥1 边）；java/go 产出 CFG 但裂块粗（见下）。
- **回归**：`test_cpg` 全目录 58 passed（仅 1 既有 `test_supports_language` 失败，与本次无关）；改 `cfg/base.py` 后 `test_cfg` 18 全绿。
- **既有失败（24，全在 test_l3，均与 D6 无关，非本次回归）**：`max_concurrent` 默认值、dedup/gatekeeper/semgrep/detector/adjudication 等模块。

### ⚠️ 已知边界（诚实披露，非静默）
> 下方 #1/#2 已在追加记录（P9-01 + Go 裂块修复）中**修复**；保留原文以记录发现过程。
1. ~~**P9-01 连接 bug（阻 provider 级 e2e，超出 D6 范围）**~~：入口 `call_function` CPG 节点与函数体 `function_definition` CPG 节点是两个未连通的节点 → BFS 无法 entry→sink → `PythonCPGProvider.get_paths` 对真源码返回 `[]`。**✅ 已修**（见追加记录：`_link_call_to_definition` 加 `defines` 边；provider e2e 全绿）。
2. ~~**Java/Go CFG 裂块粗**~~：Java 实测本就正确裂块（初判为误诊）；Go 因 `block→statement_list` 包装未解包致单块。**✅ Go 已修**（`go_cfg._extract_function_body` 解包 `statement_list`）。四语言现均裂块。
3. D6 状态行/TL;DR 未同步更新（按 `/ai-feat` 仅追加；建议 `/ai-sync` 更新 D6 为 done）。

---

## Feat Record (追加): 2026-06-19 P9-01 连接 + Go 裂块修复

### 需求描述
用户：「先继续修复 bug」。修上条 D6 记录披露的两个边界 bug，使 CPG 攻击路径特性真正端到端可用 + 多语言精度对齐。

### 实现方案
- **P9-01（连接）**：`CPGBuilder._link_call_to_definition` —— 同一函数在 CPG 里是两个未连通节点（`call_function` 入口 vs `function_definition` 体节点，`contains` 边挂在后者）。按 `file`(后缀匹配，容忍相对/绝对路径不一致) + `line` 匹配两者，加 `defines` 边 `call_function→function_definition`，BFS 得以 entry→体→sink。
- **Go 裂块**：`go_cfg._extract_function_body` 解包 `block→statement_list→statements`（base 止于 `block` 返回 `[statement_list]` 单节点致整函数 1 块）。
- **Java**：复测确认本就正确裂块（`if`+`return` → 2 块 1 边；`return` 后死代码 → 孤儿块），无需改。

### 修改文件
- `src/layers/l3_analysis/engines/ast_engine/cpg/builder.py`：+`_link_call_to_definition()` + `_files_match()`；`_fuse_graphs` 末尾调用。
- `src/layers/l3_analysis/engines/ast_engine/cfg/builders/go_cfg.py`：+`_extract_function_body` 解包 `statement_list`。
- `tests/unit/test_l3/test_path_finder/test_finder.py`：原 P9-01 xfail → 2 个真实 provider e2e 测试（可达/死代码 reaches_sink）；`TestMultiLanguageCFGBuild` 升级为四语言参数化裂块断言。

### 验证结果
- `test_path_finder` + `test_cpg` + `test_cfg` = **109 passed**（含四语言裂块 + provider e2e 可达/死代码）。
- `test_cpg_agent`(集成) + `test_opencode_agent` = 42 passed（仅既有 `max_concurrent` 默认值失败，与本次无关）。
- provider e2e 实证：`PythonCPGProvider().get_paths(真 .py)` 现返回非空路径；可达 `eval`→`reaches_sink=True`，`return` 后死 `eval`→`False`。
- **CPG 攻击路径特性此前从未端到端工作过**（P9-01 致 `get_paths` 恒返回 `[]`）；现修复。


