# Current Goal

> **状态**: 进行中 🚧 — 第一/二批 + P6-eval + **第三批 P5 续扫完整性 + P7 可靠性** 已完成并 push（`a9ef21a` + `bc1db1f`，本地=origin=bc1db1f）；**第四批 P6 低风险子项（子项3 LIKELY→MEDIUM + 子项4 删死机械 + 子项5 策略知识注入基础版 prompt）已完成、未提交**；**P6 对抗接线硬骨头（子项1 gatekeeper / 子项2 min_evidence_dimensions）仍留独立会话（用户 2026-06-20 决定）**；剩 C6 引擎级checkpoint / P3 可达性质量 / P6 硬骨头
> **目标**: Phase 18 — 精度链路接通与多语言可达性补齐（基于全量实现审查）
> **Goal ID**: phase18-precision-link-reachability
> **创建日期**: 2026-06-20（最近更新：2026-06-20 第三批 P5/P7 push 后）
>
> **📊 进度快照（新会话先看这个）**：
> - ✅ **第一批**（`4ee490b`）：P0 精度链路 / P1 Java call_graph 注册 / P4 语言收敛+CodeQL 类型
> - ✅ **第二批**（`6b0f290`+`4b15224`）：三语言 py/go/java CPG 可达性全部接通
> - ✅ **P6-eval**（`4409eb4`）：round_four severity 保底（防漏报）
> - ✅ **第三批 P5 续扫完整性**（`a9ef21a`）：H2a pause 真停（revoke）+ H2b clone 防挂死（kill_after_timeout）+ task6 `_finalize_results` DB 去重 + task7 阶段命名统一收敛 ScanPhase（**修复 resume 全量重跑根因**）
> - ✅ **第三批 P7 可靠性**（`a9ef21a`+`bc1db1f`）：C3 git timeout + C4 baseline fixed 加 scanned_files 覆盖判定 + C5 增量 relative import level 解析 + C7 finding_budget 截断前排序 + 删死代码（`_deduplicate_findings`/`calculate_finding_confidence`）
> - ✅ **P8 测试真实性**（横穿，`a9ef21a`）：3 个 web 测试文件 fixture 修复（AsyncSessionLocal→get_session_local，setup ERROR→全绿）+ 删 4 CLIAdapter 死测试；全 test_l3 **2200 passed / 23 既有失败（零回归，+10 新真实测试）**
> - ✅ **已 push** `origin/feat/static-evidence-grounding`（fca0c22..bc1db1f，本地=origin，工作区干净）
> - ⏳ **P6 对抗接线 → 独立会话**（用户 2026-06-20 决定）：子项评估见下；**C6 引擎级 checkpoint / P3 可达性质量** 也待做
> - ⚠️ **治本（P6-rootcause）已评估回退**：taint→None 正确但与 round_four_llm/codeql 测试架构冲突（8 回归），保底已解决核心，归后续重构测试架构时做
> - 全 test_l3 始终 **23 既有失败、零回归**（既有失败：verification_gatekeeper×5/deduplicator-async/adjudication×3/ast_engine×3/detectors×2/pre_filter×3/semgrep×1/opencode_agent×1，与本 goal 无关）
>
> **🧭 冷启动 TL;DR（2026-06-20）**：Phase 17 此前记录为"全部 done"，但 **2026-06-20 全量实现审查**（8 路并行审计，12 万行）发现**多个"声称完成但生产路径上未生效"的核心功能**：① 四轮审计实际**只跑 Round1**（Round2/3 漏调 `add_candidate`，连锁 skip Round3/4）；② 裁决结果映射**属性名错**，`scan_orchestrator.py:1377,1381` 读 `candidate.exploitability/confidence_score`（对象无此属性），导致 exploitability 全丢、**Web 端 confidence 恒为 0**；③ **D5 打分只统一一半**（`finding.confidence_score` 设了，但驱动排序的 `finding.confidence` 没被接管）；④ **CPG 可达性 JS/Java/Go 产 0 路径**（`call_graph/analyzer.py:55` 只注册了 Python builder）且嵌套 sink 恒判可达；⑤ **D3 续扫 resume 失效**（新旧双阶段命名对不上 + 实例状态未恢复 + 落库无去重）；⑥ **pause 假停**（不 revoke Celery）；⑦ **~2000 行对抗增强层是死代码**（enhanced/convergence/strategy_library/gatekeeper 未接线）。
>
> 本 goal 按**用户 2026-06-20 确认的场景**重新定优先级：**内网单用户**（→ 安全组降级暂缓）、**语言收窄 py/go/java**（→ **放弃 C/C++**）、核心诉求是**检测流程完整 / 链路清晰 / 静态与 AI 真正结合 / 提升效果**。分批修复，第一批 P0+P1+P4 改动最小、杠杆最大。

---

## 第一批实施记录（2026-06-20，P0+P1+P4 完成 ✅）

TDD 推进，全 test_l3 **2189 passed / 24 既有失败（零回归）**，12 个新测试全绿（基线 2177→2189）。

| 项 | 改动 | 验证 |
|---|---|---|
| **P0-A1** ✅ | `round_two/round_three` 的 `execute` 开头把传入 candidates 逐个 `round_result.add_candidate(c)` 回填 | `TestRoundTwoThreeCandidatePropagation` 2 测试（修复前 `0 candidates`→红，修复后绿） |
| **P0-A2** ✅ | 提取 `VulnerabilityCandidate.to_exploitability_verification_metadata()`（读 `finding.confidence_score`/`exploitability`，非不存在的 candidate 属性）；`scan_orchestrator` 映射调用它 | `TestCandidateExploitabilityMapping` 2 测试 |
| **P0-A3** ✅ | `round_four._apply_verification_result` 同步 `finding.confidence=result.confidence` + `finding.exploitability=result.status.value`（D5 单一真相源贯彻，final_score 读到统一值） | `test_finding_confidence_and_exploitability_synced` |
| **P1** ✅ | `call_graph/analyzer.py` 注册 `JavaCallGraphBuilder()`（已实现的 395 行类） | `TestJavaCallGraphBuilder` 2 测试；Java 进入 call graph（3 节点 1 HTTP entry，此前完全跳过） |
| **P4-C1** ✅ | `ast_engine` supported_languages 收敛 py/js/ts/java/go；`_get_source_files` 返回 `(files, skipped)`；scan raw_output 记 `skipped_unsupported_files`+`supported_languages` | `TestLanguageScopingP4C1` 2 测试 |
| **P4-C2** ✅ | `codeql/executor.py` `_create_taint_source/_sink` 签名 `ParsedDataflowPath`→`PathLocation`，去掉 `hasattr` 兜底 | `test_codeql_dataflow_executor_typing.py` 3 测试 |

**⚠️ P1 端到端发现（归 P2/P3，非 P1 范围）**：注册 JavaCallGraphBuilder 后 Java 文件进入 CallGraphAnalyzer 构建（此前完全跳过）。但 **CPG attack-path 端到端仍返回 0** —— 根因不是 call_graph edges（CPG 用自己的 AST 图，不依赖 CallGraphAnalyzer 的 edges），而是 `finder.py:58 "No entry points found in CPG"`：CPG 层找不到 Java 的入口节点（call_function→function_definition 连接/标记问题，类 P9-01 但针对 Java）。此外 `base.py:_create_callee_id` 用 `Unknown:` 前缀致 CallGraphAnalyzer edges=0（影响 find_callers/check_reachability，Python 同款）。两点均归入 **P2（Go builder + CPG 多语言 entry/callee 连接）**。

**改动文件**：`round_two.py` / `round_three.py` / `round_four.py` / `rounds/models.py` / `scan_orchestrator.py` / `call_graph/analyzer.py` / `ast_engine.py` / `codeql/executor.py` + 测试（`test_rounds.py`/`test_call_graph.py`/`test_ast_engine.py` 追加 + 新建 `test_codeql_dataflow_executor_typing.py`）。**未 commit**（遵循不自动提交规则）。

---

## 第二批实施记录（2026-06-20，P2-前置 + P2-Go 完成 ✅，三语言可达性接通）

TDD + 端到端验证，全 test_l3 **2194 passed / 23 既有失败（零回归）**。三语言（py/go/java）CPG attack-path 全部端到端通（`reaches_sink=True`）——此前 JS/Java/Go 一律 0 paths。

| commit | 内容 |
|---|---|
| `6b0f290` P2-前置 | CPG entry/callee/sink 连通，Java 端到端通（0→2 paths）。三处通用修复：① `cpg/models.py merge_call_graph` 把 `CallNode.is_entry_point/entry_point_type` 写入 CPG call_function metadata（finder 靠真实 HTTP/RPC/main 入口而非脆弱的函数名 pattern）② `base.build_file_graph` 加边前 resolve callee_id 到实际 node（`_create_callee_id` 的 `Unknown:` 前缀致 calls 边全丢→0 edges）③ `finder._find_sinks` 用 `re.search`（pattern 是正则 alternation 如 `exec|getRuntime`，子串匹配永远 False→sinks 空）。顺手修了 `test_supports_language` 既有矛盾。 |
| `4b15224` P2-Go | 新建 `go_builder.py`（func/method declaration + call expression[identifier/selector/chain] + entry 检测[main/init/http handler 签名]）+ `go_provider.py` + path_provider/analyzer 注册。Go 端到端通（0→1 path）。 |

**⚠️ P3（嵌套 sink 可达性质量）评估后建议归第三批**：
- "嵌套 sink 判不可达"本质需要**条件求值**（识别 `if False` 死分支），非 `identify_basic_blocks` 递归能解决——CFG 是结构可达（边可达），不做条件求值。
- "`_verify_cfg_reachability` 兜底默认 True 改保守"有**回归风险**：刚接通的 py/go/java `reaches_sink=True` 部分依赖兜底 True，改保守会让它们变 False（漏报）。
- P3 是精度改进（防误报方向），非功能阻断；建议与 P5/P7 在第三批一起深做（含条件求值设计）。

**改动文件**：`cpg/models.py` / `call_graph/builders/base.py` / `path_finder/finder.py`（P2-前置）+ `go_builder.py`(新) / `go_provider.py`(新) / `path_provider.py` / `analyzer.py`（P2-Go）+ 测试。**第一批(`4ee490b`)与本批(`6b0f290`/`4b15224`)均已 commit**。

---

## 第四批实施记录（2026-06-20，P6 低风险子项 完成 ✅，未提交）

用户决定 P6 硬骨头（子项1 gatekeeper 接线 / 子项2 min_evidence_dimensions）留独立会话，本批先把低风险高确定性的子项3/4 清掉，并按"删花哨的、留有用的、把它接对"新增**子项5（真能力提升）**。全 test_l3 **2186 passed / 23 既有失败（零回归）**。

| 子项 | 改动 | 验证 |
|---|---|---|
| **子项3** ✅ | `round_three.py:316` `LIKELY→ConfidenceLevel.HIGH` 改 `MEDIUM`（防"可能"与 CONFIRMED 同级误升 EXPLOITABLE；下游 `RoundResult.add_candidate` 把 LIKELY 候选从 high→medium 计数） | `test_likely_status_maps_to_medium_not_high`（修复前红/后绿）|
| **子项4** ✅ | 删死机械 `enhanced_adversarial.py`(744)+`convergence.py`(411)=1155 行；**保留** `strategy_library.py`（真知识，干净叶子，仅依赖 stdlib+pydantic）。清理 `verification/__init__.py` 的 enhanced/convergence re-export（保留 strategy_library）。修 `verification_gatekeeper.py` 两处 docstring 去掉对已删文件指代。拆 `test_enhanced_adversarial.py`(45)→`test_strategy_library.py`(26，保留 strategy 测试，删 convergence/enhanced/evolution/learning 测试) | ruff F 零新增；干净导入 `AdversarialVerifier/StrategyLibrary/create_attacker_library`；无残留引用 |
| **子项5** ✅（核心能力）| 把 `strategy_library` 真知识**按 finding vuln 类型**接进 `prompts/adversarial.py` 的 `get_attacker_user_prompt`/`get_defender_user_prompt`：attacker 注入相关绕过技巧+攻击链，defender 注入防御机制+trigger conditions+suggested defense。**生成时参考**（非增强版"生成后贴字符串"）。接地气表述（"assess whether applicable"/"verify presence"，不预设结论）。未知 vuln 类型不注入（不膨胀）| `test_adversarial_strategy_injection` 4 测试：SQLi attacker 含 comment/攻击链 + 接地气；XSS 类型感知；defender 含 parameterized + verify；未知类型无注入 |

**关键判断（驱动子项4/5 设计）**：审查 enhanced 层（`_run_enhanced_debate`）发现它**核心推理复用基础版**（直接调 `base_verifier._run_round_1/arbiter.evaluate`），策略知识是"生成后追加字符串"（`_enhance_attacker_argument`），属**花哨不更强**。故删机械、留知识、把知识接进基础版生成 prompt 才是真增强。

**改动文件**：`round_three.py` / `verification/__init__.py` / `verification_gatekeeper.py` / `prompts/adversarial.py`（子项3/4/5）+ 删 `enhanced_adversarial.py`/`convergence.py` + 测试（`test_rounds.py` 追加 / 新建 `test_strategy_library.py`(替 `test_enhanced_adversarial.py`) / 新建 `test_adversarial_strategy_injection.py`）。**未 commit**（遵循不自动提交）。

**测试数学校验**：2200(基线) − 45(删 test_enhanced) + 26(新建 strategy) + 1(子项3) + 4(子项5) = **2186 passed**，既有失败 23 不变，零回归。

---

## 需求背景

2026-06-20 对全量代码做了 8 路并行实现审查。结论：**骨架完整、纯算法层扎实**（CFG 建图、evidence_calculator、semgrep 真集成、taint_tracker、威胁情报均为真实可用实现），但**精度核心多数未真正生效**。根因集中在三类：**(a) 重构/接通改了一半**（搬了字段、接了入口，调用点和下游没跟着改全）；**(b) 跨子系统协议没对齐**（新旧阶段命名、语言 builder 注册）；**(c) 端到端测试是 mock**（D3 Celery / E5 GLM / checkpoint 持久化 / CodeQL 全是 Mock/stub，所以这些断裂没被测出来）。

> ⚠️ **诚实披露**：本 goal 的根因/定位来自并行代码审查，**绝大多数带 `file:line` 证据**；少数标 SUSPECT（如并发 `_borrowed` 记账、config 路径错配）需在 TDD 时坐实后再修。

---

## 场景约束（用户 2026-06-20 确认，决定优先级）

1. **内网单用户使用** → 安全组（IDOR / WS 认证 / 源路径白名单 / 弱口令 / 限速 / API key 明文 / CSV 注入 / git 注入 / JWT 失效）**整体降级为暂缓**；仅做轻量加固。待将来公网/多用户时再整体补多租户。
2. **语言收窄到 Python / Go / Java**；**放弃 C/C++**（从地基起步的独立大工程，不立项）。
3. **核心诉求**：检测流程完整、链路清晰、静态工具与 AI 真正结合、提升检测效果。

---

## 语言支持现状矩阵（2026-06-20 核实）

| 能力层 | Python | Java | Go |
|---|---|---|---|
| sinks/sources 注册 | ✅ | ✅ | ✅ |
| CFG builder | ✅ | ✅ | ✅ |
| AST 规则 | ✅ | ✅ | ✅ |
| CPG provider 注册 | ✅ | ✅ | ❌ 注释成 TODO |
| **call_graph builder** | ✅ | ⚠️ **已实现(395行)未注册** | ❌ 文件不存在 |
| **可达性 attack-path 端到端** | ✅ 通 | ❌ 断(call_graph) | ❌ 多处断 |

**关键事实**：`src/layers/l3_analysis/call_graph/builders/java_builder.py` 是**完整的 395 行实现**（方法/构造器/继承/接口/Spring 入口/调用解析全有），仅 `analyzer.py:55` 未注册（注释 "Java and Go builders will be added later"）→ **Java 可达性接通近乎免费**。Go 的 call_graph builder 文件不存在 + `GoCPGProvider` 注释成 TODO → Go 需新建 builder + provider（中等工程）。

---

## 待办目标（按优先级 P0–P8，附提升建议）

### P0 — 精度链路打通（A1+A2+A3）｜工作量 S｜对应：流程完整 + 链路清晰

**根因/定位**：
- A1：`rounds/round_two.py` / `round_three.py` 全文**从未调用 `round_result.add_candidate()`**，直接改传入 candidate 引用 → `termination.py:315` 见空 `next_round_candidates` 立即 NO_CANDIDATES 早停 → **Round3/4 永不执行**。
- A2：`scan_orchestrator.py:1377,1381` 读 `candidate.exploitability` / `candidate.confidence_score`，但 `VulnerabilityCandidate`（`rounds/models.py:44`）**无此属性**（真实字段在 `candidate.finding.*`）→ exploitability 全丢、confidence 恒 0。
- A3：`round_four.py:1428` 只设 `finding.confidence_score`，但 `final_score.py:310 calculate_finding_score` 仍读 `finding.confidence`(0-1)，D5 的"单一真相源"没贯彻。

**修复步骤**：
1. Round2/3 每个 phase 开头把传入 candidates 逐个 `round_result.add_candidate(c)` 回填（保持同引用以保留 confidence 更新）。
2. `scan_orchestrator.py:1377,1381` 改读 `candidate.finding.exploitability` / `candidate.finding.confidence_score` / `candidate.confidence.value`。
3. D5 后让 `round_four` 同步更新 `finding.confidence`（或让 `final_score` 直接用 `confidence_score/100`）。

**验证**：Round2/3 回填单测 + 裁决 mapping 属性单测 + 断言 confidence 不再恒 0；全 test_l3 零回归。
**预期效果**：四轮审计、裁决映射、打分统一三条链同时复活；前端置信度/可利用性正确。

### P1 — Java 可达性接通（A4-Java）｜工作量 S｜对应：静态+AI 结合 + 覆盖 Java

**根因/定位**：`call_graph/analyzer.py:53-58` `_register_builders` 只注册 `PythonCallGraphBuilder`；但 `java_builder.py` 已完整实现。
**修复步骤**：`analyzer.py:55` builders 列表加入 `JavaCallGraphBuilder()`（import 已存在的类）；确认 `build_graph` 默认 patterns 含 `.java`（已含，line 295）。
**验证**：Java 真源码 attack-path 端到端（可达/不可达）——不再恒空；入口（Spring `@GetMapping`/servlet/main）→ sink 能出路径。
**预期效果**：Java 的入口→sink 可达性硬证据开始喂给裁决。

### P2 — Go 可达性接通（A4-Go）｜工作量 M｜对应：覆盖 Go

**根因/定位**：Go call_graph builder 文件不存在；`cpg/path_provider.py:50` `GoCPGProvider` 注释成 TODO。
**修复步骤**：
1. 新建 `call_graph/builders/go_builder.py`（仿 `java_builder.py`：func 声明/调用/入口 `net/http` handler、`main`、init 的提取）。
2. 新建 `cpg/providers/go_provider.py`（仿 java_provider）+ `path_provider.py` 注册 `"go": GoCPGProvider()`。
3. `analyzer.py` 注册 Go builder。
**验证**：Go 真源码 attack-path 端到端；三主力语言可达性补齐。
**预期效果**：Go 可达性链路通。

### P3 — 可达性质量（A4 嵌套 sink + 兜底取向）｜工作量 M｜对应：提升效果

**根因/定位**：
- 4 个 CFG builder 的 `identify_basic_blocks` 只铺函数**顶层语句**，`if/for/while` 体内的 sink 定位不到 block → `_locate_block` 返回 None → `continue` 视为可达（`finder.py:273-274`）。
- `_verify_cfg_reachability` 所有"找不到证据"的兜底**默认 True**（激进=放大误报），与保守立场相反。

**修复步骤**：
1. `identify_basic_blocks` 递归进入 `if/for/while/switch` 体内语句建 block（或让 `_locate_block` 落空时保守返回不可达/Unknown，而非 continue）。
2. 兜底分支从默认 True 改为 Unknown/保守（与 taint_tracker 的 `is_reachable=False` 取向一致）。
**验证**：`if False: eval(x)` 等条件守护死分支能判 False 的负样本测试；现有 Python 可达正样本不回归。
**预期效果**：最常见的"分支/循环内 sink"可达性判准；不再倾向误报。

### P4 — 语言声明收敛 + CodeQL 类型（C1+C2）｜工作量 S｜对应：链路清晰（不静默漏报）

**根因/定位**：
- C1：`ast_engine.py:39` `supported_languages` 声称 10 种，`rules/ast_query/` 实际只有 py/js/go/java；不支持的返回 0 findings 且 `success=True` → 静默漏报。
- C2：`codeql/executor.py:332` 把 `PathLocation` 当 `ParsedDataflowPath` 传，靠 `hasattr` 兜底。

**修复步骤**：
1. `supported_languages` 收敛到 py/go/java（C/C++ 显式标"不支持"，返回 `skipped` 状态而非 success+0 findings，让下游可区分"没洞"与"没实现"）。
2. 修 `_create_taint_source/_sink` 参数类型为 `PathLocation | None`。
**验证**：不支持的语言不再 success+0；CodeQL executor 类型契约正确。
**预期效果**：杜绝"扫了等于没扫"。

### P5 — 续扫流程完整（A5+A6）｜工作量 M-L｜对应：流程完整

**根因/定位**：
- A5：`pipeline/phases.py` 新 10 阶段 `ScanPhase` 与 `models/scan.py:31` 旧 7 阶段 `PhaseName` 并存，resume 算出的阶段名对不上；实例状态（tech_stack/attack_surface_report_obj）只恢复 findings → 下游 `None` 崩；`_finalize_results`(orchestrator:1731) 落库无去重 → resume 重跑重复 findings。
- A6：`scan_executor.py:486` pause 只改 DB 状态，不 revoke Celery → 双任务并发。

**修复步骤**：
1. 统一阶段命名：`scan_executor._create_initial_phases` / `PhaseManager.PHASE_ORDER` / `CheckpointService.get_resume_strategy.phase_order` / `progress_broadcaster` 全部改用 `ScanPhase`。
2. resume 序列化恢复 tech_stack + attack_surface_report_obj（一并进 checkpoint resume_data）。
3. `_finalize_results` 按 `(scan_id, rule_id, file, line)` upsert 去重。
4. `pause_scan` 接 `revoke(terminate=True)`，`_execute_scan_async` 守卫 PAUSED 状态。
**验证**：中断→resume 不重跑 engine_execution、不丢/重 findings；pause 真停。
**预期效果**：断点续扫名实相符。

### P6 — 对抗增强接线（A7 + 硬证据门 + LIKELY 映射）｜工作量 M｜对应：提升效果 + 静态+AI 结合

**根因/定位**：
- `verification_gatekeeper.py`（省 40% LLM + 硬证据守护）未接线，生产用 `adversarial_service.py:573` 手写极简版。
- `scoring/models.py:154` `min_evidence_dimensions=1` 可被单维 reachability 软标签绕过 EXPLOITABLE 判定。
- `round_three.py:309` 把 LIKELY(0.6-0.85) 映射为 HIGH，与 CONFIRMED 同级 → 可能误升 EXPLOITABLE。
- `enhanced_adversarial.py`(744) / `convergence.py`(411) / `strategy_library.py`(771) 约 2000 行未接线死代码。

**修复步骤**：
1. 用 `VerificationGatekeeper` 替换 `adversarial_service.should_verify_finding` 手写版（并修其 FP 正则行锚定）。
2. `min_evidence_dimensions` 提到 2，或把 reachability（非 source/sink 硬证据）移出 `evidence_dimensions`。
3. 修 LIKELY→MEDIUM（而非 HIGH）。
4. 决定 enhanced/convergence/strategy_library：接线 or 删除（消除误导性死代码）。
**验证**：gatekeeper 接线后单测；硬证据门负样本（单维软证据不判 EXPLOITABLE）。
**预期效果**：误报压制真生效、省 LLM、裁决更准。

### P7 — 可靠性（C3-C7）｜工作量 M｜对应：流程完整 + 提升效果

- **C3** `git_operations.py:122`：`clone_timeout` 传给 `clone_from`（防挂死 worker）。
- **C4** `baseline_manager.py:428`：fixed 判定叠加"该文件本次是否被扫描覆盖"，否则误报已修复。
- **C5** `dependency_graph.py:246`：修相对 import 路径拼接（防增量漏扫，含 java/go import）。
- **C6** `scan_pipeline.py`：engine_execution 增加引擎级增量 checkpoint（中途崩溃可续）。
- **C7** `finding_budget.py`：截断前按 final_score 降序排序（防随机丢弃高分）。
- 顺带清理死代码：`_deduplicate_findings`(orchestrator:1814)、`calculate_finding_confidence`(confidence_scorer:317)。

**验证**：各项配 TDD；git 超时/baseline 覆盖/import 拼接/budget 排序负样本。

### P8 — 测试真实性（E，横穿全程）｜工作量 M｜对应：保证修复可验证

**根因/定位**：D3 Celery（`test_pause_resume.py:13` `sys.modules[...]=Mock`）、E5 GLM（27 测试全用 stub）、checkpoint 持久化（`_save_checkpoint_file` mock 成 return True）、CodeQL（patch is_available）全是 mock；24 个"既有失败"中 8+ 是 async-当-sync 空转测试（`coroutine never awaited`），5 个 gatekeeper 是疑似真 bug。
**修复步骤**：每修一处 P 就把它从 mock 升级为真实测试；删/修 8 个 async-当-sync 空转测试；复核 5 个 gatekeeper 行为不符（修实现或修测试）；修 `test_path_provider.py:36` 与 Java 注册的矛盾（"109 passed"实为 +1 failed）。
**验证**：测试"绿"真正代表功能对。

### P9（降级）— 安全组暂缓 + 轻量加固｜工作量 S（加固部分）

**用户确认暂缓（单用户内网）**：IDOR / WS 无认证 / 源路径无白名单 / `/auth/seed` 未授权+弱口令 / 限速默认关 / API key 明文 / CSV 注入 / git 参数注入 / JWT 无失效。
**仅做轻量加固**（不阻塞功能）：改默认口令为强随机；`get_db` 加 `except: rollback`；repository 不内部 commit（改 flush，调用方控事务）。
**触发条件**：将来要公网/多用户时，整体补多租户（Scan/Finding 加 owner_id + 端点校验 + WS 认证 + 源路径白名单）。

---

## 提升建议（用户问"还有什么要提升"，非阻塞、按需排期）

1. **证据链可视化**（服务"链路清晰"）：修好 P0 后，每个 finding 在 API/报告层输出完整证据链——`哪个引擎发现 → 经历哪几轮 → 各维度分数(reachability/taint/codeql) → 为什么 confirmed/rejected`，便于人工核验。
2. **source→sink 完整路径展示**：可达性修好后，把 `AttackPath`（入口→...→sink 调用链 + 分支条件）写进 finding evidence，而非只一个布尔 `reaches_sink`。
3. **静态↔AI 双向闭环**：当前是单向（静态→AI 裁决）。可加"AI 反查静态引擎"——AI 对可疑点要求 CodeQL/taint 复核特定路径，迭代深化。
4. **误报反馈通路**：单用户标记的 false positive 回写、用于调阈值/规则。
5. **精度漏斗可观测性**：扫描中实时展示"每引擎产出 N → 预过滤剩 M → 多轮收敛 K → confirmed J"，让损失/误杀透明。

---

## 实施顺序建议（分批，每批跑 test_l3 验证零回归）

- **第一批（最高杠杆、改动最小）**：P0（精度链路）+ P1（Java 注册）+ P4（语言收敛）。工作量 S+S+S，一次性让"精度数据链路 + Java 可达性 + 语言诚实声明"到位。
- **第二批**：P3（可达性质量）+ P2（Go 接通）——三语言可达性补齐并提质。
- **第三批**：P5（续扫完整）+ P7（可靠性）+ P6（对抗接线）。
- **横穿全程**：P8 测试真实性——每修一处即升级为真实测试。
- **暂缓**：P9 安全组（待公网）、C/C++（不立项）。

---

## 验证环境（每次会话复用）

```bash
cd /opt/pro/deepvuln
export OPENAI_API_KEY="$ANTHROPIC_AUTH_TOKEN"
export OPENAI_BASE_URL="https://open.bigmodel.cn/api/coding/paas/v4"
# glm-4.5-air（快）；本机 1.9GB（无 CodeQL）；测试用 sqlite

# 全量回归
python3 -m pytest tests/unit/test_l3 -q 2>&1 | tail -30   # 期望 2195 passed / 23 既有失败，关注失败数不增
# 防回归
python3 -c "import ast,pathlib;[ast.parse(f.read_text()) for f in pathlib.Path('src').rglob('*.py')];print('OK')"
ruff check src/ --select F
```

**基准测试项目** `/tmp/vuln_test/app.py`（Python eval/SQLi/cmd 注入三件套，沿用 Phase 17）；Java/Go 基准待 P1/P2 时各建一个最小可复现（Spring `@GetMapping`→`Runtime.exec` / `net/http` handler→`os/exec`）。

---

## 新 agent 接力指南（冷启动必读）

### 1. 先读这些建立上下文
1. 本文件顶部 TL;DR + 各 P 项状态。
2. 跨会话记忆：`/root/.claude/projects/-opt-pro-deepvuln/memory/`（含 `deepvuln-phase18-precision-fix.md`、`deepvuln-web-only-no-cli.md`）。
3. `git log --oneline -8` + 分支 `feat/static-evidence-grounding`。
4. **审查原始发现**见本 goal 各 P 项的"根因/定位"行号锚点；若要复核某 SUSPECT 项，先读对应 file:line。

### 2. 关键约束（勿忘）
- **web-only**（CLI 已移除，不再维护）。
- **放弃 C/C++**；语言聚焦 py/go/java。
- **安全组降级**（单用户内网），别在 Phase 18 里花精力修 IDOR/WS 除非用户改主意。
- LLM 用 GLM Coding Plan 端点；本机无 CodeQL，引擎降级路径要保。

### 3. 当前进度 + 第三批起点
**第一/二批 + P6-eval + 第三批 P5/P7 已完成并 push（`a9ef21a`/`bc1db1f`）**。剩 **P6（→独立会话）/ C6 引擎级 checkpoint / P3 可达性质量**：

| 项 | 文件:锚点 | 动作 | 工作量 |
|---|---|---|---|
| **P3 可达性质量** | `cfg/builders/*_cfg.py identify_basic_blocks` + `path_finder/finder.py _verify_cfg_reachability` | ⚠️ 需**条件求值**（if False 死分支），非 basic_blocks 递归能解决；兜底改保守有回归风险（破坏刚接通的 reaches_sink=True）。深做前先设计 | M |
| **C6 引擎级 checkpoint** | `src/web/services/scan_orchestrator.py:926`(`_execute_engines`) / `scan_pipeline` engine_execution | engine_execution 现**整阶段级** checkpoint（全引擎跑完才写）。改 per-engine：每引擎完成写 + resume 跳过已完成引擎。⚠️ `_execute_engines` 是并发（cpu_intensive+concurrent 两路 ThreadPoolExecutor），per-engine checkpoint 需处理并发同步 + resume 恢复 completed_engines。**会话末尾不宜仓促做** | M-L |
| **P6 对抗接线**（→ 独立会话） | `verification_gatekeeper.py:54` / `scoring/models.py:154`(`min_evidence_dimensions`) / `round_three.py:315`(`LIKELY→HIGH`) / `adversarial_service.py:573`(手写版) / `scan_orchestrator.py:1522`(调用点) | **用户 2026-06-20 决定整体留独立会话**。子项评估（独立会话起点）：**子项3** round_three:315 `LIKELY→MEDIUM`（一行，低风险，防与 CONFIRMED 同级误升 EXPLOITABLE）；**子项4** 删 enhanced_adversarial/convergence/strategy_library 1926行（✅ 已确认只 `verification/__init__.py` re-export、无功能引用，可删 + 清 __init__）；**子项2** `min_evidence_dimensions` 1→2（⚠️ 精度/召回权衡，本机无 CodeQL→仅 taint+reachability 达2，改后单硬证据真漏洞可能漏报，需评估召回）；**子项1** VerificationGatekeeper 接线替换 adversarial_service:573 手写版（⚠️ `test_verification_gatekeeper` 有5个既有失败，接线前先修 gatekeeper 本身） | M |

**开工第一步**：先跑回归确认基线 `python3 -m pytest tests/unit/test_l3 -q`（期望 **2200 passed / 23 既有失败**）。P6 在独立会话做（子项评估见上表）；C6/P3 可在本会话继续。

> **上一目标**：Phase 17 — AI 与静态最优结合的深化（status: completed，commit `fca0c22`）。其"全部 done"的结论已被本次审查修正——多项功能实际未生效，正是本 Phase 18 要接通的。
