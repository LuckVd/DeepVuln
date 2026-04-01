# DeepVuln 项目路线图

> 三层核心架构智能漏洞挖掘系统开发规划（高精度重构版）

---

## 项目概览

|字段|值|
|---|---|
|**名称**|DeepVuln|
|**类型**|backend|
|**描述**|三层核心架构智能漏洞挖掘系统，AI Agent 为主、SAST 工具为辅，实现攻击面驱动与可利用性优先裁决|
|**技术栈**|Python 3.10+ / LLM API (OpenAI) / Semgrep / CodeQL / Tree-sitter|

---

## 开发阶段

|阶段|目标|核心交付|状态|预计完成|
|---|---|---|---|---|
|Phase 1|基础设施搭建|L1 初版|done|2026-02|
|Phase 2|核心分析能力|L3 三引擎 + 多轮审计|done|2026-02|
|Phase 3|精度重构|Rule Gating + TechStack 重构|done|2026-03|
|Phase 4|裁决统一|Exploitability 主裁决 + 误报压制|done|2026-03-06|
|Phase 5|精度深化|可利用性评估增强 + 调用图分析|done|2026-03|
|Phase 6|报告可信度|结果边界清晰化 + 噪声治理 + 覆盖率透明|in_progress|2026-03|
|Phase 6.5|code-audit 集成|防幻觉规则 + 覆盖率矩阵 + 污点分析模板 + 漏洞验证方法论|in_progress|2026-03|
|Phase 6.6|Readiness Gate 自动修复|尽量构建环境而非跳过|active|2026-03|
|Phase 7|CodeQL 智能构建|LLM 语言决策 + 分语言构建编排 + 多语言构建成功率提升|todo|2026-Q2|

---

## Phase 6.5 详细任务：code-audit 集成

### P6-03: 证据强度字段引入（P0）

|任务|描述|依赖|状态|
|---|---|---|---|
|P6-03|证据强度字段引入（集成防幻觉规则+覆盖率矩阵）|-|done|
|P6-03a|集成防幻觉规则到 LLM 验证流程|P6-03|done|
|P6-03b|判定依据：source/sink/entry point/数据流/PoC/跨引擎印证|P6-03a|done|
|P6-03c|[Suspicious] 类结果强制标记 speculative|P6-03b|done|

**实现文件**: `src/layers/l3_analysis/models.py:EvidenceStrength`, `src/layers/l3_analysis/evidence_calculator.py`

### P6-04: conditional/informational 细分（P1）

|任务|描述|依赖|状态|
|---|---|---|---|
|P6-04|conditional/informational 细分（集成污点分析模板+验证方法论）|P6-03|done|
|P6-04a|conditional 细分：conditional-strong / conditional-weak|P6-04|done|
|P6-04b|informational 细分：not_exploitable / speculative_signal / environmental_risk|P6-04a|done|
|P6-04c|规范化污点分析报告模板（Source/Propagation/Sink/Sanitizer/Exploitability）|P6-04|done|
|P6-04d|集成漏洞验证方法论到置信度评分|P6-04c|done|

**实现文件**: `src/layers/l3_analysis/models.py:ConditionalSubtype, InformationalSubtype`, `src/layers/l3_analysis/taint_report.py`

### P6-05: 术语重命名与规则库扩展（P2）

|任务|描述|依赖|状态|
|---|---|---|---|
|P6-05|术语重命名：Verified → Processed（同时扩展规则库）|P6-04|done|
|P6-05a|扩展 Sink/Source 危险函数库|P6-05|done|
|P6-05b|集成语言检查清单到规则库（Java/Python/Go/PHP/JS/Ruby/.NET/Rust/C++）|P6-05a|done|

**实现文件**: `src/layers/l3_analysis/sinks_sources/` (Python/Java registries)

### P6-06: Agent 覆盖率统计（P3）

|任务|描述|依赖|状态|
|---|---|---|---|
|P6-06|Agent 覆盖率统计（同时设计业务逻辑检测方法论）|P6-05|done|
|P6-06a|输出统计字段：total_files/scanned_files/skipped_files|P6-06|done|
|P6-06b|设计业务逻辑检测方法论 (D9 维度)|P6-06a|done|

**实现文件**: `src/layers/l3_analysis/rounds/models.py:CoverageStats`, `src/layers/l3_analysis/methodology/`

### P6-07: 目录分类与降权策略（P3）

|任务|描述|依赖|状态|
|---|---|---|---|
|P6-07|目录分类与降权策略|P6-06|done|
|P6-07a|新增目录分类：production_code/test_code/sample_code/fixture_code/challenge_code|P6-07|done|
|P6-07b|非生产代码降权处理（score_multiplier）|P6-07a|done|
|P6-07c|配置项支持自定义目录分类和降权因子|P6-07b|done|
|P6-07d|导入 WooYun 案例库作为漏洞模式参考|P6-07|done|

**实现文件**: `src/core/file_filtering.py:DirectoryClass, classify_directory, get_score_multiplier`, `src/layers/l3_analysis/models.py:Finding.directory_class`, `src/core/final_score.py:directory_multiplier`, `src/core/config/__init__.py:get_directory_classification_config`

### P6-13: CodeQL 稳定性加固（P0）

|任务|描述|依赖|状态|
|---|---|---|---|
|P6-13|CodeQL 稳定性加固（构建超时、pack 预检、suite 解析、多语言构建上下文）|-|done|
|P6-13a|修复 BuildExecutor 误用通用 timeout 导致的大项目提前超时|P6-13|done|
|P6-13b|query pack 不可用时提前失败，避免落入模糊的 analyze 失败|P6-13|done|
|P6-13c|query suite 解析优先选择最新已安装 pack 版本|P6-13|done|
|P6-13d|多语言扫描优先保留仓库根构建上下文，降低 monorepo 子目录建库失败率|P6-13|done|

**实现文件**: src/layers/l3_analysis/engines/codeql.py, tests/unit/test_l3/test_codeql_engine.py

### P6-14: CodeQL 条件启用 / Readiness Gating（P0）

|任务|描述|依赖|状态|
|---|---|---|---|
|P6-14|默认扫描下的 CodeQL readiness gating|-|done|
|P6-14a|设计快速 readiness probe，优先判断 CodeQL 能否短时间启动并进入扫描前期|P6-14|done|
|P6-14b|默认 full/base 扫描按 readiness 结果决定是否启用 CodeQL|P6-14a|done|
|P6-14c|显式强制请求 CodeQL 时绕过 gating|P6-14b|done|
|P6-14d|在结果中显式报告 gated/skipped/forced/executed 状态|P6-14c|done|

**实现文件**: src/layers/l3_analysis/engines/codeql.py, src/cli/main.py, tests/unit/test_l3/test_codeql_engine.py


### P6-15: 稳定性与打包缺陷修复（P0）

|任务|描述|依赖|状态|
|---|---|---|---|
|P6-15|修复仓库审查发现的稳定性与打包缺陷|-|done|
|P6-15a|修复 agent 在多语言项目中的文件扩展名提取错误|P6-15|done|
|P6-15b|修复 threat-intel CLI 同步包装器污染全局 event loop 状态|P6-15|done|
|P6-15c|修复 Python 3.12 下增量分析测试夹具的 event loop 脆弱性|P6-15b|done|
|P6-15d|补齐缺失的 README 以满足 pyproject 打包元数据|P6-15|done|

**实现文件**: src/cli/main.py, src/cli/intel.py, tests/unit/test_l3/test_incremental.py, README.md

### P6-16: Readiness Gate 自动修复机制（P0）

|任务|描述|依赖|状态|
|---|---|---|---|
|P6-16|Readiness Gate 自动修复：尽量构建环境而非跳过|-|done|
|P6-16a|Query Pack 未安装时自动调用 `_ensure_query_pack` 下载|P6-16|done|
|P6-16b|构建工具缺失时集成 RuntimeVersionManager 自动安装|P6-16, P8-01|done|
|P6-16c|移除 docker-compose-tun.yml 空代理环境变量（修复 Semgrep）|P6-16|done|
|P6-16d|增强 Readiness Gate 日志，显示自动修复操作|P6-16a,b,c|done|

**实现文件**: `src/layers/l3_analysis/engines/codeql.py`, `src/layers/l3_analysis/readiness_gate.py`, `docker-compose-tun.yml`
**完成日期**: 2026-04-01
**提交**: 51f58a6

### P6-08~P6-12: 覆盖率矩阵与测试

|任务|描述|依赖|状态|
|---|---|---|---|
|P6-08|多语言覆盖矩阵|P6-07|done|
|P6-08a|language x engine x dimension x status 矩阵数据结构|P6-08|done|
|P6-09|结果状态模型测试|P6-01|done|
|P6-10|噪声分层测试|P6-04|done|
|P6-11|覆盖率表达测试|P6-06|done|
|P6-12|目录分类测试|P6-07|done|

**实现文件**: `src/layers/l3_analysis/coverage/matrix.py`, `src/layers/l3_analysis/coverage/evaluator.py`

---

## Phase 7 详细任务：CodeQL 智能决策与分语言构建编排

> 目标：通过 LLM 智能决策、项目构建画像、工具兼容性判定和分语言执行策略，显著提升 CodeQL 多语言扫描成功率，降低扫描时间

### 目标效果

| 语言 | 当前成功率 | 目标成功率 |
|------|------------|------------|
| Python | 95% | 99% |
| JavaScript/TypeScript | 95% | 99% |
| Java | 60% | 85% |
| Go | 70% | 90% |
| C/C++ | 30% | 70% |

### P7-01: LLM 智能语言决策（P0）

|任务|描述|依赖|状态|
|---|---|---|---|
|P7-01|LLM 驱动的 CodeQL 语言选择决策器|-|done|
|P7-01a|设计 LanguageDecisionInput 数据结构（语言结构/模块摘要/攻击面/Semgrep结果/构建难度）|P7-01|done|
|P7-01b|实现 LLM 决策 Prompt 模板（安全优先/效率平衡/风险聚焦原则）|P7-01a|done|
|P7-01c|实现 CodeQLLanguageDecider 类（调用 LLM 获取语言推荐列表）|P7-01b|done|
|P7-01d|实现时间预算机制（确保总扫描时间在限制内）|P7-01c|done|
|P7-01e|添加决策结果解析与验证逻辑|P7-01d|done|
|P7-01f|实现 deterministic baseline，作为回退与效果对照|P7-01e|done|

**实现文件**: `src/layers/l3_analysis/decision/__init__.py`, `src/layers/l3_analysis/decision/models.py`, `src/layers/l3_analysis/decision/language_decider.py`, `src/layers/l3_analysis/decision/prompts.py`, `src/layers/l3_analysis/decision/build_assessor.py`, `tests/unit/test_l3/test_decision.py`

### P7-02: 构建难度评估器（P0）

|任务|描述|依赖|状态|
|---|---|---|---|
|P7-02|各语言的构建难度评估机制|P7-01|partial|
|P7-02a|定义 BuildDifficulty 数据结构（level/estimated_time/blockers）|P7-02|done|
|P7-02b|实现 Python/JS/TS 难度评估（默认轻构建/免构建，支持升级条件）|P7-02a|done|
|P7-02c|实现 Java 难度评估（medium，检测 pom.xml/build.gradle/JDK版本）|P7-02a|partial|
|P7-02d|实现 Go 难度评估（medium，检测 go.mod/cgo/private module 风险）|P7-02a|partial|
|P7-02e|实现 C/C++ 难度评估（hard，检测构建系统/依赖复杂度/compile_commands 可用性）|P7-02a|partial|
|P7-02f|集成到 LLM 决策流程作为输入|P7-02c,d,e|done|

**实现文件**: `src/layers/l3_analysis/decision/build_assessor.py`（基础版已在 P7-01 实现，P7-02 需增强版本检测）

### P7-03: 项目构建画像与版本推断（P0）

|任务|描述|依赖|状态|
|---|---|---|---|
|P7-03|仓库级项目构建画像与环境需求推断|-|done|
|P7-03a|实现 ModuleDiscovery，识别 monorepo/子模块/语言边界|P7-03|done|
|P7-03b|实现 BuildTargetExtractor，提取可构建单元和推荐入口|P7-03a|done|
|P7-03c|实现 VersionDetector 基础框架|P7-03|done|
|P7-03d|Java 版本检测：解析 pom.xml（maven.compiler.source/release）|P7-03c|done|
|P7-03e|Java 版本检测：解析 build.gradle（sourceCompatibility/toolchain）|P7-03c|done|
|P7-03f|Go 版本检测：解析 go.mod|P7-03c|done|
|P7-03g|Node 版本检测：解析 .nvmrc/package.json engines|P7-03c|done|
|P7-03h|实现项目配置解析器（devcontainer/CI配置/版本管理器配置）|P7-03c|todo|
|P7-03i|实现外部依赖可达性检查（私有 registry/submodule/系统依赖）|P7-03b|todo|

**实现文件**: `src/layers/l3_analysis/build/module_discovery.py`（已完成）, `src/layers/l3_analysis/build/target_extractor.py`（已完成）, `src/layers/l3_analysis/build/version_detector.py`（已完成）, `src/layers/l3_analysis/build/project_config.py`

### P7-04: 工具解析与兼容性判定（P0）

|任务|描述|依赖|状态|
|---|---|---|---|
|P7-04|发现已有工具并判断是否满足构建需求|P7-03|done|
|P7-04a|实现 ToolResolver（system/local cache/managed path）|P7-04|done|
|P7-04b|实现 CompatibilityChecker（版本匹配/能力匹配/缺失原因）|P7-04a|done|
|P7-04c|实现 ProvisionPolicy（strict/reuse-only/managed-cache）|P7-04b|done|
|P7-04d|支持本地预装缓存工具目录，但默认不联网下载|P7-04c|done|
|P7-04e|输出标准化 readiness/incompatibility 报告|P7-04b|done|

**实现文件**: `src/layers/l3_analysis/build/tool_resolver.py`

### P7-05: 构建计划生成与执行编排（P0）

|任务|描述|依赖|状态|
|---|---|---|---|
|P7-05|按构建单元生成 build plan 并受控执行|P7-03, P7-04|done|
|P7-05a|实现 BuildPlanGenerator（命令/超时/风险/回退策略）|P7-05|done|
|P7-05b|实现 BuildExecutor 统一封装（输出捕获/超时/错误分类）|P7-05a|done|
|P7-05c|实现结果缓存（探测结果/构建结果/失败分类）|P7-05a|done|
|P7-05d|实现标准化可解释输出（selected/skipped/failed reasons）|P7-05b|done|
|P7-05e|集成到 CodeQL 引擎的 scan 流程|P7-05d|done|

**实现文件**: `src/layers/l3_analysis/engines/codeql.py`, `src/cli/main.py`

### P7-06: Go/Java 标准构建支持（P1）

|任务|描述|依赖|状态|
|---|---|---|---|
|P7-06|优先支持标准构建入口明确的语言|P7-05|done|
|P7-06a|实现 Go module 构建策略（go.mod/go build ./...）|P7-06|done|
|P7-06b|实现 Java Maven 构建策略（wrapper 优先，compile/classes）|P7-06|done|
|P7-06c|实现 Java Gradle 构建策略（wrapper 优先，classes）|P7-06|done|
|P7-06d|针对 Go/Java 增强失败分类和跳过原因|P7-06a,b,c|done|

**实现文件**: `src/layers/l3_analysis/build/builders/go.py`, `src/layers/l3_analysis/build/builders/java.py`

### P7-07: Python/JS/TS 轻构建与免构建路径（P1）

|任务|描述|依赖|状态|
|---|---|---|---|
|P7-07|为动态/脚本语言提供默认轻路径|P7-05|done|
|P7-07a|实现 Python 免构建路径（源码+元数据+解释器要求）|P7-07|done|
|P7-07b|实现 JS/TS 免构建路径（源码+package/tsconfig/workspace）|P7-07|done|
|P7-07c|定义升级到真实构建的条件（代码生成/框架约束/alias/project references）|P7-07a,b|done|
|P7-07d|在需要时生成受控 build plan，而非默认安装依赖|P7-07c|done|

**实现文件**: `src/layers/l3_analysis/build/builders/python.py`, `src/layers/l3_analysis/build/builders/javascript.py`

### P7-08: C/C++ 标准构建系统支持（P1）

|任务|描述|依赖|状态|
|---|---|---|---|
|P7-08|仅支持标准构建系统，避免无边界猜测式构建|P7-05|done|
|P7-08a|实现 CppBuilder 基础框架|P7-08|done|
|P7-08b|实现现有 compile_commands.json 检测与验证|P7-08a|done|
|P7-08c|实现 CMake 导出策略（cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON）|P7-08a|done|
|P7-08d|实现 Makefile 保守策略（必要时结合 Bear/compiledb）|P7-08a|done|
|P7-08e|实现 header-only/无标准构建系统的跳过与说明|P7-08a|done|
|P7-08f|明确止损线：高风险场景直接跳过，不做无限回退|P7-08e|done|

**实现文件**: `src/layers/l3_analysis/build/builders/cpp.py`, `src/layers/l3_analysis/build/builders/__init__.py`, `tests/unit/test_l3/test_builders/test_cpp_builder.py`

### P7-09: Readiness Gate 与 CLI 集成（P0）

|任务|描述|依赖|状态|
|---|---|---|---|
|P7-09|增强现有 Readiness Gate 集成决策与构建编排|P7-01, P7-05|done|
|P7-09a|重构 _apply_codeql_readiness_gate 集成 LLM 决策器|P7-09|done|
|P7-09b|添加构建画像和兼容性报告到 Readiness Gate|P7-09a|done|
|P7-09c|更新 CLI 输出显示 selected/skipped/failed reasons|P7-09a|done|
|P7-09d|添加 --force-codeql-all 选项覆盖 LLM 决策|P7-09a|done|

**实现文件**: `src/layers/l3_analysis/readiness_gate.py`, `src/cli/main.py`

### P7-10: 基线策略、测试与效果评估（P1）

|任务|描述|依赖|状态|
|---|---|---|---|
|P7-10|验证 LLM 决策相对规则基线是否有净收益|P7-01~P7-09|done|
|P7-10a|实现 deterministic baseline（主语言优先/攻击面优先/Semgrep 优先）|P7-10|done|
|P7-10b|单元测试：LLM 决策器与结果解析|P7-10|done|
|P7-10c|单元测试：版本检测/工具兼容性/构建计划|P7-10|done|
|P7-10d|集成测试：多语言项目扫描|P7-10|done|
|P7-10e|评估指标：耗时、成功率、发现损失率|P7-10d|done|
|P7-10f|回归测试：确保不破坏现有功能|P7-10|done|

**实现文件**: `src/layers/l3_analysis/decision/models.py`, `src/layers/l3_analysis/decision/language_decider.py`, `src/layers/l3_analysis/readiness_gate.py`, `tests/unit/test_l3/test_decision.py`, `tests/unit/test_l3/test_version_detector.py`, `tests/unit/test_l3/test_tool_resolver.py`, `tests/integration/test_decision_e2e.py`

### P7-11a: 完整 Builder 集成与单元测试（P1）

|任务|描述|依赖|状态|
|---|---|---|---|
|P7-11a|扩展 BuildPlanGenerator 支持所有 5 种语言，添加单元测试|P7-05, P7-06, P7-07, P7-08|done|
|P7-11a-S1|扩展 BUILDER_LANGUAGES 包含 python/javascript/cpp|P7-11a|done|
|P7-11a-S2|创建 TestBuildPlanGeneratorWithAllBuilders 测试类|P7-11a-S1|done|
|P7-11a-S3|扩展 test_readiness_gate.py 添加 Builder 集成测试|P7-11a-S2|done|
|P7-11a-S4|运行完整测试套件验证覆盖率 >= 90%|P7-11a-S3|done|

**实现文件**: `src/layers/l3_analysis/build/build_plan.py`, `tests/unit/test_l3/test_build_plan.py`, `tests/unit/test_l3/test_readiness_gate.py`

### P7-11b 系列：Docker 集成测试（P2）

|任务|描述|依赖|状态|
|---|---|---|---|
|P7-11b-1|Python Docker 集成测试|P7-11a|done|
|P7-11b-2|JavaScript/TypeScript Docker 集成测试|P7-11a|done|
|P7-11b-3|Go Docker 集成测试|P7-11a|done|
|P7-11b-4|Java Docker 集成测试|P7-11a|done|
|P7-11b-5|C/C++ Docker 集成测试|P7-11a|done|

**实现文件**: `tests/integration/docker/`

### P8-01: 多版本运行时环境管理器（P0）

|任务|描述|依赖|状态|
|---|---|---|---|
|P8-01|运行时版本自动检测、安装和切换|-|done|
|P8-01-S1|创建 src/layers/l3_analysis/build/runtime/ 目录结构|P8-01|done|
|P8-01-S2|实现 RuntimeRegistry 运行时版本注册表|P8-01|done|
|P8-01-S3|实现 RuntimeInstaller 基础框架和各语言安装器|P8-01|done|
|P8-01-S4|实现 RuntimeSwitcher 环境变量切换|P8-01|done|
|P8-01-S5|实现 RuntimeVersionManager 统一管理|P8-01|done|
|P8-01-S6|修改 ProvisionPolicy 添加 AUTO_INSTALL|P8-01|done|
|P8-01-S7|修改 ReadinessGate 集成版本管理器|P8-01|done|
|P8-01-S12|单元测试覆盖|P8-01|done|

**实现文件**: `src/layers/l3_analysis/build/runtime/`, `tests/unit/test_l3/test_runtime/`

---

## 里程碑

|里程碑|交付物|能力描述|状态|日期|
|---|---|---|---|---|
|v0.1|L1|支持源码获取、技术栈识别、攻击面探测|done|2026-02|
|v0.2|+ Semgrep|支持模式匹配扫描|done|2026-02|
|v0.2.1|+ CodeQL|支持数据流分析|done|2026-02|
|v0.2.2|+ Agent|支持 AI 驱动深度审计|done|2026-02|
|v0.3|L3 完整|三引擎 + 多轮审计|done|2026-02|
|v0.4|精度重构|Rule Gating + 语言重构|done|2026-03|
|v0.5|裁决统一|Exploitability 主导裁决|done|2026-03-06|
|v0.6|精度深化|可利用性评估增强 + 调用图分析|done|2026-03-09|
|v0.7|报告可信度|结果边界清晰 + 噪声治理 + 覆盖率透明|in_progress|2026-03|
|v0.75|CodeQL 智能构建|LLM 决策 + 分语言构建编排 + 构建成功率提升|todo|2026-Q2|
|v0.8|企业稳定版|高精度、低误报、CI 可用|todo|2026-Q2|

---

## 当前焦点

|字段|值|
|---|---|
|**阶段**|Phase 6.6 - Readiness Gate 自动修复机制|
|**当前进度**|P6-16 已完成|
|**当前目标**|无活跃目标|
|**下一步**|等待下一个目标|
|**最近完成**|P6-16 (Readiness Gate 自动修复)|
|**重点模块**|src/layers/l3_analysis/engines/codeql.py, src/layers/l3_analysis/readiness_gate.py, docker-compose-tun.yml|

---

## 风险与依赖

### 技术依赖

|类型|描述|影响|状态|
|---|---|---|---|
|依赖|LLM API|高 - Agent 核心能力|待确认|
|依赖|Semgrep CLI|中|已安装|
|依赖|CodeQL CLI|中|已安装|
|依赖|Python 3.10+|高|已确认|

### 技术风险

|类型|描述|影响|状态|缓解措施|
|---|---|---|---|---|
|风险|规则误报爆炸|高|存在|引入 Rule Gating|
|风险|CodeQL 构建/分析失败|高|存在|Phase 7: LLM 决策 + 构建画像 + 分语言执行策略|
|风险|confirmed/不可利用冲突|高|存在|统一裁决模型|
|风险|多语言误匹配|高|存在|主语言识别|
|风险|C/C++ 构建复杂|高|存在|Phase 7: 仅支持标准构建系统 + 明确止损线|
|风险|工具版本不匹配|中|存在|Phase 7: 版本检测 + 工具兼容性判定|
|风险|LLM 决策收益不稳定|中|新增|Phase 7: deterministic baseline 对照评估|

---

## 性能目标

|指标|目标值|说明|
|---|---|---|
|单项目分析耗时|< 45min|100K LOC|
|误报率|< 20%|v0.5 目标|
|confirmed 与 exploitability 冲突|0|强制规则|
|markdown 被扫描|0|文件级过滤|
|单规则爆炸率|自动抑制|Finding Budget|
|CodeQL Java 构建成功率|> 85%|Phase 7 目标|
|CodeQL C/C++ 构建成功率|> 70%|Phase 7 目标（仅标准构建系统）|
|多语言项目扫描时间|降低 40%|Phase 7: LLM 智能选择语言|
|策略解释覆盖率|100%|每个 selected/skipped 语言都有明确原因|

---

## 核心设计理念

1. **攻击面驱动扫描**：规则执行由项目真实特征决定
2. **Exploitability 优先裁决**：不可利用不允许标记 confirmed
3. **规则前置裁剪**：禁止规则误报爆炸
4. **语义级去重**：基于 AST 而非行号
5. **精度优先于召回**
6. **LLM 智能决策**（Phase 7）：让 LLM 决定最优扫描策略，平衡安全收益与资源消耗
7. **分语言构建编排**（Phase 7）：按语言类型选择轻路径、标准构建或高风险跳过
8. **解释优先于猜测**（Phase 7）：所有选择、跳过和失败都必须给出结构化原因
