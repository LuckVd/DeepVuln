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

### P6-17: 两阶段混合去重策略（P0）

|任务|描述|依赖|状态|
|---|---|---|---|
|P6-17|两阶段混合去重：位置聚类 + LLM 判断|-|done|
|P6-17a|位置聚类实现：按 file_path + line_range 分组|P6-17|done|
|P6-17b|LLM 判断实现：判断聚类内 findings 是否重复|P6-17a|done|
|P6-17c|保留策略实现：保留 final_score 最高的|P6-17b|done|
|P6-17d|集成到 adjudication：替换 ASTDeduplicator|P6-17c|done|
|P6-17e|单元测试：覆盖核心逻辑|P6-17d|done|
|P6-17f|集成测试：验证跨引擎去重效果|P6-17d|done|

**实现文件**: `src/layers/l3_analysis/deduplicator.py`, `src/layers/l3_analysis/adjudication.py`, `tests/integration/test_deduplication.py`
**完成日期**: 2026-04-01
**目标**: 解决不同引擎 rule_id 不同导致的跨引擎去重失效问题

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

### Phase 8: AST Engine 与代码图构建

> **目标**：构建语句级别的代码理解能力，与 Call Graph 形成互补，为 AI Agent 提供结构化上下文

#### 核心价值

| 维度 | 说明 |
|------|------|
| **能力补充** | AST（语句级） + Call Graph（函数级） + Dataflow（数据流级） |
| **AI 协同** | 结构化代码上下文 → 更稳定的 AI 推理 |
| **最终目标** | Code Property Graph (CPG) → 攻击路径自动发现 |

#### 架构定位

```
Multi Engine Scan
├─ Semgrep      → Pattern 匹配
├─ CodeQL       → 数据流分析
├─ AST Engine   → 结构级代码理解 ← 新增
└─ Agent        → 业务逻辑分析

                    ↓
            Code Graph Builder
                    ↓
            Finding Graph + Vuln Chaining
```

#### 与现有组件的关系

| 现有组件 | 位置 | 与 AST Engine 的关系 |
|----------|------|---------------------|
| Call Graph | `src/layers/l3_analysis/call_graph/models.py` | 复用 `CallNode`, `CallEdge`, `CallGraph` 数据结构 |
| tree-sitter | `src/layers/l1_intelligence/attack_surface/ast/` | 复用 `ASTDetector` 基类和语言加载器 |
| BaseEngine | `src/layers/l3_analysis/engines/base.py` | AST Engine 继承此基类 |

---

### P8-02: AST Engine 基础设施（P0）

|任务|描述|依赖|状态|
|---|---|---|---|
|P8-02|AST Engine 核心架构与基础设施|-|done|
|P8-02a|创建引擎目录结构与 ast_engine.py 基类（继承 BaseEngine）|P8-02|done|
|P8-02b|实现 TreeSitterManager（复用 L1 language_loader）|P8-02a|done|
|P8-02c|实现 QueryEngine（封装 tree-sitter query）|P8-02b|done|
|P8-02d|集成到 engine_registry，实现 scan() 接口|P8-02c|done|
|P8-02e|单元测试：parser + query engine|P8-02d|done|

**实现文件**:
- `src/layers/l3_analysis/engines/ast_engine/__init__.py`
- `src/layers/l3_analysis/engines/ast_engine/ast_engine.py`
- `src/layers/l3_analysis/engines/ast_engine/parser/tree_sitter_manager.py`
- `src/layers/l3_analysis/engines/ast_engine/queries/query_engine.py`
- `tests/unit/test_l3/test_ast_engine/`

**关键设计**:
```python
class ASTEngine(BaseEngine):
    """AST-based structural vulnerability detection engine"""
    name = "ast_engine"
    supported_languages = ["python", "javascript", "java", "go"]

    async def scan(self, source_path: Path, **options) -> ScanResult:
        # 1. Parse source code with tree-sitter
        # 2. Run AST queries
        # 3. Generate findings
        pass
```

---

### P8-03: 结构型漏洞检测器（P0）

|任务|描述|依赖|状态|
|---|---|---|---|
|P8-03|结构型漏洞检测器实现|P8-02|done|
|P8-03a|BaseDetector 抽象类与检测框架|P8-03|done|
|P8-03b|DangerousAPIDetector（eval/exec/system/os.system）|P8-03a|done|
|P8-03c|CryptoMisuseDetector（md5/sha1/DES/ECB）|P8-03a|done|
|P8-03d|DeserializationDetector（pickle/yaml/marshal）|P8-03a|done|
|P8-03e|单元测试：各检测器覆盖核心场景|P8-03d|done|

**实现文件**:
- `src/layers/l3_analysis/engines/ast_engine/detectors/base_detector.py`
- `src/layers/l3_analysis/engines/ast_engine/detectors/dangerous_api_detector.py`
- `src/layers/l3_analysis/engines/ast_engine/detectors/crypto_detector.py`
- `src/layers/l3_analysis/engines/ast_engine/detectors/deserialization_detector.py`
- `rules/ast_query/` (10 YAML 规则文件)
- `tests/unit/test_l3/test_detectors/`

**测试结果**: 16/16 通过
**完成日期**: 2026-04-04

**规则目录**:
```
rules/ast_query/
├── python/
│   ├── dangerous_eval.yaml
│   ├── crypto_weak_hash.yaml
│   ├── deserialization.yaml
│   └── subprocess_shell_true.yaml
├── javascript/
│   ├── dangerous_eval.yaml
│   └── crypto_weak_hash.yaml
└── java/
    ├── runtime_exec.yaml
    └── deserialization.yaml
```

**检测能力**:
| 类别 | 检测模式 | 示例 |
|------|----------|------|
| 危险 API | `eval($X)`, `exec($X)`, `os.system($X)` | 代码注入 |
| 加密误用 | `hashlib.md5()`, `Crypto.Cipher.ARC4` | 弱加密 |
| 反序列化 | `pickle.load()`, `yaml.load()` | RCE |
| 参数检测 | `subprocess.Popen(..., shell=True)` | 命令注入 |

---

### P8-04: AST Graph Builder（P1）

|任务|描述|依赖|状态|
|---|---|---|---|
|P8-04|AST Graph 构建与图分析 (选项A: 简单图构建)|P8-02|done|
|P8-04a|定义 ASTNode/ASTEdge 数据结构（简化版）|P8-04|done|
|P8-04b|实现 ASTGraphBuilder（遍历 AST 生成图）|P8-04a|done|
|P8-04c|实现基础图索引（文件/类型）|P8-04b|done|
|P8-04d|基础查询接口（get_node/get_children/get_nodes_by_type）|P8-04c|done|
|P8-04e|单元测试：图构建与查询|P8-04d|done|

**实现文件**:
- `src/layers/l3_analysis/engines/ast_engine/graph/models.py`
- `src/layers/l3_analysis/engines/ast_engine/graph/builder.py`

**数据结构 (选项A - 简化版)**:
```python
@dataclass
class ASTNode:
    id: str              # 唯一标识
    type: str            # call_expression, identifier, etc.
    name: str            # 节点名称
    file: str            # 文件路径
    line: int            # 行号
    parent_id: str | None = None
    children: list[str]  # 子节点 ID

@dataclass
class ASTGraph:
    nodes: dict[str, ASTNode]
    file_index: dict[str, list[str]]  # file -> [node_ids]
    type_index: dict[str, list[str]]  # type -> [node_ids]
```

**技术决策**:
- 选项 A (简单图构建): 基础节点/边 + 简单遍历
- 实际代码量: ~360 行
- **升级评估**: P8-05 时评估是否需要升级到选项 B (完整图系统)

**测试结果**: 23/23 通过
**完成日期**: 2026-04-04

---

### P8-05: 与 Call Graph 桥接（P1）

|任务|描述|依赖|状态|
|---|---|---|---|
|P8-05|AST Graph 与 Call Graph 融合|P8-04|done|
|P8-05a|评估 P8-04 升级需求（选项A→B）|P8-04|done|
|P8-05b|实现 GraphBridge（连接两种图）|P8-05a|done|
|P8-05c|统一查询接口（跨图遍历）|P8-05b|done|
|P8-05d|集成测试：端到端图查询|P8-05c|done|

**P8-05 完成总结** (2026-04-04):
- ✅ **实现文件**: `bridge.py` (~370 行), `unified.py` (~500 行)
- ✅ **测试结果**: 58/58 测试通过（14 + 18 + 23 + 3）
- ✅ **核心功能**:
  - `GraphBridge`: 跨图导航（AST ↔ Call Graph）
  - `UnifiedGraphQuery`: 统一查询接口（sink 检测、可达性、上下文）
  - `DANGEROUS_SINKS`: 6 类漏洞模式（code_injection, command_injection, sql_injection, path_traversal, deserialization, weak_crypto）
- ✅ **设计决策**: 保持选项 A，基于 tree-sitter 父子关系，完全准确

**P8-05c 实现总结** (2026-04-04):
- ✅ **实现文件**: `src/layers/l3_analysis/engines/ast_engine/graph/unified.py`
- ✅ **测试结果**: 18/18 单元测试通过
- ✅ **核心方法**:
  - `find_all_sinks()` - 查找所有危险 sink
  - `find_reachable_sinks()` - 从入口点到可达 sink 的路径
  - `get_function_context()` - 获取位置的完整上下文
  - `get_attack_paths()` - 获取完整攻击路径
- ✅ **支持模式**: code_injection, command_injection, sql_injection, path_traversal, deserialization, weak_crypto

**P8-05b 实现总结** (2026-04-04):
- ✅ **实现文件**: `src/layers/l3_analysis/engines/ast_engine/graph/bridge.py`
- ✅ **测试结果**: 14/14 单元测试通过
- ✅ **核心方法**:
  - `find_containing_function()` - AST → Call Graph（向上遍历 parent_id）
  - `find_ast_nodes_in_function()` - Call Graph → AST（向下遍历子树）
  - `trace_to_sink()` - 端到端路径追踪
- ✅ **准确性**: 基于 tree-sitter 父子关系，完全准确

**P8-05a 评估结果** (2026-04-04):
- ✅ **结论**: 保持选项 A，直接实现桥接
- ✅ **理由**: 坐标匹配 + 文件索引已满足基础桥接需求
- ✅ **代码量**: ~360 行，测试覆盖完整（23/23 通过）

**升级评估检查点**:
- [x] 当前 AST Graph 是否满足桥接需求？→ **是**
- [x] 是否需要更多边类型 (CALL/ARGUMENT/REFERENCE)？→ **否，基础桥接不需要**
- [x] 是否需要路径查询和可达性分析？→ **否，Call Graph 已提供**

**选项 B 升级触发条件** (满足任一即考虑升级):
1. 需要在 AST Graph 内进行可达性分析（跨语句数据流）
2. 需要跨函数的数据流追踪（如参数污点分析）
3. 需要复杂的图模式查询（如"找到所有调用了 eval 的 lambda"）
4. 发现选项 A 导致性能瓶颈或功能限制

**桥接策略**:
```
HTTP Endpoint (Call Graph)
    ↓
    handler_function (Call Graph)
    ↓
    function_calls (Call Graph)
    ↓
    dangerous_api (AST Graph) ← 语句级精确匹配
```

---

### P8-06: AI Agent 结构化上下文（P1）

|任务|描述|依赖|状态|
|---|---|---|---|
|P8-06|为 AI Agent 提供 AST 结构化上下文|P8-04|done|
|P8-06a|实现 ContextExtractor（提取 AST 结构）|P8-06|done|
|P8-06b|增强 Agent Prompt（包含结构化信息）|P8-06a|done|
|P8-06c|集成测试：AI 推理精度验证|P8-06b|done|

**P8-06 实现总结** (2026-04-04):
- ✅ **实现文件**: `src/layers/l3_analysis/engines/ast_engine/context/extractor.py`
- ✅ **测试结果**: 11/11 单元测试通过
- ✅ **核心功能**:
  - `ASTContextExtractor`: 提取 AST 结构化上下文
  - `ASTContext`: 上下文数据结构（code_snippet, ast_structure, parent_context, risk_analysis）
  - 风险分析：支持 6 类危险函数检测（code_injection, command_injection, sql_injection, path_traversal, deserialization, weak_crypto）
- ✅ **集成点**:
  - `build_audit_prompt()` 添加 `ast_context` 参数
  - `OpenCodeAgent._analyze_single_file()` 集成 AST 提取
- ✅ **Prompt 增强**: AST Structure Analysis 部分自动添加到 AI prompt

**上下文格式**:
```json
{
  "code_snippet": "eval(user_input)",
  "ast_structure": {
    "type": "call_expression",
    "function": "eval",
    "arguments": [{
      "type": "identifier",
      "name": "user_input"
    }]
  },
  "risk_analysis": {
    "sink_type": "code_execution",
    "confidence": 0.95
  }
}
```

---

### P8-07: 规则库扩展（P2）

|任务|描述|依赖|状态|
|---|---|---|---|
|P8-07|扩展 AST Query 规则库|P8-03|done|
|P8-07a|Python 规则：框架误用（Flask/Django/FastAPI）|P8-07|done|
|P8-07b|JavaScript 规则：原型污染/模板注入|P8-07|done|
|P8-07c|Java 规则：反射/JNI 误用|P8-07|done|
|P8-07d|Go 规则：context/defer 误用|P8-07|done|

**P8-07 实现总结** (2026-04-04):
- ✅ **实现文件**:
  - `src/layers/l3_analysis/engines/ast_engine/detectors/framework_detector.py`
  - `rules/ast_query/framework/` (13 YAML 规则文件)
  - `tests/unit/test_l3/test_ast_engine/test_framework_detector.py`
- ✅ **测试结果**: 19/19 单元测试通过
- ✅ **框架规则覆盖**:
  - **Flask** (4): render_template_string, secret_key_hardcoded, allow_all_hosts, redirect_user_input
  - **Django** (2): render_xss, extra_raw_sql
  - **FastAPI** (1): corp_auto_origin (CORS)
  - **Express** (2): prototype_pollution_merge, template_injection_ejs
  - **Java** (2): reflection_class_forname, jni_register_natives
  - **Go** (2): context_without_deadline, defer_close_file
- ✅ **检测能力**:
  - SSTI (模板注入) - Flask render_template_string, EJS
  - 硬编码密钥 - Flask SECRET_KEY
  - 开放重定向 - Flask redirect
  - XSS - Django render
  - SQL 注入 - Django extra/raw SQL
  - CORS 配置错误 - FastAPI
  - 原型污染 - Object.assign
  - 反射误用 - Java Class.forName
  - JNI 风险 - Java registerNatives
  - 资源泄漏 - Go defer in loop
  - DoS 风险 - Go context without deadline

---

### P8-08: 前置防误报架构（P0）✅ 完成

> **核心理念**: 防误报应该**靠前进行**，在源头防止而非事后过滤
>
> **设计原则**:
> 1. **参考 code-audit skill** 的防幻觉规则 (`/opt/AI/code-audit/SKILL.md`, `agent.md`)
> 2. **去重前置** - 在 Agent 产生 findings 时立即去重，而非等待后期处理
> 3. **误报前置** - 在扫描各阶段设置门槛，减少进入下一阶段的数据量
> 4. **节省资源** - 减少不必要的 LLM 调用和对抗验证

**完成日期**: 2026-04-05

**问题背景**:
- 当前误报率 ~40%，其中 Agent ~50%，CodeQL ~80%
- 重复检测率 ~46%（同一漏洞在调用链不同层级被多次检测）
- 大量资源浪费在处理明显的误报上（LLM 调用、对抗验证、Token 消耗）

**预期效果**:
| 指标 | 当前 | 预期 | 改善 |
|------|------|------|------|
| Agent 误报率 | ~50% | ~25% | **-50%** |
| CodeQL 误报率 | ~80% | ~40% | **-50%** |
| 重复检测率 | ~46% | ~20% | **-56%** |
| 对抗验证减少 | - | ~40% | **节省 40% 资源** |

#### P8-08a: 文件级预过滤器（P0）✅

|任务|描述|依赖|状态|
|---|---|---|---|
|P8-08a|文件级预过滤器 - 扫描前判断文件是否值得分析|-|done|
|P8-08a-S1|创建 FilePreFilter 模块|P8-08a|done|
|P8-08a-S2|跳过配置文件、测试文件、生成代码|P8-08a-S1|done|
|P8-08a-S3|跳过只有常量/定义的文件（无可执行代码）|P8-08a-S1|done|
|P8-08a-S4|检查攻击面可达性（Call Graph 验证）|P8-08a-S1|done|
|P8-08a-S5|单元测试：覆盖所有过滤条件|P8-08a-S4|done|

**实现文件**: `src/layers/l3_analysis/pre_filter/file_pre_filter.py`
**测试结果**: 36/36 单元测试通过

#### P8-08b: Agent Prompt 增强 - 防幻觉规则（P0）✅

|任务|描述|依赖|状态|
|---|---|---|---|
|P8-08b|集成 code-audit skill 的防幻觉规则到 Agent Prompt|P8-08a|done|
|P8-08b-S1|读取并解析 `/opt/AI/code-audit/SKILL.md` 和 `agent.md`|P8-08b|done|
|P8-08b-S2|提取 Anti-Hallucination Rules 核心内容|P8-08b-S1|done|
|P8-08b-S3|添加 Execution Evidence Requirements（执行证据要求）|P8-08b-S2|done|
|P8-08b-S4|添加 Few-Shot Examples（正反例对比）|P8-08b-S2|done|
|P8-08b-S5|修改 `security_audit.py` 中的 `build_audit_prompt()`|P8-08b-S4|done|
|P8-08b-S6|测试验证 Prompt 增强效果|P8-08b-S5|done|

**实现文件**:
- `src/layers/l3_analysis/prompts/enhanced_audit_prompt.py`
- `src/layers/l3_analysis/prompts/security_audit.py` (修改)

#### P8-08c: Finding 流式验证（P0）✅

|任务|描述|依赖|状态|
|---|---|---|---|
|P8-08c|Finding 流式验证 - 在产生 finding 时立即验证|P8-08b|done|
|P8-08c-S1|创建 StreamingValidator 模块|P8-08c|done|
|P8-08c-S2|检查执行证据（has_execution_evidence）|P8-08c-S1|done|
|P8-08c-S3|置信度合理性校准（高置信度需要强证据）|P8-08c-S1|done|
|P8-08c-S4|配置问题分离（Dockerfile、配置文件）|P8-08c-S1|done|
|P8-08c-S5|集成到 `_parse_llm_response()` - 即时过滤|P8-08c-S4|done|
|P8-08c-S6|单元测试：覆盖各种误报模式|P8-08c-S5|done|

**实现文件**: `src/layers/l3_analysis/pre_filter/streaming_validator.py`
**测试结果**: 14/14 单元测试通过

#### P8-08d: CodeQL 预过滤器（P1）✅

|任务|描述|依赖|状态|
|---|---|---|---|
|P8-08d|CodeQL 预过滤器 - 在扫描前调整规则|P8-08a|done|
|P8-08d-S1|创建 CodeQLPreFilter 模块|P8-08d|done|
|P8-08d-S2|根据项目类型调整规则置信度|P8-08d-S1|done|
|P8-08d-S3|降低泛化规则（如 XSS）默认置信度|P8-08d-S1|done|
|P8-08d-S4|响应类型检测（JSON vs HTML）|P8-08d-S1|done|
|P8-08d-S5|集成到 `codeql.py` 扫描流程|P8-08d-S4|done|
|P8-08d-S6|测试验证 CodeQL 过滤效果|P8-08d-S5|done|

**实现文件**: `src/layers/l3_analysis/pre_filter/codeql_pre_filter.py`
**测试结果**: 19/19 单元测试通过

#### P8-08e: 去重前置（P0）✅

|任务|描述|依赖|状态|
|---|---|---|---|
|P8-08e|去重前置 - 在 Agent 产生 findings 时立即去重|P8-08c|done|
|P8-08e-S1|创建 InMemoryDeduplicator（内存级去重器）|P8-08e|done|
|P8-08e-S2|文件级去重（同一文件同一行号只保留最高分）|P8-08e-S1|done|
|P8-08e-S3|调用链去重（同一漏洞在不同层级只保留一个）|P8-08e-S1|done|
|P8-08e-S4|集成到 `_parse_llm_response()` - 去重后返回|P8-08e-S3|done|
|P8-08e-S5|与 P6-17 ClusterBasedDeduplicator 协同|P8-08e-S4|done|
|P8-08e-S6|单元测试：覆盖各种重复场景|P8-08e-S5|done|

**实现文件**: `src/layers/l3_analysis/pre_filter/in_memory_deduplicator.py`
**测试结果**: 19/19 单元测试通过

#### P8-08f: 对抗验证准入门槛（P1）✅

|任务|描述|依赖|状态|
|---|---|---|---|
|P8-08f|对抗验证准入门槛 - 只验证真正不确定的|P8-08e|done|
|P8-08f-S1|创建 VerificationGatekeeper 模块|P8-08f|done|
|P8-08f-S2|低置信度+低严重级 → 跳过对抗验证|P8-08f-S1|done|
|P8-08f-S3|明显误报模式 → 自动拒绝|P8-08f-S1|done|
|P8-08f-S4|强证据+高置信度 → 自动确认|P8-08f-S1|done|
|P8-08f-S5|集成到 `enhanced_adversarial.py`|P8-08f-S4|done|
|P8-08f-S6|测试验证准入门槛效果|P8-08f-S5|done|

**实现文件**: `src/layers/l3_analysis/verification/verification_gatekeeper.py`
**测试结果**: 21/21 单元测试通过

#### P8-08g: 集成测试与效果评估（P1）✅

|任务|描述|依赖|状态|
|---|---|---|---|
|P8-08g|集成测试与效果评估|P8-08f|done|
|P8-08g-S1|端到端测试：扫描测试项目|P8-08g|done|
|P8-08g-S2|对比误报率变化（前后对比）|P8-08g-S1|done|
|P8-08g-S3|对比资源消耗（Token、时间）|P8-08g-S1|done|
|P8-08g-S4|调优参数（置信度阈值、过滤规则）|P8-08g-S3|done|
|P8-08g-S5|文档更新：架构设计、使用指南|P8-08g-S4|done|

**实现文件**: `tests/integration/test_pre_filter/test_e2e.py`
**测试结果**: 16/16 集成测试通过

#### P8-08h: 修复 P6-17 LLM 去重解析（P0）✅

|任务|描述|依赖|状态|
|---|---|---|---|
|P8-08h|修复 P6-17 ClusterBasedDeduplicator 的 LLM 解析失败|P8-08e|done|
|P8-08h-S1|增强 JSON 解析容错（处理 GLM-5 格式）|P8-08h|done|
|P8-08h-S2|处理 reasoning_content 字段|P8-08h-S1|done|
|P8-08h-S3|添加降级策略（LLM 失败时的回退逻辑）|P8-08h-S2|done|
|P8-08h-S4|测试验证去重效果|P8-08h-S3|done|

**实现文件**: `src/layers/l3_analysis/deduplicator.py` (修改)
**测试结果**: 7/7 单元测试通过

#### P8-08 测试结果汇总

| 组件 | 单元测试 | 集成测试 |
|------|----------|----------|
| FilePreFilter | 36/36 ✅ | - |
| StreamingValidator | 14/14 ✅ | - |
| CodeQLPreFilter | 19/19 ✅ | - |
| InMemoryDeduplicator | 19/19 ✅ | - |
| VerificationGatekeeper | 21/21 ✅ | - |
| **总计** | **109/109** ✅ | **16/16** ✅ |

---

### P8-09: CPG 基础（Phase 2，P3）

```
src/layers/l3_analysis/pre_filter/
├── __init__.py
├── file_pre_filter.py          # P8-08a: 文件级预过滤
├── streaming_validator.py      # P8-08c: Finding 流式验证
├── codeql_pre_filter.py        # P8-08d: CodeQL 预过滤
├── in_memory_deduplicator.py    # P8-08e: 去重前置
└── config.py                   # 配置参数

src/layers/l3_analysis/prompts/
├── enhanced_audit_prompt.py    # P8-08b: 增强审计 Prompt
└── security_audit.py           # 修改：集成防幻觉规则

src/layers/l3_analysis/verification/
└── verification_gatekeeper.py  # P8-08f: 对抗验证门槛

tests/unit/test_l3/test_pre_filter/
├── test_file_pre_filter.py
├── test_streaming_validator.py
├── test_codeql_pre_filter.py
├── test_in_memory_deduplicator.py
└── test_verification_gatekeeper.py
```

---

### P8-09: CPG 基础（Phase 2，P3）

|任务|描述|依赖|状态|
|---|---|---|---|
|P8-09|Code Property Graph 基础实现|P8-05|todo|
|P8-09a|融合 AST Graph + Call Graph|P8-09|todo|
|P8-09b|添加 CFG（控制流图）支持|P8-09a|todo|
|P8-09c|攻击路径搜索算法|P8-09b|todo|

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
|v0.75|CodeQL 智能构建|LLM 决策 + 分语言构建编排 + 构建成功率提升|in_progress|2026-03|
|v0.8|AST Engine|结构级代码理解 + Code Graph + AI 结构化上下文|in_progress|2026-04|
|v0.9|CPG 基础|完整代码图 + 攻击路径搜索|todo|2026-Q2|
|v1.0|企业稳定版|高精度、低误报、CI 可用|todo|2026-Q2|

---

## 当前焦点

|字段|值|
|---|---|
|**阶段**|Phase 8 - AST Engine 与代码图构建 + 前置防误报架构|
|**当前进度**|P8-07 已完成，准备启动 P8-08|
|**当前目标**|P8-08: 前置防误报架构 ⚠️ 高优先级|
|**开始日期**|2026-04-05|
|**下一步**|P8-08a: 文件级预过滤器（扫描前判断）|
|**最近完成**|P8-07 (规则库扩展), P8-06 (AI Agent 结构化上下文), P8-05 (Call Graph 桥接)|
|**重点模块**|src/layers/l3_analysis/pre_filter/ (新增)|
|**设计原则**|⚠️ **防误报靠前**，参考 code-audit skill，节省资源|

---

## 风险与依赖

### 技术依赖

|类型|描述|影响|状态|
|---|---|---|---|
|依赖|LLM API|高 - Agent 核心能力|待确认|
|依赖|Semgrep CLI|中|已安装|
|依赖|CodeQL CLI|中|已安装|
|依赖|Python 3.10+|高|已确认|
|依赖|tree-sitter（已存在）|低|已集成在 L1|
|依赖|多语言 tree-sitter 语言包|中|Phase 8: 需要维护更新|

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
|风险|AST 解析性能|中|Phase 8: 并行解析 + 文件缓存|
|风险|大仓库内存占用|中|Phase 8: 增量解析 + LRU 缓存|
|风险|图构建复杂度|中|Phase 8: 分阶段实现，先简单后复杂|

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
