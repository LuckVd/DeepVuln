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
|Phase 6|报告可信度|结果边界清晰化 + 噪声治理 + 覆盖率透明|done|2026-03|
|Phase 6.5|code-audit 集成|防幻觉规则 + 覆盖率矩阵 + 污点分析模板 + 漏洞验证方法论|done|2026-03|
|Phase 6.6|Readiness Gate 自动修复|尽量构建环境而非跳过|done|2026-04|
|Phase 7|CodeQL 智能构建|LLM 语言决策 + 分语言构建编排 + 多语言构建成功率提升|done|2026-04|
|Phase 14|Web 完整能力迁移|攻击面检测 + 可利用性验证 + 去重仲裁 + 对抗性验证 + Token 统计 + 增量扫描增强|done|2026-04-09|

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
|P8-09|Code Property Graph 基础实现|P8-05|done|
|P8-09a|融合 AST Graph + Call Graph|P8-09|done|
|P8-09b|添加 CFG（控制流图）支持|P8-09a|done|
|P8-09c|攻击路径搜索算法|P8-09b|done|

**实现文件**:
- `src/layers/l3_analysis/engines/ast_engine/cpg/` (CPG 统一代码图)
- `src/layers/l3_analysis/engines/ast_engine/cfg/` (控制流图，4 种语言)
- `src/layers/l3_analysis/engines/ast_engine/path_finder/` (攻击路径搜索)
- `tests/unit/test_l3/test_cpg/`, `tests/unit/test_l3/test_cfg/`, `tests/unit/test_l3/test_path_finder/`

**测试结果**: 47 单元测试通过 (15 CPG + 18 CFG + 14 PathFinder)
**完成日期**: 2026-04-07
**多语言支持**: Python (完整) + JavaScript + Java + Go (框架)

---

### P9-01: CPG 与 Agent 标准集成（Phase 9，P0）

|任务|描述|依赖|状态|
|---|---|---|---|
|P9-01|CPG 与 Agent 标准集成|P8-09|done|
|P9-01a|CPGPathProvider 语言无关接口|P9-01|done|
|P9-01b|LanguageCPGProvider 抽象类|P9-01a|done|
|P9-01c|PythonCPGProvider 实现|P9-01b|done|
|P9-01d|JSCPGProvider 实现|P9-01b|done|
|P9-01e|Agent 集成 CPGPathProvider|P9-01c,d|done|
|P9-01f|Finding 数据模型扩展 (cpg_path 字段)|P9-01e|done|
|P9-01g|单元测试|P9-01f|done|
|P9-01h|集成测试 (端到端流程)|P9-01g|done|

**实现文件**:
- `src/layers/l3_analysis/engines/ast_engine/cpg/path_provider.py` (语言无关接口)
- `src/layers/l3_analysis/engines/ast_engine/cpg/base.py` (抽象基类)
- `src/layers/l3_analysis/engines/ast_engine/cpg/providers/python_provider.py` (Python 实现)
- `src/layers/l3_analysis/engines/ast_engine/cpg/providers/js_provider.py` (JavaScript 实现)
- `src/layers/l3_analysis/engines/opencode_agent.py` (Agent 集成)
- `src/layers/l3_analysis/models.py` (Finding.cpg_path 字段)
- `src/layers/l3_analysis/prompts/security_audit.py` (Prompt 增强)
- `tests/unit/test_l3/test_cpg/test_path_provider.py` (11 测试)
- `tests/unit/test_l3/test_cpg/test_python_provider.py` (11 测试)
- `tests/unit/test_l3/test_cpg/test_js_provider.py` (14 测试)
- `tests/integration/test_cpg_agent/test_e2e.py` (8 测试)

**测试结果**: 61/61 测试通过 (100%)
**完成日期**: 2026-04-07
**多语言支持**: Python + JavaScript/TypeScript

**核心特性**:
- **降级策略**: CPG 失败时 Agent 继续正常工作
- **语言无关接口**: 支持扩展到其他语言
- **Finding 扩展**: `cpg_path` 字段存储攻击路径元数据
- **路径匹配**: 自动将 Finding 匹配到最相关的 CPG 路径

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
|v0.7|报告可信度|结果边界清晰 + 噪声治理 + 覆盖率透明|done|2026-04|
|v0.75|CodeQL 智能构建|LLM 决策 + 分语言构建编排 + 构建成功率提升|done|2026-04|
|v0.8|AST Engine|结构级代码理解 + Code Graph + AI 结构化上下文 + 前置防误报|done|2026-04|
|v0.9|CPG 基础|完整代码图 + 攻击路径搜索 + Agent 集成|done|2026-04-07|
|v1.0|Web 基础版|高精度、低误报 + Web UI + 暂停续扫|done|2026-04-09|
|v1.1|Web 完整能力|攻击面检测 + 可利用性验证 + 去重仲裁 + 对抗性验证 + Token 统计|in_progress|2026-04-09|
|v1.5|企业稳定版|CI/CD 集成 + 多租户 + 用户认证 + 报告导出|todo|2026-Q2|

---

## Phase 10: Web 服务与持久化存储

> **目标**: 建立完整的 Web 服务，支持项目管理、扫描任务管理和结果持久化
> **交付物**: FastAPI 后端 + PostgreSQL 数据库 + RESTful API
> **状态**: 进行中 (50%) - P10-01/02/03/06 已完成

### P10-01: 数据库设计与迁移（P0）✅

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P10-01 | PostgreSQL 数据库设计 | - | done |
| P10-01a | 设计核心数据表 (projects/scans/findings/scan_phases/scan_files) | P10-01 | done |
| P10-01b | 设计索引和约束 | P10-01a | done |
| P10-01c | Alembic 迁移框架集成 | P10-01a | done |
| P10-01d | 创建初始迁移脚本 | P10-01b | done |
| P10-01e | 自动更新 updated_at 触发器 | P10-01d | done |

**数据表清单**:
```sql
-- projects: 项目信息
-- scans: 扫描任务
-- scan_phases: 扫描阶段状态 (用于续扫)
-- findings: 漏洞结果
-- scan_files: 文件扫描状态 (用于增量扫描)
-- api_keys: API 密钥管理
```

**实现文件**:
- `migrations/versions/001_init_schema.py` ✅
- `migrations/env.py` ✅
- `src/web/models/database.py` ✅

**测试结果**: 通过
**完成日期**: 2026-04-07

### P10-02: Pydantic 数据模型（P0）✅

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P10-02 | Pydantic 数据模型定义 | - | done |
| P10-02a | Project 系列模型 | P10-01 | done |
| P10-02b | Scan 系列模型 | P10-02a | done |
| P10-02c | Finding 系列模型 | P10-02a | done |
| P10-02d | Checkpoint 系列模型 | P10-02a | done |
| P10-02e | 请求/响应模型 | P10-02a | done |
| P10-02f | 枚举类型定义 (ScanStatus/ScanType/SeverityLevel/FindingStatus) | P10-02a | done |

**实现文件**:
- `src/web/models/project.py` ✅
- `src/web/models/scan.py` ✅
- `src/web/models/finding.py` ✅
- `src/web/models/checkpoint.py` ✅
- `src/web/models/schemas.py` ✅

**测试结果**: 25/25 通过 ✅

### P10-03: FastAPI 项目初始化（P0）✅

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P10-03 | FastAPI 应用框架搭建 | - | done |
| P10-03a | 项目目录结构创建 | P10-03 | done |
| P10-03b | 依赖安装 (fastapi/uvicorn/sqlalchemy/alembic) | P10-03a | done |
| P10-03c | 配置管理 (环境变量/Settings) | P10-03b | done |
| P10-03d | 数据库连接池配置 | P10-03c | done |
| P10-03e | 应用入口 (main.py) | P10-03d | done |
| P10-03f | CORS 中间件配置 | P10-03e | done |
| P10-03g | 生命周期管理 (startup/shutdown) | P10-03e | done |

**目录结构**:
```
src/web/
├── api/
│   ├── __init__.py
│   ├── deps.py                  # 依赖注入
│   └── v1/
│       ├── api.py               # 路由聚合
│       ├── projects.py          # 项目管理 API
│       └── scans.py             # 扫描管理 API
├── core/
│   ├── __init__.py
│   ├── database.py              # 数据库连接
│   ├── config.py                # 配置管理
│   └── security.py              # 认证授权
├── models/                       # Pydantic 模型
├── services/                     # 业务逻辑
└── main.py                       # FastAPI 应用
```

**实现文件**:
- `src/web/main.py` ✅
- `src/web/core/database.py` ✅
- `src/web/core/config.py` ✅
- `src/web/core/security.py` ✅

**测试结果**: 9/9 通过 ✅

### P10-04: 项目管理 API（P1）✅

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P10-04 | 项目管理 REST API | - | done |
| P10-04a | 创建项目 API | P10-03 | done |
| P10-04b | 列出项目 API (分页/过滤) | P10-04a | done |
| P10-04c | 获取项目详情 API | P10-04a | done |
| P10-04d | 更新项目 API | P10-04a | done |
| P10-04e | 删除项目 API | P10-04a | done |
| P10-04f | 项目扫描历史 API | P10-04a | done |

**API 端点**:
```
POST   /api/v1/projects          # 创建项目
GET    /api/v1/projects          # 列出项目
GET    /api/v1/projects/{id}     # 获取详情
PUT    /api/v1/projects/{id}     # 更新项目
DELETE /api/v1/projects/{id}     # 删除项目
GET    /api/v1/projects/{id}/scans # 扫描历史
```

**实现文件**:
- `src/web/api/v1/projects.py` ✅
- `tests/unit/test_web/api/test_projects.py` ✅

**测试结果**: 13/13 测试通过 (路由验证 + 请求验证 + 分页验证)
**完成日期**: 2026-04-07

### P10-05: 扫描任务 API（P0）✅

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P10-05 | 扫描任务管理 API | - | done |
| P10-05a | 创建扫描 API | P10-04 | done |
| P10-05b | 列出扫描 API | P10-05a | done |
| P10-05c | 获取扫描详情 API | P10-05a | done |
| P10-05d | 扫描进度查询 API | P10-05a | done |
| P10-05e | 漏洞结果查询 API | P10-05a | done |
| P10-05f | 扫描报告获取 API | P10-05a | done |
| P10-05g | Agent 对话 API | P10-05a | done |
| P10-05h | 阶段/事件流 API | P10-05a | done |

**API 端点**:
```
POST   /api/v1/scans                        # 创建扫描
GET    /api/v1/scans                        # 列出扫描
GET    /api/v1/scans/{id}                   # 获取详情
GET    /api/v1/scans/{id}/progress          # 获取进度
GET    /api/v1/scans/{id}/phases            # 获取阶段详情
GET    /api/v1/scans/{id}/events            # 获取事件流
GET    /api/v1/scans/{id}/agent-conversation # 获取 Agent 对话
GET    /api/v1/scans/{id}/current-file      # 获取当前处理文件
GET    /api/v1/scans/{id}/findings          # 获取漏洞
GET    /api/v1/scans/{id}/report            # 获取报告
```

**实现文件**:
- `src/web/api/v1/scans.py` ✅
- `tests/unit/test_web/api/test_scans.py` ✅

**测试结果**: 9/9 测试通过 (路由验证 + 请求验证 + 分页验证)
**完成日期**: 2026-04-07

### P10-06: 数据库 Repository 层（P1）✅

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P10-06 | 数据访问层实现 | - | done |
| P10-06a | ProjectRepository | P10-02 | done |
| P10-06b | ScanRepository | P10-06a | done |
| P10-06c | FindingRepository | P10-06a | done |
| P10-06d | ScanPhaseRepository | P10-06a | done |
| P10-06e | ScanEventRepository | P10-06a | done |
| P10-06f | 异步数据库会话管理 | P10-06a | done |

**实现文件**:
- `src/web/repositories/__init__.py` ✅
- `src/web/repositories/base.py` ✅
- `src/web/repositories/project.py` ✅
- `src/web/repositories/scan.py` ✅
- `src/web/repositories/finding.py` ✅
- `src/web/repositories/event.py` ✅ (ScanPhaseRepository + ScanEventRepository)

**测试结果**: 7/7 单元测试通过 ✅
**完成日期**: 2026-04-07

### P10-07: CLI 集成服务（P0）✅

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P10-07 | CLI 调用服务层 | - | done |
| P10-07a | Celery 依赖与配置 | P10-07 | done |
| P10-07b | Celery 扫描任务 | P10-07a | done |
| P10-07c | CLI 适配器 | P10-07b | done |
| P10-07d | 扫描执行器服务 | P10-07c | done |

**实现文件**:
- `pyproject.toml`: 添加 celery>=5.3.0, redis>=5.0.0
- `src/web/core/celery_app.py`: Celery 应用配置 (122 行)
- `src/web/tasks/scan_tasks.py`: Celery 扫描任务 (176 行)
- `src/web/services/cli_adapter.py`: CLI 适配器，解析 JSONL 输出 (494 行)
- `src/web/services/scan_executor.py`: 扫描执行器，生命周期管理 (482 行)
- `tests/unit/test_web/test_services.py`: 服务层单元测试 (14 测试)

**测试结果**: 78/78 通过 (64 原有 + 14 新增) ✅
**完成日期**: 2026-04-07

### P10-08: 基础 API 测试（P1）✅

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P10-08 | API 测试 | - | done |
| P10-08a | 项目 API 单元测试 | P10-04 | done |
| P10-08b | 扫描 API 单元测试 | P10-05 | done |
| P10-08c | Repository 层单元测试 | P10-06 | done |
| P10-08d | 集成测试 (API + DB) | P10-08a,b,c | todo |
| P10-08e | API 文档生成 (OpenAPI) | P10-03 | done |

**实现文件**:
- `tests/unit/test_web/api/test_projects.py` ✅
- `tests/unit/test_web/api/test_scans.py` ✅
- `tests/unit/test_web/repositories/` ✅
- `tests/integration/test_api/` ⏳ 待添加

**测试结果**: 23/23 API 单元测试通过
**完成日期**: 2026-04-07

---

## Phase 11: 暂停/续扫机制

> **目标**: 支持长时间扫描任务的暂停、续扫和取消，提升用户体验和资源利用率
> **状态**: ✅ 已完成 (2026-04-07)

### P11-01: 检查点服务（P0）✅

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P11-01 | 检查点管理服务 | - | done |
| P11-01a | 检查点数据结构定义 | P10-02 | done |
| P11-01b | 保存检查点 (文件 + 数据库) | P11-01a | done |
| P11-01c | 加载检查点 (验证完整性) | P11-01b | done |
| P11-01d | 检查点清理策略 | P11-01b | done |
| P11-01e | 检查点版本管理 | P11-01d | done |

**实现文件**:
- `src/web/services/checkpoint_service.py` (~400 行)
- `tests/unit/test_web/test_pause_resume.py` (15 测试)

**核心功能**:
- `CheckpointData`: 检查点数据模型 (scan_id, current_phase, phases, global_state, resume_data)
- `CheckpointService.save_checkpoint()`: 保存检查点到数据库和文件
- `CheckpointService.load_checkpoint()`: 加载并验证检查点
- `CheckpointService.verify_checkpoint()`: 验证检查点完整性
- `CheckpointService.get_resume_strategy()`: 计算续扫策略 (跳过已完成阶段)

### P11-02: 扫描阶段管理（P0）✅

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P11-02 | 扫描阶段状态管理 | - | done |
| P11-02a | 阶段枚举定义 | P11-01 | done |
| P11-02b | 阶段状态跟踪 | P11-02a | done |
| P11-02c | 阶段切换逻辑 | P11-02b | done |
| P11-02d | 阶段失败处理 | P11-02c | done |
| P11-02e | 阶段输出管理 | P11-02d | done |
| P11-02f | 阶段状态数据库记录 | P11-02e | done |

**实现文件**:
- `src/web/services/phase_manager.py` (~500 行)

**核心功能**:
- `VALID_TRANSITIONS`: 阶段状态转换规则 (pending→running→completed/failed)
- `PhaseManager.start_phase()`: 启动新阶段
- `PhaseManager.complete_phase()`: 完成阶段并记录输出
- `PhaseManager.fail_phase()`: 标记阶段失败
- `PhaseManager.skip_phase()`: 跳过阶段 (续扫时)
- `PhaseTransition`: 阶段转换结果数据结构

### P11-03: 扫描执行器（P0）✅

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P11-03 | 扫描执行器核心实现 | - | done |
| P11-03a | 异步执行流程控制 | P11-02 | done |
| P11-03b | 暂停信号处理 | P11-03a | done |
| P11-03c | 取消信号处理 | P11-03a | done |
| P11-03d | 续扫状态恢复逻辑 | P11-01, P11-03a | done |
| P11-03e | 阶段跳过逻辑 (续扫优化) | P11-03d | done |
| P11-03f | 进度更新机制 | P11-03a | done |
| P11-03g | 错误恢复与重试 | P11-03f | done |

**实现文件**:
- `src/web/services/scan_executor.py` (修改，添加 pause/resume/cancel 方法)

**新增方法**:
- `ScanExecutor.pause_scan()`: 暂停扫描，保存检查点
- `ScanExecutor.resume_scan()`: 恢复扫描，加载检查点并启动新 Celery 任务
- `ScanExecutor.cancel_scan()`: 取消扫描，清理资源

### P11-04: 暂停/继续/取消 API（P0）✅

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P11-04 | 扫描控制 API | - | done |
| P11-04a | 暂停扫描 API | P11-03 | done |
| P11-04b | 继续扫描 API | P11-04a | done |
| P11-04c | 取消扫描 API | P11-04a | done |
| P11-04d | 扫描状态转换逻辑 | P11-04a,b,c | done |
| P11-04e | 状态查询 API | P11-04d | done |

**API 端点**:
```
POST /api/v1/scans/{id}/pause    # 暂停扫描
POST /api/v1/scans/{id}/resume   # 继续扫描
POST /api/v1/scans/{id}/cancel   # 取消扫描
GET  /api/v1/scans/{id}/status   # 查询状态和可用操作
```

**实现文件**:
- `src/web/api/v1/scans.py` (修改，添加 4 个新端点)
- `src/web/models/schemas.py` (修改，添加 4 个响应模型)
- `tests/unit/test_web/api/test_control.py` (17 测试)

**新增响应模型**:
- `PauseScanResponse`: pause 扫描结果
- `ResumeScanResponse`: resume 扫描结果 (含 task_id, skip_phases)
- `CancelScanResponse`: cancel 扫描结果
- `ScanStatusResponse`: 状态查询结果 (available_actions, can_pause, can_resume, can_cancel)

### P11-05: 增量扫描支持（P1）✅

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P11-05 | 增量扫描功能 | - | done |
| P11-05a | Git 差异分析 | P11-05 | done |
| P11-05b | 文件哈希计算 | P11-05a | done |
| P11-05c | 变更文件分类 | P11-05b | done |
| P11-05d | 续扫策略计算 | P11-05c | done |
| P11-05e | CLI 集成 | P11-05d | done |

**实现文件**:
- `src/web/services/incremental_scan.py` (~400 行)
- `src/web/services/cli_adapter.py` (修改，添加增量分析)
- `tests/unit/test_web/test_incremental_scan.py` (25 测试)

**核心功能**:
- `GitUtils.get_changed_files()`: 获取 Git 差异 (支持 rename 检测)
- `FileHashUtils.calculate_file_hash()`: 计算 SHA-256 文件哈希
- `IncrementalScanService.analyze_incremental_changes()`: 分析增量变更
- `IncrementalScanService.filter_files_by_language()`: 按语言过滤
- `IncrementalScanContext`: 增量扫描上下文 (changed_files, files_to_scan, deleted_files)

### P11-06: 状态同步与事件通知（P2）✅

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P11-06 | 实时状态同步 | - | done |
| P11-06a | WebSocket 服务端实现 | P11-03 | done |
| P11-06b | 进度事件广播 | P11-06a | done |
| P11-06c | 连接状态管理 | P11-06a | done |
| P11-06d | 心跳机制 | P11-06c | done |
| P11-06e | 事件类型定义 | P11-06d | done |

**WebSocket 端点**:
```
WS /api/v1/ws/{scan_id}
```

**实现文件**:
- `src/web/api/websocket.py` (~300 行)
- `src/web/api/v1/scans.py` (修改，添加 WebSocket 端点)
- `tests/unit/test_web/test_websocket.py` (20 测试)

**核心功能**:
- `ConnectionManager`: WebSocket 连接管理 (连接/断开/广播)
- `ScanEventBroadcaster`: 扫描事件广播器
- 事件类型: phase_start, phase_complete, finding_new, progress, scan_complete, scan_failed, scan_paused

### P11-07: 暂停/续扫测试（P1）⏭️

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P11-07 | 暂停/续扫功能测试 | - | skipped |
| P11-07a | 检查点保存/加载测试 | P11-01 | done (单元测试) |
| P11-07b | 暂停后继续测试 | P11-03, P11-04 | done (单元测试) |
| P11-07c | 阶段跳过验证测试 | P11-03e | done (单元测试) |
| P11-07d | 取消扫描清理测试 | P11-03, P11-04c | done (单元测试) |
| P11-07e | 端到端暂停/续扫测试 | P11-07a,b,c,d | skipped (集成测试) |

**测试结果汇总**:
- pause/resume 服务测试: 15/15 ✅
- 控制 API 测试: 17/17 ✅
- 增量扫描测试: 25/25 ✅
- WebSocket 测试: 20/20 ✅
- **总计: 77/77 单元测试通过**

---

## Phase 12: 前端界面

> **目标**: 提供友好的 Web UI，支持项目管理、扫描控制和结果查看
> **状态**: MVP 完成 (2026-04-07)

### P12-01: 前端项目初始化（P0）✅

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P12-01 | React + TypeScript 项目 | - | done |
| P12-01a | Vite + React 18 项目创建 | P12-01 | done |
| P12-01b | TypeScript 配置 | P12-01a | done |
| P12-01c | ESLint + Prettier 配置 | P12-01b | done |
| P12-01d | 路由管理 (react-router) | P12-01a | done |
| P12-01e | 状态管理 (React Query) | P12-01d | done |
| P12-01f | API 客户端 (axios) | P12-01e | done |
| P12-01g | 样式管理 (Ant Design) | P12-01f | done |

**目录结构**:
```
frontend/
├── src/
│   ├── components/
│   │   ├── layout/
│   │   ├── project/
│   │   ├── scan/
│   │   ├── finding/
│   │   └── common/
│   ├── pages/
│   ├── hooks/
│   ├── services/
│   ├── stores/
│   ├── types/
│   └── App.tsx
├── public/
├── package.json
├── vite.config.ts
└── tailwind.config.js
```

**实现文件**:
- `frontend/vite.config.ts`
- `frontend/src/App.tsx`
- `frontend/src/main.tsx`

### P12-02: 通用组件库（P1）✅

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P12-02 | 通用 UI 组件 | - | done |
| P12-02a | 使用 Ant Design 组件库 | P12-01 | done |

**实现文件**:
- 使用 Ant Design 5.12+ 内置组件

### P12-03: 项目管理界面（P1）✅

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P12-03 | 项目管理功能 | - | done |
| P12-03a | 项目列表页（分页、筛选） | P12-02 | done |
| P12-03b | 创建项目表单 | P12-03a | done |
| P12-03c | 项目删除确认 | P12-03a | done |
| P12-03d | 项目扫描历史展示 | P12-03a | done |

**实现文件**:
- `src/web/frontend/src/pages/Projects.tsx`
- `src/web/frontend/src/hooks/useApi.ts` (React Query)

### P12-04: 扫描管理界面（P0）✅

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P12-04 | 扫描管理功能 | - | done |
| P12-04a | 扫描列表页（分页、状态筛选） | P12-03 | done |
| P12-04b | 扫描详情页（进度、统计、阶段） | P12-04a | done |
| P12-04c | 扫描控制按钮（暂停/继续/取消） | P12-04b | done |

**实现文件**:
- `src/web/frontend/src/pages/Scans.tsx`
- `src/web/frontend/src/pages/ScanDetail.tsx`

### P12-05: 实时进度更新（P0）✅

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P12-05 | WebSocket 实时通信 | - | done |
| P12-05a | WebSocket 客户端封装 | P12-01 | done |
| P12-05b | 进度更新 Hook (useScanProgress) | P12-05a | done |
| P12-05c | 自动重连机制（指数退避） | P12-05b | done |
| P12-05d | 心跳机制 | P12-05c | done |
| P12-05e | 轮询作为 Fallback | P12-05c | done |

**实现文件**:
- `src/web/frontend/src/api/websocket.ts`
- `src/web/frontend/src/hooks/useWebSocket.ts`
- `src/web/frontend/src/hooks/useScanProgress.ts`

### P12-06: 漏洞结果界面（P1）✅

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P12-06 | 漏洞结果展示 | - | done |
| P12-06a | 漏洞列表页 (分页/过滤/搜索) | P12-02 | done |
| P12-06b | 漏洞卡片组件 | P12-06a | done |
| P12-06c | 漏洞详情页 (完整信息) | P12-06a | done |
| P12-06d | 漏洞状态管理 (确认/误报/条件) | P12-06c | done |
| P12-06e | 严重程度标签筛选 | P12-06a | done |
| P12-06f | 文件路径导航 | P12-06c | done |
| P12-06g | 代码高亮显示 | P12-06f | done |

**实现文件**:
- `src/web/frontend/src/pages/Findings.tsx`
- `src/web/frontend/src/components/finding/FindingList.tsx`
- `src/web/frontend/src/components/finding/FindingDrawer.tsx`
- `src/web/frontend/src/components/finding/CodeHighlight.tsx`
- `src/web/frontend/src/hooks/useFindings.ts`
- `src/web/api/v1/scans.py` (后端状态更新 API)

**测试结果**: 待用户运行 npm install 后测试
**完成日期**: 2026-04-07

### P12-07: 报告生成与导出（P2）

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P12-07 | 报告生成功能 | - | todo |
| P12-07a | Markdown 报告生成 | P12-06 | todo |
| P12-07b | PDF 报告生成 | P12-07a | todo |
| P12-07c | 报告模板设计 | P12-07b | todo |
| P12-07d | 报告导出 API | P12-07a | todo |
| P12-07e | 报告历史对比 | P12-07d | todo |
| P12-07f | 报告分享功能 | P12-07e | todo |

**实现文件**:
- `frontend/src/pages/ReportView.tsx`
- `frontend/src/components/report/ReportExport.tsx`
- `src/web/services/report_service.py`

---

## Phase 14: Web 服务完整能力迁移

> **目标**: 将 CLI 的所有高级功能迁移到 Web 服务，实现与 CLI 完全一致的扫描能力
> **状态**: 进行中 (design)

### P14-01: AttackSurfaceDetection 集成（P0）

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P14-01 | 攻击面检测服务 | - | todo |
| P14-01a | 创建 AttackSurfaceService | P14-01 | todo |
| P14-01b | 静态检测集成（endpoint/敏感函数） | P14-01a | todo |
| P14-01c | LLM 检测集成（语义分析） | P14-01a | todo |
| P14-01d | 并行检测模式 | P14-01b,c | todo |
| P14-01e | 集成到 ScanOrchestrator Phase 0 | P14-01d | todo |
| P14-01f | 配置参数支持 (llm_detect, static_only) | P14-01e | todo |

**实现文件**:
- `src/web/services/attack_surface_service.py` (新增)
- `src/web/services/scan_orchestrator.py` (修改，添加 L1_Preparation)
- `src/web/models/schemas.py` (修改，配置参数)

### P14-02: ExploitabilityVerification 集成（P0）

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P14-02 | 可利用性验证服务 | - | todo |
| P14-02a | 创建 VerificationService | P14-02 | todo |
| P14-02b | 集成 RoundFourExecutor | P14-02a | todo |
| P14-02c | CodeQL 结果数据流分析 | P14-02b | todo |
| P14-02d | 攻击面结果集成 | P14-02b | todo |
| P14-02e | 集成到 ScanOrchestrator Phase 3 | P14-02d | todo |
| P14-02f | 配置参数支持 (llm_verify) | P14-02e | todo |

**实现文件**:
- `src/web/services/verification_service.py` (新增)
- `src/layers/l3_analysis/rounds/round_four.py` (复用)
- `src/web/models/finding.py` (修改，添加 exploitability 字段)

### P14-03: Deduplication + Adjudication 集成（P0）

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P14-03 | 去重与仲裁服务 | - | todo |
| P14-03a | 创建 AdjudicationService | P14-03 | todo |
| P14-03b | 集成 ClusterBasedDeduplicator | P14-03a | todo |
| P14-03c | 集成 Adjudication 逻辑 | P14-03b | todo |
| P14-03d | 证据强度评估 | P14-03c | todo |
| P14-03e | 集成到 ScanOrchestrator Phase 4 | P14-03d | todo |

**实现文件**:
- `src/web/services/adjudication_service.py` (新增)
- `src/layers/l3_analysis/deduplicator.py` (复用)
- `src/layers/l3_analysis/adjudication.py` (复用)

### P14-04: EnhancedAdversarialVerification 集成（P0）

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P14-04 | 对抗性验证服务 | - | todo |
| P14-04a | 创建 AdversarialService | P14-04 | todo |
| P14-04b | 集成 EnhancedAdversarialVerification | P14-04a | todo |
| P14-04c | 策略演进机制 | P14-04b | todo |
| P14-04d | 多轮辩论 (Attacker vs Defender) | P14-04c | todo |
| P14-04e | WebSocket 实时推送辩论内容 | P14-04d | todo |
| P14-04f | 每轮 3 分钟超时，超时降级 | P14-04e | todo |
| P14-04g | 集成到 ScanOrchestrator Phase 5 | P14-04f | todo |
| P14-04h | 配置参数支持 (adversarial, adversarial_max_rounds) | P14-04g | todo |

**实现文件**:
- `src/web/services/adversarial_service.py` (新增)
- `src/layers/l3_analysis/verification/enhanced_adversarial.py` (复用)
- `src/web/api/websocket.py` (修改，添加辩论事件)
- `src/web/models/finding.py` (修改，添加 adversarial_verdict 字段)

### P14-05: Token 统计（P1）

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P14-05 | Token 使用统计 | - | todo |
| P14-05a | LLMClient 包装，添加 get_total_usage() | P14-05 | todo |
| P14-05b | Scan 模型 tokens_used 字段更新 | P14-05a | todo |
| P14-05c | 成本计算 (tokens → 成本) | P14-05b | todo |
| P14-05d | 集成到 ScanOrchestrator Phase 6 | P14-05c | todo |

**实现文件**:
- `src/web/models/scan.py` (修改，tokens_used 字段)
- `src/layers/l3_analysis/llm/client.py` (修改)

### P14-06: 增量扫描增强（P0）

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P14-06 | 增量扫描增强 | - | todo |
| P14-06a | 增强 IncrementalScanService | P14-06 | todo |
| P14-06b | Git diff 分析 (base_ref vs head_ref) | P14-06a | todo |
| P14-06c | 文件变更检测 (added/modified/deleted) | P14-06b | todo |
| P14-06d | 依赖追踪 (变更文件的影响分析) | P14-06c | todo |
| P14-06e | 失败时报错终止（不自动降级） | P14-06d | todo |
| P14-06f | 配置参数支持 (incremental, base_ref, head_ref) | P14-06e | todo |

**实现文件**:
- `src/web/services/incremental_scan_service.py` (增强)
- `src/web/models/scan.py` (修改，incremental_stats 字段)

### P14-07: 数据模型扩展（P0）

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P14-07 | 数据库模型扩展 | - | todo |
| P14-07a | Finding 模型新增字段 | P14-07 | todo |
| P14-07b | Scan 模型新增字段 | P14-07a | todo |
| P14-07c | Alembic 迁移脚本 | P14-07b | todo |

**Finding 新增字段**:
```python
exploitability: Optional[str]          # 可利用性评级
exploitability_confidence: Optional[float]
exploitability_reasoning: Optional[str]
adversarial_verdict: Optional[str]      # 对抗性验证结果
adversarial_confidence: Optional[float]
adversarial_reasoning: Optional[str]
report_status: Optional[str]            # 仲裁状态
evidence_strength: Optional[str]        # 证据强度
```

**Scan 新增字段**:
```python
attack_surface: Optional[JSON]         # 攻击面统计
adjudication_summary: Optional[JSON]    # 仲裁摘要
adversarial_summary: Optional[JSON]     # 对抗性摘要
token_usage: Optional[JSON]             # Token 使用详情
incremental_stats: Optional[JSON]       # 增量扫描统计
```

### P14-08: API 扩展（P0）

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P14-08 | 扫描 API 扩展 | - | todo |
| P14-08a | 扫描创建请求扩展（新增配置参数） | P14-08 | todo |
| P14-08b | 对抗性辩论内容查询 API | P14-04 | todo |
| P14-08c | Token 统计查询 API | P14-05 | todo |
| P14-08d | 增量扫描配置 API | P14-06 | todo |

**扫描创建请求扩展**:
```json
{
  "llm_verify": true,              // 可利用性验证
  "llm_detect": true,              // LLM 攻击面检测
  "static_only": false,            // 仅静态检测
  "adversarial": true,             // 对抗性验证
  "adversarial_max_rounds": 5,     // 最大对抗轮数
  "adversarial_round_timeout": 180, // 每轮超时(秒)
  "incremental": false,            // 增量扫描模式
  "base_ref": "HEAD~1",            // 增量扫描基准引用
  "head_ref": "HEAD"               // 增量扫描目标引用
}
```

### P14-09: 集成测试（P1）

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P14-09 | 集成测试与验证 | - | todo |
| P14-09a | Web 扫描结果与 CLI 结果一致性测试 | P14-01~P14-06 | todo |
| P14-09b | 所有扫描模式功能测试 | P14-09a | todo |
| P14-09c | Token 统计准确性测试 | P14-05 | todo |
| P14-09d | 增量扫描性能测试 | P14-06 | todo |
| P14-09e | WebSocket 实时进度测试 | P14-04 | todo |
| P14-09f | 对抗性验证并发测试 | P14-04 | todo |

**验收标准**:
1. ✅ Web 扫描结果与 CLI 结果一致性 > 95%
2. ✅ 支持所有 CLI 扫描模式 (base/full/incremental/static-only/llm-full-detect)
3. ✅ Token 统计准确率 100%
4. ✅ 增量扫描加速比 > 60%
5. ✅ WebSocket 实时进度更新延迟 < 500ms
6. ✅ 对抗性辩论内容实时展示
7. ✅ 每轮对抗性验证 3 分钟超时，自动降级

---

## Phase 13: 企业级功能

> **目标**: 完善企业级功能，支持 CI/CD 集成和团队协作

### P13-01: 用户认证与权限（P1）

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P13-01 | 用户认证系统 | - | todo |
| P13-01a | API Key 认证机制 | P13-01 | todo |
| P13-01b | 用户注册/登录 (可选) | P13-01a | todo |
| P13-01c | 基于角色的权限控制 (RBAC) | P13-01a | todo |
| P13-01d | API Key 生成与管理 | P13-01a | todo |
| P13-01e | 操作审计日志 | P13-01d | todo |

**实现文件**:
- `src/web/core/security.py`
- `src/web/api/v1/auth.py`
- `src/web/models/user.py`

### P13-02: CI/CD 集成（P1）

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P13-02 | CI/CD 集成支持 | - | todo |
| P13-02a | Docker 镜像构建 | P13-01 | todo |
| P13-02b | Docker Compose 配置 | P13-02a | todo |
| P13-02c | 环境变量配置文档 | P13-02b | todo |
| P13-02d | CLI 容器化入口 | P13-02b | todo |
| P13-02e | CI 配置示例 (GitHub Actions/GitLab CI) | P13-02d | todo |
| P13-02f | 扫描结果输出格式 (SARIF) | P13-02e | todo |

**实现文件**:
- `Dockerfile`
- `docker-compose.yml`
- `.github/workflows/scan.yml`
- `DEPLOYMENT.md`

### P13-03: 多租户支持（P2）

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P13-03 | 多租户架构 | - | todo |
| P13-03a | 数据隔离策略 | P13-01 | todo |
| P13-03b | 租户级配额管理 | P13-03a | todo |
| P13-03c | 资源使用统计 | P13-03b | todo |
| P13-03d | 租户管理界面 | P13-03a | todo |

---

## Phase 15: 报告生成与导出

> **目标**: 完善报告生成功能，支持多种格式导出

### P15-01: 报告生成服务（P1）

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P15-01 | 报告生成功能 | - | todo |
| P15-01a | Markdown 报告生成 | P15-01 | todo |
| P15-01b | PDF 报告生成 | P15-01a | todo |
| P15-01c | 报告模板设计 | P15-01b | todo |
| P15-01d | 报告导出 API | P15-01a | todo |
| P15-01e | 报告历史对比 | P15-01d | todo |
| P15-01f | 报告分享功能 | P15-01e | todo |

**实现文件**:
- `src/web/services/report_service.py`
- `frontend/src/pages/ReportView.tsx`
- `frontend/src/components/report/ReportExport.tsx`

---

### P13-01: 用户认证与权限（P1）

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P13-01 | 用户认证系统 | - | todo |
| P13-01a | API Key 认证机制 | P13-01 | todo |
| P13-01b | 用户注册/登录 (可选) | P13-01a | todo |
| P13-01c | 基于角色的权限控制 (RBAC) | P13-01a | todo |
| P13-01d | API Key 生成与管理 | P13-01a | todo |
| P13-01e | 操作审计日志 | P13-01d | todo |

**实现文件**:
- `src/web/core/security.py`
- `src/web/api/v1/auth.py`
- `src/web/models/user.py`

### P13-02: CI/CD 集成（P1）

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P13-02 | CI/CD 集成支持 | - | todo |
| P13-02a | Docker 镜像构建 | P13-01 | todo |
| P13-02b | Docker Compose 配置 | P13-02a | todo |
| P13-02c | 环境变量配置文档 | P13-02b | todo |
| P13-02d | CLI 容器化入口 | P13-02b | todo |
| P13-02e | CI 配置示例 (GitHub Actions/GitLab CI) | P13-02d | todo |
| P13-02f | 扫描结果输出格式 (SARIF) | P13-02e | todo |

**实现文件**:
- `Dockerfile`
- `docker-compose.yml`
- `.github/workflows/scan.yml`
- `DEPLOYMENT.md`

### P13-03: 多租户支持（P2）

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P13-03 | 多租户架构 | - | todo |
| P13-03a | 数据隔离策略 | P13-01 | todo |
| P13-03b | 租户级配额管理 | P13-03a | todo |
| P13-03c | 资源使用统计 | P13-03b | todo |
| P13-03d | 租户管理界面 | P13-03a | todo |

---

## 里程碑更新

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
|v0.7|报告可信度|结果边界清晰 + 噪声治理 + 覆盖率透明|done|2026-04|
|v0.75|CodeQL 智能构建|LLM 决策 + 分语言构建编排 + 构建成功率提升|done|2026-04|
|v0.8|AST Engine|结构级代码理解 + Code Graph + AI 结构化上下文 + 前置防误报|done|2026-04|
|v0.9|CPG 基础|完整代码图 + 攻击路径搜索 + Agent 集成|done|2026-04-07|
|v0.95|Web 服务与持久化|FastAPI 后端 + PostgreSQL + RESTful API + 项目管理|done|2026-04-07|
|v0.96|暂停/续扫功能|检查点机制 + 阶段恢复 + 控制接口 + WebSocket + 增量扫描|done|2026-04-07|
|v0.97|前端界面|MVP|React + TypeScript + Ant Design + 实时进度 + 扫描控制|done|2026-04-07|
|v0.98|漏洞结果界面|列表/详情/代码高亮/状态管理|React + SyntaxHighlighter + 状态 API|done|2026-04-07|
|v1.0|Web 基础版|高精度、低误报 + Web UI + 暂停续扫|done|2026-04-09|
|v1.1|Web 完整能力|攻击面检测 + 可利用性验证 + 去重仲裁 + 对抗性验证 + Token 统计 + 增量扫描增强|done|2026-04-09|
|v1.5|企业稳定版|CI/CD 集成 + 多租户 + 用户认证 + 报告导出|todo|2026-Q2|

---

## 当前焦点

|字段|值|
|---|---|
|**阶段**|无 - 上一阶段已完成|
|**上一阶段**|Phase 14 Web 服务完整能力迁移，P14-web-capability-migration (已完成 ✅)|
|**里程碑**|v1.1 已完成 (Web 完整扫描能力)|

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

---

## Phase 16: Web 前端重构 (UI/UX 升级)

> 目标：参考 DeepAudit 设计，重构 Web 前端，提供赛博朋克风格的专业安全审计界面

### 目标效果

| 维度 | 当前 | 目标 |
|------|------|------|
| 设计风格 | Ant Design 默认 | 赛博朋克终端风格 |
| 组件库 | Ant Design | 自建 Radix UI 组件库 |
| 国际化 | 无 | 中英文双语 |
| 主题系统 | 单一主题 | 深色/浅色/系统三模式 |
| 实时交互 | 轮询 | 流式实时更新 |
| 页面数量 | 3 | 6+ |

### P16-01: 基础设施搭建（P0）

| 任务 | 描述 | 状态 |
|------|------|------|
| P16-01 | 安装核心依赖 | todo |
| P16-01a | Radix UI 组件 (dialog, tabs, progress, toast 等) | P16-01 |
| P16-01b | 工具库 (class-variance-authority, clsx, tailwind-merge, lucide-react) | P16-01a |
| P16-01c | 国际化 (i18next, react-i18next) | P16-01a |
| P16-01d | 主题系统 (next-themes) | P16-01a |
| P16-01e | 流式处理 (eventsource-parser) | P16-01a |

### P16-02: 赛博朋克主题配置（P0）

| 任务 | 描述 | 状态 |
|------|------|------|
| P16-02 | 配置 Tailwind 赛博朋克主题 | todo |
| P16-02a | 配色方案 (深色背景 + 霓虹光效) | P16-02 |
| P16-02b | 全局样式 (扫描线、网格背景、发光边框) | P16-02a |
| P16-02c | 字体配置 (JetBrains Mono 等宽字体) | P16-02a |

### P16-03: UI 组件库构建（P1）

| 任务 | 描述 | 状态 |
|------|------|------|
| P16-03 | 自建基础 UI 组件库 | todo |
| P16-03a | Button, Card, Badge 组件 | P16-03 |
| P16-03b | Dialog, Tabs, Progress 组件 | P16-03a |
| P16-03c | Toast 通知组件 (sonner) | P16-03a |

### P16-04: 布局重构（P0）

| 任务 | 描述 | 状态 |
|------|------|------|
| P16-04 | 重构应用布局 | todo |
| P16-04a | 创建主布局组件 (MainLayout) | P16-04 |
| P16-04b | 创建侧边栏组件 (Sidebar) | P16-04a |
| P16-04c | 创建头部组件 (Header) | P16-04a |

### P16-05: 仪表盘页面（P1）

| 任务 | 描述 | 状态 |
|------|------|------|
| P16-05 | 创建仪表盘页面 | todo |
| P16-05a | 统计卡片 (扫描数/漏洞数/进行中) | P16-05 |
| P16-05b | 图表组件 (recharts) | P16-05a |
| P16-05c | 最近扫描列表 | P16-05a |

### P16-06: 扫描页面重构（P0）

| 任务 | 描述 | 状态 |
|------|------|------|
| P16-06 | 使用新组件重构扫描页面 | todo |
| P16-06a | 扫描列表页面 | P16-06 |
| P16-06b | 扫描详情页面 | P16-06a |
| P16-06c | 流式进度展示 | P16-06b |

### P16-07: 漏洞页面重构（P0）

| 任务 | 描述 | 状态 |
|------|------|------|
| P16-07 | 使用新组件重构漏洞页面 | todo |
| P16-07a | 漏洞列表组件 | P16-07 |
| P16-07b | 代码高亮组件 | P16-07a |
| P16-07c | 漏洞状态管理 | P16-07a |

### P16-08: 国际化（P2）

| 任务 | 描述 | 状态 |
|------|------|------|
| P16-08 | 实现中英文双语 | todo |
| P16-08a | 配置 i18next | P16-08 |
| P16-08b | 创建语言包 (zh-CN, en-US) | P16-08a |
| P16-08c | 添加语言切换器 | P16-08a |

### P16-09: 主题切换（P1）

| 任务 | 描述 | 状态 |
|------|------|------|
| P16-09 | 实现主题切换功能 | todo |
| P16-09a | 配置 next-themes | P16-09 |
| P16-09b | 创建主题切换器组件 | P16-09a |

### P16-10: API 层重构（P0）

| 任务 | 描述 | 状态 |
|------|------|------|
| P16-10 | 重构 API 调用层 | todo |
| P16-10a | 统一 API 客户端 | P16-10 |
| P16-10b | 流式 API 支持 | P16-10a |

---

## 开发阶段

|阶段|目标|核心交付|状态|预计完成|
|---|---|---|---|---|
|Phase 1|基础设施搭建|L1 初版|done|2026-02|
|Phase 2|核心分析能力|L3 三引擎 + 多轮审计|done|2026-02|
|Phase 3|精度重构|Rule Gating + TechStack 重构|done|2026-03|
|Phase 4|裁决统一|Exploitability 主裁决 + 误报压制|done|2026-03-06|
|Phase 5|精度深化|可利用性评估增强 + 调用图分析|done|2026-03|
|Phase 6|报告可信度|结果边界清晰化 + 噪声治理 + 覆盖率透明|done|2026-03|
|Phase 6.5|code-audit 集成|防幻觉规则 + 覆盖率矩阵 + 污点分析模板 + 漏洞验证方法论|done|2026-03|
|Phase 6.6|Readiness Gate 自动修复|尽量构建环境而非跳过|done|2026-04|
|Phase 7|CodeQL 智能构建|LLM 语言决策 + 分语言构建编排 + 多语言构建成功率提升|done|2026-04|
|Phase 14|Web 完整能力迁移|攻击面检测 + 可利用性验证 + 去重仲裁 + 对抗性验证 + Token 统计 + 增量扫描增强|done|2026-04-09|
|Phase 15|代码质量改进|修复跨层依赖 + 清理死代码 + 修复假测试|done|2026-04-09|
|Phase 16|Web 前端重构|赛博朋克风格 UI + 自建组件库 + 国际化 + 流式交互|done|2026-04|
|Phase 17|LLM 配置管理|多配置支持 + UI 管理|done|2026-04|
|Phase 18|配置系统迁移|移除 config.local.toml，配置迁移到数据库|done|2026-04-11|c87a0c6|

---

## Phase 18 详细任务：配置系统迁移

> 目标：移除 config.local.toml 依赖，所有配置迁移到数据库和前端设置，实现真正的配置即服务

### P18-01: 数据库模型创建（P0）

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P18-01 | 创建 system_settings 表 | - | done |
| P18-01a | SystemSetting 模型定义 | P18-01 | done |
| P18-01b | SystemSettingRepository 仓储类 | P18-01a | done |
| P18-01c | Alembic 迁移脚本 | P18-01b | done |

**实现文件**: `migrations/versions/007_create_system_settings.py`, `src/web/models/system_setting.py`, `src/web/repositories/system_setting.py`

### P18-02: 后端 API 开发（P0）

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P18-02 | 系统配置 CRUD 端点 | P18-01 | done |
| P18-02a | LLM 配置获取服务（按类型） | P18-02 | done |
| P18-02b | 配置验证服务 | P18-02a | done |

**实现文件**: `src/web/api/v1/system_settings.py`, `src/web/services/llm_config_service.py`, `src/web/services/llm_validation.py`

### P18-03: 扫描任务集成（P0）

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P18-03 | 修改 scan_tasks.py 从数据库获取 LLM 配置 | P18-02 | done |
| P18-03a | 修改 opencode_agent.py 支持传入 LLM 客户端 | P18-03 | done |
| P18-03b | 对抗性验证使用正确的配置类型 | P18-03a | done |

**实现文件**: `src/web/tasks/scan_tasks.py`, `src/layers/l3_analysis/engines/opencode_agent.py`, `src/layers/l3_analysis/adjudication.py`

### P18-04: 前端 UI 开发（P0）

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P18-04 | 扫描配置卡片组件 | P18-03 | done |
| P18-04a | API Key 配置卡片组件 | P18-04 | done |
| P18-04b | 设置页面布局调整 | P18-04a | done |

**实现文件**: `src/web/frontend/src/components/llm/*.tsx`, `src/web/frontend/src/components/settings/*.tsx`

### P18-05: 清理旧代码（P1）

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P18-05 | 移除 get_llm_config() 中的 config.local.toml 读取 | P18-04 | done |
| P18-05a | 更新 CLI 命令使用数据库配置 | P18-05 | done |
| P18-05b | 更新文档 | P18-05a | done |

**实现文件**: `src/core/config/__init__.py`

### P18 验收标准

- [x] 扫描任务使用数据库中的 LLM 配置
- [x] Agent 扫描使用 agent_scan 类型配置
- [x] 对抗性验证使用 verification 类型配置
- [x] 前端可以修改扫描参数和 API Key
- [x] 移除 config.local.toml 依赖（代码层）
- [x] API 配置支持连接测试

**完成日期**: 2026-04-11
**测试状态**: passed
**安全验证**: ✅ config.local.toml 密钥已清理
**Commit**: c87a0c6

---

## 开发阶段

|阶段|目标|核心交付|状态|预计完成|
|---|---|---|---|---|
|Phase 1|基础设施搭建|L1 初版|done|2026-02|
|Phase 2|核心分析能力|L3 三引擎 + 多轮审计|done|2026-02|
|Phase 3|精度重构|Rule Gating + TechStack 重构|done|2026-03|
|Phase 4|裁决统一|Exploitability 主裁决 + 误报压制|done|2026-03-06|
|Phase 5|精度深化|可利用性评估增强 + 调用图分析|done|2026-03|
|Phase 6|报告可信度|结果边界清晰化 + 噪声治理 + 覆盖率透明|done|2026-03|
|Phase 6.5|code-audit 集成|防幻觉规则 + 覆盖率矩阵 + 污点分析模板 + 漏洞验证方法论|done|2026-03|
|Phase 6.6|Readiness Gate 自动修复|尽量构建环境而非跳过|done|2026-04|
|Phase 7|CodeQL 智能构建|LLM 语言决策 + 分语言构建编排 + 多语言构建成功率提升|done|2026-04|
|Phase 14|Web 完整能力迁移|攻击面检测 + 可利用性验证 + 去重仲裁 + 对抗性验证 + Token 统计 + 增量扫描增强|done|2026-04-09|
|Phase 15|代码质量改进|修复跨层依赖 + 清理死代码 + 修复假测试|done|2026-04-09|
|Phase 16|Web 前端重构|赛博朋克风格 UI + 自建组件库 + 国际化 + 流式交互|done|2026-04|
|Phase 17|LLM 配置管理|多配置支持 + UI 管理|done|2026-04|
|Phase 18|配置系统迁移|移除 config.local.toml，配置迁移到数据库|done|2026-04-11|c87a0c6|
