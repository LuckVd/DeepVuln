# Change Log

## 2026-03-27

### P7-08: C/C++ 标准构建系统支持完成

- **Goal ID**: P7-08
- **Summary**: 为 C/C++ 项目提供标准构建系统支持，仅支持标准构建系统（compile_commands.json、CMake、Makefile），明确止损线，避免无边界猜测式构建
- **Impact**:
  - `src/layers/l3_analysis/build/builders/cpp.py`: CppBuilder 实现（643 行）
  - `src/layers/l3_analysis/build/builders/__init__.py`: 导出 CppBuilder
  - `tests/unit/test_l3/test_builders/test_cpp_builder.py`: 28 个单元测试（428 行）
- **Test Coverage**:
  - compile_commands.json 检测（根目录、build/、out/）
  - CMake 支持（生成 compile_commands，复杂选项跳过）
  - Makefile 保守策略（简单/复杂区分）
  - Header-only 检测与说明
  - 止损线验证（非标准系统、sudo、复杂配置）
  - 失败诊断（编译器错误、链接错误、CMake 错误、权限错误）
- **Tests**: 28 passed (CppBuilder), 152 passed (all builders)
- **Dead Code**: not run
- **Security**: No secrets exposed
- **Commit**: a7eb212

### P7-10: 基线策略、测试与效果评估完成

- **Goal ID**: P7-10
- **Summary**: 验证 LLM 决策相对规则基线是否有净收益，补充测试覆盖，并建立评估指标体系
- **Impact**:
  - `src/layers/l3_analysis/decision/models.py`: 新增 `BaselineStrategy` 枚举和 `LanguageDecisionMetrics` 数据类
  - `src/layers/l3_analysis/decision/language_decider.py`: 实现 4 种 baseline 策略（hybrid/language_first/attack_surface_first/semgrep_first）
  - `src/layers/l3_analysis/decision/__init__.py`: 导出新类型
  - `src/layers/l3_analysis/readiness_gate.py`: 集成 metrics 收集
  - `src/layers/l3_analysis/build/version_detector.py`: 补充边缘格式支持（.nvmrc lts/*、package.json .x）
  - `src/layers/l3_analysis/build/tool_resolver.py`: 补充版本范围匹配（>=, ^, ~）
  - `tests/unit/test_l3/test_decision.py`: 扩展至 51 个单元测试（+16 个）
  - `tests/unit/test_l3/test_version_detector.py`: 25 个单元测试
  - `tests/unit/test_l3/test_tool_resolver.py`: 48 个单元测试
  - `tests/integration/test_decision_e2e.py`: 新增集成测试文件
- **Test Coverage**:
  - Baseline 策略切换测试（4 种策略）
  - LLM 决策器边缘场景（空响应、超时、格式错误、不支持语言过滤）
  - 版本检测边缘格式（.nvmrc lts/*、package.json .x）
  - 工具兼容性版本范围匹配（>=, ^, ~）
  - LanguageDecisionMetrics 收集和汇总
- **Tests**: 153 passed (decision: 51, version_detector: 25, tool_resolver: 48, + 29 other L3 tests)
- **Dead Code**: not run
- **Security**: No secrets exposed
- **Commit**: c3205d3

## 2026-03-26

### P7-05e: 集成 Builder 系统到 CodeQL scan 流程完成

- **Goal ID**: P7-05e
- **Summary**: 将已实现的 PythonBuilder、JavaScriptBuilder、GoBuilder、JavaBuilder 集成到 CodeQL 引擎的 scan 流程，替换旧的 BuildSystemDetector，实现完整的智能构建分析链路
- **Impact**:
  - `src/layers/l3_analysis/engines/codeql.py`: 集成 Builder 系统 (+150 行)
  - `src/cli/main.py`: 传递 readiness_result + 显示警告 (+10 行)
  - `tests/unit/test_l3/test_codeql_builder_integration.py`: 12 个单元测试
- **Test Coverage**:
  - `_execute_build()` 使用 Builder 和 ReadinessInfo
  - `scan()` 接受 `readiness_result` 参数
  - `scan_multi_language()` 传递 readiness_result
  - 向后兼容（无 readiness_result 时回退）
  - Builder 警告传递到 metadata
- **Tests**: 12 passed
- **Dead Code**: not run
- **Security**: No secrets exposed
- **Commit**: pending

### P7-07: Python/JS/TS 轻构建与免构建路径完成

### P7-07: Python/JS/TS 轻构建与免构建路径完成

- **Goal ID**: P7-07
- **Summary**: 为 Python、JavaScript、TypeScript 实现免构建路径，这些动态语言在 CodeQL 分析中不需要编译，但检测可能需要构建的场景并给出警告
- **Impact**:
  - `src/layers/l3_analysis/build/builders/python.py`: Python 构建器（407 行）
  - `src/layers/l3_analysis/build/builders/javascript.py`: JS/TS 构建器（487 行）
  - `src/layers/l3_analysis/build/builders/__init__.py`: 导出新 Builder
  - `tests/unit/test_l3/test_builders/test_python_builder.py`: 29 个单元测试（377 行）
  - `tests/unit/test_l3/test_builders/test_javascript_builder.py`: 31 个单元测试（446 行）
- **Test Coverage**:
  - PythonBuilder: pyproject.toml/requirements.txt/setup.py 检测、Poetry/uv 包管理器识别、Cython/Protobuf 检测警告、版本解析
  - JavaScriptBuilder: package.json/tsconfig.json 检测、TypeScript 区分、project refs/paths aliases/workspace 检测警告、npm/yarn/pnpm 区分
- **Tests**: 60 passed
- **Dead Code**: not run
- **Security**: No secrets exposed
- **Commit**: pending

### P7-06: Go/Java 标准构建支持完成

### P7-06: Go/Java 标准构建支持完成

- **Goal ID**: P7-06
- **Summary**: 实现 Go 和 Java 专用构建器，提供智能构建策略（wrapper 检测、CGO 处理、多模块支持、失败诊断）
- **Impact**:
  - `src/layers/l3_analysis/build/builders/base.py`: Builder 协议和基类（200 行）
  - `src/layers/l3_analysis/build/builders/go.py`: Go 构建器（490 行）
  - `src/layers/l3_analysis/build/builders/java.py`: Java 构建器（480 行）
  - `src/layers/l3_analysis/build/build_plan.py`: 集成 Builder（+100 行）
  - `src/layers/l3_analysis/readiness_gate.py`: 集成构建分析（+80 行）
  - `tests/unit/test_l3/test_builders/`: 64 个单元测试（940 行）
- **Test Coverage**:
  - Go Builder: CGO 检测、vendor 处理、私有模块、失败诊断（20 tests）
  - Java Builder: Wrapper 检测、Maven/Gradle 策略、JDK 版本、失败诊断（25 tests）
  - BuildPlanGenerator 集成测试（39 tests）
  - ReadinessGate 集成测试（23 tests）
- **Tests**: 64 passed (all L3 tests: 1596 passed)
- **Dead Code**: not run
- **Security**: No secrets exposed
- **Commit**: 724c281

## 2026-03-25

### P7-09: Readiness Gate 与 CLI 集成完成

- **Goal ID**: P7-09
- **Summary**: 增强 Readiness Gate 集成 LLM 决策、构建画像和工具兼容性，提升 CodeQL 启动决策的可解释性
- **Impact**:
  - `src/layers/l3_analysis/readiness_gate.py`: CodeQLReadinessGate 核心实现（464 行）
  - `src/cli/main.py`: CLI 增强（--force-codeql-all 选项 + 增强输出）
  - `tests/unit/test_l3/test_readiness_gate.py`: 23 个单元测试（512 行）
- **Test Coverage**:
  - CodeQLReadinessGate 三层决策测试
  - LLM 决策集成和 baseline 回退测试
  - 构建画像集成测试
  - 工具兼容性检查测试
  - Force 模式测试
- **Tests**: 23 passed (all L3 tests: 1532 passed)
- **Dead Code**: not run
- **Security**: No secrets exposed
- **Commit**: pending

### P7-05: 构建计划生成与执行编排完成

- **Goal ID**: P7-05
- **Summary**: 实现构建计划生成与执行编排，为 CodeQL 提供可预测、可解释、可回退的构建流程
- **Impact**:
  - `src/layers/l3_analysis/build/build_plan.py`: BuildPlan 核心实现（846 行）
  - `src/layers/l3_analysis/build/__init__.py`: 新增导出
  - `tests/unit/test_l3/test_build_plan.py`: 39 个单元测试（644 行）
- **Test Coverage**:
  - BuildPlan, BuildStep, RiskLevel, FallbackStrategy 数据模型测试
  - BuildPlanGenerator 计划生成测试
  - BuildCache 缓存存取/过期/LRU 淘汰测试
  - BuildOrchestrator 计划协调执行测试
  - BuildSummary 标准化输出测试
- **Tests**: 39 passed (all L3 tests: 1509 passed)
- **Dead Code**: not run
- **Security**: No secrets exposed
- **Commit**: pending

### P7-04: 工具解析与兼容性判定完成

- **Goal ID**: P7-04
- **Summary**: 实现工具发现与兼容性检查，从多源解析构建工具并判定版本是否满足需求
- **Impact**:
  - `src/layers/l3_analysis/build/tool_resolver.py`: ToolResolver 核心实现（706 行）
  - `src/layers/l3_analysis/build/__init__.py`: 新增导出
  - `tests/unit/test_l3/test_tool_resolver.py`: 48 个单元测试（566 行）
- **Test Coverage**:
  - ToolType, ToolSource, ToolInfo 数据模型测试
  - 版本解析与匹配测试（精确/>=/>/范围）
  - ToolResolver 三源发现测试（Managed/Cache/PATH）
  - CompatibilityChecker 兼容性检查测试
  - ProvisionPolicy 三种策略测试
  - ReadinessReport 报告生成测试
- **Tests**: 48 passed (all L3 tests: 1470 passed)
- **Dead Code**: not run
- **Security**: No secrets exposed
- **Commit**: pending

### P7-03c~g: VersionDetector 完成

- **Goal ID**: P7-03c~g
- **Summary**: 实现版本检测器，解析项目配置文件检测所需的运行时版本（Java/Go/Node），为 CodeQL 构建提供环境需求信息
- **Impact**:
  - `src/layers/l3_analysis/build/version_detector.py`: VersionDetector 核心实现（476 行）
  - `src/layers/l3_analysis/build/__init__.py`: 新增导出
  - `tests/unit/test_l3/test_version_detector.py`: 25 个单元测试（457 行）
- **Test Coverage**:
  - RuntimeType, VersionInfo, VersionRequirement 数据模型测试
  - Java pom.xml maven.compiler.source/target/release 解析
  - Java build.gradle sourceCompatibility/toolchain 解析
  - Java build.gradle.kts Kotlin DSL 支持
  - Go go.mod 版本解析
  - Node .nvmrc 文件解析（支持 v 前缀、lts 处理）
  - Node package.json engines 解析（支持 >=, ^, .x 版本格式）
  - 多运行时同时检测测试
  - 优先级测试（.nvmrc > engines）
- **Tests**: 25 passed (all L3 tests: 1422 passed)
- **Dead Code**: not run
- **Security**: No secrets exposed
- **Commit**: pending

### P7-03b: BuildTargetExtractor 完成

- **Goal ID**: P7-03b
- **Summary**: 实现构建目标提取器，提取可构建单元、识别入口点、生成 CodeQL 构建推荐
- **Impact**:
  - `src/layers/l3_analysis/build/target_extractor.py`: BuildTargetExtractor 核心实现
  - `src/layers/l3_analysis/build/__init__.py`: 新增导出
  - `tests/unit/test_l3/test_target_extractor.py`: 17 个单元测试
- **Test Coverage**:
  - BuildTarget, EntryPoint, BuildRecommendation 数据模型测试
  - Java Maven/Gradle 目标提取测试
  - Go main package 识别测试
  - Node.js 包目标提取测试
  - Python 入口点检测测试
  - 构建策略判定测试
- **Tests**: 17 passed (all L3 tests: 1397 passed)
- **Dead Code**: not run
- **Security**: not run
- **Commit**: c9aca8f

### P7-03a: ModuleDiscovery 完成

- **Goal ID**: P7-03a
- **Summary**: 实现仓库级模块发现与边界识别
- **Impact**:
  - `src/layers/l3_analysis/build/module_discovery.py`: ModuleDiscovery 核心实现
  - `src/layers/l3_analysis/build/__init__.py`: 新增导出
  - `tests/unit/test_l3/test_module_discovery.py`: 20 个单元测试
- **Test Coverage**:
  - Monorepo 检测（go.work, Maven, Gradle, pnpm, Lerna, 目录约定）
  - 模块边界识别
  - 语言检测
  - 构建信号提取
  - LOC 估算
- **Tests**: 20 passed (all L3 tests: 1380 passed)
- **Dead Code**: not run
- **Security**: not run
- **Commit**: 2a6b892

### P7-01: LLM 智能语言决策完成

- **Goal ID**: P7-01
- **Summary**: 实现 LLM 驱动的 CodeQL 语言选择决策器
- **Impact**:
  - `src/layers/l3_analysis/decision/__init__.py`: 模块初始化和导出
  - `src/layers/l3_analysis/decision/models.py`: 6 个数据模型定义
  - `src/layers/l3_analysis/decision/build_assessor.py`: 构建难度评估器
  - `src/layers/l3_analysis/decision/prompts.py`: LLM Prompt 模板
  - `src/layers/l3_analysis/decision/language_decider.py`: 核心决策器实现
  - `tests/unit/test_l3/test_decision.py`: 35 个单元测试
- **Test Coverage**:
  - LanguageStructure, DecisionConstraints, LanguageDecision 模型测试
  - BuildDifficultyAssessor 各语言难度评估测试
  - Prompt 格式化和验证测试
  - Baseline 决策逻辑测试
  - LLM 决策和回退测试
  - 集成测试
- **Tests**: 35 passed (all L3 tests: 1360 passed)
- **Design Decisions**:
  - 模块输入格式：模块级摘要（可扩展）
  - 回退策略：混合策略（主语言 60% + 攻击面 40%）
- **Dead Code**: not run
- **Security**: not run
- **Commit**: eabf8dc

## 2026-03-21

### P6-12: Directory Classification Tests Verified

- **Goal ID**: P6-12
- **Summary**: Verified existing tests for P6-07 directory classification
- **Impact**:
  - `tests/unit/test_core/test_file_filtering.py`: 41 tests (already existed)
- **Test Coverage**:
  - DirectoryClass enum (3 tests)
  - classify_directory() function (23 tests)
  - get_score_multiplier() function (10 tests)
  - Score multipliers constants (2 tests)
  - Classification rules (3 tests)
- **Tests**: 41 passed
- **Status**: Tests already existed and passed
- **Commit**: N/A (no code changes needed)

### P6-11: Coverage Stats Tests Complete

- **Goal ID**: P6-11
- **Summary**: Unit tests for P6-06 CoverageStats and EngineStats models
- **Impact**:
  - `tests/unit/test_l3/test_coverage_stats.py`: 30 new tests
- **Test Coverage**:
  - CoverageStats creation and defaults (4 tests)
  - File coverage calculation (5 tests)
  - Target coverage calculation (5 tests)
  - Entry point coverage (4 tests)
  - Dimension matrix integration (4 tests)
  - EngineStats model (5 tests)
  - Integration scenarios (3 tests)
- **Tests**: 30 passed
- **Dead Code**: not run
- **Security**: not run
- **Commit**: pending

### P6-10: Noise Layering Tests Complete

- **Goal ID**: P6-10
- **Summary**: Unit tests for P6-04 conditional/informational subtype classification
- **Impact**:
  - `tests/unit/test_l3/test_noise_layering.py`: 35 new tests
- **Test Coverage**:
  - ConditionalSubtype: STRONG/WEAK enum (5 tests)
  - InformationalSubtype: NOT_EXPLOITABLE/SPECULATIVE_SIGNAL/ENVIRONMENTAL_RISK (5 tests)
  - Finding + ConditionalSubtype integration (6 tests)
  - Finding + InformationalSubtype integration (6 tests)
  - TaintReport models: SourceType, SinkType, SanitizerType, Controllability (8 tests)
  - Noise layering integration scenarios (5 tests)
- **Tests**: 35 passed
- **Dead Code**: not run
- **Security**: not run
- **Commit**: pending

### P6-07d: WooYun Vulnerability Case Library Import Complete

- **Goal ID**: P6-07d
- **Summary**: Imported WooYun vulnerability case library with 88,636 real cases as Agent audit reference
- **Impact**:
  - `src/layers/l3_analysis/methodology/wooyun/`: 9 case files (INDEX.md + 8 vuln types)
  - `src/layers/l3_analysis/methodology/__init__.py`: Added get_wooyun_path(), list_available_wooyun_types(), get_wooyun_stats()
  - `tests/unit/test_l3/test_methodology.py`: 26 new WooYun tests (52 total)
- **Case Distribution**: SQL injection (27,732), Unauthorized access (14,377), Logic flaws (8,292), XSS (7,532), Info disclosure (7,337), Command execution (6,826), File traversal (2,854), File upload (2,711)
- **Tests**: 52 passed
- **Dead Code**: not run
- **Security**: not run
- **Commit**: pending

## 2026-03-20

### P6-08: Multi-Language Coverage Matrix Complete

- **Goal ID**: P6-08
- **Summary**: Implemented language x engine x dimension x status coverage matrix for audit tracking
- **Impact**:
  - `src/layers/l3_analysis/coverage/__init__.py`: Module entry
  - `src/layers/l3_analysis/coverage/matrix.py`: CoverageMatrix, DimensionCoverage, CoverageStatus, DimensionType
  - `src/layers/l3_analysis/coverage/evaluator.py`: CoverageEvaluator with 3 dimension type evaluators
  - `src/layers/l3_analysis/rounds/models.py`: Added dimension_matrix field to CoverageStats
  - `tests/unit/test_l3/test_coverage_matrix.py`: 54 unit tests
- **Coverage Types**: Sink-driven (D1,D4,D5,D6), Control-driven (D3,D9), Config-driven (D2,D7,D8,D10)
- **Languages**: 10 core languages (Python, JavaScript, TypeScript, Java, Go, PHP, Ruby, C#, C++, Rust)
- **Tests**: 54 passed
- **Dead Code**: No issues found
- **Security**: No secrets exposed
- **Commit**: 086e8ec

### P6-06b: Business Logic Detection Methodology Complete

- **Goal ID**: P6-06b
- **Summary**: Created D9 dimension business logic detection methodology for Agent audits
- **Impact**:
  - `src/layers/l3_analysis/methodology/__init__.py`: Module entry with `get_methodology_path()`, `list_available_methodologies()`
  - `src/layers/l3_analysis/methodology/business_logic.md`: General methodology with 6 D9 subtypes
  - `src/layers/l3_analysis/methodology/python_business_logic.md`: Python patterns (Django/Flask/FastAPI)
  - `src/layers/l3_analysis/methodology/java_business_logic.md`: Java patterns (Spring Boot)
  - `src/layers/l3_analysis/methodology/go_business_logic.md`: Go patterns (Gin/Echo/Fiber)
  - `src/layers/l3_analysis/sinks_sources/__init__.py`: Added `BusinessLogicCategory` enum
  - `tests/unit/test_l3/test_methodology.py`: 26 unit tests
- **D9 Subtypes**: IDOR, Mass Assignment, State Machine, Race Condition, Data Export, Multi-tenant
- **Tests**: 26 passed
- **Dead Code**: No issues found
- **Security**: No secrets exposed
- **Commit Status**: pending

### P6-07: Directory Classification Complete

- **Goal ID**: P6-07
- **Summary**: Implemented directory classification and score multiplier for non-production code
- **Impact**:
  - `src/core/file_filtering.py`: Added `DirectoryClass` enum, `classify_directory()`, `get_score_multiplier()`
  - `src/layers/l3_analysis/models.py`: Added `directory_class`, `score_multiplier` fields to `Finding`
  - `src/core/final_score.py`: Added `directory_multiplier` to `FinalScore`, updated calculation functions
  - `src/core/config/__init__.py`: Added configuration functions for directory classification
  - `config.example.toml`: Added `[directory_classification]` configuration section
  - `tests/unit/test_core/test_file_filtering.py`: New test file with 41 tests
- **Tests**: 41 tests passed for file_filtering, 58 tests passed for final_score
- **Dead Code**: not run
- **Security**: not run
- **Commit Status**: not committed

### AI Workflow Adoption Complete

- **Goal ID**: adopt-workflow
- **Summary**: Adopted AI workflow into existing DeepVuln project
- **Impact**:
  - Updated `docs/ai/project-summary.md` with actual project state
  - Updated `docs/ai/project-tree.md` with directory structure
  - Synced `docs/ai/roadmap.md` from `docs/ROADMAP.md` with status corrections
  - Updated `docs/ai/constraints/project.md` with project-specific constraints
  - Removed duplicate `docs/ROADMAP.md` and `docs/CURRENT_GOAL.md`
  - Created goal candidates for P6-06b, P6-07, P6-08
- **Tests**: structure verification passed
- **Dead Code**: not run
- **Security**: not run
- **Commit Status**: not committed

### Status Corrections Made

During adoption, discovered that roadmap task status was outdated:
- P6-03 Evidence Strength: marked todo → **done** (verified in models.py)
- P6-04 Status Subtypes: marked todo → **done** (verified in models.py, taint_report.py)
- P6-05 Sink/Source Library: marked todo → **done** (verified in sinks_sources/ module)
- P6-06 Coverage Stats: marked todo → **partial** (CoverageStats done, D9 pending)

### Next Recommended Commands

- `/ai-sync` - Sync workflow state after goal completion
- `/ai-roadmap` - Review or update the roadmap
- `/ai-goal` - Select next goal (P6-06b or P6-08)

## 2026-03-19

- Goal ID: bootstrap
- Summary: Initialized the Claude Code workflow skeleton.
- Impact: `docs/ai`, `.claude/commands`, `.claude/skills`, `.claude/agents`
- Tests: structure verification pending
- Dead Code: not run
- Security: not run
- Commit Status: not committed
