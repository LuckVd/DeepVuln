# Change Log

## 2026-03-25

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
