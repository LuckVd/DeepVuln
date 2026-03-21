# Change Log

## 2026-03-21

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
