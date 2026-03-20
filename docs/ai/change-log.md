# Change Log

## 2026-03-20

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
