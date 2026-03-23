# Current Goal

## Status

Completed - 2026-03-23

## Goal

P6-15: Stability and Packaging Bug Fixes

## Summary

Completed the repository bugfix pass identified during full review. The repair set fixed agent multi-language file targeting, eliminated threat-intel CLI event-loop leakage, stabilized incremental tests under Python 3.12 full-suite execution, and restored packaging metadata by adding the missing README target.

## Scope

| Item | Content |
|------|------|
| **Problem** | The repo had correctness and stability defects after P6-14, including scan coverage loss, event-loop contamination, brittle tests, and broken packaging metadata |
| **Focus Areas** | agent file targeting, CLI asyncio lifecycle hygiene, incremental test reliability, packaging metadata consistency |
| **Implementation Files** | src/cli/main.py, src/cli/intel.py, tests/unit/test_l3/test_incremental.py, tests/unit/test_cli/test_main.py, tests/unit/test_cli/test_intel.py, README.md |

## Deliverables

| File | Status |
|------|------|
| src/cli/main.py | updated |
| src/cli/intel.py | updated |
| tests/unit/test_l3/test_incremental.py | updated |
| tests/unit/test_cli/test_main.py | updated |
| tests/unit/test_cli/test_intel.py | added |
| README.md | added |
| docs/ai/roadmap.md | updated |

## Acceptance Criteria

1. Agent file selection includes all detected languages instead of silently degrading on `LanguageInfo` objects.
2. Threat-intel CLI async helpers do not leave the process with a closed current event loop.
3. Incremental test fixtures are stable under Python 3.12 and full-suite execution.
4. Packaging metadata points to a real README file.
5. Relevant targeted tests and a full regression run pass.

## Implementation Steps

| Step | Task | Status |
|------|------|------|
| S1 | Confirm the previous goal is complete and update roadmap/current-goal docs for the bugfix pass | completed |
| S2 | Fix agent multi-language file targeting in full scans | completed |
| S3 | Fix CLI event-loop lifecycle handling and incremental-test loop setup | completed |
| S4 | Restore packaging metadata consistency by adding the missing README target | completed |
| S5 | Run targeted and full regression tests, then sync docs with final results | completed |

## Validation

| Command | Result |
|--------|--------|
| pytest -q tests/unit/test_cli/test_main.py tests/unit/test_cli/test_intel.py tests/unit/test_l3/test_incremental.py | 93 passed |
| pytest -q | 2165 passed, 7 skipped |

## Key Changes

1. Added `_normalize_detected_language_name()` so full-scan agent file selection correctly handles `LanguageInfo` objects from the tech-stack detector.
2. Updated `src/cli/intel.py::run_async()` to restore the previous event loop instead of leaving a closed loop registered globally.
3. Replaced the incremental test fixture's implicit `get_event_loop()` usage with `asyncio.run()` and added CLI loop-management regression tests.
4. Added a root `README.md` so `pyproject.toml` points at a real file during packaging.

## References

- src/cli/main.py
- src/cli/intel.py
- tests/unit/test_l3/test_incremental.py
- tests/unit/test_cli/test_main.py
- tests/unit/test_cli/test_intel.py
- README.md
- docs/ai/roadmap.md
