# Structure Constraints

This directory defines the enforceable structure and synchronization rules for the project.

## Fact Sources

- `STRUCTURE_CONTRACT.yaml`: allowed paths, module roles, and sync obligations
- `SYNC_RULES.yaml`: change-triggered documentation sync rules

## Human Summary

- `.claude/` and `tools/` are governance-core and require structure doc updates when changed.
- `docs/goals/`, `docs/roadmap/`, and `docs/history/` are planning-state.
- `src/` is the runtime code area and must sync file, function, API, and model docs as applicable.
