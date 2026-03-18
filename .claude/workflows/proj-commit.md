# Proj-Commit Workflow

1. Confirm the user explicitly asked for `/proj-commit`.
2. Refresh the latest change intent reference.
3. Run authorization, protection, scope, goal, task-board, cleanup, and structure-sync checks.
4. Run API review when needed.
5. Write `docs/reports/commit-gate-latest.md` as a derived gate record.
6. Stop if unresolved cleanup items or unfinished checkpoints remain.
7. Commit only after the gate passes.
