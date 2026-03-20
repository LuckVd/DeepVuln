Run a workflow health check for the active goal.

Respond in Chinese for all user-facing natural language output. Keep commands, file paths, and code identifiers in their original form.

Use these skills when needed:

- `project-fit-check`
- `constraints-loader`
- `security-secrets-scan`

Check for:

1. Missing or stale workflow files.
2. Mismatch between `current-goal.md` and `current-goal.state.yaml`.
3. Missing acceptance criteria or test plan.
4. Implementation drift from project conventions.
5. Security blockers that should stop sync.
6. Open questions that still block implementation.

Output:

- Findings first, ordered by severity.
- Then the exact next action needed.
