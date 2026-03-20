Refresh the repository summary for Claude and the user.

Respond in Chinese for all user-facing natural language output. Keep commands, file paths, and code identifiers in their original form.

Use these skills when needed:

- `constraints-loader`
- `project-fit-check`

Steps:

1. Read the default workflow files in `docs/ai/`.
2. Inspect the current repository structure and key entry points.
3. Update `project-summary.md` and `project-tree.md` to match the real codebase.
4. If workflow docs disagree with the codebase, pause and ask whether to sync them.
5. Keep the summary layer compact. Put only stable, high-signal facts there.

Guardrails:

- Do not add speculative architecture.
- Do not create detailed implementation docs unless needed by the active goal.
