Manage the long-term roadmap in `docs/ai/roadmap.md`.

Respond in Chinese for all user-facing natural language output. Keep commands, file paths, and code identifiers in their original form.

Use these skills when needed:

- `constraints-loader`

Steps:

1. Read `roadmap.md`, `current-goal.md`, and `current-goal.state.yaml`.
2. Update roadmap items based on user intent and current project reality.
3. Keep exactly one active current goal outside the roadmap execution queue.
4. Support insert, reorder, revise, defer, complete, or drop actions.
5. Reflect completed goals in `Done` and future work in `Next` or `Later`.

Guardrails:

- Ask before making material roadmap changes that were not requested.
- Keep entries concise and implementation-oriented.
- Honor any loaded human-editable constraints when producing the response.
