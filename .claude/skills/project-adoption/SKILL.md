# project-adoption

Use this skill for `/ai-adopt` when embedding the workflow into an existing in-development repository.

Use Chinese for all user-facing natural language output. Keep commands, file paths, and code identifiers in their original form.

Keep the workflow lightweight. Do not repeat generic scan or roadmap behavior that already belongs to other commands.

Responsibilities:

- classify the repository adoption state
- structure a compact adoption report
- generate small, realistic current-goal candidates

Adoption state:

- `not_adopted`: `.claude/` or `docs/ai/` are missing
- `partial`: workflow files exist but are incomplete, template-like, or not aligned with the repository
- `adopted`: workflow files exist and already reflect the repository well enough to continue
- `conflict`: an existing workflow or document set would be risky to overwrite or merge without user confirmation

Report format:

- `Adoption State`: one of the states above
- `Detected Stack`: only high-confidence stack or runtime facts
- `Safe To Create`: missing workflow files or directories that can be added safely
- `Needs Confirmation`: files or assumptions that should not be updated silently
- `Conflicts`: only real overlap or overwrite risk
- `Open Questions`: only questions that materially affect roadmap or goal setup
- `Recommended Next Command`: usually `/ai-roadmap` or `/ai-goal`

Goal candidate rules:

- prefer 2-3 candidates maximum
- prefer small, reviewable, testable work
- prefer goals that align with the current repository stage
- avoid goals that require broad refactors or unclear product decisions
- if the repository context is too weak, ask for clarification instead of inventing goals

Guardrails:

- do not rewrite meaningful existing documents without confirmation
- do not treat inferred business intent as fact
- do not enter implementation
