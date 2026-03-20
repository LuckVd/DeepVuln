# AI Workflow

This repository uses a lightweight Claude Code workflow.

Shared state lives in this directory. Process behavior lives under `.claude/`.

Default read set:

- `project-tree.md`
- `roadmap.md`
- `current-goal.md`
- `current-goal.state.yaml`
- `change-log.md`

Rules:

- Do not auto-commit or auto-push.
- Do not create isolated code that does not fit the existing project.
- If workflow docs disagree with the codebase, ask the user whether to sync the docs.
- Only one active current goal is allowed at a time.

Slash commands:

- `/ai-help`
- `/ai-ask`
- `/ai-init`
- `/ai-adopt`
- `/ai-scan`
- `/ai-roadmap`
- `/ai-goal`
- `/ai-check`
- `/ai-sync`
- `/ai-deadcode`
- `/ai-security`

Command intent:

- `/ai-help` explains the workflow, shows current state, and recommends the next command.
- `/ai-ask` is strictly read-only and cannot modify files or workflow state.
- `/ai-init` can initialize a blank or near-blank project from a long technical roadmap document or a repository-local roadmap blueprint file.
- `/ai-adopt` can safely embed this workflow into an existing in-development repository and stop before implementation.

Document roles:

- `roadmap.md` is the single source of truth for overall technical design and long-term progress.
- `current-goal.md` is the execution document for the active goal, with steps, tasks, blockers, and sync notes.
- `project-summary.md` is optional shorthand context derived from the roadmap when useful.

Human-editable constraints live in `constraints/`. Claude-native behavior lives in `.claude/skills` and `.claude/agents`.
