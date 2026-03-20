# init-from-proposal

Use this skill when `/ai-init` receives a long technical roadmap / blueprint document or a repository-local roadmap path.

Use Chinese for all user-facing natural language output. Keep commands, file paths, and code identifiers in their original form.

Goals:

- bootstrap a blank or near-blank repository from a technical roadmap blueprint
- initialize planning docs without generating business implementation code
- extract candidate first goals without locking one in

Required extraction:

- overall technical objective
- core modules and boundaries
- roadmap goals and subgoals
- dependency relationships
- project-specific constraints
- candidate current goals

Write targets:

- `docs/ai/roadmap.md`
- `docs/ai/current-goal.md`
- `docs/ai/current-goal.state.yaml`
- `docs/ai/project-summary.md`
- `docs/ai/constraints/project.md`

Rules:

- planning docs only
- no business code
- no automatic current-goal selection
- keep candidates concise and executable
- treat `roadmap.md` as the primary long-term design document
