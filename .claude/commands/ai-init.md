Initialize or repair the lightweight AI workflow skeleton for this repository.

Respond in Chinese for all user-facing natural language output. Keep commands, file paths, and code identifiers in their original form.

Use these skills when needed:

- `init-from-proposal`
- `constraints-loader`

Steps:

1. Verify that `docs/ai` and `.claude/{commands,skills,agents}` exist.
2. If core workflow files are missing, create or restore them with the repository templates.
3. If the repository is empty or nearly empty, accept either:
   - a long pasted technical roadmap / blueprint document
   - a repository-local path to a technical roadmap / blueprint document
4. Parse the roadmap blueprint into:
   - overall technical objective and boundaries
   - architecture and module plan
   - milestone goals and subgoals
   - dependency relationships
   - initial project constraints
   - candidate first goals
5. Write or update planning documents only:
   - `roadmap.md`
   - `current-goal.md`
   - `current-goal.state.yaml`
   - `project-summary.md`
   - `constraints/project.md`
6. Do not auto-select the first current goal. Produce candidates and let `/ai-goal` finalize one.
7. Do not overwrite filled-in project content unless the user asks.
8. Summarize what was created, repaired, or initialized from the roadmap blueprint.

Guardrails:

- Never commit or push.
- Treat workflow files as shared state.
- If files already contain meaningful content, preserve it.
- Do not generate business implementation code during roadmap-based initialization.
