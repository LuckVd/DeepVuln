Synchronize workflow state after a goal has been implemented and verified.

Respond in Chinese for all user-facing natural language output. Keep commands, file paths, and code identifiers in their original form.

Use these skills when needed:

- `constraints-loader`
- `sync-and-history`
- `security-secrets-scan`
- `dead-code-detection`

Steps:

1. Confirm that current-goal-related tests have passed.
2. Update `roadmap.md`, `current-goal.md`, `current-goal.state.yaml`, and `change-log.md`.
3. Write the current goal result back into the roadmap table, including status, dependency-relevant notes, test status, implementation date, and commit id if one exists.
4. Summarize the completed work, impact area, test result, dead-code result, and security result.
5. Show the user a proposed commit message.
6. Ask for explicit confirmation before any `git add`, `git commit`, or `git push`.
7. If the user approves commit, create the local commit.
8. If the user approves push, try to push to the configured remote.
9. If remote push fails, report the failure and keep the local commit.

Guardrails:

- Never commit or push without explicit confirmation.
- Security blockers stop the commit/push flow unless the user explicitly overrides them.
- Push failure does not roll back a local commit.
- Honor any loaded human-editable constraints when producing the response.
