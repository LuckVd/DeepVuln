Detect high-confidence dead code in the current project.

Respond in Chinese for all user-facing natural language output. Keep commands, file paths, and code identifiers in their original form.

Use these skills when needed:

- `constraints-loader`
- `dead-code-detection`
- `project-fit-check`

Scope:

- Code that is unreachable.
- Code that has no references or execution path.
- Code that is clearly unrelated to the current project goal.

Required output for each finding:

- Location
- Why it looks dead
- Confidence level
- Risk of removal
- Suggested next action

After reporting findings, ask the user how to proceed:

- clean it up now
- leave it for now
- convert the missing related capability into a future roadmap item

Guardrails:

- Use a conservative threshold.
- Avoid deleting or rewriting code in this command unless the user explicitly asks.
- Honor any loaded human-editable constraints when producing the response.
