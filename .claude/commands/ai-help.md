Explain the workflow in a concise, actionable format.

Respond in Chinese for all user-facing natural language output. Keep commands, file paths, and code identifiers in their original form.

Use these skills when needed:

- `constraints-loader`
- `help-router`

Output requirements:

1. A markdown table with every workflow command.
2. For each command, include:
   - command name
   - purpose
   - whether it is read-only
   - when to use it
   - one short example
3. A current state summary based on workflow files.
4. A recommendation for the single best next command and why.

Commands to include:

- `/ai-help`
- `/ai-ask`
- `/ai-init`
- `/ai-scan`
- `/ai-roadmap`
- `/ai-goal`
- `/ai-check`
- `/ai-sync`
- `/ai-deadcode`
- `/ai-security`

Guardrails:

- Prefer the current workflow state over generic advice.
- If no goal is active, explain that clearly.
- Honor any loaded human-editable constraints when producing the response.
