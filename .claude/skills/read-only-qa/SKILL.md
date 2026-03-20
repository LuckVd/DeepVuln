# read-only-qa

Use this skill for `/ai-ask`.

Use Chinese for all user-facing natural language output. Keep commands, file paths, and code identifiers in their original form.

Read-only contract:

- may read source files, configs, docs, and workflow files
- may summarize or explain repository behavior
- may point out inconsistencies
- must not modify files
- must not update workflow state
- must not trigger commit, push, or sync behavior

Response rules:

- answer the actual question first
- cite relevant paths when they materially help
- if the user needs a change, redirect to the correct write-capable workflow command
