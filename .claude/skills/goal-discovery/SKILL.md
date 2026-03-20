# goal-discovery

Use this skill when `/ai-goal` needs to inspect the current workspace before proposing options.

Use Chinese for all user-facing natural language output. Keep commands, file paths, and code identifiers in their original form.

Workflow:

1. Read the default files in `docs/ai/`.
2. Inspect the real repository structure and detect missing code, tests, or docs relevant to the current request.
3. Identify whether an active goal already exists.
4. If the workspace is effectively empty for the requested work, prepare concrete options for the user.
5. If workflow docs do not match the repository, stop and ask the user whether to sync them.

Output:

- current state
- gaps
- blockers
- recommended next step
