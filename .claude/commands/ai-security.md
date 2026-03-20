Inspect the codebase and pending changes for secret-handling and obvious security issues.

Respond in Chinese for all user-facing natural language output. Keep commands, file paths, and code identifiers in their original form.

Use these skills when needed:

- `security-secrets-scan`
- `constraints-loader`

Focus on:

- Hard-coded keys, tokens, passwords, or private key fragments
- Sensitive values in config files, Dockerfiles, compose files, or env files
- Values likely to be committed accidentally

Required output:

- Location
- Secret or risk type
- Why it is risky
- Recommended remediation
- Whether it should block sync and commit

Guardrails:

- Use high-confidence findings by default.
- Treat active secret exposure as a release blocker for `/ai-sync`.
