# DeepVuln AI Workflow Commands

This project includes custom AI workflow commands. Use them by typing the command name (e.g., `ai-help`) directly in your prompt.

## Available Commands

| Command | Purpose | Read-only |
|---------|---------|-----------|
| `/ai-help` | Show this command table and current state | Yes |
| `/ai-init` | Initialize or repair the workflow skeleton | No |
| `/ai-scan` | Refresh repository summary | No |
| `/ai-roadmap` | Manage the long-term roadmap | No |
| `/ai-goal` | Drive the current-goal workflow | No |
| `/ai-check` | Run a health check for the active goal | Yes |
| `/ai-sync` | Sync state after goal completion | No |
| `/ai-deadcode` | Detect dead code | Yes |
| `/ai-security` | Scan for secrets/security issues | Yes |
| `/ai-adopt` | Adopt this workflow into an existing repo | No |
| `/ai-notes` | Read or append to AI notes | No |
| `/ai-bugfix` | Fix bugs with analysis, proposal, and verification | No |

## Current State

Run `/ai-help` to see the current workflow state and get a recommendation for the next command.
