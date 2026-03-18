# Governance Core Files

| Path | Role | Sync Requirement |
|---|---|---|
| `.claude/CONSTITUTION.md` | top-level workflow rules | update `docs/context/structure/README.md` when rules change |
| `.claude/commands/**` | command contracts | update command docs and structure docs when behavior changes |
| `.claude/workflows/**` | workflow steps | update workflow docs and structure docs when behavior changes |
| `.claude/policies/**` | policy sources for checks and scope control | update related checks and structure docs when policy semantics change |
| `.claude/templates/**` | reusable framework templates | update init/adopt docs when template semantics change |
| `tools/*.sh` | local execution helpers | update structure docs and relevant README sections when behavior changes |
