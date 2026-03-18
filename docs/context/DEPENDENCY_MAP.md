# Dependency Map

## Allowed High-Level Dependencies

- `tools/**` may depend on project state files under `docs/goals/**` and `docs/roadmap/**`
- `.claude/**` defines policies and workflows; it should not depend on runtime `src/**`
- `src/**` may depend on internal runtime modules, but governance docs must not depend on runtime code to remain readable without execution

## Current State

- No runtime dependency graph is defined yet because `src/` is still empty.
