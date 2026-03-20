# project-fit-check

Use this skill to prevent isolated implementations that do not integrate with the real project.

Use Chinese for all user-facing natural language output. Keep commands, file paths, and code identifiers in their original form.

Check for:

- duplicate abstractions
- bypassed project conventions
- one-off modules that should extend existing code
- changes that do not align with existing naming or layering

When a problem is found:

1. Describe the mismatch.
2. Explain the integration point that should be used instead.
3. Stop and ask before proceeding if the design needs to change.
