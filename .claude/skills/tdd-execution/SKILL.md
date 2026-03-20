# tdd-execution

Use this skill when the current goal enters implementation.

Use Chinese for all user-facing natural language output. Keep commands, file paths, and code identifiers in their original form.

Rules:

- Start from a failing or missing test case whenever feasible.
- Keep the test scope tied to the current goal.
- Alternate between test updates and implementation updates.
- If tests fail, continue fixing until the current-goal-related test set passes.
- Do not claim completion while relevant tests still fail.

Always verify:

- the change matches the goal
- the change fits existing project structure
- the tests prove the intended behavior
