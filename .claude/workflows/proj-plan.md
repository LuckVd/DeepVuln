# Proj-Plan Workflow

1. Read `CONSTITUTION.md`, `CURRENT_GOAL.yaml`, `CURRENT_TASKS.yaml`, `INBOX.yaml`, and `ROADMAP.md`.
2. Detect whether the invocation is structured flags or a freeform planning description.
3. Infer `mode`, `title`, `objective`, `work_type`, tasks, and checkpoints from freeform input when needed.
4. Rewrite `CURRENT_GOAL.yaml` and `CURRENT_TASKS.yaml`.
5. Attach required structure-sync docs based on `work_type`.
6. Optionally archive replaced goal or roadmap files.
7. Write `docs/reports/plan-current-latest.md` as a derived planning record.
