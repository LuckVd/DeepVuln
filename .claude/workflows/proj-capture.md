# Proj-Capture Workflow

1. Read `CURRENT_GOAL.yaml` and `CURRENT_TASKS.yaml`.
2. Detect whether the invocation is structured flags or a freeform interrupt description.
3. Infer `type`, `priority`, and `decision` when the input is freeform.
4. Add the item to `INBOX.yaml`.
5. Mark the current goal as `interrupted` when the item is an immediate interrupt.
6. Refresh task-board visibility so the next `/proj-readproject` call surfaces the interrupt clearly.
