# `/proj-plan`

直接执行当前目标与任务板规划命令，原生支持长文本规划描述。

## Execution

If the user provides structured flags, pass them through directly.

If the user provides a freeform planning description, run:

```bash
tools/proj_plan.sh <freeform brief>
```

Behavior:
- infer `mode`, `title`, `objective`, and `work_type`
- split sentences into tasks and checkpoints
- treat review/confirm/approve style sentences as checkpoints

Return the helper output and summarize the resulting goal title, work type, and task-board changes.
