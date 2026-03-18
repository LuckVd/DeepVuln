# `/proj-commit`

直接执行提交 gate 命令。

## Execution

Run the helper with no user-facing arguments:

```bash
tools/proj_commit.sh
```

The helper itself must confirm commit authorization from the current task board state. Return the helper output summary and explicitly call out authorization, task-board, and structure-sync failures when present.
