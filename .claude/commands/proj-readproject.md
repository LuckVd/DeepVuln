# `/proj-readproject`

直接执行项目读取命令。

默认输出执行快照，适合快速判断当前状态和下一步动作。需要完整上下文时，使用 `--full`。

## Execution

When this command is invoked, run:

```bash
tools/proj_readproject.sh
```

For the full context view, run:

```bash
tools/proj_readproject.sh --full
```

Return the command output directly, then answer follow-up questions against that state.
