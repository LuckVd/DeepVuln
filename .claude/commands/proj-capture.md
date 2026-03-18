# `/proj-capture`

直接执行临时事项捕获命令，原生支持长文本事项描述。

## Execution

If the user provides structured flags, pass them through directly.

If the user provides a freeform description, run:

```bash
tools/proj_capture.sh <freeform brief>
```

Behavior:
- infer `title`, `type`, `priority`, and `decision`
- default to a follow-up when the text is ambiguous

Return the helper output and mention any interruption to the current goal if it occurs.
