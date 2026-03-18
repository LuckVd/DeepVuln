# `/proj-init`

直接执行工作区初始化命令，原生支持长文本项目描述。

## Execution

If the user provides structured flags, pass them through directly.

If the user provides a freeform project description, treat the whole text as a native init brief and run:

```bash
tools/proj_init.sh <freeform brief>
```

Behavior:
- infer project name, type, language, current goal, and roadmap seed from the text
- build a temporary init brief
- execute the real init helper

Return the helper output and highlight generated or updated state files when relevant.
