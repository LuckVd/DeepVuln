# `/proj-adopt`

将 ClaudeDevKit 接入一个已经开发中的项目目录。

## Execution

When this command is invoked, run:

```bash
tools/proj_adopt.sh --target <project-path>
```

If the user also provides a current delivery target, pass it through with:

```bash
tools/proj_adopt.sh --target <project-path> --goal-title "<goal>"
```

Behavior:
- copy the full ClaudeDevKit governance layer into the target repository, including `.claude/**`, `tools/**`, and command usage examples
- infer project language, type, and active module paths from the live repository
- generate an adoption brief inside the target repository
- run `tools/proj_init.sh --mode adopt` in the target repository

Return the helper output and clearly state that historical work before adoption is summarized as context rather than reconstructed as completed tasks.
