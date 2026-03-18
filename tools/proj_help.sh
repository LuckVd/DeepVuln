#!/usr/bin/env bash
set -euo pipefail

cat <<'EOF'
# ClaudeDevKit Help

| Command | Purpose | Typical Use |
|---|---|---|
| `/proj-help` | 查看命令速查 | 忘记命令时 |
| `/proj-init` | 初始化或重构工作区 | 新项目或大改版 |
| `/proj-adopt` | 把 ClaudeDevKit 接入一个已有项目 | 直接说“接管 /path/to/project” |
| `/proj-readproject` | 默认输出执行快照，支持“看完整上下文” | 新会话开始时 |
| `/proj-capture` | 记录插单、bug、想法 | 中途出现临时事项时 |
| `/proj-plan` | 规划或调整当前 goal 和 task board | 开工前或范围变化时 |
| `/proj-task` | 查看或更新 task/checkpoint | 直接说“开始 task-001” |
| `/proj-check` | 运行当前 gate 检查 | 直接执行即可 |
| `/proj-commit` | 唯一合法提交入口 | 用户确认 `ccp-001` 后直接执行 |

默认直接用自然语言，不必先拼参数。只有需要精确控制时再使用 `--target`、`--status`、`--note` 这类参数。

## References

- Overview: `README.md`
- Examples: `docs/usage/CLAUDE_COMMAND_EXAMPLES.md`
- Source of truth: `.claude/project.yaml`, `docs/goals/CURRENT_GOAL.yaml`, `docs/goals/CURRENT_TASKS.yaml`
EOF
