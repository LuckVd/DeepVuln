# Constitution

这是项目最高优先级规则。任何 workflow 都必须先遵守这里，再执行其他说明。

## Non-Negotiable Rules

1. 只有用户明确触发 `/proj-commit` 时，才允许执行 `git commit`。
2. 修改 `core` 文件前必须先停下并征求确认。
3. 修改 `stable` 文件前必须先给出修改提案。
4. 没有明确的 `acceptance_criteria`，不得宣称任务完成。
5. 没有 `change intent`，不得开始实施代码变更。
6. 遇到 API、schema、migration 相关变更时，必须进入额外检查。
7. 当计划或目标发生调整时，必须同步清理已经失效的内容，禁止保留明显冗余。

## Mandatory Checkpoints

- `/proj-init` 前：确认输入来源和不确定项
- `/proj-readproject` 前：读取当前目标、任务板和 inbox
- `/proj-plan` 前：确认这是新规划还是中途调整
- `/proj-check` 前：读取最新 change intent
- `/proj-commit` 前：再次确认提交授权、目标验收、冗余清理
