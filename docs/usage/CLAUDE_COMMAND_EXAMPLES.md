# Claude Command Examples

This page shows the intended direct command flow inside Claude. Use the `/proj-*` commands directly rather than describing the helper scripts.

## Start A Session

Read the current project state:

```text
/proj-readproject
```

Expected use:
- get the current execution snapshot
- inspect the active focus and readiness
- choose the next action

Read the full context when needed:

```text
/proj-readproject 看完整上下文
```

Adopt an existing repository:

```text
/proj-adopt 接管 /path/to/existing-project，当前目标先收尾支付主流程
```

## Create Or Rebuild A Workspace

Initialize from a design brief:

```text
/proj-init --source docs/design/brief.md
```

Initialize directly from a long description:

```text
/proj-init 我想创建一个 TypeScript 后端服务，用于管理认证流程。第一阶段只做邮箱密码登录，后续再扩展注册和找回密码。
```

Use this when:
- starting a new governed project
- reinitializing after a major design change

## Plan Work

Create a plan directly from a long description:

```text
/proj-plan 我想把登录功能拆成一个最小切片。先实现邮箱密码登录接口，再确认返回结构，最后补 API 文档。
```

Adjust the current goal:

```text
/proj-plan --mode adjust --title "Refine auth flow" --objective "Reduce scope to login only" --work-type refactor --checkpoint "Review reduced API surface"
```

## Inspect And Update Tasks

List current tasks and checkpoints:

```text
/proj-task 列出任务
```

Start a task:

```text
/proj-task 开始 task-001
```

Close a user checkpoint:

```text
/proj-task 完成 ucp-001，备注 用户已确认范围
```

Block a task:

```text
/proj-task 阻塞 task-002，等待接口确认
```

## Capture Interrupts

Record a follow-up:

```text
/proj-capture --title "Review login copy"
```

Record directly from a long description:

```text
/proj-capture 登录接口现在 token 过期后会返回 401，但前端没有正确提示用户重新登录，这个问题今天需要处理。
```

Record an interrupt that must happen now:

```text
/proj-capture --type interrupt --title "Fix auth regression" --decision do_now
```

## Check And Commit

Run the active gates:

```text
/proj-check
```

Run the commit gate after explicit user approval:

```text
/proj-task 完成 ccp-001，备注 用户已批准提交
/proj-commit
```

## Recommended Daily Flow

```text
/proj-readproject
/proj-task 列出任务
/proj-plan ...        # when a new slice or scope change is needed
/proj-task ...        # mark task start/progress/blockers
/proj-check
/proj-commit
```

Use parameter mode only when you need exact control over fields such as `--target`, `--status`, or `--note`. `proj-check` and `proj-commit` are intended to run without extra user-facing parameters.
