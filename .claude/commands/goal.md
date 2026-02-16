# `/goal` Command

> 管理当前开发目标 — 查看状态、设置目标、标记完成

---

## 用法

```bash
/goal                    # 查看当前目标
/goal set <任务描述>      # 设置新目标
/goal done               # 标记当前目标完成
/goal block <原因>       # 标记目标阻塞
/goal unblock            # 解除阻塞状态
```

---

## 执行流程

### `/goal` — 查看当前目标

1. 读取 `docs/CURRENT_GOAL.md`
2. 输出目标详情

**输出格式**:

```
📌 Current Goal

Task: 实现用户登录 API
Status: in_progress
Priority: high
Created: 2026-02-15

Completion Criteria:
- 登录 API 通过测试，返回正确 token

Related Modules:
- backend-features

Progress:
| Time | Progress |
|------|----------|
| 2026-02-15 10:00 | Started implementation |
| 2026-02-15 14:30 | Added login endpoint |

Notes:
- 需要 DBA 配置数据库权限
```

**无目标时**:

```
💡 No Active Goal

Set a new goal to track your progress:
/goal set <task description>
```

---

### `/goal set <任务描述>` — 设置新目标

1. 检查是否存在进行中的目标
2. 若存在，询问是否覆盖
3. 收集目标详情（可选）
4. 更新 `docs/CURRENT_GOAL.md`
5. 输出确认

**询问格式**:

```
🎯 Setting New Goal

Current goal in progress:
- 实现用户登录 API (in_progress)

Do you want to replace it? [y/N]

If yes, the current goal will be marked as abandoned.
```

**收集信息**:

```
📝 Goal Details

Task: 实现用户注册 API
Priority: [high/medium/low] (default: medium)
Completion Criteria: 注册 API 通过测试，返回用户信息
Related Modules: backend-features
Notes: (optional)

Confirm goal? [Y/n]
```

**确认输出**:

```
✅ New Goal Set

Goal: 实现用户注册 API
Status: in_progress
Priority: high
Created: 2026-02-15

Completion Criteria:
- 注册 API 通过测试，返回用户信息

Related Modules:
- backend-features

Now tracking progress. Use /commit to record progress.
```

---

### `/goal done` — 标记完成

1. 读取 `docs/CURRENT_GOAL.md`
2. 确认完成
3. 更新 `docs/CURRENT_GOAL.md`
4. 询问下一个目标

**确认格式**:

```
🎉 Mark Goal as Completed?

Current Goal: 实现用户登录 API
Status: in_progress
Created: 2026-02-15
Progress: 3 commits

Completion Criteria:
- 登录 API 通过测试，返回正确 token

Did you meet all completion criteria? [y/N]
```

**确认后输出**:

```
✅ Goal Completed!

Updated docs/CURRENT_GOAL.md:
- Status: in_progress → completed
- Completed at: 2026-02-15

Total Progress:
- 3 commits
- Duration: 5 hours

What's your next goal?
→ _
```

---

### `/goal block <原因>` — 标记阻塞

1. 读取 `docs/CURRENT_GOAL.md`
2. 更新状态为 `blocked`
3. 记录阻塞原因
4. 输出确认

**输出格式**:

```
🚧 Goal Blocked

Goal: 实现用户登录 API
Status: in_progress → blocked

Blocked Reason:
- 等待 DBA 配置数据库权限

Progress recorded. Use /goal unblock when resolved.
```

**CURRENT_GOAL.md 更新**:

```markdown
## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | 实现用户登录 API |
| **状态** | blocked |
| **优先级** | high |
| **创建日期** | 2026-02-15 |

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-02-15 10:00 | Started implementation |
| 2026-02-15 14:30 | 🚧 阻塞：等待 DBA 配置数据库权限 |
```

---

### `/goal unblock` — 解除阻塞

1. 读取 `docs/CURRENT_GOAL.md`
2. 检查是否为 `blocked` 状态
3. 更新为 `in_progress`
4. 输出确认

**输出格式**:

```
✅ Goal Unblocked

Goal: 实现用户登录 API
Status: blocked → in_progress

You can continue working on this goal.
```

---

## 目标状态流转

```
        ┌─────────────────┐
        │   (无目标)       │
        └────────┬────────┘
                 │ /goal set
                 ▼
        ┌─────────────────┐
        │  in_progress    │◄──────────┐
        └────────┬────────┘           │
                 │                    │
       ┌─────────┼─────────┐          │
       │         │         │          │
       ▼         ▼         │          │
┌──────────┐ ┌──────────┐  │          │
│completed │ │ blocked  │──┼──────────┘
└──────────┘ └──────────┘  │ /goal unblock
       │                   │
       │ /goal set         │
       ▼                   │
  (设置新目标)              │
                           │
                   /goal done
```

---

## CURRENT_GOAL.md 更新规则

### 设置新目标

```markdown
## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | <任务描述> |
| **状态** | in_progress |
| **优先级** | <priority> |
| **创建日期** | YYYY-MM-DD |

## 完成标准

<completion criteria>

## 关联模块

- <related modules>

## 进度记录

| 时间 | 进展 |
|------|------|
| - | （自动追加） |

## 备注

<notes>
```

### 标记完成

```markdown
## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | <任务描述> |
| **状态** | completed |
| **优先级** | <priority> |
| **创建日期** | YYYY-MM-DD |
| **完成日期** | YYYY-MM-DD |

## 进度记录

| 时间 | 进展 |
|------|------|
| ... | ... |
| YYYY-MM-DD | ✅ 完成目标 |
```

---

## 与 /commit 命令集成

- `/commit` 执行时会调用 goal-tracker 检查目标进度
- 提交时可选择标记目标完成
- 进度自动追加到 `docs/CURRENT_GOAL.md`

---

## 禁止行为

- 未经确认覆盖进行中的目标
- 自动设置新目标
- 删除历史进度记录
- 跳过完成确认直接标记完成
