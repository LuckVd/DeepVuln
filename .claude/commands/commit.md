# `/commit` Command

> Git 提交流程 + Skills 集成 + 自动更新状态文件

---

## ⚠️ 核心规则（必须遵守）

### 1. 唯一提交入口

**只有用户执行 `/commit` 命令时才能执行 `git commit`。**

- ❌ 禁止在其他任何时候手动执行 `git commit`
- ❌ 禁止在代码编写完成后自动提交
- ❌ 禁止在修复问题后自动提交

### 2. 单次提交原则

**每次 `/commit` 只产生一个 commit。**

所有变更（代码、文档、配置）必须在同一次提交中完成：
- Stage 所有相关文件
- 执行一次 `git commit`
- 更新所有状态文件后 amend 到同一个 commit（可选）

### 3. 失败处理

**当 `/commit` 流程中任何步骤失败时：**

```
❌ Commit Failed

Step: <失败步骤名称>
Reason: <失败原因>

How would you like to proceed?
[ ] Retry - 重试当前步骤
[ ] Skip - 跳过当前步骤（如果安全）
[ ] Abort - 取消整个提交流程
[ ] Manual - 我将手动处理，请告诉我需要做什么
```

**禁止行为：**
- ❌ 失败后静默跳过
- ❌ 失败后手动执行 git commit
- ❌ 失败后不告知用户

---

## 执行流程

### 1. Pre-commit 检查

按优先级检测并执行 lint：

```
package.json → npm run lint / pnpm lint / yarn lint
Makefile     → make lint
Python       → ruff check . / flake8 / black --check .
```

- Lint 失败 → 停止流程，输出错误

### 2. 调用 workspace-governor Skill

读取 `.claude/PROJECT.md`，执行文件保护检查：

**详见**: `.claude/skills/workspace-governor.md`

| 模块 Level | 动作 |
|------------|------|
| `core` | 输出 Core Protection Warning，拒绝自动提交 |
| `stable` | 输出 Stability Modification Proposal，等待确认 |
| `active` | 允许继续 |

### 3. 调用 api-governor Skill（如涉及 API 文件）

若变更涉及 API 相关文件，执行 Breaking Change 检测：

**详见**: `.claude/skills/api-governor.md`

**API 相关路径**:
- `docs/api/**`
- `**/routes/**`
- `**/api/**`
- `**/controllers/**`
- `**/endpoints/**`

| 检测结果 | 动作 |
|----------|------|
| Breaking Change | 输出 API Change Proposal，等待确认 |
| Non-Breaking | 允许继续，提示更新文档 |

### 4. 调用 goal-tracker Skill

检查当前目标进度，询问用户目标是否完成：

**详见**: `.claude/skills/goal-tracker.md`

| 目标状态 | 动作 |
|----------|------|
| `in_progress` | 输出目标完成询问 |
| `completed` | 提示设置新目标 |
| `blocked` | 输出阻塞原因 |

**目标完成询问格式**:

```
📌 Goal Progress Check

Current Goal: <任务描述>
Status: in_progress
Created: <创建日期>
Progress: <提交次数> commits

Changes to commit:
- <变更文件列表>

Is this goal completed?
[ ] Yes - Mark as completed
[ ] No - Continue tracking
```

**用户确认后**:
- 完成 → 更新 `docs/CURRENT_GOAL.md` 状态为 `completed` → 询问下一个目标
- 未完成 → 追加进度记录到 PROJECT.md → 继续提交流程

### 5. Stage

```
git add <files>
```

### 6. 生成 Commit Message

分析 `git diff --cached`，按 Conventional Commits 生成：

```
<type>[scope][!]: <description>

<body>

<footer>
```

**Type 列表：**
- `feat` - 新功能
- `fix` - Bug 修复
- `refactor` - 重构
- `perf` - 性能优化
- `docs` - 文档
- `style` - 代码风格
- `test` - 测试
- `build` - 构建
- `ci` - CI/CD
- `chore` - 杂项
- `deps` - 依赖
- `config` - 配置

**Breaking Change：** 使用感叹号或 footer 中的 BREAKING CHANGE 声明

### 7. 执行 Commit

```
git commit
```

### 8. 自动更新状态文件

提交成功后，更新以下文件：

**1. PROJECT.md — 追加开发历史**

```markdown
| 日期 | Commit | 描述 |
|------|--------|------|
| 2026-02-15 | abc1234 | feat: add user authentication |
```

**2. CURRENT_GOAL.md — 更新进度记录**

```markdown
## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-02-15 | 开始实现登录逻辑 |
| 2026-02-15 14:30 | feat: add user authentication |
```

**3. ROADMAP.md — 同步当前焦点（如目标/阶段变化）**

```markdown
## 当前焦点

| 字段 | 值 |
|------|-----|
| **阶段** | Phase 1 |
| **目标** | 实现用户登录 API |
| **重点模块** | backend-features |
```

**4. 检测模块状态升级**

检查每个 `dev` 状态的模块：
- 获取最近 3 次 commit 的变更文件列表
- 若模块路径无变动 → 输出升级建议

```
Module Upgrade Suggestion:
- backend-core: dev → done (3 commits without changes)
  Confirm upgrade? [y/N]
```

**5. 检测 API 变更**

若变更涉及 `docs/api/**` 或 API 相关代码：
```
API Change Detected:
- Modified: docs/api/API.md
- Remember to update API documentation
```

### 9. 更新 Git 历史记录

提交成功后，更新 Git 历史文档系统：

#### 9.1 更新 history.md（简洁摘要）

追加一行到 `docs/git/history.md`：

```markdown
| 2026-02-15 14:30 | a1b2c3d | feat(auth): 实现用户登录 API，支持 JWT 认证 |
```

**格式要求**：
- 时间：`YYYY-MM-DD HH:MM`
- Commit：短 ID（7 位）
- 简介：不超过 50 字，来源于 commit message 的精简

**操作步骤**：
1. 读取 `docs/git/history.md`
2. 移除 `| - | - | （暂无记录） |` 占位行（如存在）
3. 追加新行到表格末尾

#### 9.2 创建详细日志文件

**路径**: `docs/git/logs/YYYY-MM-DD-HHMM-commitid.md`

**示例**: `docs/git/logs/2026-02-15-1430-a1b2c3d.md`

**内容模板**：

```markdown
# <commit-id>

## 基本信息

| 字段 | 值 |
|------|-----|
| **时间** | <YYYY-MM-DD HH:MM> |
| **Commit** | <完整 commit hash> |
| **Message** | <完整 commit message> |

## 简介

<commit message 的中文精简描述>

## 变更文件

| 文件 | 操作 |
|------|------|
| `src/auth/login.ts` | 新增 |
| `src/auth/token.ts` | 修改 |
| `tests/auth.test.ts` | 删除 |

## API 变更

> 如涉及 API 变更

| 端点 | 操作 | 说明 |
|------|------|------|
| `POST /api/login` | 新增 | 用户登录，返回 JWT token |

## 功能变更

| 功能 | 操作 | 说明 |
|------|------|------|
| JWT 认证 | 新增 | 支持 token 生成和验证 |
| 密码验证 | 新增 | bcrypt 密码比对 |

## 关联目标

- 目标：<当前目标描述>
- 状态：<目标状态>
```

**信息收集来源**：

| 信息 | 来源 | 用途 |
|------|------|------|
| Commit ID | `git rev-parse HEAD` | 日志文件名 + 内容 |
| Commit Message | `git log -1 --pretty=%B` | 简介 + Message 字段 |
| 变更文件列表 | `git diff --name-status HEAD~1` | 变更文件表 |
| API 变更 | api-governor 检测结果 | API 变更表 |
| 目标信息 | `docs/CURRENT_GOAL.md` | 关联目标 |
| 时间戳 | 系统时间 | 记录时间 |

### 10. Push

```
git push
```

---

## Skills 集成详情

### workspace-governor 调用

**触发**: 所有文件变更

**执行**:
1. 读取 PROJECT.md 获取模块定义
2. 匹配变更文件到模块
3. 检查模块 Level
4. 执行保护逻辑

**输出**:
- `core` → Core Protection Warning → 阻止
- `stable` → Stability Modification Proposal → 等待确认
- `active` → 静默通过

### api-governor 调用

**触发**: API 相关文件变更

**执行**:
1. 分析变更内容
2. 判断是否 Breaking Change
3. 输出提案或允许执行

**输出**:
- Breaking Change → API Change Proposal → 等待确认
- Non-Breaking → 允许执行，提示更新文档

### goal-tracker 调用

**触发**: 所有提交

**执行**:
1. 读取 `docs/CURRENT_GOAL.md`
2. 检查目标状态
3. 输出目标完成询问
4. 根据用户回答更新状态

**输出**:
- in_progress → 目标完成询问 → 等待确认
- completed → 提示设置新目标
- blocked → 输出阻塞原因

---

## 流程图

```
/commit
   │
   ▼
┌──────────────────┐
│ 1. Lint Check    │── Fail ──→ Stop
└────────┬─────────┘
         │ Pass
         ▼
┌──────────────────┐
│ 2. workspace-    │
│    governor      │── core ────→ ⛔ Block
│    Skill         │
└────────┬─────────┘
         │ stable ──→ ⚠️ Wait Confirm
         │ active
         ▼
┌──────────────────┐
│ 3. api-governor  │
│    Skill         │── Breaking ──→ ⚠️ Wait Confirm
│ (if API files)   │
└────────┬─────────┘
         │ OK
         ▼
┌──────────────────┐
│ 4. goal-tracker  │
│    Skill         │── completed ──→ 💡 Prompt new goal
│                  │
└────────┬─────────┘
         │ in_progress
         ▼
┌──────────────────┐
│ 5. Stage         │
└────────┬─────────┘
         ▼
┌──────────────────┐
│ 6. Generate      │
│    Commit Msg    │
└────────┬─────────┘
         ▼
┌──────────────────┐
│ 7. Commit        │
└────────┬─────────┘
         ▼
┌──────────────────┐
│ 8. Update        │
│ - PROJECT.md     │
│ - CURRENT_GOAL   │
│ - ROADMAP.md     │
└────────┬─────────┘
         ▼
┌──────────────────┐
│ 9. Git History   │
│ - history.md     │
│ - logs/详细日志  │
└────────┬─────────┘
         ▼
┌──────────────────┐
│ 10. Push         │
└──────────────────┘
```

---

## 输出格式

```
✅ Commit Successful

Commit: abc1234
Message: feat(auth): add user authentication

Skills Executed:
- workspace-governor: passed (active modules)
- api-governor: skipped (no API changes)
- goal-tracker: progress recorded (goal in progress)

Updated:
- .claude/PROJECT.md (history)
- docs/CURRENT_GOAL.md (progress)
- docs/ROADMAP.md (focus)
- docs/git/history.md (summary)
- docs/git/logs/2026-02-15-1430-abc1234.md (detail)

Suggestions:
- backend-core: consider upgrading to done/stable

Push: Success
```

---

## Stability Modification Proposal

修改 `stable` 模块时输出：

```
⚠️ Stability Modification Proposal

Module: <module-name>
Level: stable
Files: <changed-files>

Changes:
<change-summary>

Impact:
<impact-analysis>

Confirm modification? [y/N]
```

---

## Core Protection Warning

修改 `core` 模块时输出：

```
⛔ Core Protection Warning

Module: <module-name>
Level: core
Files: <changed-files>

This module is protected from automatic modification.

To modify:
1. Manually edit .claude/PROJECT.md
2. Change module level: core → stable
3. Re-run /commit

Operation blocked.
```

---

## API Change Proposal

检测到 Breaking Change 时输出：

```
⚠️ API Change Proposal

Breaking Change Detected!

Affected Endpoint: <method> <path>
Files: <changed-files>

Changes:
<change-details>

Impact:
<impact-analysis>

Required Actions:
[ ] Update docs/api/API.md
[ ] Notify API consumers

Confirm this Breaking Change? [y/N]
```

---

## 禁止行为

- Lint 失败仍提交
- 跳过保护检查（workspace-governor）
- 跳过 API 变更检测（api-governor）
- 跳过目标进度检查（goal-tracker）
- 自动升级模块 Level
- 覆盖历史记录
- 忽略 Skills 输出
- 未经确认修改目标状态
- **在 /commit 之外执行 git commit**
- **一次 /commit 产生多个 commit**
- **失败后不询问用户直接处理**
