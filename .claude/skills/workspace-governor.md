# Workspace Governor Skill

> 执行文件等级保护，防止误改稳定/核心代码

---

## 目标

- 基于 PROJECT.md 模块定义执行保护
- 防止未授权修改 core 模块
- 确保 stable 模块变更经过确认
- 自动更新 PROJECT.md 开发历史

---

## 必读文件

| 文件 | 用途 |
|------|------|
| `.claude/PROJECT.md` | 模块定义、保护规则、开发历史 |

---

## 触发条件

- 任何写操作前
- `/commit` 命令执行时
- 文件修改请求

---

## 模块等级定义

| Level | 含义 | 修改规则 |
|-------|------|----------|
| `active` | 活跃开发 | 自由修改 |
| `stable` | 已稳定 | 需确认 |
| `core` | 核心保护 | 禁止自动修改 |

### 模块状态定义

| Status | 说明 |
|--------|------|
| `todo` | 未开始 |
| `dev` | 开发中 |
| `done` | 已完成 |

---

## 执行流程

```
写操作请求
     │
     ▼
读取 PROJECT.md
     │
     ▼
匹配变更文件到模块
     │
     ├── 匹配成功 ──────────────────┐
     │                              │
     ▼                              ▼
检查模块 Level               使用默认规则 (active)
     │
     ├─→ core
     │        │
     │        ▼
     │   Core Protection Warning
     │        │
     │        ▼
     │   阻止操作
     │
     ├─→ stable
     │        │
     │        ▼
     │   Stability Modification Proposal
     │        │
     │        ├─→ 确认 → 允许执行
     │        │
     │        └─→ 拒绝 → 停止操作
     │
     └─→ active
              │
              ▼
         允许执行
```

---

## 保护逻辑

### Core Protection Warning

修改 `core` 模块时：

```
⛔ Core Protection Warning

Module: <module-name>
Level: core
Files: <changed-files>

This module is protected from automatic modification.

Reason: <protection-reason>

To modify:
────────────────────────────────────────────────────
1. Manually edit .claude/PROJECT.md
2. Change module level: core → stable
3. Re-run the operation

Alternative:
────────────────────────────────────────────────────
- Request human override
- Document the exception reason

Operation blocked.
```

### Stability Modification Proposal

修改 `stable` 模块时：

```
⚠️ Stability Modification Proposal

Module: <module-name>
Level: stable
Status: <status>
Files: <changed-files>

Current State:
────────────────────────────────────────────────────
<current-state-summary>

Proposed Changes:
────────────────────────────────────────────────────
<change-details>

Impact Analysis:
────────────────────────────────────────────────────
<potential-impact>

Risks:
────────────────────────────────────────────────────
<identified-risks>

Recommendation:
────────────────────────────────────────────────────
<suggestion>

Confirm modification? [y/N]
```

---

## 文件-模块匹配规则

### 路径匹配优先级

1. **精确匹配** — 完整路径匹配
2. **前缀匹配** — 路径前缀匹配模块路径
3. **通配符匹配** — glob 模式匹配
4. **默认规则** — 未匹配视为 `active`

### 匹配示例

| 文件路径 | 匹配模块 | Level |
|----------|----------|-------|
| `.claude/PROJECT.md` | `claude-control` | core |
| `.claude/commands/commit.md` | `claude-control` | core |
| `docs/api/API.md` | `governance-specs` | core |
| `backend/src/core/auth.ts` | `backend-core` | active |
| `frontend/src/features/user/` | `frontend-features` | active |

---

## 自动更新

### 1. 追加 PROJECT.md 开发历史

操作确认后，追加记录：

```markdown
| 日期 | Commit | 描述 |
|------|--------|------|
| 2026-02-15 | abc1234 | <change-summary> |
```

### 2. 模块状态升级建议

检测条件：
- 模块状态为 `dev`
- 最近 3 次提交无该模块变动

```
📊 Module Status Review

Module: <module-name>
Current: dev
Last Change: <date>
Commits Without Changes: 3

Suggestion:
────────────────────────────────────────────────────
Consider upgrading to:
  Status: done
  Level: stable

Rationale:
────────────────────────────────────────────────────
- No recent changes indicate stability
- Module appears feature-complete

Confirm upgrade? [y/N]
```

### 3. 保护规则变更提示

当频繁修改 `stable` 模块时：

```
💡 Frequent Stable Module Modification Notice

Module: <module-name>
Level: stable
Recent Modifications: 5 in last week

Suggestion:
────────────────────────────────────────────────────
This module is being actively modified despite stable status.
Consider:
- Downgrading to 'active' if still in development
- Or completing the changes and marking as 'core'
```

---

## 默认原则

| 原则 | 说明 |
|------|------|
| **未定义模块** | 默认视为 `active` |
| **不确定时** | 默认视为 `stable` |
| **Level 升级** | AI 不得自动升级（active → stable → core） |
| **Level 降级** | 需人工确认 |
| **Status 升级** | 可建议，需确认 |

---

## 禁止行为

- ❌ 跳过保护检查
- ❌ 自动修改 core 模块
- ❌ 不经确认修改 stable 模块
- ❌ 自动升级模块 Level
- ❌ 覆盖开发历史记录
- ❌ 忽略保护警告

---

## 与 commit.md 集成

在 `/commit` 流程中的位置：

```
1. Pre-commit 检查 (lint)
2. ⬇️ workspace-governor 检查 ⬅️ 此处
3. Stage
4. 生成 Commit Message
5. 执行 Commit
6. 更新状态文件 (PROJECT.md / CURRENT_GOAL.md / ROADMAP.md)
7. 更新 Git 历史记录 (docs/git/history.md + logs/)
8. Push
```

---

## 示例场景

### 场景 1：修改 core 模块

```
请求: 修改 .claude/PROJECT.md
模块: claude-control (core)
结果: ⛔ Core Protection Warning
处理: 阻止操作，提示手动降级
```

### 场景 2：修改 stable 模块

```
请求: 修改 backend/src/features/auth/login.ts
模块: backend-features (假设设为 stable)
结果: ⚠️ Stability Modification Proposal
处理: 等待用户确认
```

### 场景 3：修改 active 模块

```
请求: 修改 frontend/src/components/Button.tsx
模块: frontend-features (active)
结果: ✅ 允许执行
处理: 直接执行修改
```

### 场景 4：未定义模块

```
请求: 修改 utils/helpers.ts
模块: 未定义
结果: ✅ 允许执行（默认 active）
处理: 直接执行修改
```
