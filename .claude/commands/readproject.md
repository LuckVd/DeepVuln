# `/readproject` Command

> 新会话时快速建立项目认知 — 读取项目信息、模块状态、当前目标、开发历史

---

## 用法

```bash
/readproject
```

---

## 用途

在新 Claude Code 会话开始时执行此命令，帮助 AI 快速了解：

1. 项目基本信息
2. 模块定义和状态
3. 当前开发目标
4. 最近开发历史

---

## 执行流程

1. 读取 `.claude/PROJECT.md`
2. 读取 `docs/ROADMAP.md`
3. 读取 `docs/CURRENT_GOAL.md`
4. 读取 `docs/git/history.md`
5. 输出结构化项目概览

---

## 输出格式

```
📋 Project Overview

Project: ClaudeDevKit
Type: fullstack
Description: Claude Code 开发模板套件

📂 Modules:
| Module | Path | Status | Level |
|--------|------|--------|-------|
| claude-control | .claude/** | done | core |
| backend-features | backend/src/features/** | dev | active |

🗺️ Roadmap:
Phase: Phase 1 - MVP
Milestone: v0.5 内测版本 (in_progress)
Focus: 用户认证系统

📌 Current Goal:
Task: 实现用户登录 API
Status: in_progress
Priority: high
Created: 2026-02-15

📊 Recent History (last 3):
| Date | Commit | Description |
|------|--------|-------------|
| 2026-02-15 | abc1234 | feat: add user authentication |

💡 Ready to continue development!
Focus on: 实现用户登录 API
```

---

## 无目标时的输出

```
📌 Current Goal:
(No active goal)

💡 Tip: Set a goal to track your progress
   /goal set <task description>
```

---

## 无历史记录时的输出

```
📊 Recent History:
(No commits yet)

💡 Tip: Use /commit to record your first progress
```

---

## 使用场景

### 1. 新会话开始

```bash
# 用户打开新的 Claude Code 会话
> /readproject

# AI 输出项目概览，立即了解上下文
```

### 2. 切换任务后恢复上下文

```bash
# 隔天继续开发
> /readproject

# 快速回顾：项目状态、当前目标、最近做了什么
```

### 3. 向新成员介绍项目

```bash
# 新成员加入项目
> /readproject

# 一目了然的项目状态报告
```

---

## 与其他命令配合

```
新会话开始
    │
    ├──→ /readproject (了解项目状态)
    │
    ├──→ /goal (查看/设置目标)
    │
    ├──→ (开发工作)
    │
    └──→ /commit (提交并更新状态)
```

---

## 输出内容说明

| 章节 | 来源 | 说明 |
|------|------|------|
| Project | PROJECT.md 项目信息 | 名称、类型、描述 |
| Modules | PROJECT.md 模块定义 | 路径、状态、保护等级 |
| Roadmap | docs/ROADMAP.md | 阶段、里程碑、风险 |
| Current Goal | docs/CURRENT_GOAL.md | 当前短期目标 |
| Recent History | docs/git/history.md | 最近 3 条提交记录 |

---

## 最佳实践

1. **每次新会话先执行** `/readproject`
2. **根据输出决定下一步** — 继续目标或设置新目标
3. **关注模块状态** — 识别哪些模块已完成、哪些在开发
4. **检查最近历史** — 了解上次做了什么

---

## 禁止行为

- 修改任何文件（此命令只读）
- 自动设置或修改目标
- 跳过任何章节的输出
