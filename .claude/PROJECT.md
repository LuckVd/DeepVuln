# PROJECT.md

> ClaudeDevKit 唯一配置文档 — 项目信息、模块定义、保护规则、开发历史

---

## 项目信息

| 字段 | 值 |
|------|-----|
| **名称** | DeepVuln |
| **类型** | backend |
| **描述** | 七层架构智能漏洞挖掘系统，AI Agent 为主、SAST 工具为辅 |

---

## 模块定义

### 模块状态说明

| Status | 说明 |
|--------|------|
| `todo` | 未开始 |
| `dev` | 开发中 |
| `done` | 已完成 |

### 模块等级说明

| Level | 含义 | 修改规则 |
|-------|------|----------|
| `active` | 活跃开发 | 自由修改 |
| `stable` | 已稳定 | 需确认 |
| `core` | 核心保护 | 禁止自动修改 |

### 模块列表

| 模块 | 路径 | Status | Level |
|------|------|--------|-------|
| claude-control | `.claude/**` | done | core |
| governance-specs | `docs/api/**`, `docs/CURRENT_GOAL.md`, `docs/ROADMAP.md` | done | core |
| git-history | `docs/git/**` | done | stable |
| project-docs | `docs/*.md`, `README.md` | todo | active |
| l1-intelligence | `src/layers/l1_intelligence/**` | done | stable |
| l2-understanding | `src/layers/l2_understanding/**` | todo | active |
| l3-analysis | `src/layers/l3_analysis/**` | done | stable |
| l4-environment | `src/layers/l4_environment/**` | todo | active |
| l5-verification | `src/layers/l5_verification/**` | todo | active |
| l6-fusion | `src/layers/l6_fusion/**` | todo | active |
| l7-governance | `src/layers/l7_governance/**` | todo | active |
| core-modules | `src/core/**`, `src/models/**` | done | stable |
| rules-library | `rules/**` | dev | active |
| cli-entry | `src/cli/**` | done | stable |
| deployment | `deploy/**` | todo | active |

---

## 保护规则

### 文件保护

```
Level: core  → 禁止自动修改，需人工降级
Level: stable → 修改前输出 Stability Modification Proposal，等待确认
Level: active → 允许自由修改
```

### API 保护

API 文件变更时：
- 检测 Breaking Change（参数删除/类型变更/响应结构变化）
- 稳定 API 变更需确认
- 自动提示更新 `docs/api/API.md`

### 默认原则

- 未定义的模块默认为 `active`
- 不确定时默认视为 `stable`
- AI 不得自动升级 Level（active → stable → core）

---

## 开发历史

> 每次提交后自动追加

| 日期 | Commit | 描述 |
|------|--------|------|
| 2026-03-01 | 5de94c3 | feat(l3): add CodeQL build system support and enhance LLM error handling |
| 2026-02-27 | 26be3ae | feat(l1): add batch LLM entry point detection for 15x speedup |
| 2026-02-21 | b2fe941 | feat(l1): improve attack surface detection for non-mainstream frameworks |
| 2026-02-21 | 698b1ec | feat(l3): improve vulnerability judgment accuracy (P0+P1+P3) |
| 2026-02-20 | c7a36ad | feat(l3): implement P2-10 evidence chain builder |
| 2026-02-20 | 7798ff1 | feat(l3): implement P2-09 round termination decider |
| 2026-02-20 | b93e56b | feat(l3): implement P2-08 round three correlation verification |
| 2026-02-20 | 69eed1c | feat(l3): implement P2-07 round two deep tracking |
| 2026-02-20 | 9e01851 | feat(l3): implement P2-06 multi-round audit system and fix bugs |
| 2026-02-19 | 438f51d | style: clean up unused imports and optimize f-strings |
| 2026-02-19 | 6839a6c | feat(l3): implement P2-04 strategy engine and P2-05 task dispatcher |
| 2026-02-19 | 7f6fbb6 | feat(l3): implement P2-01 Semgrep engine integration |
| 2026-02-18 | 9a69205 | chore(config): add uv environment configuration and set P2-01 goal |
| 2026-02-18 | 063ae45 | feat(l1): implement CVE zero false positive optimization |
| 2026-02-18 | 11e0194 | feat(l1): implement P1-10 build configuration security analyzer |
| 2026-02-18 | 6a4a8a5 | feat(l1): implement P1-07 code structure parser (Java/Python/Go) |
| 2026-02-17 | 2985add | feat(l1): implement P1-09 Tree-sitter AST-based attack surface detection |
| 2026-02-17 | 00bd232 | feat(l1): complete P1-08 attack surface detector (Phase 3-4) |
| 2026-02-16 | bc12d26 | feat(cli): integrate threat intelligence module into CLI TUI |
| 2026-02-16 | 95e316b | feat(l1): implement threat intelligence sync module (P1-04) |
| 2026-02-16 | ef7c2fa | feat(cli): implement interactive CLI with Rich TUI |

---

## 自动升级规则

提交后自动检测：

1. **模块状态升级建议**
   - 条件：模块 `dev` + 最近 3 次提交无该模块变动
   - 动作：建议升级为 `done` + `stable`

2. **API 变更检测**
   - 条件：检测到 API 文件变更
   - 动作：提示更新 `docs/api/API.md`

3. **保护文件警告**
   - 条件：修改 `stable` 或 `core` 文件
   - 动作：输出提示，等待确认

---

## 当前目标

> 当前开发目标独立维护，详见 `docs/CURRENT_GOAL.md`

**快速操作：**
- 查看目标：`/goal`
- 设置目标：`/goal set <任务描述>`
- 标记完成：`/goal done`
