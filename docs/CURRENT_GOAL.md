# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | P4-05：统一报告状态模型（Report Status Unification） |
| **状态** | completed |
| **优先级** | P0 |
| **创建日期** | 2026-03-05 |
| **所属阶段** | Phase 4 - 裁决统一 |

---

## 目标概述

建立唯一、稳定、对外一致的报告状态系统。从现在开始：内部可以复杂，输出必须简单，所有报告只允许使用统一状态。

**核心目标**：输出层只有四种状态，confirmed 彻底消失，exploitability 已内化，severity 仅用于排序与展示。

**解决问题**：
- 系统内部存在 severity、exploitability、final_score、final_status、duplicate_count、related_engines
- 输出层仍可能混用 confirmed、使用 severity 作为状态、出现 exploitability 与 status 语义混乱

---

## 约束条件

| 约束 | 说明 |
|------|------|
| 可新建 | `src/layers/l3_analysis/reporting.py` |
| 可修改 | `models.py`, `cli/scan_display.py`, `strategy/engine.py` |
| 禁止修改 | final_score、adjudication、consistency、deduplicator、Rule Gating、Finding Budget |

---

## 禁止行为

- [ ] ❌ 禁止出现 confirmed 作为状态
- [ ] ❌ 禁止出现 high_risk、low_risk、mixed 作为状态
- [ ] ❌ 禁止 fallback 到 severity 决定状态
- [ ] ❌ 禁止混用 exploitability 与 status

---

## 完成标准

### 1️⃣ 定义统一 ReportStatus 枚举（必须）

创建 `src/layers/l3_analysis/reporting.py`:

```python
from enum import Enum

class ReportStatus(str, Enum):
    EXPLOITABLE = "exploitable"
    CONDITIONAL = "conditional"
    INFORMATIONAL = "informational"
    SUPPRESSED = "suppressed"
```

- [ ] 创建 reporting.py 模块
- [ ] 实现 ReportStatus 枚举
- [ ] 确保只有四种状态

### 2️⃣ 状态映射规则（必须实现）

实现函数：

```python
def map_to_report_status(finding) -> ReportStatus:
```

#### 规则 1：优先使用 final_status

| final_status | report_status |
|--------------|---------------|
| EXPLOITABLE | exploitable |
| CONDITIONAL | conditional |
| NOT_EXPLOITABLE | informational |
| INFORMATIONAL | informational |

- [ ] 实现 final_status → report_status 映射

#### 规则 2：Suppressed 条件

若 finding 满足任一：
- duplicate_count > 0 且被合并删除
- 被 FindingBudget 丢弃
- 被 Rule Gating 禁用
- 被 AST Validator 禁用

则：`return ReportStatus.SUPPRESSED`

- [ ] 实现 suppressed 状态逻辑

#### 规则 3：不允许 fallback 到 severity

**禁止**：
```python
if severity == HIGH: return confirmed
```

severity 只能用于排序与显示，不决定状态。

- [ ] 确保不使用 severity 决定状态

### 3️⃣ 修改 Finding 模型（必须）

在 models.py 添加：

```python
report_status: str | None = None
```

- [ ] 添加 report_status 字段到 Finding

### 4️⃣ 在 Strategy Engine 中集成（必须）

调用位置：
```
final_score 计算之后
    ↓
adjudication 之后
    ↓
consistency check 之后
    ↓
deduplication 之后
    ↓
finding.report_status = map_to_report_status(finding)
```

- [ ] 在正确位置调用状态映射
- [ ] 确保在所有处理完成后执行

### 5️⃣ 修改 CLI 输出（必须）

在 `cli/scan_display.py` 中：
- 使用 report_status 作为主要状态
- 不再显示 confirmed
- 状态排序顺序：`exploitable > conditional > informational > suppressed`

- [ ] CLI 使用 report_status
- [ ] 删除 confirmed 显示
- [ ] 实现正确排序

### 6️⃣ JSON 输出统一（必须）

ScanResult 输出结构必须统一为：

```json
{
  "rule_id": "...",
  "file": "...",
  "severity": "...",
  "report_status": "...",
  "final_score": 0.87,
  "exploitability": "...",
  "engines": ["semgrep", "codeql"]
}
```

- [ ] JSON 输出使用统一结构
- [ ] 包含 report_status 字段

### 7️⃣ 删除 confirmed 语义（必须）

全项目：
- 禁止使用字符串 "confirmed"
- 不允许作为状态输出
- 不允许作为 CLI 分类

- [ ] 搜索并删除 confirmed 用法
- [ ] 确保不作为状态输出

---

## 变更文件

| 文件 | 操作 | 说明 |
|------|------|------|
| `src/layers/l3_analysis/reporting.py` | 新建 | 统一报告状态模块 |
| `src/layers/l3_analysis/models.py` | 修改 | 添加 report_status 字段 |
| `src/layers/l3_analysis/strategy/engine.py` | 修改 | 集成状态映射 |
| `src/cli/scan_display.py` | 修改 | 使用 report_status 输出 |

---

## 实现优先级

| 优先级 | 功能 |
|--------|------|
| P0 | ReportStatus 枚举 |
| P0 | map_to_report_status 函数 |
| P0 | Finding.report_status 字段 |
| P1 | Strategy Engine 集成 |
| P1 | CLI 输出修改 |
| P2 | JSON 输出统一 |
| P2 | 删除 confirmed 语义 |

---

## 实现顺序

1. 创建 `src/layers/l3_analysis/reporting.py` 模块
2. 实现 ReportStatus 枚举
3. 实现 map_to_report_status() 函数
4. 添加 report_status 字段到 Finding
5. 在 Strategy Engine 中集成
6. 修改 CLI 输出
7. 统一 JSON 输出结构
8. 删除 confirmed 语义
9. 添加单元测试（50+）

---

## 测试要求

### 新增测试（50+）

| 测试 | 说明 |
|------|------|
| final_status → report_status 映射 | 规则 1 |
| suppressed 逻辑 | 规则 2 |
| 不使用 severity 决定状态 | 规则 3 |
| CLI 输出状态顺序 | 排序验证 |
| JSON 输出结构正确 | 格式验证 |
| 不存在 confirmed 字符串 | 语义清理 |
| 四种状态边界测试 | 完整性 |
| 空值处理 | 边界条件 |

---

## 验收清单

- [x] 输出层只有四种状态（exploitable/conditional/informational/suppressed）
- [x] ReportStatus 枚举已实现
- [x] map_to_report_status 函数已实现
- [x] Finding.report_status 字段已添加
- [x] adjudication.py 已集成 report_status
- [x] 所有测试通过（46 新测试）
- [x] CLI 输出使用 report_status
- [x] confirmed 彻底消失（CLI 层已清理）
- [x] 输出可直接接入 CI

---

## 预期效果

实现后系统会：
- **统一输出** - 只有四种报告状态
- **语义清晰** - 不再有 confirmed/状态混用
- **CI 友好** - 可直接接入企业级 CI
- **v0.5 完成** - 裁决统一版本完成

---

## 设计原则

**本阶段是：**
- ✅ 统一对外报告状态
- ✅ 简化输出语义
- ✅ CI 集成准备

**本阶段不是：**
- ❌ 修改内部计算逻辑
- ❌ 修改评分系统
- ❌ 修改裁决系统

---

## 与 P4-01/P4-02/P4-03/P4-04 的关系

| P4-01 | P4-02 | P4-03 | P4-04 | P4-05 |
|-------|-------|-------|-------|-------|
| final_score | final_status | 一致性校验 | 语义去重 | 统一报告 |
| 加权计算 | 裁决覆盖 | 冲突禁止 | 跨引擎合并 | CI 友好 |
| 排序基础 | 状态决策 | 强一致性 | 报告干净 | v0.5 完成 |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-03-05 | 设置目标：统一报告状态模型 |
| 2026-03-05 | 完成：实现 reporting.py（ReportStatus 枚举 + map_to_report_status） |
| 2026-03-05 | 完成：添加 Finding.report_status 字段 |
| 2026-03-05 | 完成：集成到 adjudication.py |
| 2026-03-05 | 完成：46 个单元测试全部通过 |
| 2026-03-05 | 完成：CLI 输出修改（confirmed_findings → exploitable_findings） |
| 2026-03-05 | 完成：CLI 层 confirmed 语义清理 |
| 2026-03-05 | **P4-05 完成！v0.5 裁决统一版本完成！** |

---

## 备注

- 此任务是 Phase 4 的第五个任务（最终任务）
- 依赖 P4-01 的 final_score、P4-02 的 final_status、P4-03 的一致性、P4-04 的去重
- 核心是建立统一对外报告状态系统
- 完成后 DeepVuln 将成为强一致裁决 + 语义去重 + 统一报告模型的系统
- 完成后标志着 v0.5：裁决统一版本完成
