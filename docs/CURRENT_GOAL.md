# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | P4-02：Exploitability 成为主裁决权重（Override 机制） |
| **状态** | completed |
| **优先级** | P0 |
| **创建日期** | 2026-03-05 |
| **完成日期** | 2026-03-05 |
| **所属阶段** | Phase 4 - 裁决统一 |

---

## 目标概述

建立 Exploitability Override 裁决机制。Exploitability 决定状态上限：不可利用不允许标记 confirmed，Exploitability 优先级高于 severity，final_score 只用于排序不再决定最终状态。

**核心目标**：这是裁决逻辑，不是评分逻辑。建立 Exploitability 主导的最终状态决策系统。

---

## 约束条件

| 约束 | 说明 |
|------|------|
| 可新建 | `src/layers/l3_analysis/adjudication.py` |
| 可修改 | `src/layers/l3_analysis/strategy_engine.py`, `src/layers/l3_analysis/models.py` |
| 禁止修改 | Finding Budget、Rule Gating、File Filtering、AST Validator、CodeQL Health、CLI、Agent 核心逻辑 |

---

## 禁止行为

- [x] ❌ 不允许直接删除 finding
- [x] ❌ 不允许隐藏 finding
- [x] ❌ 不允许静默覆盖而不记录
- [x] ❌ 不允许改变 severity 原字段
- [x] ❌ 不删除 final_score
- [x] ❌ 不改变 Finding Budget
- [x] ❌ 不修改 Rule Gating
- [x] ❌ 不修改 File Filtering
- [x] ❌ 不修改 AST Validator
- [x] ❌ 不修改 CodeQL Health
- [x] ❌ 不改变 CLI 输出结构

---

## 完成标准

### 1️⃣ FinalStatus 枚举（必须）

```python
class FinalStatus(str, Enum):
    EXPLOITABLE = "exploitable"
    CONDITIONAL = "conditional"
    NOT_EXPLOITABLE = "not_exploitable"
    INFORMATIONAL = "informational"
```

- [ ] 实现 `FinalStatus` 枚举
- [ ] 定义四种最终状态

### 2️⃣ 新建裁决控制模块（必须）

创建 `src/layers/l3_analysis/adjudication.py`:

```python
def apply_exploitability_override(finding):
    """
    Exploitability 决定状态上限
    """
```

- [ ] 创建 adjudication.py 模块
- [ ] 实现 apply_exploitability_override() 函数
- [ ] 实现 validate_no_conflict() 函数

### 3️⃣ 状态强制规则（必须）

| 规则 | 条件 | 结果 |
|------|------|------|
| 规则 1 | `exploitability == NOT_EXPLOITABLE` | `final_status = not_exploitable` (无条件覆盖) |
| 规则 2 | `exploitability == UNLIKELY` + `severity in [HIGH, CRITICAL]` | 降级为 `conditional` |
| 规则 3 | `exploitability == EXPLOITABLE` + `severity in [HIGH, CRITICAL]` | `final_status = exploitable` |
| 规则 4 | 无 exploitability 字段 | 保持原逻辑，标记为 `conditional` |

- [ ] 实现 NOT_EXPLOITABLE 强制覆盖
- [ ] 实现 UNLIKELY 降级逻辑
- [ ] 实现 EXPLOITABLE 提升逻辑
- [ ] 实现无 exploitability 默认行为

### 4️⃣ 冲突禁止机制（必须）

```python
def validate_no_conflict(finding):
    if (
        finding.exploitability == "NOT_EXPLOITABLE"
        and finding.final_status == "exploitable"
    ):
        raise ArchitectureViolationError(...)
```

- [ ] 实现冲突检测函数
- [ ] 定义 ArchitectureViolationError 异常
- [ ] 不允许 confirmed 与 not_exploitable 并存

### 5️⃣ Finding 模型修改（必须）

在 `models.py` 中添加：

```python
class Finding(BaseModel):
    # ... existing fields ...
    final_status: FinalStatus | None = Field(
        default=None,
        description="Final adjudication status based on exploitability override",
    )
```

- [ ] 添加 `final_status` 字段
- [ ] 保持向后兼容（可选字段）

### 6️⃣ Strategy Engine 集成（必须）

在所有 final_score 计算后执行：

```python
for finding in findings:
    # 先计算 final_score
    score = calculate_finding_score(finding)
    finding.final_score = score.total

    # 再应用 exploitability override
    apply_exploitability_override(finding)
```

- [ ] 在 final_score 计算后执行 override
- [ ] 为 finding 添加 final_status
- [ ] 不再依赖原始 severity 决定最终状态

### 7️⃣ Metadata 记录（必须）

在 `ScanResult.metadata` 中新增：

```json
{
  "adjudication": {
    "override_enabled": true,
    "conflict_detected": false,
    "overrides_applied": 12,
    "by_status": {
      "exploitable": 5,
      "conditional": 15,
      "not_exploitable": 3,
      "informational": 2
    }
  }
}
```

- [ ] 存储 override_enabled 状态
- [ ] 存储 conflict_detected 标志
- [ ] 存储各状态数量统计

---

## 变更文件

| 文件 | 操作 | 说明 |
|------|------|------|
| `src/layers/l3_analysis/adjudication.py` | 新建 | Exploitability 裁决模块 |
| `src/layers/l3_analysis/strategy_engine.py` | 修改 | 集成裁决流程 |
| `src/layers/l3_analysis/models.py` | 修改 | Finding 添加 final_status |

---

## 实现优先级

| 优先级 | 功能 |
|--------|------|
| P0 | FinalStatus 枚举 |
| P0 | apply_exploitability_override() |
| P0 | 状态强制规则 1-4 |
| P0 | validate_no_conflict() |
| P1 | Finding 模型修改 |
| P1 | Strategy Engine 集成 |
| P2 | Metadata 记录 |

---

## 实现顺序

1. 创建 `src/layers/l3_analysis/adjudication.py` 模块
2. 实现 FinalStatus 枚举
3. 实现 apply_exploitability_override() 函数
4. 实现状态强制规则
5. 实现 validate_no_conflict() 函数
6. 修改 Finding 模型添加 final_status
7. 在 Strategy Engine 中集成
8. 添加 Metadata 记录
9. 添加单元测试

---

## 测试要求

### 新增测试

| 测试 | 说明 |
|------|------|
| NOT_EXPLOITABLE 强制覆盖 | 无条件覆盖 severity/final_score/confidence |
| HIGH + UNLIKELY → CONDITIONAL | 降级测试 |
| EXPLOITABLE + CRITICAL → EXPLOITABLE | 提升测试 |
| 冲突检测触发 | ArchitectureViolationError |
| 无 exploitability 默认行为 | 标记为 conditional |
| final_score 仍然存在 | 验证不被删除 |

---

## 验收清单

- [ ] 不存在 confirmed / not_exploitable 冲突
- [ ] Exploitability 成为最终裁决主导
- [ ] final_score 仅用于排序
- [ ] 所有测试通过
- [ ] 架构不破坏现有系统
- [ ] final_status 字段正确添加

---

## 预期效果

实现后系统会：
- **裁决优先** - Exploitability > Severity > Confidence
- **状态控制** - final_status 由 exploitability 决定
- **冲突禁止** - 不允许 confirmed + not_exploitable
- **向后兼容** - final_score 保留用于排序
- **可追溯** - metadata 记录裁决过程

---

## 设计原则

**本阶段是：**
- ✅ 裁决逻辑实现
- ✅ 状态决策控制
- ✅ 冲突解决机制

**本阶段不是：**
- ❌ 评分逻辑修改
- ❌ 删除现有功能
- ❌ 改变 CLI 输出

---

## 与 P4-01 的关系

| P4-01 | P4-02 |
|-------|-------|
| 建立 final_score | 建立 final_status |
| 用于排序 | 用于状态决策 |
| 加权计算 | 裁决覆盖 |
| 不决定状态 | 决定最终状态 |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-03-05 | 设置目标：Exploitability 主裁决 |
| - | （待更新） |

---

## 备注

- 此任务是 Phase 4 的第二个任务
- 依赖 P4-01 的 final_score 基础
- final_score 保留用于排序，不删除
- 核心是建立裁决逻辑，不是修改评分
- 系统将从"加权评分"升级为"Exploitability 主导裁决"
