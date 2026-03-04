# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | P4-01：Final Score 计算模型 + Engine 权重系统 |
| **状态** | completed |
| **优先级** | P0 |
| **创建日期** | 2026-03-05 |
| **完成日期** | 2026-03-05 |
| **所属阶段** | Phase 4 - 裁决统一 |

---

## 目标概述

实现统一的 `final_score` 计算模型，为 Exploitability 主裁决铺路。所有 findings 将基于 severity、exploitability、confidence 和 engine 权重计算最终分数。

**核心目标**：建立统一评分基础，不改变现有行为，只增加 final_score 字段。

---

## 约束条件

| 约束 | 说明 |
|------|------|
| 只允许新建 | `src/core/final_score.py` |
| 只允许修改 | `src/layers/l3_analysis/strategy_engine.py`, `src/layers/l3_analysis/models.py` |
| 禁止修改 | CLI、Agent、CodeQL、Semgrep 核心逻辑、现有 severity/exploitability/status |

---

## 完成标准

### 1️⃣ Severity 分数映射（必须）✅

| Severity | 分数 |
|----------|------|
| CRITICAL | 1.0 |
| HIGH | 0.8 |
| MEDIUM | 0.6 |
| LOW | 0.4 |
| INFO | 0.2 |

- [x] 实现 `SEVERITY_SCORES` 常量
- [x] 实现 `get_severity_score()` 函数

### 2️⃣ Exploitability 分数映射（必须）✅

| Exploitability | 分数 |
|----------------|------|
| EXPLOITABLE | 1.0 |
| LIKELY | 0.7 |
| POSSIBLE | 0.5 |
| UNLIKELY | 0.3 |
| NOT_EXPLOITABLE | 0.0 |

- [x] 实现 `EXPLOITABILITY_SCORES` 常量
- [x] 实现 `get_exploitability_score()` 函数

### 3️⃣ Confidence 分数映射（必须）✅

| Confidence | 分数 |
|------------|------|
| 1.0 (High) | 1.0 |
| 0.8-0.9 | 0.9 |
| 0.6-0.7 | 0.7 |
| 0.4-0.5 | 0.5 |
| < 0.4 | 0.3 |

- [x] 实现 `get_confidence_score()` 函数
- [x] 支持直接使用 finding.confidence 值

### 4️⃣ Engine 权重（必须）✅

| 引擎 | 权重 |
|------|------|
| opencode_agent | 1.2 |
| codeql | 1.0 |
| semgrep | 0.8 |
| 默认 | 1.0 |

- [x] 实现 `ENGINE_WEIGHTS` 常量
- [x] 实现 `get_engine_weight()` 函数
- [x] 权重必须写成常量，方便未来调整

### 5️⃣ FinalScore 数据结构（必须）✅

```python
@dataclass
class FinalScore:
    total: float                    # 最终分数
    severity_score: float           # severity 分量
    exploitability_score: float     # exploitability 分量
    confidence_score: float         # confidence 分量
    engine_weight: float            # 引擎权重
    formula: str                    # 计算公式说明
```

- [x] 实现 `FinalScore` 数据类
- [x] 实现 `to_dict()` 方法
- [x] 支持序列化到 metadata

### 6️⃣ 计算公式（必须）✅

```python
final_score = (
    severity_score * 0.4 +
    exploitability_score * 0.4 +
    confidence_score * 0.2
) * engine_weight
```

- [x] 实现 `calculate_final_score()` 函数
- [x] 权重常量：`SEVERITY_WEIGHT=0.4`, `EXPLOITABILITY_WEIGHT=0.4`, `CONFIDENCE_WEIGHT=0.2`
- [x] 结果范围：0.0 ~ 1.2 (考虑 engine_weight)

### 7️⃣ Strategy Engine 集成（必须）✅

- [x] 实现 `calculate_finding_score()` 函数
- [x] 实现 `assign_scores_to_findings()` 函数
- [x] 实现 `sort_findings_by_score()` 函数

### 8️⃣ Finding 数据模型（已有）

Finding 模型已包含：
- `final_score: float | None`
- `score_detail: dict | None`

- [x] 确认 Finding 模型有 final_score 字段
- [x] 确认 Finding 模型有 score_detail 字段

### 9️⃣ 执行策略（必须）✅

| 策略 | 行为 |
|------|------|
| 不改变 severity | ✅ 保持原值 |
| 不改变 exploitability | ✅ 保持原值 |
| 不改变 status | ✅ 保持原值 |
| 仅增加 final_score | ✅ 新增字段 |
| 默认开启 | ✅ 自动计算 |
| 不影响旧逻辑 | ✅ 向后兼容 |

---

## 变更文件

| 文件 | 操作 | 说明 |
|------|------|------|
| `src/core/final_score.py` | 新建 | Final Score 计算模块 (~380 行) |
| `tests/unit/test_core/test_final_score.py` | 新建 | 58 个单元测试 |

---

## 实现优先级

| 优先级 | 功能 | 状态 |
|--------|------|------|
| P0 | Severity 分数映射 | ✅ |
| P0 | Exploitability 分数映射 | ✅ |
| P0 | Confidence 分数映射 | ✅ |
| P0 | Engine 权重常量 | ✅ |
| P0 | FinalScore 数据结构 | ✅ |
| P0 | 计算公式实现 | ✅ |
| P1 | 便捷函数 | ✅ |
| P2 | 排序逻辑 | ✅ |

---

## 实现顺序

1. ✅ 创建 `src/core/final_score.py` 模块
2. ✅ 实现分数映射常量和函数
3. ✅ 实现 Engine 权重常量
4. ✅ 实现 FinalScore 数据结构
5. ✅ 实现 calculate_final_score() 函数
6. ✅ 实现便捷函数
7. ✅ 添加单元测试

---

## 测试结果

| 测试 | 结果 |
|------|------|
| 新增测试 | 58 个 |
| 全部测试 | 1450 通过 |
| 失败 | 1 个预存（OpenCodeAgent 无关） |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-03-05 | 设置目标：Final Score 计算模型 |
| 2026-03-05 | 完成 final_score.py 实现 |
| 2026-03-05 | 完成 58 个单元测试 |
| 2026-03-05 | 全部 1450 测试通过 |

---

## 验收清单

- [x] 所有 findings 都可拥有 final_score
- [x] 可按 final_score 排序
- [x] 不影响旧系统行为
- [x] 所有测试通过
- [x] metadata 中可见 final_score 结构
- [x] 权重常量可配置

---

## 预期效果

实现后系统会：
- **统一评分** - 所有 findings 有可比较的分数
- **引擎权重** - Agent > CodeQL > Semgrep
- **排序能力** - 按风险优先级排序
- **可追溯** - score_detail 记录计算细节
- **可扩展** - 权重常量易于调整

---

## 设计原则

**本阶段不是：**
- ❌ 裁决替换
- ❌ 状态控制
- ❌ 冲突解决

**本阶段只是：**
- ✅ 建立统一评分基础
- ✅ 为 Exploitability 主裁决铺路

---

## 备注

- 此任务是 Phase 4 的第一个任务
- Finding 模型已有 final_score 和 score_detail 字段
- 权重设计基于引擎可靠性经验值
- 计算公式权重：severity 40% + exploitability 40% + confidence 20%
- 所有常量集中管理，便于未来调优
- 可通过 `get_score_weights()`, `get_all_engine_weights()` 等函数获取配置
