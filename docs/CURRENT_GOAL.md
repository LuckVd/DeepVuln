# 当前目标

> 单一焦点：本次会话关注的核心任务
---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | P5-01d：多维评分系统 |
| **状态** | completed |
| **优先级** | P0 |
| **创建日期** | 2026-03-06 |
| **完成日期** | 2026-03-07 |
| **所属阶段** | Phase 5 - 精度深化 |
| **模块层级** | L3 Analysis Layer |
| **依赖** | P5-01c（已完成） |
| **父任务** | P5-01：可利用性评估增强 |

---

## 问题背景

当前可利用性评估存在多个维度的证据来源，但缺乏统一的评分融合模型：

| 问题 | 现状 | 影响 |
|------|------|------|
| CodeQL 数据流 | 精确的污点路径，但仅限部分规则 | 未与其他证据融合 |
| AST 调用图 | 完整的可达性分析 | 未计入评分 |
| 污点追踪 | 路径消毒剂检测 | 未计入评分 |
| 攻击面报告 | 入口点类型识别 | 未充分利用 |
| 评分割裂 | 各维度独立判断 | 置信度不一致 |

---

## 核心目标

**构建统一的多维评分系统，融合 CodeQL/调用图/污点追踪/攻击面证据，输出一致的可利用性置信度。**

---

## 技术方案

### 1. 评分维度定义

```python
@dataclass
class MultiDimScore:
    # 维度 1: CodeQL 数据流评分 (0-1)
    codeql_confidence: float

    # 维度 2: 调用图可达性评分 (0-1)
    reachability_score: float

    # 维度 3: 污点追踪评分 (0-1, 包含消毒剂检测)
    taint_score: float

    # 维度 4: 攻击面评分 (0-1, 入口点类型权重)
    attack_surface_score: float

    # 综合评分
    final_score: float

    # 评分依据
    evidence: dict[str, Any]
```

### 2. 融合策略

```
综合评分 = w1 * codeql + w2 * reachability + w3 * taint + w4 * attack_surface

权重分配：
- w1 (CodeQL): 0.35 - 精确数据流，最高权重
- w2 (可达性): 0.25 - 调用图分析
- w3 (污点追踪): 0.30 - 包含消毒剂检测
- w4 (攻击面): 0.10 - 入口点类型调整
```

### 3. 降级策略

```
优先级：CodeQL > Taint Tracking > Reachability > Static

当高优先级证据不可用时：
- 使用次优证据替代
- 置信度衰减 (0.9^n)
- 标记评分来源
```

---

## 新建文件

| 文件 | 用途 |
|------|------|
| `src/layers/l3_analysis/scoring/multi_dim_scorer.py` | 多维评分器 |
| `src/layers/l3_analysis/scoring/models.py` | 评分数据模型 |
| `src/layers/l3_analysis/scoring/strategy.py` | 融合策略配置 |
| `tests/unit/test_l3/test_multi_dim_scorer.py` | 评分器测试 |

---

## 修改文件

| 文件 | 改动 |
|------|------|
| `src/layers/l3_analysis/rounds/round_four.py` | 集成多维评分到裁决 |
| `src/layers/l3_analysis/call_graph/__init__.py` | 导出评分模块 |

---

## 验收标准

| 标准 | 指标 |
|------|------|
| 多维评分模型 | 四个维度评分 + 融合算法 |
| 融合策略 | 权重可配置，降级策略完善 |
| Round 4 集成 | 替换现有评分逻辑 |
| 测试覆盖 | 20+ 新测试 |
| 性能 | 评分计算 < 10ms/候选 |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-03-06 | 创建 P5-01d 目标 |
| 2026-03-07 | ✅ 完成多维评分系统实现（4维度+3策略+40测试） |
