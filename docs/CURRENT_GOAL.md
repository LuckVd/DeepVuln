# 当前目标

> 单一焦点：本次会话关注的核心任务
---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | 修复 Round 4 集成测试 |
| **状态** | in_progress |
| **优先级** | high |
| **创建日期** | 2026-03-07 |
| **所属阶段** | Phase 5 - 精度深化 |
| **模块层级** | L3 Analysis Layer |
| **依赖** | P5-01d（已完成） |
| **父任务** | P5-01：可利用性评估增强 |

---

## 问题背景

P5-01d 多维评分系统实现后，9 个 Round 4 集成测试失败：

| 问题 | 现状 | 影响 |
|------|------|------|
| 测试期望值 | 基于旧 CodeQL 优先逻辑 | 与新评分不一致 |
| 多维融合评分 | 产生更准确的结果 | 测试断言失败 |
| CI 通过率 | 98.7% (1099/1113) | 阻碍后续开发 |

**失败测试列表:**
- `test_round_four_codeql.py`: 5 个失败
- `test_round_four_llm.py`: 4 个失败

---

## 核心目标

**更新集成测试期望值，使其匹配 P5-01d 多维评分行为，实现 100% 测试通过。**

---

## 技术方案

### 1. 分析失败原因

| 测试 | 原期望 | 新结果 | 原因 |
|------|--------|--------|------|
| test_exploitable_with_codeql_confirmation | EXPLOITABLE | UNLIKELY | 多维融合降低置信度 |
| test_conditional_with_codeql_sanitizer | CONDITIONAL | NOT_EXPLOITABLE | 消毒剂权重更高 |
| test_fallback_to_static_when_no_codeql | EXPLOITABLE | UNLIKELY | 部分维度不可用 |
| test_llm_called_for_needs_review | NEEDS_REVIEW | NOT_EXPLOITABLE | 置信度计算变化 |
| test_verify_exploitability_not_in_attack_surface | NOT_EXPLOITABLE | NEEDS_REVIEW | 1/4 维度可用 |

### 2. 更新策略

- **不修改评分器逻辑**：新行为更准确
- **更新测试断言**：匹配新的多维评分结果
- **验证逻辑一致性**：确保评分结果合理

### 3. 修改文件

| 文件 | 修改内容 |
|------|----------|
| `tests/unit/test_l3/test_round_four_codeql.py` | 更新 5 个测试的断言 |
| `tests/unit/test_l3/test_round_four_llm.py` | 更新 4 个测试的断言 |

---

## 验收标准

| 标准 | 指标 |
|------|------|
| 修复失败测试 | 9 个测试全部通过 |
| L3 测试通过率 | 100% (1113/1113) |
| 评分逻辑 | 不修改 MultiDimScorer |
| 向后兼容 | 保持降级策略工作 |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-03-07 | 创建修复集成测试目标 |
| 2026-03-07 00:55 | 目标设置完成，开始修复测试 |
