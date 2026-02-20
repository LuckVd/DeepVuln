# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | P2-09 多轮审计 - 轮次终止决策器 |
| **状态** | completed |
| **优先级** | high |
| **创建日期** | 2026-02-20 |
| **完成日期** | 2026-02-20 |

---

## 背景说明

轮次终止决策器负责判断多轮审计何时应该停止。它基于多种条件（置信度阈值、收益递减、资源限制等）来决定是否继续下一轮审计。

**核心功能**：
1. **收益评估**：评估继续审计的预期收益
2. **置信度检查**：判断漏洞候选是否已有足够置信度
3. **资源监控**：考虑时间、token、成本等资源限制
4. **决策输出**：给出明确的继续/终止建议

**设计理念**：
- 收益驱动：只在预期收益大于成本时继续
- 可配置：支持自定义终止条件和阈值
- 可解释：提供决策理由

---

## 完成标准

### Phase 1: 决策模型
- [x] 创建 `TerminationReason` 枚举
- [x] 创建 `DecisionMetrics` 指标模型
- [x] 创建 `TerminationDecision` 决策模型

### Phase 2: 决策器实现
- [x] 创建 `TerminationDecider` 类
- [x] 实现收益递减检测
- [x] 实现置信度阈值检查
- [x] 实现资源限制检查

### Phase 3: 集成到控制器
- [x] 修改 `RoundController` 集成决策器
- [x] 支持提前终止逻辑
- [x] 记录终止原因

### Phase 4: 测试与文档
- [x] 单元测试覆盖 (33 新测试)
- [ ] 更新 ROADMAP.md (待 commit 时更新)

---

## 实现详情

### 已创建文件

1. **`src/layers/l3_analysis/rounds/termination.py`** (~580 lines)
   - `TerminationReason` 枚举 - 7 种终止原因
   - `FindingsTrend` 枚举 - 4 种发现趋势
   - `DecisionMetrics` 模型 - 决策指标集合
   - `TerminationDecision` 模型 - 终止决策结果
   - `TerminationConfig` 模型 - 配置参数
   - `TerminationDecider` 类 - 核心决策逻辑

### 已修改文件

1. **`src/layers/l3_analysis/rounds/controller.py`**
   - 集成 `TerminationDecider`
   - 重构 `_should_continue()` 使用决策器
   - 添加 `request_early_stop()` 方法
   - 添加 `last_termination_decision` 属性

2. **`src/layers/l3_analysis/rounds/__init__.py`**
   - 导出新的终止决策相关类

3. **`tests/unit/test_l3/test_rounds.py`**
   - 新增 33 个测试用例
   - 总计 121 个测试全部通过

---

## 测试覆盖

| 测试类 | 测试数量 |
|--------|----------|
| TestTerminationReason | 1 |
| TestFindingsTrend | 1 |
| TestDecisionMetrics | 4 |
| TestTerminationDecision | 4 |
| TestTerminationConfig | 3 |
| TestTerminationDecider | 13 |
| TestRoundControllerTerminationIntegration | 7 |
| **总计** | **33** |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-02-20 | 设置新目标：P2-09 轮次终止决策器 |
| 2026-02-20 | 完成 Phase 1-4：所有功能实现并通过测试 |

---

## 下一步

准备 commit P2-09，然后继续 P2-10 或其他任务
