# Current Goal

## Status

Design - 2026-03-26

## Goal

P7-10: 基线策略、测试与效果评估

## Summary

验证 LLM 决策相对规则基线是否有净收益，补充测试覆盖，并建立评估指标体系。

## Context

### 现有测试覆盖

| 模块 | 测试文件 | 测试数 | 状态 |
|------|----------|--------|------|
| 决策模型 | `test_decision.py` | 35 | ✅ 基础覆盖 |
| 版本检测 | `test_version_detector.py` | 25 | ✅ 完整覆盖 |
| 工具兼容性 | `test_tool_resolver.py` | 48 | ✅ 完整覆盖 |
| 构建计划 | `test_build_plan.py` | 39 | ✅ 完整覆盖 |
| Readiness Gate | `test_readiness_gate.py` | 23 | ✅ 完整覆盖 |
| Builder 集成 | `test_codeql_builder_integration.py` | 12 | ✅ 新增 |

### 现有 Baseline 实现

```python
# _make_baseline_decision() 使用混合策略
scores[lang] = 0.6 * language_score + 0.4 * attack_score
# + Semgrep severity boost (cap at 0.3)
```

### 缺失部分

1. **Baseline 策略可配置** - 当前固定权重，缺少其他策略选项
2. **LLM vs Baseline 对照测试** - 缺少对比验证
3. **评估指标收集** - 缺少耗时/成功率/发现损失率统计
4. **集成测试** - 缺少多语言项目端到端测试

## Scope

### In Scope

- P7-10a: 增强可配置 baseline 策略
- P7-10b: 补充 LLM 决策器测试
- P7-10c: 补充版本检测/工具兼容性/构建计划边缘场景
- P7-10d: 集成测试：多语言项目扫描
- P7-10e: 评估指标收集与报告
- P7-10f: 回归测试

### Out of Scope

- P7-08: C/C++ 构建支持
- 新增 Builder
- CodeQL 引擎修改

## Design

### 1. P7-10a: 增强 Baseline 策略

**新增 `BaselineStrategy` 枚举:**

```python
class BaselineStrategy(str, Enum):
    """Deterministic baseline strategies for language selection."""

    HYBRID = "hybrid"           # 60% size + 40% attack surface (default)
    LANGUAGE_FIRST = "language_first"  # Primary language only
    ATTACK_SURFACE_FIRST = "attack_surface_first"  # Most entry points
    SEMGREP_FIRST = "semgrep_first"  # Most findings first
```

**修改 `DecisionConstraints`:**

```python
@dataclass
class DecisionConstraints:
    # ... existing fields ...
    baseline_strategy: BaselineStrategy = BaselineStrategy.HYBRID
```

**新增策略实现:**

```python
def _make_baseline_decision(self, input_data: LanguageDecisionInput) -> LanguageDecision:
    if self.constraints.baseline_strategy == BaselineStrategy.LANGUAGE_FIRST:
        return self._language_first_baseline(input_data)
    elif self.constraints.baseline_strategy == BaselineStrategy.ATTACK_SURFACE_FIRST:
        return self._attack_surface_first_baseline(input_data)
    elif self.constraints.baseline_strategy == BaselineStrategy.SEMGREP_FIRST:
        return self._semgrep_first_baseline(input_data)
    else:
        return self._hybrid_baseline(input_data)  # default
```

### 2. P7-10b/c: 补充单元测试

**新增测试场景:**

| 测试类别 | 测试场景 |
|----------|----------|
| LLM 决策器 | LLM 返回空推荐、超时、格式错误 |
| LLM 决策器 | Baseline 策略切换 |
| LLM 决策器 | 时间预算裁剪 |
| 版本检测 | 边缘格式（.nvmrc lts/*、package.json .x） |
| 工具兼容性 | 版本范围匹配（>=, ^, ~） |
| 构建计划 | 失败回退、超时处理 |

### 3. P7-10d: 集成测试

**新增测试文件:** `tests/integration/test_decision_e2e.py`

```python
class TestDecisionE2E:
    """End-to-end tests for language decision."""

    async def test_monorepo_python_java(self):
        """Test decision for Python+Java monorepo."""

    async def test_javascript_typescript_mixed(self):
        """Test decision for JS+TS project."""

    async def test_llm_vs_baseline_comparison(self):
        """Compare LLM decision vs baseline on same project."""
```

### 4. P7-10e: 评估指标

**新增 `LanguageDecisionMetrics` 数据类:**
（注意：命名为 LanguageDecisionMetrics 以避免与 rounds/termination.py 中的 DecisionMetrics 冲突）

```python
@dataclass
class LanguageDecisionMetrics:
    """Metrics for evaluating language decision quality."""

    decision_source: str  # "llm" or "baseline"
    languages_selected: list[str]
    languages_skipped: list[str]

    # Timing
    decision_time_ms: float
    total_scan_time_ms: float | None = None

    # Results
    scan_success: bool = True
    findings_count: int = 0

    # For comparison
    baseline_languages: list[str] | None = None
    finding_loss_rate: float | None = None  # vs baseline
```

**集成点:** `CodeQLReadinessGate.check()` 返回 metrics

### 5. P7-10f: 回归测试

运行完整 L3 测试套件，确保无破坏。

## Acceptance Criteria

1. **Baseline 策略**
   - [ ] 新增 `BaselineStrategy` 枚举
   - [ ] 支持 4 种策略：hybrid、language_first、attack_surface_first、semgrep_first
   - [ ] `DecisionConstraints` 可配置策略

2. **测试覆盖**
   - [ ] 新增 LLM 决策器边缘场景测试（10+ tests）
   - [ ] 新增 baseline 策略切换测试（8+ tests）
   - [ ] 新增集成测试（5+ tests）

3. **评估指标**
   - [ ] 新增 `LanguageDecisionMetrics` 数据类
   - [ ] ReadinessGate 返回决策指标
   - [ ] CLI 输出显示指标摘要

4. **回归测试**
   - [ ] 全部 L3 测试通过

## Test Plan

### 单元测试

**文件:** `tests/unit/test_l3/test_decision.py` (扩展)

```python
class TestBaselineStrategies:
    """Tests for different baseline strategies."""

    def test_hybrid_strategy(self): ...
    def test_language_first_strategy(self): ...
    def test_attack_surface_first_strategy(self): ...
    def test_semgrep_first_strategy(self): ...
    def test_strategy_with_no_semgrep(self): ...

class TestLLMDecisionEdgeCases:
    """Tests for LLM decision edge cases."""

    async def test_llm_empty_response(self): ...
    async def test_llm_invalid_json(self): ...
    async def test_llm_timeout_fallback(self): ...
    async def test_llm_unsupported_language_filtered(self): ...
```

### 集成测试

**文件:** `tests/integration/test_decision_e2e.py` (新增)

```python
class TestDecisionE2E:
    """End-to-end decision tests."""

    async def test_python_project_baseline(self): ...
    async def test_java_maven_project_llm(self): ...
    async def test_multi_language_project_comparison(self): ...
```

## Steps

### Phase 1: Baseline 策略增强 (P7-10a)

1. 新增 `BaselineStrategy` 枚举到 `decision/models.py`
2. 修改 `DecisionConstraints` 添加策略配置
3. 实现各策略方法
4. 编写策略切换测试

### Phase 2: 单元测试补充 (P7-10b/c)

1. 补充 LLM 决策器边缘场景测试
2. 补充版本检测边缘场景测试
3. 补充构建计划边缘场景测试

### Phase 3: 集成测试 (P7-10d)

1. 创建测试项目 fixture
2. 编写端到端决策测试
3. 编写 LLM vs baseline 对比测试

### Phase 4: 评估指标 (P7-10e)

1. 新增 `DecisionMetrics` 数据类
2. 集成到 ReadinessGate
3. CLI 输出指标摘要

### Phase 5: 回归测试 (P7-10f)

1. 运行完整 L3 测试套件
2. 修复发现的回归问题

## Files

| 文件 | 操作 | 描述 |
|------|------|------|
| `src/layers/l3_analysis/decision/models.py` | 修改 | 新增 BaselineStrategy |
| `src/layers/l3_analysis/decision/language_decider.py` | 修改 | 实现策略切换 |
| `src/layers/l3_analysis/readiness_gate.py` | 修改 | 添加 DecisionMetrics |
| `tests/unit/test_l3/test_decision.py` | 修改 | 扩展测试 |
| `tests/integration/test_decision_e2e.py` | 新增 | 集成测试 |

## Risks

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| LLM API 不可用 | 集成测试失败 | Mock LLM 响应 |
| 测试项目准备 | 时间消耗 | 使用 fixture 创建简单项目 |
| 指标收集开销 | 性能影响 | 仅在需要时收集 |

## Next Recommended

完成 P7-10 后:
- P7-08: C/C++ 标准构建系统支持
- v0.75 里程碑发布准备
