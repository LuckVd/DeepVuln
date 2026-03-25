# Current Goal

## Status

Completed - 2026-03-25

## Goal

P7-01: LLM 智能语言决策

## Summary

实现 LLM 驱动的 CodeQL 语言选择决策器，根据语言结构、模块边界、攻击面分析结果、Semgrep 发现和构建难度，智能决定对哪些语言进行 CodeQL 深度扫描，以平衡安全收益与扫描资源消耗，并为后续分语言构建编排提供清晰输入。

## Background

### 问题

1. 当前 CodeQL 扫描所有检测到的支持语言，可能导致：
   - 扫描时间过长（多语言项目 25-40 分钟）
   - 构建失败率高（C/C++ 约 70% 失败）
   - 资源浪费（扫描低风险语言）
   - monorepo 中不同模块被粗粒度地混在一起，缺少构建单元意识

2. Readiness Gate 只检查主要语言，但扫描时却尝试所有语言

### 解决方案

引入 LLM 智能决策层：
- 综合分析语言占比、模块边界、攻击面分布、Semgrep 结果、构建难度
- 输出优先级排序的推荐扫描语言列表
- 限制最大扫描语言数和总时间预算
- 保留 deterministic baseline 作为效果对照和回退依据

## Scope

| Item | Content |
|------|---------|
| **问题** | 多语言项目 CodeQL 扫描效率低、成功率低、缺乏智能选择机制 |
| **关注点** | LLM 决策输入构建、Prompt 设计、结果解析、时间预算控制、与构建画像的接口 |
| **实现文件** | src/layers/l3_analysis/decision/__init__.py, language_decider.py, prompts.py, models.py |
| **集成点** | src/cli/main.py::_apply_codeql_readiness_gate |

## Deliverables

| File | Description |
|------|-------------|
| src/layers/l3_analysis/decision/__init__.py | 模块初始化和导出 |
| src/layers/l3_analysis/decision/models.py | 数据模型定义 |
| src/layers/l3_analysis/decision/language_decider.py | 核心决策器实现 |
| src/layers/l3_analysis/decision/prompts.py | LLM Prompt 模板 |
| src/layers/l3_analysis/decision/build_assessor.py | 构建难度评估（简化版） |
| src/layers/l3_analysis/build/module_discovery.py | 为决策输入提供模块/子项目边界 |
| tests/unit/test_l3/test_decision.py | 单元测试 |

## Acceptance Criteria

1. **功能正确性**
   - [x] LanguageDecisionInput 正确聚合语言结构、模块边界、攻击面、Semgrep 结果
   - [x] LLM 返回有效的 JSON 决策结果
   - [x] 决策结果包含：推荐语言列表、优先级分数、决策理由、跳过原因

2. **时间预算控制**
   - [x] 当推荐语言总时间超过预算时，自动裁剪低优先级语言
   - [x] 时间预算可配置（默认 30 分钟）

3. **降级处理与基线对照**
   - [x] LLM 调用失败时，回退到 deterministic baseline，而不是直接退回全扫
   - [x] 配置项支持禁用 LLM 决策
   - [x] baseline 至少支持主语言优先/攻击面优先两种模式

4. **测试覆盖**
   - [x] 单元测试覆盖决策器核心逻辑（35 tests passed）
   - [x] Mock LLM 响应进行边界测试

## Implementation Steps

| Step | Task | Status |
|------|------|--------|
| S1 | 创建 decision 模块目录结构和 __init__.py | done |
| S2 | 实现数据模型：LanguageInfo, BuildDifficulty, ModuleSummary, LanguageDecisionInput, LanguageDecision | done |
| S3 | 接入模块边界输入（来自 module discovery/target extraction 的简化摘要） | done |
| S4 | 实现简化版 BuildDifficultyAssessor（为 LLM 提供构建难度输入） | done |
| S5 | 实现 LLM Prompt 模板（安全优先/效率平衡/风险聚焦原则） | done |
| S6 | 实现 CodeQLLanguageDecider 核心类 | done |
| S7 | 实现时间预算控制逻辑 | done |
| S8 | 实现结果解析、验证和结构化解释输出 | done |
| S9 | 实现 deterministic baseline 与 LLM 失败回退 | done |
| S10 | 编写单元测试并更新文档/配置项 | done |

## Technical Design

### 数据模型

```python
# src/layers/l3_analysis/decision/models.py

@dataclass
class LanguageStructure:
    """语言结构信息"""
    name: str                    # 语言名称
    file_count: int              # 文件数量
    line_count: int              # 代码行数
    percentage: float            # 占比百分比

@dataclass
class BuildDifficulty:
    """构建难度评估"""
    level: str                   # easy/medium/hard/unknown
    estimated_time: int          # 预估时间（秒）
    has_build_config: bool       # 是否有构建配置
    blockers: list[str]          # 阻碍因素列表

@dataclass
class AttackSurfaceSummary:
    """攻击面摘要"""
    entry_points_by_language: dict[str, int]  # 按语言的入口点数量
    sensitive_data_flows: list[str]            # 敏感数据流
    external_dependencies: list[str]           # 外部依赖

@dataclass
class SemgrepSummary:
    """Semgrep 扫描结果摘要"""
    findings_by_language: dict[str, dict[str, int]]  # 按语言的发现统计
    # {"java": {"critical": 0, "high": 3, "medium": 8}}

@dataclass
class ModuleSummary:
    """模块/子项目摘要"""
    name: str
    path: str
    primary_language: str
    languages: list[str]
    build_signals: list[str]

@dataclass
class LanguageDecisionInput:
    """LLM 决策的完整输入"""
    languages: list[LanguageStructure]
    modules: list[ModuleSummary]
    attack_surface: AttackSurfaceSummary
    semgrep_result: SemgrepSummary | None
    build_difficulties: dict[str, BuildDifficulty]
    constraints: dict[str, Any]  # max_languages, max_time_budget

@dataclass
class LanguageDecision:
    """LLM 决策结果"""
    recommended_languages: list[str]
    priority_scores: dict[str, float]
    reasoning: dict[str, str]
    skipped_languages: list[str]
    skip_reasons: dict[str, str]
    estimated_total_time: str
    confidence: float
    time_budget_applied: bool = False
```

### 核心流程

```
输入收集
    │
    ├─ 技术栈检测结果 → LanguageStructure 列表
    ├─ 模块发现结果 → ModuleSummary 列表
    ├─ 攻击面分析结果 → AttackSurfaceSummary
    ├─ Semgrep 扫描结果 → SemgrepSummary（可选）
    └─ 构建难度评估 → BuildDifficulty 字典
    │
    ▼
Prompt 构建
    │
    ├─ 格式化语言表格
    ├─ 格式化模块摘要
    ├─ 格式化攻击面摘要
    ├─ 格式化 Semgrep 结果
    └─ 添加决策原则和约束
    │
    ▼
LLM 调用
    │
    ├─ 发送 Prompt
    └─ 接收 JSON 响应
    │
    ▼
结果处理
    │
    ├─ 解析 JSON
    ├─ 验证格式
    ├─ 应用时间预算（如需要）
    ├─ 产出 selected/skipped 的结构化解释
    └─ 返回 LanguageDecision
```

### Prompt 模板要点

```
你是一个安全扫描专家，需要决定对哪些编程语言进行 CodeQL 深度扫描。

决策原则：
1. 安全优先：优先扫描攻击面大、入口点多的语言
2. 效率平衡：在有限时间内获得最大安全收益
3. 风险聚焦：优先扫描 Semgrep 发现高风险的语言
4. 可行性强：避免构建难度过高导致失败的语言
5. 模块感知：不要因为 monorepo 聚合而误判低价值语言

约束条件：
- 最大扫描语言数：{max_languages}
- 最大时间预算：{max_time_budget} 秒

输入数据：
{formatted_input}

输出 JSON 格式：
{
  "recommended_languages": ["Java", "Python"],
  "priority_scores": {"Java": 0.9, "Python": 0.7},
  "reasoning": {"Java": "...", "Python": "..."},
  "skipped_languages": ["C++"],
  "skip_reasons": {"C++": "构建难度高"},
  "estimated_total_time": "8-12 minutes",
  "confidence": 0.85
}
```

## Test Plan

### 单元测试

| 测试用例 | 描述 |
|----------|------|
| test_build_difficulty_assessor | 验证各语言难度评估正确 |
| test_module_summary_integration | 验证模块边界输入被正确纳入决策 |
| test_prompt_construction | 验证 Prompt 格式化正确 |
| test_decision_parsing | 验证 JSON 解析和验证 |
| test_time_budget_enforcement | 验证时间预算裁剪逻辑 |
| test_fallback_on_llm_failure | 验证 LLM 失败时回退到 baseline |
| test_baseline_strategy | 验证 deterministic baseline 行为 |

### 集成测试（P7-09）

- 与 Readiness Gate 集成
- 与真实 LLM 调用集成
- 与多语言扫描流程集成

## Configuration

```toml
# config.toml 新增配置项

[codeql.decision]
# 是否启用 LLM 智能决策
enabled = true

# 最大扫描语言数
max_languages = 3

# 最大时间预算（秒）
max_time_budget = 1800  # 30 分钟

# LLM 失败时回退策略
fallback_strategy = "primary-language"

# 决策置信度阈值
min_confidence = 0.7

# LLM 调用超时（秒）
llm_timeout = 30
```

## Dependencies

| 依赖 | 说明 |
|------|------|
| LLM API | 已有，通过 src/core/llm 调用 |
| 技术栈检测 | 已有，TechStackDetector |
| 攻击面分析 | 已有，AttackSurfaceAnalyzer |
| Semgrep 扫描 | 可选，作为输入 |
| 模块发现 | Phase 7 新增，为 monorepo/子模块提供边界 |

## Design Decisions (Confirmed)

| 决策点 | 选择 | 理由 |
|--------|------|------|
| module discovery 输入格式 | **模块级摘要** | 快速实现，LLM token 少，后续 P7-03 可扩展 |
| LLM 失败回退策略 | **混合策略** | 主语言 60% + 攻击面 40% 权重，平衡可靠性与安全收益 |

### Baseline 混合策略算法

```python
def calculate_baseline_score(language: LanguageStructure, attack_surface: AttackSurfaceSummary) -> float:
    """计算 baseline 优先级分数"""
    # 主语言权重 60%
    language_score = language.percentage  # 代码占比

    # 攻击面权重 40%
    entry_points = attack_surface.entry_points_by_language.get(language.name, 0)
    max_entry_points = max(attack_surface.entry_points_by_language.values()) or 1
    attack_score = entry_points / max_entry_points

    return 0.6 * language_score + 0.4 * attack_score
```

## Risks

| 风险 | 缓解措施 |
|------|----------|
| LLM 响应格式不稳定 | JSON 解析失败时回退到混合 baseline |
| LLM 决策漏掉重要语言 | 提供配置项禁用；提供 --force-codeql-all 覆盖 |
| monorepo 粗粒度统计导致误判 | 补充模块边界摘要输入 |
| 决策时间增加 | LLM 调用限制在 30 秒内 |

## References

- docs/ai/roadmap.md (Phase 7)
- src/cli/main.py::_apply_codeql_readiness_gate
- src/layers/l3_analysis/engines/codeql.py
- src/core/llm/
