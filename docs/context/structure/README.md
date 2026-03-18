# Structure Context

> 自动生成的结构上下文文档

## 更新记录

- 2026-03-18: P6-04 conditional/informational 细分集成完成
- 2026-03-18: Phase 6.5 集成任务规划，更新 ROADMAP.md 和任务看板
- 2026-03-18: 同步 .claude/settings.local.json 变更，确认核心配置调整

## 相关文件

- docs/ROADMAP.md
- docs/goals/CURRENT_GOAL.yaml
- docs/goals/CURRENT_TASKS.yaml

## 核心配置变更

### .claude/settings.local.json

本地 Claude Code 设置文件，包含项目特定的配置选项。

## P6-04: conditional/informational 细分集成

### 新增模块

| 模块 | 路径 | 功能 |
|------|------|------|
| 置信度评分 | `src/layers/l3_analysis/confidence_scorer.py` | 基于 code-audit 验证方法论的置信度评分系统 |
| 污点分析报告 | `src/layers/l3_analysis/taint_report.py` | 标准化污点分析报告模板 (Source/Propagation/Sink/Sanitizer) |

### 状态细分

**Conditional 子类型:**
- `conditional-strong`: 高置信度，需环境验证
- `conditional-weak`: 低置信度，需人工确认

**Informational 子类型:**
- `not_exploitable`: 确认不可利用
- `speculative_signal`: 推测性信号，可能误报
- `environmental_risk`: 环境相关风险

### 集成点

1. `models.py`: ConditionalSubtype, InformationalSubtype 枚举
2. `reporting.py`: determine_conditional_subtype(), determine_informational_subtype()
3. `round_four.py`: _calculate_confidence_score(), _build_taint_analysis_report()

