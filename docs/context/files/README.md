# File Index

Tracks structure-level files by area so humans and checks can answer:
- what each file is for
- where a new file should live
- which docs must be updated when a file changes

## Current Split

- `governance-core.md`: `.claude/**`, `tools/**`
- `planning-state.md`: `docs/goals/**`, `docs/roadmap/**`, `docs/history/**`
- `product-code.md`: reserved for `src/**`

## Recent Changes (P6-04)

### New Files

| File | Purpose | Area |
|------|---------|------|
| `src/layers/l3_analysis/confidence_scorer.py` | P6-04d: 置信度评分模块，集成验证方法论 | product-code |
| `src/layers/l3_analysis/taint_report.py` | P6-04c: 污点分析报告模板，集成 code-audit 模板 | product-code |

### Modified Files

| File | Change | Area |
|------|--------|------|
| `src/layers/l3_analysis/models.py` | P6-04: 新增 ConditionalSubtype, InformationalSubtype 枚举；扩展 Finding 模型 | product-code |
| `src/layers/l3_analysis/reporting.py` | P6-04: 新增状态子类型判定逻辑 | product-code |
| `src/layers/l3_analysis/rounds/round_four.py` | P6-04: 集成置信度评分和污点分析报告 | product-code |

