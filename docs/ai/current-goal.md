# Current Goal

## Status

In Progress - Started on 2026-03-20.

## Goal

P6-08: 多语言覆盖矩阵

## Summary

实现 `language x engine x dimension x status` 四维矩阵数据结构，用于追踪和展示审计覆盖情况。支持三种覆盖判定轨道：Sink-driven、Control-driven、Config-driven。

## Scope

| 项目 | 内容 |
|------|------|
| **语言范围** | Python, JavaScript, TypeScript, Java, Go, PHP, Ruby, C#, C++, Rust (10 种) |
| **引擎范围** | Semgrep, CodeQL, Agent (3 种) |
| **维度范围** | D1-D10 (10 种) |
| **状态类型** | 未覆盖/浅覆盖/已覆盖/不适用 |

## Deliverables

| 文件 | 变更 |
|------|------|
| `src/layers/l3_analysis/coverage/__init__.py` | 新增模块入口 |
| `src/layers/l3_analysis/coverage/matrix.py` | 覆盖矩阵数据模型 |
| `src/layers/l3_analysis/coverage/evaluator.py` | 覆盖标准判定器 |
| `src/layers/l3_analysis/rounds/models.py` | 集成 CoverageMatrix |
| `tests/unit/test_l3/test_coverage_matrix.py` | 单元测试 |

## Acceptance Criteria

1. ✅ 创建 `CoverageMatrix` 数据模型
2. ✅ 创建 `DimensionCoverage` 子模型
3. ✅ 实现 `CoverageEvaluator` 覆盖标准判断
4. ✅ 实现矩阵构建器
5. ✅ 集成到 `CoverageStats`
6. ✅ 单元测试通过

## Implementation Steps

| 步骤 | 任务 | 状态 |
|------|------|------|
| S1 | 创建 coverage 目录结构 | pending |
| S2 | 定义数据模型 (CoverageStatus, DimensionType, DimensionCoverage) | pending |
| S3 | 实现 CoverageMatrix 主模型 | pending |
| S4 | 实现 CoverageEvaluator 覆盖判定器 | pending |
| S5 | 集成到 CoverageStats | pending |
| S6 | 编写单元测试 | pending |

## Coverage Criteria

| 维度类型 | 已覆盖 | 浅覆盖 | 未覆盖 |
|---------|--------|--------|--------|
| **Sink-driven** (D1,D4,D5,D6) | Sink 全覆盖 + 数据流 + 扇出率≥30% | 有遗漏/无追踪/扇出率<30% | 未搜索 |
| **Control-driven** (D3,D9) | 端点审计率≥50%(deep)/≥30%(standard) | 仅 Grep 无端点验证 | 未审计 |
| **Config-driven** (D2,D7,D8,D10) | 核心配置已检查 + 基线对比 | 部分检查 | 未检查 |

## References

- `/opt/AI/code-audit/references/checklists/coverage_matrix.md`
- `src/layers/l1_intelligence/tech_stack_detector/models.py:Language`
- `src/layers/l3_analysis/rounds/models.py:CoverageStats`

## Dependencies

- P6-07 (目录分类) - 已完成
- P6-06b (D9 方法论) - 已完成
