# Current Goal

## Status

Completed on 2026-03-20.

## Goal

P6-06b: 业务逻辑检测方法论设计 (D9 维度)

## Summary

在 `src/layers/l3_analysis/methodology/` 目录下创建业务逻辑检测方法论文档，为 Agent 审计提供 D9 维度的检测指导。覆盖 IDOR、Mass Assignment、状态机完整性、竞态条件、数据导出、多租户隔离等业务逻辑漏洞类型。

## Deliverables

| 文件 | 变更 |
|------|------|
| `src/layers/l3_analysis/methodology/__init__.py` | 新增模块入口，提供 `get_methodology_path()`, `list_available_methodologies()` |
| `src/layers/l3_analysis/methodology/business_logic.md` | 通用业务逻辑检测方法论 (D9 六大子类型) |
| `src/layers/l3_analysis/methodology/python_business_logic.md` | Python 专项检测模式 (Django/Flask/FastAPI) |
| `src/layers/l3_analysis/methodology/java_business_logic.md` | Java 专项检测模式 (Spring Boot) |
| `src/layers/l3_analysis/methodology/go_business_logic.md` | Go 专项检测模式 (Gin/Echo/Fiber) |
| `src/layers/l3_analysis/sinks_sources/__init__.py` | 新增 `BusinessLogicCategory` 枚举 |
| `tests/unit/test_l3/test_methodology.py` | 26 个单元测试 |

## Key Features

1. **D9 六大子类型**:
   - IDOR / 资源归属校验
   - Mass Assignment
   - 状态机完整性
   - 竞态条件 (TOCTOU, Lost Update)
   - 数据导出与批量操作
   - 多租户隔离

2. **Control-driven 审计模型**:
   - 枚举端点 → 验证控制存在 → 缺失=漏洞
   - 区别于 Sink-driven 方法

3. **语言专项覆盖**:
   - Python: Django/Flask/FastAPI
   - Java: Spring Boot
   - Go: Gin/Echo/Fiber

## Test Results

```
tests/unit/test_l3/test_methodology.py: 26 passed
```

## References

- `/opt/AI/code-audit/references/security/business_logic.md`
- `/opt/AI/code-audit/references/core/phase2_deep_methodology.md` (Phase 2.6)

## Next Goal Candidates

- P6-08: 多语言覆盖矩阵
- P6-07d: 导入 WooYun 案例库
