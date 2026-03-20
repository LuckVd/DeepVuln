# Current Goal

## Status

Completed on 2026-03-20.

## Goal

P6-07: 目录分类与降权策略

## Summary

实现目录级别的代码分类系统，对非生产代码（测试、示例、fixture、challenge 等）进行降权处理，减少扫描报告中的噪声。

## Deliverables

| 文件 | 变更 |
|------|------|
| `src/core/file_filtering.py` | 新增 `DirectoryClass` 枚举, `classify_directory()`, `get_score_multiplier()` |
| `src/layers/l3_analysis/models.py` | `Finding` 新增 `directory_class`, `score_multiplier` 字段 |
| `src/core/final_score.py` | `FinalScore` 新增 `directory_multiplier` 字段，计算函数支持降权 |
| `src/core/config/__init__.py` | 新增 `get_directory_classification_config()` 等配置函数 |
| `config.example.toml` | 新增 `[directory_classification]` 配置节 |
| `tests/unit/test_core/test_file_filtering.py` | 新增 41 个单元测试 |

## Key Features

1. **DirectoryClass 枚举**: 5 种目录类型
   - PRODUCTION (1.0)
   - TEST (0.3)
   - FIXTURE (0.2)
   - SAMPLE (0.1)
   - CHALLENGE (0.1)

2. **分类优先级**: Challenge > Fixture > Sample > Test > Production

3. **配置项支持**: 可自定义目录规则和降权因子

## Test Results

```
tests/unit/test_core/test_file_filtering.py: 41 passed
tests/unit/test_core/test_final_score.py: 58 passed
```

## Next Goal Candidates

- P6-06b: 业务逻辑检测方法论设计
- P6-08: 多语言覆盖矩阵
