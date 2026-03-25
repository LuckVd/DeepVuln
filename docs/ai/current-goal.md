# Current Goal

## Status

Completed - 2026-03-25

## Goal

P7-09: Readiness Gate 与 CLI 集成 ✓ 完成

## Summary

增强现有 Readiness Gate 集成 LLM 语言决策器、构建画像和兼容性报告，提升 CodeQL 启动决策的可解释性。

## Completion Summary

| Item | Result |
|------|--------|
| **实现文件** | `src/layers/l3_analysis/readiness_gate.py` (464 行) |
| **修改文件** | `src/cli/main.py` |
| **测试文件** | `tests/unit/test_l3/test_readiness_gate.py` (512 行, 23 tests) |
| **测试结果** | 23 passed (all L3 tests: 1532 passed) |
| **安全扫描** | 无问题 |

## Implemented Features

### 1. CodeQLReadinessGate 类
- 三层决策架构：Basic Check → Smart Decision → Tool Check
- 懒加载子组件：Decider, ModuleDiscovery, VersionDetector, ToolResolver
- Force 模式支持

### 2. LLM 决策集成
- 调用 `CodeQLLanguageDecider` 智能选择语言
- LLM 失败时自动回退到 baseline

### 3. 构建画像集成
- ModuleDiscovery 模块发现
- BuildTargetExtractor 构建目标提取
- VersionDetector 版本需求检测

### 4. 工具兼容性集成
- ToolResolver 工具发现
- ReadinessReport 工具就绪报告

### 5. CLI 增强
- `--force-codeql-all` 选项：强制扫描所有语言
- 增强输出：显示 selected/skipped languages 和工具状态
- 三种状态显示：enabled / gated / forced

### 6. ReadinessGateResult
- selected_languages: 选中的语言列表
- skipped_languages: 跳过的语言（含原因）
- decision_source: 决策来源（llm/baseline/forced）
- tool_report: 工具就绪报告

## Design Decisions

| 决策 | 选择 |
|------|------|
| 架构 | 独立 CodeQLReadinessGate 类 |
| 回退策略 | LLM 失败自动回退 baseline |
| CLI 输出 | Rich 格式化，分节显示 |

## Next Recommended

- **P7-06**: Go/Java 标准构建支持
- **P7-10**: 基线策略、测试与效果评估
