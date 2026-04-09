# Current Goal: 代码质量改进

> **目标 ID**: P15-code-quality-improvement
> **目标**: 修复跨层依赖、清理死代码、修复假测试
> **阶段**: Phase 15 - completed
> **状态**: 已完成 ✅

---

## 问题概述

基于项目全面审视，发现三个主要问题：

| # | 问题 | 严重性 | 影响范围 |
|---|------|--------|----------|
| 1 | 跨层依赖 | 🔴 高 | L3/L1 循环依赖，违反架构原则 |
| 2 | 假测试 | 🟡 中 | 2 个测试文件包含无意义断言 |
| 3 | 死代码 | 🟢 低 | ~2000 行未使用代码 |

---

## 实施计划

### 阶段 1: 死代码清理 (优先)

**原因**: 降低维护负担，减少混淆

**任务列表**:
- P15-01: 删除 `src/web/services/cli_adapter.py` (672 行)
- P15-02: 删除 `src/web/services/scan/` 子目录 (约 800 行)
- P15-03: 删除 `src/web/api/v1/scans_v2.py`
- P15-04: 更新 `src/web/services/__init__.py` 移除 CLIAdapter 导出

**验收标准**:
- ✅ 代码编译无错误
- ✅ 所有测试通过
- ✅ Web 服务正常启动

---

### 阶段 2: 修复假测试

**任务列表**:
- P15-05: 修复 `tests/unit/test_l3/test_scan_order.py:187`
- P15-06: 修复 `tests/unit/test_l1/test_llm_detector.py:302`
- P15-07: 确保每个测试都有实际断言

**验收标准**:
- ✅ 所有测试通过
- ✅ 无 `assert True` 类型的假测试

---

### 阶段 3: 修复跨层依赖

**策略**: 将共享模型移动到 `src/core/models/`

**任务列表**:
- P15-08: 创建 `src/core/models/attack_surface.py`
- P15-09: 移动 `EntryPoint`, `AttackSurfaceReport`, `EntryPointType` 等模型
- P15-10: 更新 L1 层导入
- P15-11: 更新 L3 层导入
- P15-12: 移除 L1 对 L3 的依赖 (LLMClient)
- P15-13: 验证无循环依赖

**架构变化**:

```
┌─────────────────────────────────────────────────────────────┐
│  修复前 (循环依赖):                                          │
│  L3 → L1 → Core                                             │
│  ↑         ↓                                                 │
│  └─────────┘  ← L1 导入 L3 的 LLMClient                     │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  修复后 (单向依赖):                                          │
│  L3 → Core ← L1                                             │
│         ↑       ↑                                            │
│         └───────┘  共享模型从 Core 导入                      │
└─────────────────────────────────────────────────────────────┘
```

**验收标准**:
- ✅ 无跨层直接导入
- ✅ 所有测试通过
- ✅ 运行 `python -c "import src.layers"` 无循环导入错误

---

### 阶段 4: 修复空 except 块

**任务列表**:
- P15-14: 修复 `src/web/api/v1/scans_v2.py` (如未删除)
- P15-15: 确保所有异常处理都有明确的日志

**验收标准**:
- ✅ 无空 `except:` 块
- ✅ 所有异常都有适当的日志记录

---

## 验收标准

1. ✅ 死代码已清理 (~2000 行)
2. ✅ 假测试已修复
3. ✅ 跨层依赖已解决
4. ✅ 所有测试通过
5. ✅ Web 服务正常启动运行

---

## 用户确认需求

### 实施顺序
- ✅ 死代码清理优先
- ✅ 共享模型放在 `src/core/models/`

### 待确认问题
- 是否需要创建专门的共享模块 `src/shared/`? → 用户选择 `src/core/models/`

---

## 相关文件

### 需要删除的文件
- `src/web/services/cli_adapter.py`
- `src/web/services/scan/` (整个目录)
- `src/web/api/v1/scans_v2.py`

### 需要创建的文件
- `src/core/models/attack_surface.py`

### 需要修改的文件
- `src/layers/l1_intelligence/attack_surface/llm_detector.py`
- `src/layers/l3_analysis/rounds/round_four.py`
- `src/web/services/__init__.py`
- `tests/unit/test_l3/test_scan_order.py`
- `tests/unit/test_l1/test_llm_detector.py`
