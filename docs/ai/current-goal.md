# Current Goal

## Status

**阶段**: Phase 8 - AST Engine 与代码图构建
**状态**: P8-02 进行中
**开始日期**: 2026-04-04

---

## 当前任务

### P8-02: AST Engine 核心架构与基础设施（P0）

**目标**: 构建语句级别的代码理解能力，与 Call Graph 形成互补，为 AI Agent 提供结构化上下文

#### 核心价值

| 维度 | 说明 |
|------|------|
| **能力补充** | AST（语句级） + Call Graph（函数级） + Dataflow（数据流级） |
| **AI 协同** | 结构化代码上下文 → 更稳定的 AI 推理 |
| **最终目标** | Code Property Graph (CPG) → 攻击路径自动发现 |

#### 架构定位

```
Multi Engine Scan
├─ Semgrep      → Pattern 匹配
├─ CodeQL       → 数据流分析
├─ AST Engine   → 结构级代码理解 ← 新增
└─ Agent        → 业务逻辑分析

                    ↓
            Code Graph Builder
                    ↓
            Finding Graph + Vuln Chaining
```

#### 与现有组件的关系

| 现有组件 | 位置 | 与 AST Engine 的关系 |
|----------|------|---------------------|
| Call Graph | `src/layers/l3_analysis/call_graph/models.py` | 复用 `CallNode`, `CallEdge`, `CallGraph` 数据结构 |
| tree-sitter | `src/layers/l1_intelligence/attack_surface/ast/` | 复用 `ASTDetector` 基类和语言加载器 |
| BaseEngine | `src/layers/l3_analysis/engines/base.py` | AST Engine 继承此基类 |

---

## 实施步骤

### P8-02a: 创建引擎目录结构与 ast_engine.py 基类

**状态**: ✅ 完成
**文件**: `src/layers/l3_analysis/engines/ast_engine/`

**已完成**:
- [x] 创建 `src/layers/l3_analysis/engines/ast_engine/__init__.py`
- [x] 创建 `ast_engine.py`，继承 `BaseEngine`
- [x] 实现 `is_available()` 方法
- [x] 定义 `supported_languages`：python, javascript, java, go 等

### P8-02b: 实现 TreeSitterManager

**状态**: ✅ 完成
**依赖**: P8-02a
**文件**: `src/layers/l3_analysis/engines/ast_engine/parser/tree_sitter_manager.py`

**已完成**:
- [x] 复用 L1 的 `ASTDetector` 语言加载逻辑
- [x] 支持动态加载多语言 tree-sitter 包
- [x] 实现 Parser 缓存池
- [x] 错误处理：语言包缺失时优雅降级

### P8-02c: 实现 QueryEngine

**状态**: ✅ 完成
**依赖**: P8-02b
**文件**: `src/layers/l3_analysis/engines/ast_engine/queries/query_engine.py`

**已完成**:
- [x] 封装 tree-sitter query API
- [x] 实现 `execute_query(query_text, ast_tree)` 方法
- [x] 支持 YAML 规则文件加载
- [x] 查询结果标准化输出

### P8-02d: 集成到 engine_registry

**状态**: ✅ 完成
**依赖**: P8-02c
**文件**: `src/layers/l3_analysis/engines/ast_engine/ast_engine.py`

**已完成**:
- [x] 实现 `scan()` 方法
- [x] 解析源代码 → AST
- [x] 执行查询规则
- [x] 生成 `ScanResult` 和 `Finding`
- [x] 注册到 `engine_registry`

### P8-02e: 单元测试

**状态**: ✅ 完成
**依赖**: P8-02d
**文件**: `tests/unit/test_l3/test_ast_engine/`

**已完成**:
- [x] 测试 parser 初始化
- [x] 测试 query 执行
- [x] 测试 finding 生成
- [x] 测试多语言支持
- **结果**: 14/14 测试通过

---

## 目录结构

```
src/layers/l3_analysis/engines/ast_engine/
│
├── __init__.py
├── ast_engine.py           # 主引擎，继承 BaseEngine
│
├── parser/
│   ├── __init__.py
│   └── tree_sitter_manager.py    # 复用 L1 的 language loader
│
├── queries/
│   ├── __init__.py
│   ├── query_engine.py
│   └── query_loader.py
│
├── detectors/
│   ├── __init__.py
│   ├── base_detector.py
│   ├── api_misuse_detector.py
│   ├── crypto_detector.py
│   └── deserialization_detector.py
│
└── models.py                # ASTNode, ASTEdge 等
```

---

## 规则目录

```
rules/ast_query/
├── python/
│   ├── dangerous_eval.yaml
│   ├── crypto_weak_hash.yaml
│   ├── deserialization.yaml
│   └── subprocess_shell_true.yaml
├── javascript/
│   ├── dangerous_eval.yaml
│   └── crypto_weak_hash.yaml
└── java/
    ├── runtime_exec.yaml
    └── deserialization.yaml
```

---

## 后续任务预览

| 任务 | 优先级 | 说明 |
|------|--------|------|
| P8-03 | P0 | 结构型漏洞检测器（API/Crypto/Deserialize） |
| P8-04 | P1 | AST Graph Builder |
| P8-05 | P1 | 与 Call Graph 桥接 |
| P8-06 | P1 | AI Agent 结构化上下文 |

---

## 已完成目标摘要

### P7-01: 报告导出增强 - LLM 分析详情选项

✅ **完成日期**: 2026-04-02
✅ **提交**: `323ba95`

**变更**:
- 新增 `--include-llm-details` 命令行选项
- 导出报告可包含：去重分析详情、对抗验证详情 (verdict, confidence, reasoning)

### P5-01e: 扫描顺序优化

✅ **完成日期**: 2026-04-02
✅ **提交**: `2a87275`

**变更**:
- Phase 4.25: 去重和裁决移到对抗验证之前
- 对抗验证现在仅处理去重后的 findings
- API 调用减少约 25%，Token 节省约 30%
