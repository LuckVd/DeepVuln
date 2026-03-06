# 当前目标

> 单一焦点：本次会话关注的核心任务
---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | P5-01b：AST 调用图构建与可达性分析 |
| **状态** | in_progress |
| **优先级** | P0 |
| **创建日期** | 2026-03-06 |
| **所属阶段** | Phase 5 - 精度深化 |
| **模块层级** | L3 Analysis Layer |
| **依赖** | P5-01a（已完成） |
| **父任务** | P5-01：可利用性评估增强 |

---

## 问题背景

当前 `ContextBuilder.analyze_call_chain()` 使用正则匹配，存在以下问题：

| 问题 | 现状 | 影响 |
|------|------|------|
| 调用关系检测 | 基于文本正则匹配 | 无法处理复杂调用模式 |
| 跨文件分析 | 不支持 | 无法追踪跨文件调用链 |
| 可达性判断 | 简单的入口点检测 | 无法计算完整调用路径 |
| 置信度 | 无路径长度考量 | 无法区分直接/间接可达 |

---

## 核心目标

**构建 AST 调用图，实现从入口点到漏洞点的可达性分析。**

---

## 技术方案

### 1. 模块结构

```
src/layers/l3_analysis/call_graph/
├── __init__.py
├── analyzer.py          # CallGraphAnalyzer 主类
├── models.py            # 数据模型 (CallNode, CallEdge, CallGraph)
├── builders/
│   ├── __init__.py
│   ├── base.py          # 抽象基类
│   ├── python_builder.py
│   ├── java_builder.py
│   └── go_builder.py
└── reachability.py      # 可达性分析 (BFS)
```

### 2. 核心数据模型

```python
@dataclass
class CallNode:
    id: str           # "file:function"
    name: str         # 函数名
    file_path: str    # 文件路径
    line: int         # 行号
    is_entry_point: bool
    entry_point_type: str | None

@dataclass
class CallEdge:
    caller_id: str    # 调用者
    callee_id: str    # 被调用者
    call_site: str    # 调用位置

@dataclass
class CallGraph:
    nodes: dict[str, CallNode]
    edges: list[CallEdge]
    reverse_index: dict[str, list[str]]  # callee -> callers

@dataclass
class ReachabilityResult:
    source_id: str
    target_id: str
    is_reachable: bool
    path: list[str]
    path_length: int
    confidence: float
```

### 3. Tree-sitter 查询示例

```python
# Python 函数定义
FUNCTION_QUERY = """
(function_definition
    name: (identifier) @name
    body: (block) @body
)
"""

# Python 函数调用
CALL_QUERY = """
(call
    function: (identifier) @func_name
)
"""
```

---

## 新建文件

| 文件 | 用途 |
|------|------|
| `src/layers/l3_analysis/call_graph/__init__.py` | 模块入口 |
| `src/layers/l3_analysis/call_graph/models.py` | 数据模型 |
| `src/layers/l3_analysis/call_graph/analyzer.py` | 主分析器 |
| `src/layers/l3_analysis/call_graph/builders/base.py` | 构建器基类 |
| `src/layers/l3_analysis/call_graph/builders/python_builder.py` | Python 构建器 |
| `src/layers/l3_analysis/call_graph/builders/java_builder.py` | Java 构建器 |
| `src/layers/l3_analysis/call_graph/builders/go_builder.py` | Go 构建器 |
| `src/layers/l3_analysis/call_graph/reachability.py` | 可达性分析 |
| `tests/unit/test_l3/test_call_graph.py` | 单元测试 |

---

## 修改文件

| 文件 | 改动 |
|------|------|
| `src/layers/l3_analysis/rounds/round_four.py` | 集成 CallGraphAnalyzer |

---

## 验收标准

| 标准 | 指标 |
|------|------|
| 调用图构建 | 支持 Python/Java/Go 三语言 |
| 可达性分析 | 准确识别入口点→漏洞点路径 |
| AST 解析 | 基于 Tree-sitter，复用现有基础设施 |
| 性能 | 单文件分析 < 100ms |
| 测试覆盖 | 30+ 新测试 |
| 兼容性 | 现有测试全部通过 |

---

## 设计原则

| 原则 | 实现方式 |
|------|----------|
| **复用基础设施** | 使用现有 Tree-sitter AST 解析器 |
| **渐进增强** | 可选参数，不影响现有调用 |
| **语言扩展性** | 抽象基类，易于添加新语言 |
| **性能优化** | LRU 缓存，按需解析 |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-03-06 | 创建 P5-01b 目标 |
