# Current Goal

## Status

**阶段**: Phase 8 - CPG 基础实现
**状态**: ✅ COMPLETED & SYNCED
**开始日期**: 2026-04-07
**完成日期**: 2026-04-07
**同步日期**: 2026-04-07
**提交**: 309601e
**目标**: v0.9 里程碑基础

---

## 已完成目标

### P8-09: Code Property Graph 基础实现 ✅ 已完成

---

## 问题背景

### 当前架构状态

项目已完成以下组件（P8-02 ~ P8-08）：

| 组件 | 位置 | 功能 |
|------|------|------|
| **ASTGraph** | `graph/models.py` | 语句级代码结构 |
| **CallGraph** | `call_graph/models.py` | 函数级调用关系 |
| **GraphBridge** | `graph/bridge.py` | AST ↔ Call Graph 桥接 |
| **UnifiedGraphQuery** | `graph/unified.py` | 统一查询接口 |
| **TaintTracker** | `call_graph/taint_tracker.py` | 污点追踪 |

### 缺失能力

1. **无统一代码图**: AST Graph 和 Call Graph 分离，查询需要跨图操作
2. **无控制流分析**: 无法验证代码路径的可达性
3. **无自动路径搜索**: 攻击路径发现需要手动调用多个组件

---

## 核心理念

> **CPG = AST + Call Graph + CFG 的统一视图**

不是替代现有组件，而是提供统一的上层接口：

```
┌─────────────────────────────────────────────────────────┐
│                    Code Property Graph                   │
│                     (统一查询接口)                        │
├─────────────────────────────────────────────────────────┤
│  AST Graph     │  语句级结构 (if/while/表达式)           │
│  Call Graph    │  函数级调用关系                         │
│  CFG           │  控制流图 (分支/循环/跳转)              │
│  Path Finder   │  攻击路径搜索                           │
└─────────────────────────────────────────────────────────┘
                              ↓
                    AI Agent 结构化上下文
```

---

## 多语言支持计划

### P8-09 第一版支持语言

| 语言 | 优先级 | 支持程度 | 说明 |
|------|--------|----------|------|
| **Python** | P0 | 完整支持 | 主要实现语言，所有 CFG 结构 |
| **JavaScript/TypeScript** | P1 | 核心支持 | if/while/for/try/switch |
| **Java** | P1 | 核心支持 | if/while/for/try/switch |
| **Go** | P2 | 基础支持 | if/while/for (无 try) |

### 语言扩展策略

1. **抽象语言接口**: `LanguageCFGBuilder` 基类
2. **语言特定实现**: `PythonCFGBuilder`, `JSCFGBuilder`, `JavaCFGBuilder`, `GoCFGBuilder`
3. **语言检测**: 复用 `TreeSitterManager.get_language()`
4. **回退机制**: 不支持的语言降级到简单图构建

---

## 实施步骤详解

### P8-09a: 融合 AST Graph + Call Graph

**状态**: 待开始
**优先级**: P0
**文件**: `src/layers/l3_analysis/engines/ast_engine/cpg/`

#### 设计

```python
# src/layers/l3_analysis/engines/ast_engine/cpg/models.py

from dataclasses import dataclass, field
from typing import Any

@dataclass
class CPGNode:
    """
    Code Property Graph 统一节点。

    融合 AST 节点和 Call 节点的信息，提供统一访问接口。
    """
    id: str                          # 统一标识符
    node_type: str                   # "ast_statement" | "call_function"

    # AST 信息
    ast_node_id: str | None = None
    ast_type: str | None = None      # if_statement, call_expression, etc.

    # Call Graph 信息
    call_node_id: str | None = None
    call_name: str | None = None

    # 位置信息
    file: str = ""
    line: int = 0

    # 关系
    predecessors: list[str] = field(default_factory=list)
    successors: list[str] = field(default_factory=list)

    metadata: dict[str, Any] = field(default_factory=dict)

@dataclass
class CPGEdge:
    """
    Code Property Graph 边。

    支持: AST_PARENT, CALLS, REACHES, FLOWS_TO
    """
    edge_type: str  # "ast_parent" | "calls" | "cfg" | "dataflow"
    source: str
    target: str
    metadata: dict[str, Any] = field(default_factory=dict)

@dataclass
class CodePropertyGraph:
    """
    完整的 Code Property Graph。

    融合 AST Graph + Call Graph + (未来) CFG + Dataflow
    """
    nodes: dict[str, CPGNode] = field(default_factory=dict)
    edges: list[CPGEdge] = field(default_factory=list)

    # 原始图引用
    ast_graph: ASTGraph | None = None
    call_graph: CallGraph | None = None

    # 索引
    _ast_index: dict[str, str] = field(default_factory=dict)
    _call_index: dict[str, str] = field(default_factory=dict)
    _file_index: dict[str, list[str]] = field(default_factory=dict)

    def merge_ast_graph(self, ast_graph: ASTGraph) -> None:
        """合并 AST Graph 到 CPG"""
        ...

    def merge_call_graph(self, call_graph: CallGraph) -> None:
        """合并 Call Graph 到 CPG"""
        ...
```

#### 集成点

```python
# 复用现有组件
from src.layers.l3_analysis.engines.ast_engine.graph.builder import ASTGraphBuilder
from src.layers.l3_analysis.call_graph.analyzer import CallGraphAnalyzer

# 新增 CPG 构建器
class CPGBuilder:
    def build(self, source_path: Path) -> CodePropertyGraph:
        # 1. 构建 AST Graph
        ast_builder = ASTGraphBuilder()
        ast_graph = ast_builder.build_from_file(source_path)

        # 2. 构建 Call Graph
        call_analyzer = CallGraphAnalyzer()
        call_graph = call_analyzer.build_graph(source_path)

        # 3. 融合到 CPG
        cpg = CodePropertyGraph()
        cpg.merge_ast_graph(ast_graph)
        cpg.merge_call_graph(call_graph)

        return cpg
```

#### 验收标准

- [ ] CPG 数据模型实现
- [ ] merge_ast_graph() 测试通过
- [ ] merge_call_graph() 测试通过
- [ ] 单元测试覆盖率 > 80%

---

### P8-09b: 添加 CFG（控制流图）支持

**状态**: 待开始
**优先级**: P0
**依赖**: P8-09a
**文件**: `src/layers/l3_analysis/engines/ast_engine/cfg/`

**语言支持**: Python (主要), JavaScript, Java, Go (框架支持)

#### 设计

```python
# src/layers/l3_analysis/engines/ast_engine/cfg/models.py

from dataclasses import dataclass, field
from enum import Enum

class CFGEdgeType(str, Enum):
    """控制流边类型"""
    UNCONDITIONAL = "unconditional"       # 无条件跳转
    CONDITIONAL_TRUE = "conditional_true"    # if 条件为真
    CONDITIONAL_FALSE = "conditional_false"  # if 条件为假
    LOOP_ENTER = "loop_enter"            # 进入循环
    LOOP_BACK = "loop_back"              # 循环回溯
    LOOP_EXIT = "loop_exit"              # 退出循环
    EXCEPTION = "exception"              # 异常处理

@dataclass
class CFGNode:
    """控制流图节点 - 基本块"""
    id: str                    # "file:line:block"
    file: str
    start_line: int
    end_line: int
    statements: list[str]      # AST 节点 ID 列表

    # 基本块属性
    is_entry: bool = False     # 是否入口块
    is_exit: bool = False      # 是否出口块
    has_call: bool = False     # 是否包含函数调用

@dataclass
class CFGEdge:
    """控制流边"""
    edge_type: CFGEdgeType
    source: str                # CFGNode id
    target: str                # CFGNode id
    condition: str | None = None  # 条件表达式（如果有）

@dataclass
class ControlFlowGraph:
    """函数级控制流图"""
    function_id: str           # 所属函数 ID
    nodes: dict[str, CFGNode]
    edges: list[CFGEdge]
    entry_node: str | None = None
    exit_nodes: list[str] = field(default_factory=list)

    def is_reachable(self, from_node: str, to_node: str) -> bool:
        """检查从 from_node 是否可达 to_node"""
        ...
```

#### 构建策略

基于 tree-sitter AST 分析，识别基本块：

```python
# src/layers/l3_analysis/engines/ast_engine/cfg/builder.py

class CFGBuilder:
    """从 AST 构建 CFG"""

    # 控制流节点类型
    CONTROL_FLOW_TYPES = {
        "if_statement",
        "while_statement",
        "for_statement",
        "try_statement",
        "match_statement",  # Python 3.10+
        "return_statement",
        "break_statement",
        "continue_statement",
    }

    def build_for_function(
        self,
        ast_graph: ASTGraph,
        function_node: ASTNode
    ) -> ControlFlowGraph:
        """
        为函数构建 CFG

        步骤:
        1. 识别基本块 (连续语句序列)
        2. 分析控制流结构 (if/while/for/try)
        3. 构建控制流边
        4. 标记入口/出口点
        """
        cfg = ControlFlowGraph(function_id=function_node.id)

        # 1. 获取函数体内所有节点
        body_nodes = self._get_function_body(function_node, ast_graph)

        # 2. 识别基本块
        basic_blocks = self._identify_basic_blocks(body_nodes)

        # 3. 构建控制流边
        self._build_cfg_edges(basic_blocks, cfg)

        return cfg
```

#### Tree-sitter 节点映射

| 控制结构 | Python | JavaScript | Java | Go | CFG 边类型 |
|----------|--------|------------|------|-----|------------|
| if | `if_statement` | `if_statement` | `if_statement` | `if_statement` | CONDITIONAL_TRUE/FALSE |
| while | `while_statement` | `while_statement` | `while_statement` | `while_statement` | LOOP_ENTER/LOOP_BACK/EXIT |
| for | `for_statement` | `for_statement` | `for_statement` | `for_statement` | LOOP_ENTER/LOOP_BACK/EXIT |
| try | `try_statement` | `try_statement` | `try_statement` | N/A | EXCEPTION 边 |
| match | `match_statement` | `switch_statement` | `switch_expression` | N/A | CONDITIONAL 分支 |
| async | `async_function` | `async_function_expression` | N/A | `go_statement` | 异步控制流 |
| return | `return_statement` | `return_statement` | `return_statement` | `return_statement` | 到 EXIT 节点 |
| break | `break_statement` | `break_statement` | `break_statement` | `break_statement` | 循环退出 |
| continue | `continue_statement` | `continue_statement` | `continue_statement` | `continue_statement` | 循环回溯 |

#### 验收标准

- [ ] CFG 数据模型实现
- [ ] 基本块识别正确
- [ ] 控制流边构建正确
- [ ] is_reachable() 测试通过
- [ ] 单元测试覆盖率 > 80%

---

### P8-09c: 攻击路径搜索算法

**状态**: 待开始
**优先级**: P0
**依赖**: P8-09b
**文件**: `src/layers/l3_analysis/engines/ast_engine/path_finder/`

#### 设计

```python
# src/layers/l3_analysis/engines/ast_engine/path_finder/models.py

from dataclasses import dataclass, field
from typing import Any

@dataclass
class AttackPath:
    """完整攻击路径"""
    entry_point: str         # 入口点 ID
    sink: str                # 危险函数 ID
    path: list[str]          # 完整路径 (CPG 节点 ID)

    # 路径属性
    is_sanitized: bool       # 是否有清洗
    sanitizers: list[str]    # 清洗函数 ID 列表
    is_exploitable: bool     # 是否可利用

    # CFG 信息
    reaches_sink: bool       # 控制流是否可达
    condition_paths: dict[str, bool] = field(default_factory=dict)  # 分支条件

    confidence: float
    metadata: dict[str, Any] = field(default_factory=dict)
```

#### 搜索算法

```python
# src/layers/l3_analysis/engines/ast_engine/path_finder/finder.py

class AttackPathFinder:
    """在 CPG 上搜索攻击路径"""

    def __init__(self, cpg: CodePropertyGraph):
        self.cpg = cpg
        self.logger = get_logger(__name__)

    def find_attack_paths(
        self,
        sink_pattern: str,
        max_depth: int = 10
    ) -> list[AttackPath]:
        """
        查找所有攻击路径

        算法:
        1. 从所有 entry points 开始 BFS
        2. 跟随 call edges + cfg edges
        3. 检测 sanitizer 函数
        4. 到达 sink 时构建完整路径
        5. 使用 CFG 验证可达性
        """
        paths = []

        # 1. 获取所有入口点
        entry_points = self._get_entry_points()

        # 2. 获取所有 sink 匹配
        sinks = self._find_sinks(sink_pattern)

        # 3. 对每个 sink，从入口点 BFS 搜索
        for sink in sinks:
            for entry in entry_points:
                path = self._find_path(entry, sink, max_depth)
                if path:
                    paths.append(path)

        return paths

    def _find_path(
        self,
        start: str,
        target: str,
        max_depth: int
    ) -> AttackPath | None:
        """使用 BFS 查找路径"""
        from collections import deque

        queue = deque([(start, [start])])
        visited = set()

        while queue:
            current, path = queue.popleft()

            if len(path) > max_depth:
                continue

            if current == target:
                return self._build_attack_path(path)

            if current in visited:
                continue
            visited.add(current)

            # 获取后继节点
            for successor in self.cpg.get_successors(current):
                queue.append((successor, path + [successor]))

        return None

    def verify_reachability(
        self,
        path: list[str],
        cfg: ControlFlowGraph
    ) -> bool:
        """
        使用 CFG 验证路径可达性

        检查:
        1. 所有条件分支是否可到达
        2. 循环是否会执行
        3. 异常处理是否覆盖
        """
        ...
```

#### 验收标准

- [ ] AttackPath 数据模型实现
- [ ] BFS 路径搜索测试通过
- [ ] CFG 可达性验证测试通过
- [ ] sanitizer 检测正确
- [ ] 单元测试覆盖率 > 80%
- [ ] 集成测试验证完整路径发现

---

## 目录结构规划

```
src/layers/l3_analysis/engines/ast_engine/
├── cpg/                           # 新增 CPG 模块
│   ├── __init__.py
│   ├── models.py                  # CPGNode, CPGEdge, CodePropertyGraph
│   ├── builder.py                 # CPGBuilder
│   └── query.py                   # CPGQuery (扩展查询)
│
├── cfg/                           # 新增 CFG 模块
│   ├── __init__.py
│   ├── models.py                  # CFGNode, CFGEdge, ControlFlowGraph
│   ├── base.py                    # LanguageCFGBuilder 抽象基类
│   ├── factory.py                 # CFGBuilderFactory (语言路由)
│   └── builders/                  # 语言特定实现
│       ├── __init__.py
│       ├── python_cfg.py          # Python CFG Builder (完整支持)
│       ├── js_cfg.py              # JavaScript/TypeScript CFG Builder
│       ├── java_cfg.py            # Java CFG Builder
│       └── go_cfg.py              # Go CFG Builder
│
├── path_finder/                   # 新增路径搜索模块
│   ├── __init__.py
│   ├── models.py                  # AttackPath
│   └── finder.py                  # AttackPathFinder
│
├── graph/                         # 已有
│   ├── models.py
│   ├── builder.py
│   ├── bridge.py
│   └── unified.py
```

---

## 测试计划

### 单元测试

| 组件 | 测试文件 | 覆盖目标 |
|------|----------|----------|
| CPG 模型 | `tests/unit/test_l3/test_cpg/test_models.py` | 数据结构 |
| CPG 构建器 | `tests/unit/test_l3/test_cpg/test_builder.py` | 融合逻辑 |
| CFG 模型 | `tests/unit/test_l3/test_cfg/test_models.py` | 数据结构 |
| CFG 构建器 | `tests/unit/test_l3/test_cfg/test_builder.py` | 基本块识别 |
| 路径搜索 | `tests/unit/test_l3/test_path_finder/test_finder.py` | BFS 算法 |

### 集成测试

| 场景 | 测试文件 | 验证内容 |
|------|----------|----------|
| 端到端路径发现 | `tests/integration/test_cpg/test_e2e.py` | 完整流程 |
| CFG 可达性 | `tests/integration/test_cpg/test_cfg_reachability.py` | 控制流分析 |
| 与现有组件集成 | `tests/integration/test_cpg/test_integration.py` | GraphBridge 等 |

---

## 验收标准汇总

### 功能验收

- [ ] P8-09a: CPG 统一数据模型实现，AST + Call Graph 融合
- [ ] P8-09b: CFG 基本块识别和控制流边构建
- [ ] P8-09c: 攻击路径 BFS 搜索和 CFG 可达性验证

### 测试验收

- [ ] 所有模块单元测试通过（覆盖率 > 80%）
- [ ] 集成测试验证端到端流程
- [ ] 与现有组件（GraphBridge、UnifiedGraphQuery）无冲突

### 集成验收

- [ ] CPG 查询接口扩展 UnifiedGraphQuery
- [ ] AttackPathFinder 可被 Agent 引擎调用
- [ ] 不影响现有扫描流程

### 多语言验收

- [ ] Python CFG 完整支持 (if/while/for/try/match/async)
- [ ] JavaScript CFG 核心支持 (if/while/for/try/switch)
- [ ] Java CFG 核心支持 (if/while/for/try/switch)
- [ ] Go CFG 基础支持 (if/while/for/switch)
- [ ] 语言检测和路由正确

---

## 实现步骤

| 步骤 | 任务 | 预计工作量 | 依赖 |
|------|------|------------|------|
| 1 | **P8-09a-S1**: 创建 CPG 模块目录结构 | 0.5 天 | - |
| 2 | **P8-09a-S2**: 实现 CPG 数据模型 (CPGNode, CPGEdge) | 1 天 | S1 |
| 3 | **P8-09a-S3**: 实现 CPGBuilder 融合 AST + Call Graph | 1.5 天 | S2 |
| 4 | **P8-09a-S4**: 单元测试 CPG 模块 | 1 天 | S3 |
| 5 | **P8-09b-S1**: 创建 CFG 模块目录结构 | 0.5 天 | P8-09a |
| 6 | **P8-09b-S2**: 实现 CFG 数据模型 + 语言抽象接口 | 1 天 | S5 |
| 7 | **P8-09b-S3**: 实现 PythonCFGBuilder (完整支持) | 2 天 | S6 |
| 8 | **P8-09b-S4**: 实现 JSCFGBuilder + JavaCFGBuilder (核心支持) | 1.5 天 | S7 |
| 9 | **P8-09b-S5**: 实现 GoCFGBuilder (基础支持) | 1 天 | S7 |
| 10 | **P8-09b-S6**: 单元测试 CFG 模块 (覆盖 4 种语言) | 1.5 天 | S9 |
| 11 | **P8-09c-S1**: 创建 path_finder 模块 | 0.5 天 | P8-09b |
| 12 | **P8-09c-S2**: 实现 AttackPathFinder BFS 搜索 | 2 天 | S11 |
| 13 | **P8-09c-S3**: 实现 CFG 可达性验证 | 1.5 天 | S12 |
| 14 | **P8-09c-S4**: 单元测试和集成测试 | 1.5 天 | S13 |

**总计**: 约 17 天

---

## 多语言实现详情

### CFG Builder 接口

```python
# src/layers/l3_analysis/engines/ast_engine/cfg/base.py

class LanguageCFGBuilder(ABC):
    """语言特定的 CFG 构建器抽象基类"""

    @abstractmethod
    def get_control_flow_types(self) -> set[str]:
        """返回该语言的控制流节点类型"""
        pass

    @abstractmethod
    def identify_basic_blocks(self, body_nodes: list[ASTNode]) -> list[BasicBlock]:
        """识别基本块"""
        pass

    @abstractmethod
    def build_cfg_edges(self, blocks: list[BasicBlock], cfg: ControlFlowGraph) -> None:
        """构建控制流边"""
        pass
```

### 语言特定实现

| 语言 | 文件 | CFG 覆盖 |
|------|------|----------|
| Python | `cfg/builders/python_cfg.py` | if/while/for/try/match/async/return/break/continue |
| JavaScript | `cfg/builders/js_cfg.py` | if/while/for/try/switch/async/return/break/continue |
| Java | `cfg/builders/java_cfg.py` | if/while/for/try/switch/return/break/continue |
| Go | `cfg/builders/go_cfg.py` | if/while/for/switch/go/return/break/continue |

---

## 风险与缓解

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| CFG 构建复杂度高 | 可能需要更多时间 | 优先支持常见结构 (if/while/for)，复杂结构延后 |
| 多语言支持 | 不同语言 AST 差异大 | 先支持 Python，验证设计后再扩展 |
| 性能问题 | 大项目图构建慢 | 使用增量构建和缓存 |

---

## 参考资源

### 现有组件

- `src/layers/l3_analysis/engines/ast_engine/graph/models.py` - ASTGraph
- `src/layers/l3_analysis/call_graph/models.py` - CallGraph
- `src/layers/l3_analysis/engines/ast_engine/graph/bridge.py` - GraphBridge
- `src/layers/l3_analysis/engines/ast_engine/graph/unified.py` - UnifiedGraphQuery

### 外部参考

- [Joern](https://joern.io/) - 开源代码属性图工具
- [CodeQL](https://codeql.github.com/) - GitHub 的代码分析平台

---

## 已完成目标摘要

### P8-08: 前置防误报架构

✅ **完成日期**: 2026-04-05

**变更**:
- 新增 5 个预过滤器模块
- 109 单元测试 + 16 集成测试通过
- 误报率预计降低 50%
