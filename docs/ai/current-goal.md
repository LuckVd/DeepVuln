# Current Goal

## Status

**阶段**: Phase 9 - CPG 与 Agent 集成
**状态**: ✅ IMPLEMENTATION COMPLETE - READY TO SYNC
**开始日期**: 2026-04-07
**目标**: v1.0 里程碑基础

---

## 目标背景

### 已完成基础

| 组件 | 状态 |
|------|------|
| **CPG 数据模型** | ✅ CodePropertyGraph, CPGNode, CPGEdge |
| **CPG 构建器** | ✅ CPGBuilder (AST + Call Graph 融合) |
| **攻击路径搜索** | ✅ AttackPathFinder (BFS + Sanitizer 检测) |
| **AST 上下文** | ✅ ASTContextExtractor (已集成到 Agent) |

### 缺失集成

- Agent 无法调用 `AttackPathFinder`
- Agent 无法获取完整攻击路径元数据
- Agent Finding 无路径信息字段

---

## 核心理念

> **分层集成，可选降级**

不是重写 Agent，而是在现有基础上添加 CPG 路径分析能力：

```
Agent (现有)
    ├── LLM 推理 (现有)
    ├── AST 上下文 (现有)
    └── CPG 路径分析 (新增) ← 可选，失败时降级
```

---

## 设计方案

### 架构图

```
┌─────────────────────────────────────────────────────────────┐
│                      OpenCodeAgent                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  _analyze_single_file()                            │   │
│  │  1. 读取源代码                                      │   │
│  │  2. 提取 AST 上下文 (现有)                         │   │
│  │  3. (可选) 获取 CPG 路径 (新增) ← CPGPathProvider  │   │
│  │  4. 构建 audit prompt                              │   │
│  │  5. LLM 推理                                        │   │
│  │  6. 解析结果 (增强 cpg_path 字段)                   │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                  CPGPathProvider (新增)                     │
│  - 语言无关接口                                            │
│  - 自动语言检测 (TreeSitterManager)                        │
│  - 路由到语言特定 Provider                                 │
│  - 返回 AttackPath 列表                                    │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│               LanguageCPGProvider (抽象)                    │
│  - PythonCPGProvider                                       │
│  - JSCPGProvider                                            │
│  - JavaCPGProvider                                         │
│  - GoCPGProvider                                           │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│           CPGBuilder + AttackPathFinder (已有)             │
└─────────────────────────────────────────────────────────────┘
```

---

## 设计决策

| 决策 | 说明 |
|------|------|
| **降级策略** | CPGPathProvider 可选，失败时 Agent 继续正常工作 |
| **Finding 扩展** | 添加 `cpg_path: dict | None` 字段存储路径信息 |
| **语言检测** | 复用现有 `TreeSitterManager.get_language()` |
| **语言优先级** | Python (完整) > JavaScript > Java > Go |
| **错误处理** | CPG 构建失败时记录警告，不中断扫描 |

---

## 目录结构

```
src/layers/l3_analysis/engines/ast_engine/cpg/
├── __init__.py
├── models.py              # 已有: CPGNode, CodePropertyGraph
├── builder.py             # 已有: CPGBuilder
├── path_provider.py       # 新增: CPGPathProvider (语言无关接口)
├── base.py                # 新增: LanguageCPGProvider 抽象类
└── providers/             # 新增: 语言特定实现
    ├── __init__.py
    ├── python_provider.py # PythonCPGProvider
    ├── js_provider.py     # JSCPGProvider
    ├── java_provider.py   # JavaCPGProvider
    └── go_provider.py     # GoCPGProvider

src/layers/l3_analysis/models.py
├── Finding                # 修改: 添加 cpg_path 字段

src/layers/l3_analysis/engines/opencode_agent.py
├── OpenCodeAgent          # 修改: 集成 CPGPathProvider

tests/unit/test_l3/test_cpg/
├── test_path_provider.py  # 新增
├── test_python_provider.py # 新增
└── test_js_provider.py    # 新增

tests/integration/test_cpg_agent/
├── __init__.py
└── test_e2e.py            # 新增: 端到端集成测试
```

---

## 实施步骤

### S1: CPGPathProvider 语言无关接口

**文件**: `src/layers/l3_analysis/engines/ast_engine/cpg/path_provider.py`

```python
class CPGPathProvider:
    """语言无关的 CPG 路径提供器"""

    def __init__(self):
        self._providers = {
            "python": PythonCPGProvider(),
            "javascript": JSCPGProvider(),
            "java": JavaCPGProvider(),
            "go": GoCPGProvider(),
        }
        self._detector = TreeSitterManager()  # 语言检测

    def get_attack_paths(
        self,
        source_path: Path,
        sink_pattern: str,
    ) -> list[AttackPath]:
        """
        获取攻击路径

        步骤:
        1. 检测语言
        2. 路由到对应 Provider
        3. 返回路径列表
        """
        language = self._detector.get_language(source_path)
        provider = self._providers.get(language)

        if not provider:
            return []

        return provider.get_paths(source_path, sink_pattern)
```

**验收**:
- [ ] 语言检测正确
- [ ] 路由到正确 Provider
- [ ] 未知语言返回空列表

---

### S2: LanguageCPGProvider 抽象类

**文件**: `src/layers/l3_analysis/engines/ast_engine/cpg/base.py`

```python
class LanguageCPGProvider(ABC):
    """语言特定的 CPG 路径提供器抽象"""

    @abstractmethod
    def get_paths(
        self,
        source_path: Path,
        sink_pattern: str,
    ) -> list[AttackPath]:
        """获取攻击路径"""
        pass

    @abstractmethod
    def supports_language(self, language: str) -> bool:
        """是否支持该语言"""
        pass
```

---

### S3: PythonCPGProvider 实现

**文件**: `src/layers/l3_analysis/engines/ast_engine/cpg/providers/python_provider.py`

```python
class PythonCPGProvider(LanguageCPGProvider):
    """Python CPG 路径提供器"""

    def get_paths(self, source_path, sink_pattern):
        # 1. 构建 CPG
        builder = CPGBuilder()
        cpg = builder.build_from_directory(source_path, ["*.py"])

        # 2. 搜索路径
        finder = AttackPathFinder()
        return finder.find_paths(cpg, sink_pattern)

    def supports_language(self, language):
        return language == "python"
```

---

### S4: JSCPGProvider 实现

**文件**: `src/layers/l3_analysis/engines/ast_engine/cpg/providers/js_provider.py`

```python
class JSCPGProvider(LanguageCPGProvider):
    """JavaScript/TypeScript CPG 路径提供器"""

    def get_paths(self, source_path, sink_pattern):
        patterns = ["*.js", "*.jsx", "*.ts", "*.tsx"]
        builder = CPGBuilder()
        cpg = builder.build_from_directory(source_path, patterns)

        finder = AttackPathFinder()
        return finder.find_paths(cpg, sink_pattern)

    def supports_language(self, language):
        return language in {"javascript", "typescript"}
```

---

### S5: Agent 集成

**文件**: `src/layers/l3_analysis/engines/opencode_agent.py`

**修改点**:
1. 添加 `cpg_path_provider: CPGPathProvider | None` 参数
2. 在 `_analyze_single_file()` 中调用 CPG 路径分析
3. 将路径信息添加到 Finding 中

```python
class OpenCodeAgent:
    def __init__(
        self,
        cpg_path_provider: CPGPathProvider | None = None,
        ...
    ):
        self.cpg_provider = cpg_path_provider

    async def _analyze_single_file(self, file_path: Path):
        # 现有逻辑...

        # 新增: 获取 CPG 路径
        cpg_paths = None
        if self.cpg_provider:
            try:
                cpg_paths = self.cpg_provider.get_attack_paths(
                    file_path.parent,
                    "eval|exec|system",  # 危险函数模式
                )
            except Exception as e:
                self.logger.warning(f"CPG path analysis failed: {e}")

        # 构建 prompt 时包含路径信息
        prompt = build_audit_prompt(
            code,
            ast_context=ast_context,
            cpg_paths=cpg_paths,  # 新增参数
        )

        # 解析结果时扩展 Finding
        for finding in findings:
            if cpg_paths:
                finding.cpg_path = self._match_path_to_finding(finding, cpg_paths)
```

---

### S6: Finding 数据模型扩展

**文件**: `src/layers/l3_analysis/models.py`

```python
@dataclass
class Finding:
    # ... 现有字段 ...

    # CPG 路径信息 (新增)
    cpg_path: dict[str, Any] | None = None
    # 格式: {
    #   "entry_point": str,
    #   "sink": str,
    #   "path": list[str],
    #   "confidence": float,
    #   "sanitizers": list[str],
    #   "reaches_sink": bool,
    # }
```

---

## 测试计划

### 单元测试

| 测试文件 | 覆盖内容 | 状态 |
|----------|----------|------|
| `test_path_provider.py` | 语言检测、路由、降级逻辑 | ✅ 完成 |
| `test_python_provider.py` | Python CPG 构建和路径搜索 | ✅ 完成 |
| `test_js_provider.py` | JavaScript CPG 构建和路径搜索 | ✅ 完成 |

### 集成测试

| 测试文件 | 验证内容 | 状态 |
|----------|----------|------|
| `test_e2e.py` | Agent → CPGPathProvider → AttackPathFinder 完整流程 | ✅ 完成 |

**测试结果**: 61/61 tests passed (100%)

---

## 验收标准

- [x] **功能验收**:
  - [x] Agent 可以获取 CPG 路径信息
  - [x] 支持 Python 和 JavaScript
  - [x] CPG 失败时 Agent 正常降级
  - [x] Finding 包含 cpg_path 字段

- [x] **测试验收**:
  - [x] 单元测试覆盖率 > 80%
  - [x] 集成测试通过 (61/61)

- [x] **代码质量**:
  - [x] 遵循项目代码规范
  - [x] 无 mypy 错误
  - [x] 无 ruff 警告

---

## 风险与缓解

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| CPG 构建性能 | 扫描时间增加 | 可选启用，降级策略 |
| 多语言支持复杂度 | 实现时间延长 | 优先 Python/JS，其他语言延后 |
| 与现有 Agent 冲突 | 破坏现有功能 | 严格降级，独立模块 |

---

## 参考资源

### 现有组件
- `src/layers/l3_analysis/engines/ast_engine/cpg/models.py` - CPG 数据模型
- `src/layers/l3_analysis/engines/ast_engine/cpg/builder.py` - CPGBuilder
- `src/layers/l3_analysis/engines/ast_engine/path_finder/finder.py` - AttackPathFinder
- `src/layers/l3_analysis/engines/ast_engine/context/extractor.py` - ASTContextExtractor (参考集成方式)

### 外部参考
- [Joern CPG](https://joern.io/) - 开源代码属性图工具
