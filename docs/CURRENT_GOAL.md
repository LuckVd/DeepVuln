# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | P1-07: 代码结构解析器 (Code Structure Parser) |
| **状态** | completed |
| **优先级** | high |
| **创建日期** | 2026-02-17 |

---

## 背景说明

代码结构解析是 L2-Understanding 层的核心功能，用于深入理解项目架构：

**当前问题**：
- 仅能识别技术栈，无法理解代码结构
- 缺少函数/类/模块的调用关系
- 无法识别数据流和依赖关系

**解决方案**：实现基于 Tree-sitter 的代码结构解析器，提取：
- AST (抽象语法树)
- 调用图 (Call Graph)
- 类/函数定义
- 导入依赖关系

---

## 完成标准

### Phase 1: 基础设施
- [x] 创建 CodeStructureParser 基类
- [x] 定义数据模型 (FunctionDef, ClassDef, ModuleInfo, CallGraph)
- [x] 实现模块入口

### Phase 2: Java 解析器
- [x] 实现 JavaStructureParser
- [x] 解析类定义 (class, interface, enum)
- [x] 解析方法定义
- [x] 解析字段和注解
- [x] 解析 import 语句
- [x] 构建方法调用图

### Phase 3: Python 解析器
- [x] 实现 PythonStructureParser
- [x] 解析类和函数定义
- [x] 解析装饰器
- [x] 解析 import 语句
- [x] 构建函数调用图

### Phase 4: Go 解析器
- [x] 实现 GoStructureParser
- [x] 解析 struct 和 interface
- [x] 解析函数定义
- [x] 解析 import 语句
- [x] 构建调用图

### Phase 5: 集成与测试
- [x] 集成到 L1/L2 工作流
- [x] CLI 命令支持 (deepvuln parse <path>)
- [x] 单元测试覆盖
- [x] 使用真实项目验证

---

## 技术方案

### 模块结构

```
src/layers/l1_intelligence/code_structure/
├── __init__.py
├── models.py                    # 数据模型
├── parser.py                    # 主解析器
├── base.py                      # 解析器基类
│
└── languages/                   # 语言解析器
    ├── __init__.py
    ├── base.py                  # LanguageParser 基类
    ├── java_parser.py           # Java 解析器
    ├── python_parser.py         # Python 解析器
    └── go_parser.py             # Go 解析器
```

### 数据模型

```python
from pydantic import BaseModel
from enum import Enum

class Visibility(str, Enum):
    PUBLIC = "public"
    PRIVATE = "private"
    PROTECTED = "protected"

class FunctionDef(BaseModel):
    name: str
    full_name: str  # ClassName.methodName
    parameters: list[Parameter]
    return_type: str | None
    visibility: Visibility
    is_static: bool = False
    is_async: bool = False
    decorators: list[str] = []
    docstring: str | None = None
    line_start: int
    line_end: int
    file_path: str

class ClassDef(BaseModel):
    name: str
    type: str  # class, interface, enum, struct
    bases: list[str]
    methods: list[FunctionDef]
    fields: list[FieldDef]
    annotations: list[str]
    line_start: int
    line_end: int
    file_path: str

class CallEdge(BaseModel):
    caller: str  # full_name of caller
    callee: str  # full_name of callee
    line: int
    file_path: str

class ModuleInfo(BaseModel):
    file_path: str
    language: str
    imports: list[str]
    classes: list[ClassDef]
    functions: list[FunctionDef]  # top-level functions
    call_graph: list[CallEdge]
```

### Tree-sitter 查询示例

**Java 类定义**:
```python
CLASS_QUERY = """
(class_declaration
    name: (identifier) @class_name
    bases: (class_heritage
        (identifier) @base
    )?
) @class
"""
```

**Java 方法调用**:
```python
METHOD_CALL_QUERY = """
(method_invocation
    object: (identifier) @object
    name: (identifier) @method
) @call
"""
```

**Python 函数定义**:
```python
FUNCTION_QUERY = """
(function_definition
    name: (identifier) @name
    parameters: (parameters) @params
    return_type: (type) @return_type?
) @function
"""
```

---

## 关联文件

### 需要新建
- `src/layers/l1_intelligence/code_structure/__init__.py`
- `src/layers/l1_intelligence/code_structure/models.py`
- `src/layers/l1_intelligence/code_structure/parser.py`
- `src/layers/l1_intelligence/code_structure/base.py`
- `src/layers/l1_intelligence/code_structure/languages/__init__.py`
- `src/layers/l1_intelligence/code_structure/languages/base.py`
- `src/layers/l1_intelligence/code_structure/languages/java_parser.py`
- `src/layers/l1_intelligence/code_structure/languages/python_parser.py`
- `src/layers/l1_intelligence/code_structure/languages/go_parser.py`
- `tests/unit/test_code_structure/`

### 需要修改
- `src/layers/l1_intelligence/__init__.py` - 导出新模块
- `src/cli/` - 添加 parse 命令

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-02-17 | 设置新目标：P1-07 代码结构解析器 |
| 2026-02-18 | 完成 Phase 1-5，实现 Java/Python/Go 三语言解析器，83 个测试通过 |
| 2026-02-18 | 目标完成：代码结构解析器已集成到 CLI |

---

## 备注

### 支持语言优先级

| 语言 | 优先级 | 说明 |
|------|--------|------|
| Java | P0 | Spring/Dubbo 是主要目标 |
| Python | P0 | 常用后端语言 |
| Go | P1 | 云原生项目常用 |
| TypeScript | P2 | 后续扩展 |
| JavaScript | P2 | 后续扩展 |

### 注意事项

1. **复用 Tree-sitter**: 利用已有的 tree-sitter 依赖和 AST 检测经验
2. **性能考虑**: 大项目需要增量解析和缓存
3. **调用图精度**: 静态调用图可能不完整，需标注置信度
4. **与 L3 集成**: 解析结果将供审计引擎使用
