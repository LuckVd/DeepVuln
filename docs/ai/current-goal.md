# Current Goal

## Status

Completed - 2026-03-26

## Goal

P7-07: Python/JS/TS 轻构建与免构建路径

## Summary

为 Python、JavaScript、TypeScript 实现免构建路径，这些动态语言在 CodeQL 分析中不需要编译，但某些条件下可能需要升级到真实构建。

## Context

### CodeQL 对动态语言的处理

| 语言 | 是否需要编译 | 分析方式 |
|------|--------------|----------|
| Python | 否 | 源码直接分析 |
| JavaScript | 否 | 源码直接分析 |
| TypeScript | 否* | 源码 + 类型信息 |
| Go | 是 | 编译时提取 |
| Java | 是 | 编译时提取 |

*TypeScript 虽然需要编译为 JavaScript，但 CodeQL 可以直接分析 .ts 源码。

### 需要真实构建的场景

**Python:**
- Cython 扩展 (.pyx 文件)
- Protobuf 代码生成 (.proto → _pb2.py)
- Type stub 生成 (mypy 生成的 .pyi)
- PyInstaller/Nuitka 打包项目

**JavaScript/TypeScript:**
- TypeScript project references (composite projects)
- Path aliases (tsconfig paths) 需要解析
- Babel/Webpack 代码转换
- Monorepo workspace 依赖

### 现有基础设施

| 组件 | 文件 | 功能 |
|------|------|------|
| BuildSystemDetector | `build/detector.py` | 检测 npm/yarn/pnpm/poetry |
| VersionDetector | `build/version_detector.py` | 检测 Python/Node 版本 |
| LanguageBuilder | `builders/base.py` | Builder 抽象基类 |

## Scope

### In Scope

- P7-07a: Python 免构建路径
- P7-07b: JS/TS 免构建路径
- P7-07c: 定义升级到真实构建的条件
- P7-07d: 受控构建计划生成

### Out of Scope

- P7-06: Go/Java 构建支持（已完成）
- P7-08: C/C++ 构建支持
- 实际执行构建命令（只生成计划）

## Design

### 1. PythonBuilder (`builders/python.py`)

**职责:**
- 检测 Python 项目结构
- 识别需要构建的信号
- 提供 Python 版本需求

**免构建路径输出:**
```python
BuilderOutput(
    result=BuildResult.SUCCESS,
    language="python",
    build_command=None,  # 不需要构建
    dependency_command=None,  # 默认不安装依赖
    detected_files=["pyproject.toml", "src/"],
)
```

**升级构建条件检测:**

| 条件 | 检测方式 | 行为 |
|------|----------|------|
| Cython 扩展 | 扫描 .pyx 文件 | 警告，建议跳过或安装 Cython |
| Protobuf | 扫描 .proto 文件 | 警告，建议生成代码 |
| setup.py 构建 | 存在 setup.py 且有 build 命令 | 建议运行 python setup.py build |

**依赖安装策略:**
- 默认不安装依赖（CodeQL 不需要）
- 检测 requirements.txt/pyproject.toml 存在
- 提供 optional dependency_command

### 2. JavaScriptBuilder (`builders/javascript.py`)

**职责:**
- 检测 JS/TS 项目结构
- 识别需要构建的信号
- 区分 npm/yarn/pnpm

**免构建路径输出:**
```python
BuilderOutput(
    result=BuildResult.SUCCESS,
    language="javascript",
    build_command=None,
    dependency_command=None,
    detected_files=["package.json", "tsconfig.json"],
)
```

**升级构建条件检测:**

| 条件 | 检测方式 | 行为 |
|------|----------|------|
| TypeScript project refs | tsconfig.json "references" 字段 | 警告，建议构建 |
| Path aliases | tsconfig.json "paths" 字段 | 警告，可能需要构建 |
| Babel 转换 | .babelrc 或 babel.config.js | 检测是否使用 |
| Monorepo workspace | package.json "workspaces" 字段 | 提供 workspace 信息 |

**语言区分:**
- 存在 tsconfig.json → TypeScript
- 仅 .js/.jsx 文件 → JavaScript
- 混合 → TypeScript (优先)

### 3. 构建升级决策

```python
@dataclass
class BuildUpgradeCondition:
    """Conditions that may require upgrading to real build."""

    condition: str  # 条件名称
    detected: bool  # 是否检测到
    severity: str   # "warning" / "required" / "optional"
    suggestion: str  # 建议
```

**决策流程:**

```
analyze() -> BuilderOutput
    ↓
detect_no_build_signals() -> 是否有构建信号？
    ↓ 否
return SUCCESS with no build_command
    ↓ 是
return SUCCESS with warnings + optional build_command
```

### 4. 集成点

BuildPlanGenerator 已经支持 Builder 模式，新 Builder 自动集成。

## Acceptance Criteria

1. **PythonBuilder**
   - [x] 检测 Python 项目（pyproject.toml/requirements.txt/setup.py）
   - [x] 检测 Cython 扩展（.pyx 文件）
   - [x] 检测 Protobuf 文件（.proto）
   - [x] 默认返回免构建策略
   - [x] 提供可选的依赖安装命令
   - [x] 检测 Python 版本需求

2. **JavaScriptBuilder**
   - [x] 检测 JS/TS 项目（package.json/tsconfig.json）
   - [x] 区分 JavaScript 和 TypeScript
   - [x] 检测 TypeScript project references
   - [x] 检测 tsconfig paths (alias)
   - [x] 检测 workspace (monorepo)
   - [x] 默认返回免构建策略
   - [x] 提供 npm/yarn/pnpm 区分

3. **升级条件**
   - [x] Python Cython 检测 + 警告
   - [x] TypeScript project refs 检测 + 警告
   - [x] 所有警告清晰可解释

## Test Plan

### 单元测试

```
tests/unit/test_l3/test_builders/
├── test_python_builder.py
└── test_javascript_builder.py
```

**PythonBuilder 测试用例:**
- 简单 Python 项目 → SUCCESS (无构建)
- 有 pyproject.toml → 检测到
- 有 requirements.txt → 检测到
- 有 Cython (.pyx) → 警告
- 有 Protobuf (.proto) → 警告
- 有 setup.py → 检测到
- Python 版本检测

**JavaScriptBuilder 测试用例:**
- 简单 JS 项目 → SUCCESS (无构建)
- TypeScript 项目 → language="typescript"
- 有 tsconfig.json references → 警告
- 有 tsconfig paths → 警告
- npm/yarn/pnpm 区分
- workspace 检测
- 无 package.json → SUCCESS (无构建)

## Steps

### Phase 1: Python Builder (P7-07a)

1. 创建 `builders/python.py`
2. 实现 `PythonBuilder.analyze()`
3. 实现 Cython/Protobuf 检测
4. 编写 `test_python_builder.py`
5. 注册到 BuilderRegistry

### Phase 2: JavaScript Builder (P7-07b)

1. 创建 `builders/javascript.py`
2. 实现 `JavaScriptBuilder.analyze()`
3. 实现 TypeScript 检测和区分
4. 实现 project refs/paths 检测
5. 编写 `test_javascript_builder.py`
6. 注册到 BuilderRegistry

### Phase 3: 集成验证 (P7-07c,d)

1. 验证 BuildPlanGenerator 自动使用新 Builder
2. 验证 ReadinessGate 集成
3. 端到端测试

## Files

| 文件 | 操作 | 描述 |
|------|------|------|
| `src/layers/l3_analysis/build/builders/python.py` | 新增 | Python 构建器 |
| `src/layers/l3_analysis/build/builders/javascript.py` | 新增 | JS/TS 构建器 |
| `src/layers/l3_analysis/build/builders/__init__.py` | 修改 | 导出新 Builder |
| `tests/unit/test_l3/test_builders/test_python_builder.py` | 新增 | Python 测试 |
| `tests/unit/test_l3/test_builders/test_javascript_builder.py` | 新增 | JS/TS 测试 |

## Risks

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| Python 虚拟环境检测 | 可能误判 Python 版本 | 解析多来源：.python-version/pyenv |
| TypeScript 版本差异 | tsconfig 格式可能有变化 | 使用宽松解析 |
| Monorepo 复杂度 | workspace 结构可能复杂 | 仅检测，不强制解析 |

## Next Recommended

完成 P7-07 后:
- P7-08: C/C++ 标准构建系统支持
- P7-10: 基线策略与效果评估
