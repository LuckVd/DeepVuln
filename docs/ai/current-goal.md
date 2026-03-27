# Current Goal

## Status

Design - 2026-03-27

## Goal

P7-08: C/C++ 标准构建系统支持

## Summary

为 C/C++ 项目提供标准构建系统支持，仅支持标准构建系统，避免无边界猜测式构建，明确止损线。

## Context

### 现有 Builder 架构

项目已有完整的 Builder 框架：
- `LanguageBuilder` 抽象基类（`base.py`）
- `BuilderRegistry` 注册机制
- 现有实现：GoBuilder、JavaBuilder、PythonBuilder、JavaScriptBuilder
- 测试结构：`tests/unit/test_l3/test_builders/`

### C/C++ 构建挑战

| 问题 | 风险 | 缓解措施 |
|------|------|----------|
| 构建系统多样 | 高 | 仅支持标准系统（compile_commands.json、CMake、Make） |
| 复杂依赖 | 高 | 不尝试自动安装系统依赖 |
| Header-only 项目 | 中 | 明确识别并跳过，给出说明 |
| 无限回退 | 高 | 明确止损线，高风险场景直接跳过 |

## Scope

### In Scope

- P7-08a: 实现 `CppBuilder` 基础框架
- P7-08b: 实现现有 `compile_commands.json` 检测与验证
- P7-08c: 实现 CMake 导出策略（`cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON`）
- P7-08d: 实现 Makefile 保守策略（仅检测，不盲目执行）
- P7-08e: 实现 header-only/无标准构建系统的跳过与说明
- P7-08f: 明确止损线：高风险场景直接跳过，不做无限回退

### Out of Scope

- 自动安装系统依赖（gcc、cmake、make 等）
- 非标准构建系统支持（autotools、meson、scons、bazel 等）
- Bear/compiledb 工具调用（仅检测，不自动运行）
- 自定义构建脚本执行

## Design

### 1. P7-08a: CppBuilder 基础框架

**新增文件**: `src/layers/l3_analysis/build/builders/cpp.py`

```python
@BuilderRegistry.register
class CppBuilder(LanguageBuilder):
    """Builder for C/C++ projects.

    Only supports standard build systems with clear stop-loss lines.
    """

    LANGUAGE_NAME = "cpp"
    SUPPORTED_BUILD_SYSTEMS = [
        "compile_commands",
        "cmake",
        "make",
    ]

    # Default timeout for C++ builds (10 minutes)
    DEFAULT_TIMEOUT = 600

    # Maximum timeout (30 minutes)
    MAX_TIMEOUT = 1800

    def analyze(self, project_path: Path) -> BuilderOutput:
        """Analyze C/C++ project with clear priority:
        1. Check for existing compile_commands.json
        2. Check for CMake (can generate compile_commands)
        3. Check for Makefile (conservative)
        4. Check for header-only
        5. Skip with reason if no standard build system
        """

    def diagnose_failure(self, stdout: str, stderr: str, return_code: int) -> FailureDiagnosis:
        """Diagnose C++ build failures."""
```

**构建系统优先级**:
1. `compile_commands.json` - 优先使用（最可靠）
2. CMake - 可以生成 compile_commands
3. Makefile - 保守策略（不盲目执行）
4. Header-only - 跳过并说明

### 2. P7-08b: compile_commands.json 检测与验证

**检测逻辑**:
```python
def _check_compile_commands(self, project_path: Path) -> BuilderOutput | None:
    """Check for existing compile_commands.json."""
    # Locations to check:
    # - project_path/compile_commands.json
    # - project_path/build/compile_commands.json
    # - project_path/out/compile_commands.json

    # Validation:
    # - Is valid JSON?
    # - Has at least one entry?
    # - Each entry has "directory", "command", "file"?
```

**BuilderOutput**:
- `result = SUCCESS`
- `build_command = None` (使用现有 compile_commands)
- `build_system = "compile_commands"`

### 3. P7-08c: CMake 导出策略

**检测逻辑**:
```python
def _check_cmake(self, project_path: Path) -> BuilderOutput | None:
    """Check for CMake project."""
    # Check for CMakeLists.txt in root

    # Strategy:
    # 1. Create a build directory
    # 2. Run cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..
    # 3. Use the generated compile_commands.json

    # Stop-loss:
    # - Skip if CMake not available
    # - Skip if complex custom options required
```

**BuilderOutput**:
- `result = SUCCESS`
- `dependency_command = "cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON"`
- `build_command = None` (使用生成的 compile_commands)
- `build_system = "cmake"`
- `timeout = 600`

### 4. P7-08d: Makefile 保守策略

**检测逻辑**:
```python
def _check_makefile(self, project_path: Path) -> BuilderOutput | None:
    """Check for Makefile with conservative strategy."""
    # Check for Makefile in root

    # Conservative approach:
    # - Detect but mark as HIGH risk
    # - Only suggest "make" if simple pattern detected
    # - Skip if complex/non-standard Makefile

    # Stop-loss:
    # - Skip if Makefile contains custom targets
    # - Skip if Makefile uses non-standard variables
```

**BuilderOutput** (仅简单 Makefile):
- `result = SUCCESS`
- `build_command = "make -j$(nproc)"`
- `build_system = "make"`
- `timeout = 900`
- `warnings = ["Makefile build is conservative - may fail for complex projects"]`

**BuilderOutput** (复杂 Makefile):
- `result = SKIPPED`
- `skip_reason = "Complex Makefile detected - skipping to avoid uncontrolled build"`

### 5. P7-08e: Header-only/无标准构建系统的跳过与说明

**Header-only 检测**:
```python
def _is_header_only(self, project_path: Path) -> bool:
    """Check if project is header-only."""
    # Count .h/.hpp vs .c/.cpp/.cc/.cxx files
    # If >90% headers and no build system, consider header-only
```

**无标准构建系统**:
```python
def _skip_no_build_system(self, project_path: Path) -> BuilderOutput:
    """Skip with clear reason."""
    return BuilderOutput(
        result=BuildResult.SKIPPED,
        language="cpp",
        skip_reason=(
            "No standard C/C++ build system found. "
            "Supported: compile_commands.json, CMake, Makefile. "
            "For header-only projects, CodeQL can still analyze without build."
        ),
    )
```

### 6. P7-08f: 明确止损线

**高风险场景直接跳过**:
| 场景 | 动作 | 原因 |
|------|------|------|
| 非标准构建系统 | SKIP | 避免无限猜测 |
| 需要 sudo | SKIP | 安全风险 |
| 自定义构建脚本 | SKIP | 不可预测行为 |
| autotools/meson/scons/bazel | SKIP | 超出范围 |
| 复杂 Makefile | SKIP | 保守策略 |
| CMake 需要特殊选项 | SKIP | 需要人工干预 |

## Acceptance Criteria

1. **CppBuilder 框架**
   - [ ] 新增 `CppBuilder` 类并注册到 `BuilderRegistry`
   - [ ] 实现 `analyze()` 方法
   - [ ] 实现 `diagnose_failure()` 方法

2. **compile_commands.json 支持**
   - [ ] 检测根目录、build/、out/ 下的 compile_commands.json
   - [ ] 验证 JSON 格式和必需字段
   - [ ] 有效时返回 SUCCESS

3. **CMake 支持**
   - [ ] 检测 CMakeLists.txt
   - [ ] 生成使用 `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON` 的命令
   - [ ] CMake 不可用时跳过

4. **Makefile 保守策略**
   - [ ] 检测 Makefile
   - [ ] 区分简单 vs 复杂 Makefile
   - [ ] 复杂 Makefile 跳过并说明

5. **Header-only 检测**
   - [ ] 识别 header-only 项目
   - [ ] 跳过并给出明确说明

6. **止损线**
   - [ ] 非标准构建系统直接跳过
   - [ ] 高风险场景不做回退尝试
   - [ ] 所有跳过都有清晰原因

## Test Plan

### 单元测试

**文件**: `tests/unit/test_l3/test_builders/test_cpp_builder.py`

```python
class TestCppBuilderAnalyze:
    """Tests for CppBuilder.analyze method."""

    def test_compile_commands_at_root(self, builder: CppBuilder, tmp_path: Path):
        """Test with compile_commands.json in root."""

    def test_compile_commands_in_build_dir(self, builder: CppBuilder, tmp_path: Path):
        """Test with compile_commands.json in build/."""

    def test_cmake_project(self, builder: CppBuilder, tmp_path: Path):
        """Test CMakeLists.txt project."""

    def test_simple_makefile(self, builder: CppBuilder, tmp_path: Path):
        """Test simple Makefile."""

    def test_complex_makefile_skipped(self, builder: CppBuilder, tmp_path: Path):
        """Test complex Makefile is skipped."""

    def test_header_only_project(self, builder: CppBuilder, tmp_path: Path):
        """Test header-only project is skipped with reason."""

    def test_no_build_system_skipped(self, builder: CppBuilder, tmp_path: Path):
        """Test project without build system is skipped."""

class TestCppBuilderDiagnose:
    """Tests for CppBuilder.diagnose_failure method."""

    def test_diagnose_compiler_error(self, builder: CppBuilder):
        """Test diagnosing compilation errors."""

    def test_diagnose_linker_error(self, builder: CppBuilder):
        """Test diagnosing linker errors."""

    def test_diagnose_cmake_error(self, builder: CppBuilder):
        """Test diagnosing CMake errors."""
```

### 测试场景

| 测试场景 | 预期结果 |
|----------|----------|
| compile_commands.json 存在且有效 | SUCCESS |
| compile_commands.json 无效 | SKIPPED |
| CMakeLists.txt 存在 | SUCCESS (cmake 命令) |
| 简单 Makefile | SUCCESS (make 命令) |
| 复杂 Makefile | SKIPPED |
| Header-only | SKIPPED (带说明) |
| 无构建系统 | SKIPPED (带说明) |

## Files

| 文件 | 操作 | 描述 |
|------|------|------|
| `src/layers/l3_analysis/build/builders/cpp.py` | 新增 | CppBuilder 实现 |
| `src/layers/l3_analysis/build/builders/__init__.py` | 修改 | 导出 CppBuilder |
| `tests/unit/test_l3/test_builders/test_cpp_builder.py` | 新增 | 单元测试 |

## Steps

### Phase 1: CppBuilder 基础框架 (P7-08a)

1. 创建 `cpp.py` 文件，定义 `CppBuilder` 类
2. 实现基础的 `analyze()` 方法结构
3. 实现 `diagnose_failure()` 方法框架
4. 注册到 `BuilderRegistry` 并更新 `__init__.py`
5. 编写基础测试

### Phase 2: compile_commands.json 支持 (P7-08b)

1. 实现 `_check_compile_commands()` 方法
2. 实现 JSON 验证逻辑
3. 支持多个位置检测（根目录、build/、out/）
4. 编写相关测试

### Phase 3: CMake 支持 (P7-08c)

1. 实现 `_check_cmake()` 方法
2. 生成 `cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON` 命令
3. 检查 CMake 可用性
4. 编写相关测试

### Phase 4: Makefile 保守策略 (P7-08d)

1. 实现 `_check_makefile()` 方法
2. 实现简单 vs 复杂 Makefile 检测
3. 复杂 Makefile 跳过逻辑
4. 编写相关测试

### Phase 5: Header-only 检测与跳过 (P7-08e)

1. 实现 `_is_header_only()` 方法
2. 实现无构建系统的跳过逻辑
3. 确保所有跳过都有清晰原因
4. 编写相关测试

### Phase 6: 止损线验证 (P7-08f)

1. 验证所有高风险场景跳过逻辑
2. 确保没有无限回退
3. 验证跳过原因清晰
4. 运行完整 L3 测试套件

## Risks

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| C/C++ 构建系统多样性 | 高 | 仅支持标准系统，明确止损线 |
| 系统依赖缺失 | 中 | 不尝试安装，检测后跳过 |
| Makefile 复杂度 | 中 | 保守策略，复杂时跳过 |
| Header-only 误判 | 低 | 清晰说明，CodeQL 仍可分析 |

## Next Recommended

完成 P7-08 后:
- v0.75 里程碑发布准备
- Phase 8: 性能优化与基准测试
