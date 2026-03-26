# Current Goal

## Status

Completed - 2026-03-26

## Goal

P7-05e: 集成 Builder 系统到 CodeQL scan 流程

## Summary

将已实现的 PythonBuilder、JavaScriptBuilder、GoBuilder、JavaBuilder 集成到 CodeQL 引擎的 scan 流程，替换旧的 BuildSystemDetector，实现完整的智能构建分析链路。

## Context

### 现有架构

```
CLI (main.py)
    ↓
_apply_codeql_readiness_gate() → ReadinessGateResult
    ↓                                    ↓ (build_warnings/skip_reasons 未使用)
CodeQLEngine.scan() → _execute_build() → BuildSystemDetector (旧)
                     → _create_database()
                     → _analyze_database()
```

### 问题

1. **双重检测**：ReadinessGate 使用 Builder 分析，但 CodeQLEngine 又用 BuildSystemDetector
2. **信息丢失**：Builder 的 warnings/skip_reasons 没有传递给用户
3. **代码冗余**：两套构建检测逻辑

### 目标架构

```
CLI (main.py)
    ↓
_apply_codeql_readiness_gate() → ReadinessGateResult
    ↓                                    ↓
    ↓                              (传递 build_info)
    ↓                                    ↓
CodeQLEngine.scan() → _execute_build() → Builder 系统 (新)
                     → _create_database()
                     → _analyze_database()
```

## Scope

### In Scope

- 修改 `CodeQLEngine._execute_build()` 使用 Builder 系统
- 新增 `CodeQLEngine.scan()` 接受 `readiness_result` 参数
- 传递 Builder 的 warnings 到 CLI 输出
- 更新 CLI 层集成逻辑

### Out of Scope

- C/C++ Builder（P7-08）
- 效果评估测试（P7-10）
- 新增 Builder

## Design

### 1. CodeQLEngine 修改

**文件**: `src/layers/l3_analysis/engines/codeql.py`

**修改 `_execute_build()` 方法:**

```python
async def _execute_build(
    self,
    source_path: Path,
    language: str,
    build_command: str | None = None,
    readiness_info: BuildReadinessInfo | None = None,  # 新增参数
    llm_client: Any = None,
) -> dict[str, Any] | None:
    """Execute build using Builder system."""

    # 优先使用 ReadinessGate 的分析结果
    if readiness_info:
        if readiness_info.skip_reason:
            return {
                "success": False,
                "skipped": True,
                "reason": readiness_info.skip_reason,
                "warnings": readiness_info.warnings,
            }

        # 使用 Builder 提供的 build_command（如果有）
        if readiness_info.build_command:
            build_command = readiness_info.build_command

    # 回退到 Builder 系统直接分析
    if not readiness_info:
        from src.layers.l3_analysis.build.builders import BuilderRegistry
        builder = BuilderRegistry.get(language)
        if builder:
            output = builder.analyze(source_path)
            if output.skip_reason:
                return {"success": False, "skipped": True, "reason": output.skip_reason}
            if output.build_command:
                build_command = output.build_command

    # 执行构建（如果有）
    if build_command:
        # ... 现有构建逻辑
    else:
        # 免构建语言或无构建需求
        return {"success": True, "skipped": True, "reason": "No build required"}
```

**修改 `scan()` 方法签名:**

```python
async def scan(
    self,
    source_path: Path,
    language: str | None = None,
    # ... 现有参数 ...
    readiness_result: ReadinessGateResult | None = None,  # 新增
    **options,
) -> ScanResult:
```

### 2. CLI 层修改

**文件**: `src/cli/main.py`

**修改 `_apply_codeql_readiness_gate()` 返回值使用:**

```python
# 现有代码获取 readiness_result
engines, codeql_gate = await _apply_codeql_readiness_gate(...)

# 新增：传递给 CodeQLEngine
if "codeql" in engines:
    scan_tasks.append(("codeql", codeql_engine.scan(
        source_path=source_path,
        language=primary_lang.lower(),
        readiness_result=codeql_gate,  # 新增
        # ...
    )))
```

### 3. 输出增强

**在 scan 结果中显示 Builder 警告:**

```python
# CLI 输出
if codeql_gate and codeql_gate.build_warnings:
    console.print("\n[bold yellow]Build Warnings:[/]")
    for target, warnings in codeql_gate.build_warnings.items():
        for warning in warnings:
            console.print(f"  ⚠ {target}: {warning}")
```

## Acceptance Criteria

1. **CodeQLEngine 集成**
   - [x] `_execute_build()` 使用 Builder 系统
   - [x] `scan()` 接受 `readiness_result` 参数
   - [x] 传递 Builder 的 warnings 和 skip_reasons

2. **CLI 集成**
   - [x] `readiness_result` 传递给 `CodeQLEngine.scan()`
   - [x] CLI 输出显示 Builder 警告
   - [x] 正确处理 skip 情况

3. **向后兼容**
   - [x] 无 `readiness_result` 时回退到 Builder 直接分析
   - [x] 不破坏现有 API

4. **测试**
   - [x] 单元测试：`_execute_build()` 使用 Builder
   - [x] 单元测试：`scan()` 接受 `readiness_result`
   - [x] 集成测试：完整扫描流程

## Test Plan

### 单元测试

**文件**: `tests/unit/test_l3/test_codeql_builder_integration.py`

```python
class TestCodeQLBuilderIntegration:
    """Tests for Builder integration in CodeQL engine."""

    def test_execute_build_with_readiness_info(self):
        """Test _execute_build uses ReadinessInfo."""

    def test_execute_build_without_readiness_info(self):
        """Test _execute_build falls back to Builder directly."""

    def test_execute_build_skip_reason(self):
        """Test _execute_build respects skip_reason."""

    def test_scan_accepts_readiness_result(self):
        """Test scan() accepts readiness_result parameter."""
```

### 集成测试

**文件**: `tests/integration/test_codeql_scan_flow.py`

```python
class TestCodeQLScanFlow:
    """Integration tests for full scan flow."""

    async def test_python_project_no_build(self):
        """Test Python project uses no-build path."""

    async def test_java_project_with_build(self):
        """Test Java project uses build path."""

    async def test_warnings_displayed(self):
        """Test Builder warnings are displayed in output."""
```

## Steps

### Phase 1: CodeQLEngine 修改

1. 修改 `_execute_build()` 方法
2. 修改 `scan()` 方法签名
3. 添加 Builder 警告到 scan 结果

### Phase 2: CLI 集成

1. 修改 `_apply_codeql_readiness_gate()` 调用处
2. 传递 `readiness_result` 给 `CodeQLEngine.scan()`
3. 增强 CLI 输出显示警告

### Phase 3: 测试与验证

1. 编写单元测试
2. 编写集成测试
3. 手动测试完整流程

## Files

| 文件 | 操作 | 描述 |
|------|------|------|
| `src/layers/l3_analysis/engines/codeql.py` | 修改 | 集成 Builder 系统 |
| `src/cli/main.py` | 修改 | 传递 readiness_result |
| `tests/unit/test_l3/test_codeql_builder_integration.py` | 新增 | 单元测试 |

## Risks

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| 向后兼容性 | 可能破坏现有调用 | 使用 Optional 参数，默认 None |
| 异步调用 | Builder.analyze() 是同步的 | 在异步上下文中正确调用 |
| 测试覆盖 | 需要真实项目测试 | 使用 fixture 项目 |

## Next Recommended

完成 P7-05e 后:
- P7-10: 基线策略与效果评估
- P7-08: C/C++ 标准构建系统支持
