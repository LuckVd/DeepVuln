# Current Goal

## Status

Completed - 2026-03-25

## Goal

P7-03b: BuildTargetExtractor - 构建目标提取器

## Summary

实现构建目标提取器，从模块中提取可构建单元、识别入口点、并为 CodeQL 提供最优构建策略推荐。

## Background

### 问题

1. ModuleDiscovery 识别了模块边界，但未细化模块内的可构建目标
2. BuildSystemDetector 检测了构建系统，但未提供细粒度的构建入口
3. CodeQL 需要知道最优的构建路径来创建数据库

### 解决方案

BuildTargetExtractor 作为中间层：
- 接收 ModuleSummary 输入
- 细化提取 BuildTarget 列表
- 识别入口点和构建优先级
- 为 CodeQL 提供构建推荐

## Scope

| Item | Content |
|------|---------|
| **问题** | 缺少细粒度构建目标，CodeQL 构建效率低 |
| **关注点** | Build Target 提取、Entry Point 识别、CodeQL 构建推荐 |
| **实现文件** | src/layers/l3_analysis/build/target_extractor.py |
| **依赖** | ModuleDiscovery, BuildSystemDetector |

## Deliverables

| File | Description |
|------|-------------|
| src/layers/l3_analysis/build/target_extractor.py | BuildTargetExtractor 核心实现 |
| tests/unit/test_l3/test_target_extractor.py | 单元测试 |

## Acceptance Criteria

1. **Build Target 提取**
   - [x] 为每个模块提取 BuildTarget 列表
   - [x] 支持 Java (Maven modules, Gradle subprojects)
   - [x] 支持 Go (packages, main packages)
   - [x] 支持 Node.js (packages with build scripts)

2. **Entry Point 识别**
   - [x] 识别 Java main 类
   - [x] 识别 Go main packages
   - [x] 识别 Node.js entry points (main, bin)

3. **CodeQL 构建推荐**
   - [x] 推荐最优构建策略
   - [x] 提供构建优先级排序
   - [x] 输出构建命令和参数

4. **测试覆盖**
   - [x] 单元测试覆盖核心逻辑（17 tests）

## Implementation Steps

| Step | Task | Status |
|------|------|--------|
| S1 | 实现数据模型：BuildTarget, EntryPoint, BuildRecommendation | done |
| S2 | 实现 BuildTargetExtractor 基础框架 | done |
| S3 | 实现 Java Build Target 提取 | done |
| S4 | 实现 Go Build Target 提取 | done |
| S5 | 实现 Node.js Build Target 提取 | done |
| S6 | 实现 Entry Point 识别 | done |
| S7 | 实现 CodeQL 构建推荐生成 | done |
| S8 | 编写单元测试 | done |

## Technical Design

### 数据模型

```python
@dataclass
class BuildTarget:
    """可构建单元"""
    name: str                    # 目标名称
    path: Path                   # 目标路径
    language: str                # 语言
    build_system: BuildSystem    # 构建系统
    build_command: str           # 构建命令
    priority: int                # 优先级 (1=highest)
    is_entry_point: bool         # 是否为入口点
    estimated_time: int          # 预估构建时间（秒）
    dependencies: list[str]      # 依赖的其他目标

@dataclass
class EntryPoint:
    """入口点"""
    name: str                    # 入口名称
    path: Path                   # 文件路径
    language: str                # 语言
    entry_type: str              # main, app, server, cli
    is_primary: bool             # 是否为主要入口

@dataclass
class BuildRecommendation:
    """CodeQL 构建推荐"""
    module_name: str             # 模块名称
    targets: list[BuildTarget]   # 构建目标列表
    recommended_order: list[str] # 推荐构建顺序
    build_strategy: str          # full, incremental, none
    estimated_total_time: int    # 预估总时间
    skip_reasons: dict[str, str] # 跳过原因
```

### 核心流程

```
输入: ModuleSummary, repo_path
    │
    ├─ 检测构建系统（复用 BuildSystemDetector）
    │
    ├─ 提取 Build Targets
    │   ├─ Java: Maven modules / Gradle subprojects
    │   ├─ Go: packages (识别 main packages)
    │   └─ Node.js: packages with build scripts
    │
    ├─ 识别 Entry Points
    │   ├─ Java: main 方法所在类
    │   ├─ Go: package main 文件
    │   └─ Node.js: package.json main/bin
    │
    ├─ 生成构建推荐
    │   ├─ 按优先级排序
    │   ├─ 计算依赖关系
    │   └─ 估算构建时间
    │
    ▼
输出: BuildRecommendation
```

### 各语言 Target 提取策略

| 语言 | 构建系统 | Target 提取方式 |
|------|----------|-----------------|
| Java | Maven | 解析 pom.xml modules + 检测 src/main/java |
| Java | Gradle | 解析 settings.gradle includes + 检测 src/main/java |
| Go | go.mod | 扫描 main packages + 检测 package main |
| Node | npm/yarn/pnpm | 解析 package.json workspaces + build scripts |

### Entry Point 识别

| 语言 | 识别方式 |
|------|----------|
| Java | 扫描 `public static void main` 方法 |
| Go | 扫描 `package main` + `func main()` |
| Node.js | 解析 package.json 的 `main` 和 `bin` 字段 |
| Python | 扫描 `if __name__ == "__main__"` |

## Test Plan

### 单元测试

| 测试用例 | 描述 |
|----------|------|
| test_java_maven_targets | Maven 多模块目标提取 |
| test_java_gradle_targets | Gradle 多项目目标提取 |
| test_go_main_packages | Go main package 识别 |
| test_nodejs_packages | Node.js 包目标提取 |
| test_entry_point_java | Java main 类识别 |
| test_entry_point_go | Go main 函数识别 |
| test_entry_point_nodejs | Node.js entry 识别 |
| test_build_recommendation | 构建推荐生成 |
| test_priority_ordering | 优先级排序正确 |
| test_time_estimation | 时间估算合理 |

## Dependencies

| 依赖 | 说明 |
|------|------|
| ModuleDiscovery | 提供模块边界 |
| BuildSystemDetector | 提供构建系统检测 |
| ModuleSummary | 模块摘要数据 |

## Risks

| 风险 | 缓解措施 |
|------|----------|
| 大型项目扫描慢 | 限制扫描深度，优先检测配置文件 |
| 入口点识别不完整 | 优先检测常见模式，提供手动覆盖 |
| 构建时间估算不准 | 使用历史数据校准 |
