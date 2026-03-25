# Current Goal

## Status

Completed - 2026-03-25

## Goal

P7-03a: ModuleDiscovery - 模块发现与边界识别

## Summary

实现仓库级模块发现功能，识别 monorepo 结构、子模块边界、各模块的主要语言和构建信号，为 CodeQL 智能决策和构建编排提供模块级上下文。

## Background

### 问题

1. 当前 CodeQL 扫描将整个仓库作为单一单元处理，缺少模块边界意识
2. monorepo 项目可能包含多个独立子项目，各有不同的构建系统
3. P7-01 的决策器需要 `ModuleSummary` 输入，但目前无数据来源

### 解决方案

实现 `ModuleDiscovery` 类：
- 检测 monorepo 信号（go.work, multi-module Maven, pnpm workspaces 等）
- 识别模块边界（语言边界 + 构建文件边界）
- 输出每个模块的摘要信息

## Scope

| Item | Content |
|------|---------|
| **问题** | 缺少模块边界识别，monorepo 扫描效率低 |
| **关注点** | monorepo 检测、模块边界识别、语言/构建信号提取 |
| **实现文件** | src/layers/l3_analysis/build/module_discovery.py |
| **集成点** | CodeQLLanguageDecider 输入、Readiness Gate |

## Deliverables

| File | Description |
|------|-------------|
| src/layers/l3_analysis/build/module_discovery.py | ModuleDiscovery 核心实现 |
| tests/unit/test_l3/test_module_discovery.py | 单元测试 |

## Acceptance Criteria

1. **Monorepo 检测**
   - [x] 正确识别 go.work, multi-module Maven/Gradle, pnpm workspaces
   - [x] 正确识别目录结构模式 (packages/, apps/, services/)

2. **模块边界识别**
   - [x] 每个模块输出 ModuleSummary（name, path, primary_language, languages, build_signals）
   - [x] 单一项目返回包含根目录的单元素列表

3. **构建信号提取**
   - [x] 复用现有 BuildSystemDetector 检测结果
   - [x] 每个模块报告检测到的构建文件

4. **测试覆盖**
   - [x] 单元测试覆盖 monorepo 检测（20 tests）
   - [x] 单元测试覆盖模块边界识别

## Implementation Steps

| Step | Task | Status |
|------|------|--------|
| S1 | 实现 ModuleDiscovery 类基础框架 | done |
| S2 | 实现 monorepo 检测逻辑 | done |
| S3 | 实现模块边界识别 | done |
| S4 | 集成 BuildSystemDetector | done |
| S5 | 编写单元测试 | done |

## Technical Design

### 数据模型

复用 `src/layers/l3_analysis/decision/models.py::ModuleSummary`:

```python
class ModuleSummary(BaseModel):
    name: str                    # 模块名称
    path: str                    # 相对于仓库根的路径
    primary_language: str        # 主要语言
    languages: list[str]         # 所有语言
    build_signals: list[str]     # 构建信号
    loc_estimate: int            # 代码行数估计
```

### Monorepo 检测信号

| 类型 | 检测文件 | 模块识别方式 |
|------|----------|--------------|
| Go workspace | `go.work` | 解析 use 指令 |
| Maven multi-module | 根 `pom.xml` + 子模块 `pom.xml` | 解析 modules 标签 |
| Gradle multi-project | `settings.gradle` / `settings.gradle.kts` | 解析 include 指令 |
| pnpm workspaces | `pnpm-workspace.yaml` | 解析 packages 字段 |
| Lerna | `lerna.json` | 解析 packages 字段 |
| 目录约定 | `packages/`, `apps/`, `services/`, `libs/` | 目录扫描 |

### 核心流程

```
输入: repo_path
    │
    ├─ 检测 monorepo 信号
    │   ├─ go.work -> Go workspace
    │   ├─ settings.gradle -> Gradle multi-project
    │   ├─ pnpm-workspace.yaml -> pnpm workspaces
    │   └─ 目录约定 -> packages/apps/services
    │
    ├─ 如果是 monorepo
    │   └─ 遍历子模块，生成 ModuleSummary
    │
    └─ 如果是单一项目
        └─ 返回根目录作为唯一模块
    │
    ▼
输出: list[ModuleSummary]
```

## Test Plan

### 单元测试

| 测试用例 | 描述 |
|----------|------|
| test_single_project | 单一项目返回单元素列表 |
| test_go_workspace | 检测 go.work 并识别子模块 |
| test_maven_multi_module | 检测多模块 Maven 项目 |
| test_gradle_multi_project | 检测 Gradle 多项目 |
| test_pnpm_workspaces | 检测 pnpm workspaces |
| test_directory_convention | 检测 packages/apps 目录结构 |
| test_module_language_detection | 各模块语言检测正确 |
| test_module_build_signals | 各模块构建信号提取正确 |

## Dependencies

| 依赖 | 说明 |
|------|------|
| BuildSystemDetector | 已有，复用构建系统检测 |
| ModuleSummary | 已有，P7-01 定义 |
| TechStackDetector | 可选，用于语言统计 |

## Risks

| 风险 | 缓解措施 |
|------|----------|
| 大仓库扫描慢 | 限制扫描深度，只检测配置文件 |
| 模块边界模糊 | 优先使用显式配置（go.work等），目录约定作为补充 |
| 语言统计不准确 | 使用快速估算而非精确统计 |
