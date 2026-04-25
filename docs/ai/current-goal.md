# Current Goal

> **状态**: 已完成 ✅（同步于 2026-04-25）
> **目标**: Phase 16 — 全面质量修复（深度审视 40 项问题）
> **Goal ID**: phase16-quality-fix
> **创建日期**: 2026-04-20

---

## 需求背景

基于 2026-04-20 对全项目的深度审视，发现 40 个问题点，涵盖运行时崩溃、核心功能空壳、实现偏差和负优化。全部纳入本次目标，按优先级分 6 个批次实施。

---

## 问题清单（按优先级）

### Batch 1: 致命级 — 运行时崩溃修复（1 项）

#### P1-01: Sink/Source Registry 导入不存在的模块

**文件**: `src/layers/l3_analysis/sinks_sources/registry.py:341-353`

**问题**: 代码 `from src.layers.l3_analysis.sinks_sources import java, python, go, php, javascript`，但只有 `java.py` 和 `python.py` 存在。`go.py`、`php.py`、`javascript.py` 不存在。调用 `get_sink_registry()` 或 `get_source_registry()` 立即抛出 `ImportError`。

**影响**: 污点分析、CPG 攻击路径、调用图可达性分析在 Go/JS/PHP 项目上完全不可用。

**修复**: 创建 `go.py`、`javascript.py`、`php.py` Sink/Source 定义文件。

---

### Batch 2: 高级别 — 核心功能空壳修复（7 项）

#### P2-01: 增量扫描核心方法是桩代码

**文件**: `src/layers/l3_analysis/incremental/scanner.py:422-440`

**问题**: `_scan_single_file()` 永远返回空列表，注释 `# Placeholder: In production, this would call Semgrep/CodeQL/Agent`。

**修复**: 实现 `_scan_single_file()` 调用实际引擎（至少支持 Semgrep 和 Agent）。

#### P2-02: 增量扫描项目哈希极弱

**文件**: `src/layers/l3_analysis/incremental/scanner.py:223-227`

**问题**: 仅用 `目录名 + 目录大小` 计算 MD5，不同项目可能碰撞。

**修复**: 改用项目根目录关键文件内容的 SHA256 哈希。

#### P2-03: Java/Go/JS CFG 构建器是桩实现

**文件**:
- `src/layers/l3_analysis/engines/ast_engine/cfg/builders/java_cfg.py` (89 行)
- `src/layers/l3_analysis/engines/ast_engine/cfg/builders/go_cfg.py` (87 行)
- `src/layers/l3_analysis/engines/ast_engine/cfg/builders/js_cfg.py` (91 行)

**问题**: 三个 CFG 构建器都是同一模板——每条语句一个基本块，只生成顺序边。没有条件分支、循环回边、异常边。Python CFG (409 行) 是完整的。

**修复**: 为 Java/Go/JS 实现完整的 CFG 构建器（条件分支、循环、异常处理）。

#### P2-04: CPG Provider 只注册了 Python 和 JS

**文件**: `src/layers/l3_analysis/engines/ast_engine/cpg/path_provider.py:42-48`

**问题**: Java 和 Go 的 CPG Provider 被注释掉。

**修复**: 依赖 Batch 2-03 完成后，实现 Java 和 Go 的 CPG Provider 并取消注释。但注意调用图构建器只有 Python，所以 Java/Go CPG Provider 先用简化实现（仅 AST Graph，无 Call Graph）。

#### P2-05: 调用图构建器只有 Python

**文件**: `src/layers/l3_analysis/call_graph/builders/`

**问题**: 只有 `python_builder.py` 存在。Java、Go、JavaScript 缺失。

**修复**: 实现 Java 和 JavaScript 的调用图构建器（Go 可延后，使用量较低）。每个构建器至少支持：函数调用关系、导入关系、方法调用链。

#### P2-06: AST 引擎的 FrameworkDetector 未注册

**文件**: `src/layers/l3_analysis/engines/ast_engine/ast_engine.py:67-75`

**问题**: `FrameworkDetector` 已完整实现（`detectors/framework_detector.py`），但 `ASTEngine.__init__()` 只注册了 3 个检测器，从未导入 FrameworkDetector。

**修复**: 在 `ast_engine.py` 中导入并注册 FrameworkDetector。

#### P2-07: AST 引擎未被 SmartScanner 调度

**文件**: `src/layers/l3_analysis/smart_scanner.py:475-513`

**问题**: `_run_engine_allocation()` 只处理 `"semgrep"`、`"codeql"`、`"agent"` 三种引擎。AST 引擎注册了但永远不执行。

**修复**: 在 `_run_engine_allocation()` 中添加 `"ast_engine"` 分支，与 Semgrep 并行执行（同属静态分析）。

---

### Batch 3: 中级别 — 声明未实现补全（6 项）

#### P3-01: 依赖扫描器只有 4/8 生态系统

**文件**: `src/layers/l1_intelligence/dependency_scanner/`

**问题**: `Ecosystem` 枚举声明 8 种，`CompositeScanner` 只注册 Python/NPM/Maven/Go。缺少 Cargo(Rust)、Composer(PHP)、Gem(Ruby)、NuGet(.NET)。

**修复**: 实现 4 个缺失扫描器（至少覆盖主要依赖声明文件解析）。

#### P3-02: 代码结构解析器只有 3/12 种语言

**文件**: `src/layers/l1_intelligence/code_structure/languages/`

**问题**: 只有 Python/Java/Go 解析器。TS/JS、Rust、Ruby、PHP、C#、Kotlin、Swift、Scala 缺失。

**修复**: 实现 TypeScript/JavaScript 解析器（最高优先级），其余语言可延后。

#### P3-03: 前端 HTML 报告导出走错接口

**文件**: `src/web/frontend/src/pages/Reports.tsx:90-92`

**问题**: 选择 "HTML" 导出时调用 `reportsApi.exportPdf()`（PDF 端点）但保存为 `.html` 后缀。

**修复**: 后端添加独立的 HTML 报告导出端点，或前端改为直接使用已有的 HTML 生成逻辑。

#### P3-04: 威胁情报版本匹配 TODO

**文件**: `src/layers/l1_intelligence/threat_intel/intel_service.py:215-217`

**问题**: `search_cves_by_package()` 的 `version` 参数被完全忽略（`pass`）。

**修复**: 实现基于 `packaging.version` 的版本范围匹配逻辑。

#### P3-05: CPG Path Provider 实际始终为 None

**文件**: `src/layers/l3_analysis/engines/opencode_agent.py:99,536-551`

**问题**: `cpg_path_provider` 参数接口完整，但没有任何调用者传入 provider。CPG 攻击路径分析是死代码。

**修复**: 在 `ScanOrchestrator` 中创建并传入 CPG Path Provider 实例。

#### P3-06: 对抗性验证提取规则未持久化

**文件**: `src/layers/l3_analysis/verification/enhanced_adversarial.py:172`

**问题**: `self.extracted_rules` 只存在内存中，进程重启即丢失。

**修复**: 将提取的规则序列化到文件系统（JSON），下次启动时加载。

---

### Batch 4: 实现偏差修复（9 项）

#### P4-01: OpenCode Agent 并发控制无效

**文件**: `src/layers/l3_analysis/engines/opencode_agent.py:125,436-458`

**问题**: `max_concurrent` 参数被接受但从未使用。`_analyze_files()` 用裸 `asyncio.gather` 发射所有任务。

**修复**: 添加 `asyncio.Semaphore(max_concurrent)` 限制并发。

#### P4-02: CodeQL 缓存用 mtime 而非内容哈希

**文件**: `src/layers/l3_analysis/engines/codeql.py:620-698`

**问题**: `_compute_source_hash()` 用路径+mtime+大小采样，可能缓存过期数据。

**修复**: 改用文件内容哈希（对大文件采样内容，不只采 mtime）。

#### P4-03: 前端 AuthContext 登录后 user.id 硬编码为 0

**文件**: `src/web/frontend/src/contexts/AuthContext.tsx:63-66`

**问题**: 登录响应不返回用户 ID，`UserInfo` 对象 `id` 始终为 `0`。

**修复**: 后端 `/auth/login` 响应中包含 `user_id`，前端使用真实值。

#### P4-04: 前端 401 处理绕过 React Router

**文件**: `src/web/frontend/src/api/client.ts:43-49`

**问题**: `window.location.href = '/login'` 全页面刷新，丢失所有 React 状态。

**修复**: 改用 React Router `navigate('/login')`（需通过事件/callback 通知 App 层）。

#### P4-05: 前端 WebSocket 不传 JWT

**文件**: `src/web/frontend/src/api/websocket.ts:53`

**问题**: WebSocket URL 不包含 JWT token，可能允许未认证访问。

**修复**: WebSocket 连接时在 URL query 参数或子协议中传递 token。

#### P4-06: Findings 客户端搜索在分页数据上过滤

**文件**: `src/web/frontend/src/pages/Findings.tsx:83-93`

**问题**: 客户端搜索只过滤当前页数据，搜不到其他页的结果。

**修复**: 搜索改为服务端参数（后端 API 支持 `keyword` 查询参数）。

#### P4-07: Vulnerabilities 页面"查看详情"跳到错误位置

**文件**: `src/web/frontend/src/pages/Vulnerabilities.tsx:66-68`

**问题**: 跳转到扫描的全部 findings 列表，而非单个漏洞详情。

**修复**: 支持跳转到指定 finding 的 findings 页并自动打开对应 drawer。

#### P4-08: 对抗性验证串行执行

**文件**: `src/layers/l3_analysis/verification/enhanced_adversarial.py:630-643`

**问题**: `verify_findings()` 逐个串行验证，每次多轮 LLM 调用，大量 findings 时极慢。

**修复**: 使用 `asyncio.gather` + `Semaphore` 并行验证，限制并发度。

#### P4-09: 证据强度计算条件性跳过

**文件**: `src/layers/l3_analysis/adjudication.py:569-575`

**问题**: `source_path` 为 None 时证据强度被静默跳过，导致裁决结果不一致。

**修复**: 即使无 source_path，也基于已有 finding 元数据计算证据强度。

---

### Batch 5: 负优化消除（10 项）

#### P5-01: 引擎注册表完全多余的抽象

**文件**: `src/layers/l3_analysis/engines/base.py:260`

**问题**: 全局 `engine_registry` 单例从未被 SmartScanner 或 ScanOrchestrator 使用，它们直接实例化引擎。

**修复**: 移除全局注册表，改为工厂函数模式（如果未来需要动态引擎发现，再引入）。或者让 SmartScanner 真正使用注册表。

#### P5-02: LLM 缓存无用

**文件**: `src/layers/l1_intelligence/attack_surface/llm_detector.py:519`

**问题**: `self._cache` 初始化但从未读写。

**修复**: 移除 `self._cache` 和 `clear_cache()` 方法。

#### P5-03: CodeQL 多套件 raw_output 只保留第一套

**文件**: `src/layers/l3_analysis/engines/codeql.py:1194-1254`

**问题**: 多语言扫描时 `raw_output` 只存第一个成功套件的 SARIF。

**修复**: 合并所有套件的 SARIF 到统一的 `raw_output`。

#### P5-04: 前端组件无 memoization

**文件**: `src/web/frontend/src/pages/Dashboard.tsx`

**问题**: StatisticCard/SeverityStat/QuickAction 未 memoize，30s 轮询触发全页重渲染。

**修复**: 用 `React.memo` 包装这些组件。

#### P5-05: 前端粒子效果每次渲染产生新随机值

**文件**: `src/web/frontend/src/pages/Scans.tsx:285-295`

**问题**: `Math.random()` 在渲染体内，每次重渲染粒子位置跳跃。

**修复**: 用 `useMemo` 在首次渲染时生成固定粒子位置。

#### P5-06: FindingDrawer 加载单条发现需下载全部

**文件**: `src/web/frontend/src/hooks/useFindings.ts:96-101`

**问题**: `page_size: 1000` 下载全部发现再客户端过滤一条。

**修复**: 后端添加 `GET /scans/{id}/findings/{fid}` 单条查询端点。

#### P5-07: React Query staleTime 默认为 0

**文件**: `src/web/frontend/src/App.tsx:16-23`

**问题**: 未设 `staleTime`，每次导航都重新获取。

**修复**: 设置 `staleTime: 30_000`（30 秒）。

#### P5-08: 时区设置重复加载

**文件**: ScanDetail.tsx、Scans.tsx、FindingDrawer.tsx

**问题**: 各组件各自调用 `systemSettingsApi.get()`。

**修复**: 在 App 级别加载一次，通过 Context 共享。

#### P5-09: AST 上下文每个文件构建完整 AST 图

**文件**: `src/layers/l3_analysis/engines/opencode_agent.py:503-534`

**问题**: 每个文件每次扫描都构建 AST Graph，异常被静默吞掉。

**修复**: 添加 AST 上下文缓存（按文件路径+内容哈希），异常时记录警告日志。

#### P5-10: 前端无 404 路由、无代码分割

**文件**: `src/web/frontend/src/App.tsx`

**问题**: 无通配符路由、无 `React.lazy` 代码分割。

**修复**: 添加 `*` 路由显示 404 页面；对 Settings/Reports 等低频页面用 lazy loading。

---

### Batch 6: 前端 i18n 和杂项清理（7 项）

#### P6-01: 多处硬编码中文未走 i18n

**文件**: ScanDetail.tsx、Scans.tsx、Reports.tsx、Dashboard.tsx、Settings.tsx、Login.tsx、Findings.tsx

**问题**: 约 30+ 处硬编码中文字符串未用 `t()` 包裹。

**修复**: 全部改为 `t('key')`，在 `translations.ts` 中添加对应键值。

#### P6-02: Settings 页假 uptime 和假连接状态

**文件**: `src/web/frontend/src/pages/Settings.tsx:34-46, 272-280`

**问题**: uptime 计算页面打开时长；后端/WS 状态硬编码为 connected/active。

**修复**: uptime 改为从后端获取系统启动时间；连接状态改为实际检测（heartbeat API）。

#### P6-03: Login 页版本号硬编码

**文件**: `src/web/frontend/src/pages/Login.tsx:97`

**问题**: `'DeepVuln v0.9.0'` 硬编码。

**修复**: 使用 `__APP_VERSION__` 注入（Settings.tsx 已有此模式）。

#### P6-04: 多处 `as any` 类型绕过

**文件**: ScanDetail.tsx (5处)、Vulnerabilities.tsx (3处)、FindingDrawer.tsx (4处)

**问题**: 约 12 处 `as any` 绕过 TypeScript 类型检查。

**修复**: 定义正确的接口类型替代 `any`。

#### P6-05: ScanProgress.tsx 死代码

**文件**: `src/web/frontend/src/components/scan/ScanProgress.tsx`

**问题**: 完整组件但从未被导入（ScanDetail 内联实现了自己的进度显示）。

**修复**: 删除该文件，或在 ScanDetail 中复用它。

#### P6-06: Scans.tsx 重试扫描后不导航到新扫描

**文件**: `src/web/frontend/src/pages/Scans.tsx:265-279`

**问题**: `handleRetryScan` 创建新扫描但不导航到详情页。

**修复**: 添加 `navigate(`/scans/${newScan.id}`)` 类似 `handleCreate` 的逻辑。

#### P6-07: Rounds Controller 死代码

**文件**: `src/layers/l3_analysis/rounds/controller.py:273`

**问题**: `critical_candidates = current_round.get_candidates_by_severity(...)` 赋值但从未读取。

**修复**: 移除该行，或改为实际使用它进行终止判断。

---

## 实施计划

### Batch 1: 致命级修复（预计 1-2 天）

| 步骤 | 内容 | 新增/修改文件 |
|------|------|-------------|
| 1.1 | 创建 `sinks_sources/go.py` — Go Sink/Source 定义（参考 python.py 和 java.py 的结构） | 新增 |
| 1.2 | 创建 `sinks_sources/javascript.py` — JS Sink/Source 定义 | 新增 |
| 1.3 | 创建 `sinks_sources/php.py` — PHP Sink/Source 定义 | 新增 |
| 1.4 | 修复 `registry.py` 导入逻辑，添加 try-except 容错 | 修改 |
| 1.5 | 编写 Sink/Source 测试 | 新增 |

### Batch 2: 核心功能补全（预计 3-5 天）

| 步骤 | 内容 | 新增/修改文件 |
|------|------|-------------|
| 2.1 | 实现 `_scan_single_file()` 增量扫描（P2-01） | 修改 `incremental/scanner.py` |
| 2.2 | 强化项目哈希算法（P2-02） | 修改 `incremental/scanner.py` |
| 2.3 | 实现 Java CFG 构建器（P2-03） | 修改 `cfg/builders/java_cfg.py` |
| 2.4 | 实现 Go CFG 构建器（P2-03） | 修改 `cfg/builders/go_cfg.py` |
| 2.5 | 实现 JS CFG 构建器（P2-03） | 修改 `cfg/builders/js_cfg.py` |
| 2.6 | 注册 FrameworkDetector（P2-06） | 修改 `ast_engine.py` |
| 2.7 | SmartScanner 添加 ast_engine 分支（P2-07） | 修改 `smart_scanner.py` |
| 2.8 | 实现 Java CPG Provider（P2-04） | 新增/修改 `cpg/providers/` |
| 2.9 | 实现 Java 调用图构建器（P2-05） | 新增 `call_graph/builders/java_builder.py` |
| 2.10 | 实现 JS 调用图构建器（P2-05） | 新增 `call_graph/builders/js_builder.py` |
| 2.11 | 编写 CFG/CPG/调用图测试 | 新增 |

### Batch 3: 声明功能补全（预计 2-3 天）

| 步骤 | 内容 | 新增/修改文件 |
|------|------|-------------|
| 3.1 | 实现 Cargo/Rust 依赖扫描器（P3-01） | 新增 `dependency_scanner/cargo_scanner.py` |
| 3.2 | 实现 Composer/PHP 依赖扫描器（P3-01） | 新增 `dependency_scanner/composer_scanner.py` |
| 3.3 | 实现 Gem/Ruby 依赖扫描器（P3-01） | 新增 `dependency_scanner/gem_scanner.py` |
| 3.4 | 实现 NuGet/.NET 依赖扫描器（P3-01） | 新增 `dependency_scanner/nuget_scanner.py` |
| 3.5 | 实现 TypeScript/JavaScript 代码结构解析器（P3-02） | 新增 `code_structure/languages/js_ts_parser.py` |
| 3.6 | 修复前端 HTML 报告导出（P3-03） | 修改 `Reports.tsx` + 后端 |
| 3.7 | 实现威胁情报版本匹配（P3-04） | 修改 `intel_service.py` |
| 3.8 | ScanOrchestrator 传入 CPG Path Provider（P3-05） | 修改 `scan_orchestrator.py` |
| 3.9 | 对抗验证规则持久化（P3-06） | 修改 `enhanced_adversarial.py` |

### Batch 4: 实现偏差修复（预计 2 天）

| 步骤 | 内容 |
|------|------|
| 4.1 | Agent 添加 Semaphore 并发控制（P4-01） |
| 4.2 | CodeQL 缓存改为内容哈希（P4-02） |
| 4.3 | 后端 /auth/login 返回 user_id（P4-03） |
| 4.4 | 前端 401 改用 React Router（P4-04） |
| 4.5 | WebSocket 传 JWT（P4-05） |
| 4.6 | Findings 搜索改服务端（P4-06） |
| 4.7 | Vulnerabilities 跳转修复（P4-07） |
| 4.8 | 对抗性验证并行化（P4-08） |
| 4.9 | 证据强度无条件计算（P4-09） |

### Batch 5: 负优化消除（预计 1-2 天）

| 步骤 | 内容 |
|------|------|
| 5.1 | 清理引擎注册表死代码（P5-01） |
| 5.2 | 移除 LLM 缓存无用代码（P5-02） |
| 5.3 | CodeQL 合并多套件 raw_output（P5-03） |
| 5.4 | Dashboard 组件 memoize（P5-04） |
| 5.5 | Scans 粒子效果 useMemo（P5-05） |
| 5.6 | 后端单条 finding API + 前端使用（P5-06） |
| 5.7 | React Query staleTime（P5-07） |
| 5.8 | 时区设置 Context 共享（P5-08） |
| 5.9 | AST 上下文缓存 + 异常日志（P5-09） |
| 5.10 | 404 路由 + lazy loading（P5-10） |

### Batch 6: 前端 i18n 和杂项清理（预计 1 天）

| 步骤 | 内容 |
|------|------|
| 6.1 | 全部硬编码中文改 `t()`（P6-01） |
| 6.2 | Settings 真实 uptime 和连接状态（P6-02） |
| 6.3 | Login 版本号注入（P6-03） |
| 6.4 | 消除 `as any`（P6-04） |
| 6.5 | 清理 ScanProgress 死代码（P6-05） |
| 6.6 | 重试扫描导航修复（P6-06） |
| 6.7 | Rounds Controller 死代码清理（P6-07） |

---

## 测试策略

### 后端测试

| 范围 | 测试内容 |
|------|----------|
| Sink/Source | 验证 go/javascript/php 的 sink/source 定义正确加载，registry 不崩溃 |
| CFG | Java/Go/JS CFG 构建器：条件分支、循环、异常处理的基本块和边 |
| 调用图 | Java/JS 调用图构建器：函数调用、方法链、导入关系 |
| 增量扫描 | `_scan_single_file()` 实际调用引擎、项目哈希唯一性 |
| 依赖扫描 | 4 个新扫描器：Cargo.toml、composer.json、Gemfile、.csproj 解析 |
| 版本匹配 | `search_cves_by_package()` 语义化版本过滤 |
| 并发控制 | Agent 并发度不超过 `max_concurrent` |
| 对抗验证 | 并行验证 vs 串行验证的性能对比 |

### 前端测试

| 范围 | 测试内容 |
|------|----------|
| HTML 导出 | 选择 HTML 格式后下载的是正确的 HTML（非 PDF） |
| Auth 流程 | 登录后 user.id 非零、401 跳转使用 React Router |
| 搜索 | Findings 搜索能找到非当前页的结果 |
| i18n | 语言切换后无硬编码中文残留 |

---

## 修改文件清单

### 新增文件（~15 个）

- `src/layers/l3_analysis/sinks_sources/go.py`
- `src/layers/l3_analysis/sinks_sources/javascript.py`
- `src/layers/l3_analysis/sinks_sources/php.py`
- `src/layers/l3_analysis/call_graph/builders/java_builder.py`
- `src/layers/l3_analysis/call_graph/builders/js_builder.py`
- `src/layers/l3_analysis/engines/ast_engine/cpg/providers/java_provider.py`
- `src/layers/l1_intelligence/dependency_scanner/cargo_scanner.py`
- `src/layers/l1_intelligence/dependency_scanner/composer_scanner.py`
- `src/layers/l1_intelligence/dependency_scanner/gem_scanner.py`
- `src/layers/l1_intelligence/dependency_scanner/nuget_scanner.py`
- `src/layers/l1_intelligence/code_structure/languages/js_ts_parser.py`
- `tests/unit/test_l3/test_sinks_sources_go.py`
- `tests/unit/test_l3/test_sinks_sources_js.py`
- `tests/unit/test_l3/test_sinks_sources_php.py`
- `tests/unit/test_l3/test_cfg_builders.py`（扩展）

### 修改文件（~35 个）

**后端**:
- `src/layers/l3_analysis/sinks_sources/registry.py`
- `src/layers/l3_analysis/incremental/scanner.py`
- `src/layers/l3_analysis/engines/ast_engine/cfg/builders/java_cfg.py`
- `src/layers/l3_analysis/engines/ast_engine/cfg/builders/go_cfg.py`
- `src/layers/l3_analysis/engines/ast_engine/cfg/builders/js_cfg.py`
- `src/layers/l3_analysis/engines/ast_engine/ast_engine.py`
- `src/layers/l3_analysis/smart_scanner.py`
- `src/layers/l3_analysis/engines/opencode_agent.py`
- `src/layers/l3_analysis/engines/codeql.py`
- `src/layers/l3_analysis/engines/base.py`
- `src/layers/l3_analysis/verification/enhanced_adversarial.py`
- `src/layers/l3_analysis/adjudication.py`
- `src/layers/l3_analysis/rounds/controller.py`
- `src/layers/l1_intelligence/attack_surface/llm_detector.py`
- `src/layers/l1_intelligence/threat_intel/intel_service.py`
- `src/layers/l1_intelligence/dependency_scanner/base_scanner.py`（注册新扫描器）
- `src/layers/l1_intelligence/code_structure/base.py`（注册 JS/TS 解析器）
- `src/web/services/scan_orchestrator.py`
- `src/web/api/v1/auth.py`（返回 user_id）
- `src/web/api/v1/scans.py`（单条 finding API + keyword 搜索）

**前端**:
- `src/web/frontend/src/pages/Reports.tsx`
- `src/web/frontend/src/pages/Dashboard.tsx`
- `src/web/frontend/src/pages/Scans.tsx`
- `src/web/frontend/src/pages/Findings.tsx`
- `src/web/frontend/src/pages/Vulnerabilities.tsx`
- `src/web/frontend/src/pages/Settings.tsx`
- `src/web/frontend/src/pages/Login.tsx`
- `src/web/frontend/src/contexts/AuthContext.tsx`
- `src/web/frontend/src/api/client.ts`
- `src/web/frontend/src/api/websocket.ts`
- `src/web/frontend/src/api/scans.ts`
- `src/web/frontend/src/App.tsx`
- `src/web/frontend/src/hooks/useFindings.ts`
- `src/web/frontend/src/i18n/translations.ts`
- `src/web/frontend/src/components/finding/FindingDrawer.tsx`
