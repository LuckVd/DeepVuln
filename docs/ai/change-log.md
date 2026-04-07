# Change Log

## 2026-04-07

### P9-01: CPG 与 Agent 标准集成

- **Goal ID**: P9-01
- **Summary**: 实现 CPG 与 Agent 的标准集成，为 AI 分析提供攻击路径信息
- **Impact**:
  - `src/layers/l3_analysis/engines/ast_engine/cpg/path_provider.py`: CPGPathProvider 语言无关接口
  - `src/layers/l3_analysis/engines/ast_engine/cpg/base.py`: LanguageCPGProvider 抽象基类
  - `src/layers/l3_analysis/engines/ast_engine/cpg/providers/python_provider.py`: Python 实现
  - `src/layers/l3_analysis/engines/ast_engine/cpg/providers/js_provider.py`: JavaScript 实现
  - `src/layers/l3_analysis/engines/opencode_agent.py`: Agent 集成 CPGPathProvider
  - `src/layers/l3_analysis/models.py`: Finding 添加 `cpg_path` 字段
  - `src/layers/l3_analysis/prompts/security_audit.py`: Prompt 集成 CPG 路径信息
- **Features**:
  - **CPGPathProvider**: 语言无关接口，自动路由到语言特定 Provider
  - **语言检测**: 基于文件扩展名的自动语言检测
  - **降级策略**: CPG 失败时 Agent 继续正常工作
  - **Finding 扩展**: `cpg_path` 字段存储攻击路径元数据 (entry_point, sink, path, confidence, sanitizers, reaches_sink)
  - **路径匹配**: 自动将 Finding 匹配到最相关的 CPG 路径
  - **多语言支持**: Python (完整) + JavaScript/TypeScript
- **Tests**: 61/61 测试通过 (100%)
  - test_path_provider.py: 11 单元测试
  - test_python_provider.py: 11 单元测试
  - test_js_provider.py: 14 单元测试
  - test_e2e.py: 8 集成测试
- **Security**: No secrets exposed
- **Design**: 分层集成，可选降级，不影响现有 Agent 功能

### P8-09: CPG 基础实现

### P8-09: CPG 基础实现

- **Goal ID**: P8-09
- **Summary**: 实现 Code Property Graph 基础，融合 AST Graph + Call Graph + CFG，支持攻击路径搜索
- **Impact**:
  - `src/layers/l3_analysis/engines/ast_engine/cpg/`: 新增 CPG 统一代码图模块
    - `models.py`: CPGNode, CPGEdge, CodePropertyGraph 数据结构
    - `builder.py`: CPGBuilder 融合 AST + Call Graph
  - `src/layers/l3_analysis/engines/ast_engine/cfg/`: 新增控制流图模块
    - `models.py`: CFGNode, CFGEdge, ControlFlowGraph, BasicBlock
    - `base.py`: LanguageCFGBuilder 抽象基类
    - `factory.py`: CFGBuilderFactory 语言路由
    - `builders/python_cfg.py`: Python CFG 构建器（完整支持）
    - `builders/js_cfg.py`: JavaScript/TypeScript CFG 构建器
    - `builders/java_cfg.py`: Java CFG 构建器
    - `builders/go_cfg.py`: Go CFG 构建器
  - `src/layers/l3_analysis/engines/ast_engine/path_finder/`: 新增攻击路径搜索模块
    - `models.py`: AttackPath, PathFinderConfig, PathType
    - `finder.py`: AttackPathFinder BFS 路径搜索算法
- **Features**:
  - **CPG 统一视图**: 融合 AST Graph（语句级）+ Call Graph（函数级）到统一代码图
  - **多语言 CFG 支持**: Python（完整）+ JavaScript + Java + Go（基础）
    - Python: if/while/for/try/match/async/break/continue/return
    - JavaScript: if/while/for/try/switch/break/continue
    - Java: if/while/for/try/switch/break/continue
    - Go: if/while/for/switch/break/continue
  - **语言抽象接口**: `LanguageCFGBuilder` 基类，支持扩展到其他语言
  - **攻击路径搜索**: BFS 算法从入口点到危险函数
  - **Sanitizer 检测**: 自动识别清洗函数（sanitize/escape/validate/filter）
  - **路径属性**: confidence 计算、可达性验证、条件分支记录
- **Tests**: 47 单元测试通过 (CPG: 15, CFG: 18, PathFinder: 14)
- **Multi-language**: Python (完整) + JavaScript + Java + Go (框架支持)
- **Next**: v0.9 里程碑完整验证 / CPG 与 Agent 集成

## 2026-04-05

### P8-08: 前置防误报架构

- **Goal ID**: P8-08
- **Summary**: 实现前置防误报架构，在源头防止误报，节省 ~40% LLM 调用
- **Impact**:
  - `src/layers/l3_analysis/pre_filter/`: 新增预过滤器模块目录
    - `file_pre_filter.py`: FilePreFilter 文件级预过滤 (P8-08a)
    - `streaming_validator.py`: StreamingValidator 流式验证 (P8-08c)
    - `in_memory_deduplicator.py`: InMemoryDeduplicator 前置去重 (P8-08e)
    - `codeql_pre_filter.py`: CodeQLPreFilter CodeQL 预过滤 (P8-08d)
  - `src/layers/l3_analysis/prompts/enhanced_audit_prompt.py`: 防幻觉规则 (P8-08b)
  - `src/layers/l3_analysis/verification/verification_gatekeeper.py`: 对抗验证门槛 (P8-08f)
  - `src/layers/l3_analysis/prompts/security_audit.py`: 集成增强 prompt
  - `src/layers/l3_analysis/deduplicator.py`: 支持 GLM-5 reasoning_content (P8-08h)
- **Features**:
  - **FilePreFilter**: 扫描前判断文件是否值得分析
    - 跳过配置文件、生成代码、无可执行代码的文件
    - 攻击面可达性检查
  - **EnhancedPrompt**: 集成 code-audit skill 防幻觉规则
    - 执行证据要求：必须有用户可控输入 + 危险操作 + 实际执行
    - Few-Shot 示例：正反例对比
    - 置信度校准规则
  - **StreamingValidator**: Finding 流式验证
    - 检查执行证据（危险调用 vs 仅构造）
    - 置信度合理性校准
    - XSS + JSON 响应自动降级
  - **InMemoryDeduplicator**: 前端内存去重
    - 文件级去重（同文件同行号保留最高分）
    - 调用链去重（同漏洞不同层级只保留一个）
  - **CodeQLPreFilter**: CodeQL 预过滤
    - 规则置信度调整（XSS 默认降低 0.2）
    - 响应类型检测（JSON vs HTML）
    - 通配符规则匹配
  - **VerificationGatekeeper**: 对抗验证准入门槛
    - 明显误报 → 自动拒绝
    - 强证据 + 高置信 → 自动确认
    - 低置信 + 低严重 → needs_review
  - **GLM-5 支持**: 去重器支持 reasoning_content 字段解析
- **Tests**: 109 单元测试 + 16 集成测试通过
- **Security**: No secrets exposed
- **Dead Code**: 未检测到死代码
- **Expected Effects**:
  - ~50% 减少 Agent 误报（防幻觉规则 + 流式验证）
  - ~50% 减少 CodeQL 误报（JSON 响应检测 + 规则调整）
  - ~56% 减少重复检测（前端内存去重）
  - ~40% 减少对抗验证调用（智能准入门槛）
- **Next**: P8-09 CPG 基础 (可选)

## 2026-04-04

### P8-07: 规则库扩展

- **Goal ID**: P8-07
- **Summary**: 扩展 AST Query 规则库，增加框架特定漏洞检测规则
- **Impact**:
  - `src/layers/l3_analysis/engines/ast_engine/detectors/framework_detector.py`: FrameworkDetector 实现
  - `rules/ast_query/framework/`: 13 个框架规则 YAML 文件
    - `flask/`: 4 个 Flask 规则
    - `django/`: 2 个 Django 规则
    - `fastapi/`: 1 个 FastAPI 规则
    - `express/`: 2 个 Express 规则
    - `java/`: 2 个 Java 规则
    - `go/`: 2 个 Go 规则
  - `tests/unit/test_l3/test_ast_engine/test_framework_detector.py`: 19 个单元测试
- **Features**:
  - **FrameworkDetector**: 框架专用检测器
    - 从 `rules/ast_query/framework/` 目录加载规则
    - 支持框架特定上下文验证
  - **框架规则覆盖**:
    - **Flask**: render_template_string (SSTI), secret_key_hardcoded, allow_all_hosts, redirect_user_input (开放重定向)
    - **Django**: render_xss, extra_raw_sql (SQL 注入)
    - **FastAPI**: corp_auto_origin (CORS 配置错误)
    - **Express**: prototype_pollution_merge, template_injection_ejs (SSTI)
    - **Java**: reflection_class_forname (代码注入), jni_register_natives
    - **Go**: context_without_deadline (DoS), defer_close_file (资源泄漏)
- **Tests**: 19/19 单元测试通过，覆盖所有框架检测场景
- **Security**: No secrets exposed
- **Dead Code**: 未检测到死代码
- **Next**: P8-08 CPG 基础 (Phase 2) 或其他 Phase 8 任务

### P8-06: AI Agent 结构化上下文

- **Goal ID**: P8-06
- **Summary**: 为 AI Agent 提供 AST 结构化上下文，提升推理精度
- **Impact**:
  - `src/layers/l3_analysis/engines/ast_engine/context/extractor.py`: ASTContextExtractor 实现 (~260 行)
  - `src/layers/l3_analysis/prompts/security_audit.py`: 添加 `ast_context` 参数
  - `src/layers/l3_analysis/engines/opencode_agent.py`: 集成 ASTContextExtractor
  - `tests/unit/test_l3/test_ast_context/test_extractor.py`: 11 个单元测试
- **Features**:
  - **ASTContextExtractor**: 提取 AST 结构化上下文
    - `extract_for_location()`: 提取特定位置的 AST 上下文
    - `extract_for_sinks()`: 批量提取 sink 上下文
    - `extract_for_code()`: 从代码直接提取 AST 上下文
  - **ASTContext**: 上下文数据结构（code_snippet, ast_structure, parent_context, risk_analysis）
  - **风险分析**: 支持 6 类危险函数检测（code_injection, command_injection, sql_injection, path_traversal, deserialization, weak_crypto）
  - **Prompt 增强**: AST Structure Analysis 自动添加到 AI prompt
- **Design**:
  - 降级策略：AST Graph 不可用时降级到不使用 AST 上下文
  - 风险映射：危险函数 → 漏洞类型（eval → code_injection）
- **Tests**: 11/11 单元测试通过
- **Security**: No secrets exposed
- **Dead Code**: 未检测到死代码
- **Next**: P8-07 规则库扩展（可选）

### P8-05: 与 Call Graph 桥接

- **Goal ID**: P8-05
- **Summary**: 实现 AST Graph 与 Call Graph 的桥接，提供统一查询接口
- **Impact**:
  - `src/layers/l3_analysis/engines/ast_engine/graph/bridge.py`: GraphBridge 实现 (~370 行)
  - `src/layers/l3_analysis/engines/ast_engine/graph/unified.py`: UnifiedGraphQuery 实现 (~500 行)
  - `src/layers/l3_analysis/engines/ast_engine/graph/__init__.py`: 导出新类
  - `tests/unit/test_l3/test_ast_graph/test_bridge.py`: 14 个单元测试
  - `tests/unit/test_l3/test_ast_graph/test_unified.py`: 18 个单元测试
  - `tests/integration/test_graph_bridge_e2e.py`: 3 个端到端集成测试
- **Features**:
  - **GraphBridge**: 跨图导航核心
    - `find_containing_function()`: AST 节点 → 包含它的 CallNode（向上遍历 parent_id）
    - `find_ast_nodes_in_function()`: CallNode → 函数体内的所有 ASTNode（向下遍历子树）
    - `trace_to_sink()`: 从入口点到 sink 的完整路径追踪
  - **UnifiedGraphQuery**: 高层统一查询接口
    - `find_all_sinks()`: 查找所有危险 sink（eval、system、open、pickle.load 等）
    - `find_reachable_sinks()`: 从入口点找到所有可达的危险 sink
    - `get_function_context()`: 获取某个位置的完整上下文（函数、调用者、被调用者、sinks）
    - `get_attack_paths()`: 获取到目标位置的完整攻击路径
  - **TracedPath**: 完整攻击路径数据结构（entry_point → call_chain → sink）
  - **SinkMatch**: 危险 sink 匹配结果（含 sink_type、confidence）
  - **FunctionContext**: 函数上下文（call_node、ast_nodes、callers、callees、sinks）
- **Design Decision**:
  - 选项 A (保持简单): 基于坐标匹配 + 父子关系，无需修改已有代码
  - 完全准确：利用 tree-sitter 的真实 AST 结构，向上遍历 parent_id
  - 升级触发条件记录在 roadmap 中
- **Tests**: 58/58 测试通过（14 bridge + 18 unified + 23 models + 3 builder）
- **Security**: No secrets exposed
- **Dead Code**: 未检测到死代码
- **Next**: P8-06 AI Agent 结构化上下文（可选）

### P8-04: AST Graph Builder (选项 A)

- **Goal ID**: P8-04
- **Summary**: 实现简单的 AST 代码图构建器，支持基础遍历和查询
- **Impact**:
  - `src/layers/l3_analysis/engines/ast_engine/graph/`: 新增图模块目录
  - `src/layers/l3_analysis/engines/ast_engine/graph/models.py`: ASTNode, ASTGraph 数据结构
  - `src/layers/l3_analysis/engines/ast_engine/graph/builder.py`: ASTGraphBuilder 实现
  - `tests/unit/test_l3/test_ast_graph/`: 新增 23 个单元测试
- **Features**:
  - **ASTNode**: 节点数据结构 (id, type, name, file, line, parent_id, children)
  - **ASTGraph**: 图容器，支持文件索引、类型索引
  - **ASTGraphBuilder**: 遍历 tree-sitter AST，构建代码图
  - **查询 API**: get_node, get_children, get_nodes_by_type, get_nodes_by_file, find_by_name
  - **序列化**: to_dict() 支持导出为 JSON
- **Design Decision**:
  - 选项 A (简单图构建): 基础节点/边 + 父子关系
  - P8-05 时评估是否需要升级到选项 B (完整图系统)
- **Tests**: 23/23 单元测试通过
- **Security**: No secrets exposed
- **Next**: P8-05 与 Call Graph 桥接（需先评估升级需求）

### P8-03: 结构型漏洞检测器实现

- **Goal ID**: P8-03
- **Summary**: 实现检测器框架和 YAML 规则系统，支持可扩展的结构化漏洞检测
- **Impact**:
  - `src/layers/l3_analysis/engines/ast_engine/detectors/`: 新增检测器框架目录
  - `src/layers/l3_analysis/engines/ast_engine/ast_engine.py`: 重构为检测器架构，移除硬编码规则
  - `rules/ast_query/`: 新增 YAML 规则目录，10 条规则文件
  - `tests/unit/test_l3/test_detectors/`: 新增 16 个检测器单元测试
- **Features**:
  - **BaseDetector**: 抽象基类，提供 YAML 规则加载和 `_post_validate` hook
  - **DangerousAPIDetector**: 检测 eval/exec/os.system/subprocess，支持常量字面量过滤
  - **CryptoMisuseDetector**: 检测 md5/sha1，支持测试代码过滤
  - **DeserializationDetector**: 检测 pickle/yaml unsafe load
  - **YAML 规则系统**: 规则外部化，支持多语言，易于扩展
- **Rules Added**:
  - Python: eval, exec, os.system, subprocess shell=True, md5, sha1, pickle.load, yaml.load
  - JavaScript: eval, md5
- **Tests**: 16/16 单元测试通过 + 14/14 AST Engine 测试通过
- **Security**: No secrets exposed
- **Next**: P8-04 AST Graph Builder

### P8-02a: AST Engine 基础设施

- **Goal ID**: P8-02a
- **Summary**: 实现 AST Engine 核心架构，提供语句级别的代码结构分析能力
- **Impact**:
  - `src/layers/l3_analysis/engines/ast_engine/`: 新增 AST Engine 完整模块
  - `src/layers/l3_analysis/models.py`: 添加 `ast_engine` 到 Finding.source 允许值
  - `tests/unit/test_l3/test_ast_engine/`: 新增 14 个单元测试
- **Features**:
  - **TreeSitterManager**: 动态加载多语言 tree-sitter 解析器
  - **QueryEngine**: 封装 tree-sitter 查询 API，支持结构化查询
  - **ASTEngine**: 主引擎类，继承 BaseEngine，集成到引擎注册表
  - **内置规则**: eval/exec/os.system/md5/pickle 检测
- **Supported Languages**: Python, JavaScript, TypeScript, Java, Go, C/C++, Ruby, PHP, Rust
- **Tests**: 14/14 单元测试通过
- **Security**: No secrets exposed
- **Next**: P8-03 结构型漏洞检测器扩展

## 2026-04-02

### P7-01: 报告导出增强 - LLM 分析详情选项

- **Goal ID**: P7-01
- **Summary**: 添加 `--include-llm-details` 选项，允许在导出报告中包含 LLM 评估详情
- **Impact**:
  - `src/cli/main.py`: 新增 `--include-llm-details` 参数，增强 `_export_full_scan_result` 函数
- **Features**:
  - 去重分析详情：显示合并的漏洞组及 LLM 推理原因
  - 对抗验证详情：每个漏洞的 verdict (CONFIRMED/REJECTED)、confidence、reasoning
- **Usage**:
  ```bash
  # 基本导出（不含 LLM 详情）
  deepvuln scan -p /target --full --export report.txt

  # 带 LLM 详情的导出
  deepvuln scan -p /target --full --export report.txt --include-llm-details
  ```
- **Tests**: Docker 集成测试通过 (java-simple-vuln: 4 CONFIRMED, 完整 reasoning 导出)
- **Security**: No secrets exposed

### P5-01e: 扫描顺序优化完成

### P5-01e: 扫描顺序优化完成

- **Goal ID**: P5-01e
- **Summary**: 将去重阶段移到对抗性验证之前，减少 LLM API 调用量约 25%
- **Impact**:
  - `src/cli/main.py`: 新增 Phase 4.25 (Deduplication)，移动去重逻辑到对抗验证之前
  - `tests/unit/test_l3/test_scan_order.py`: 新文件（12 个单元测试）
  - `tests/unit/test_l3/test_deduplicator.py`: 修复 `llm_timeout` 期望值 (30→180)
- **Flow Change**:
  ```
  旧: Phase 4 (Verify) → Phase 4.5 (Adversarial) → Deduplication
  新: Phase 4 (Verify) → Phase 4.25 (Deduplication) → Phase 4.5 (Adversarial)
  ```
- **Key Changes**:
  - 在 Phase 4 结束后立即调用 `adjudicate_findings()` 进行去重
  - 更新 `result["verified_findings"]` 为去重后的结果
  - Phase 4.5 现在接收去重后的 findings（191 → ~150）
- **Expected Impact**:
  - 对抗验证数量减少约 22% (191 → 150)
  - API 调用减少约 25%
  - Token 使用量减少约 30%
  - 扫描时间减少约 25%
- **Tests**: 12/12 单元测试通过
- **Commit**: 2a87275

### Bug 修复: 扫描日志问题修复

- **Goal ID**: bugfix-scan-log-issues
- **Summary**: 修复扫描日志中发现的 4 个系统问题
- **Impact**:
  - `src/layers/l3_analysis/readiness_gate.py`: 修复 RuntimeType 导入路径
  - `src/layers/l3_analysis/verification/*.py`: 集成 `robust_json_loads` 增强解析容错
  - `src/layers/l3_analysis/deduplicator.py`: 使用 `robust_json_loads`
  - `src/layers/l3_analysis/engines/codeql.py`: 修复 Java 构建命令检测逻辑
  - `src/cli/main.py`: 添加报告导出前目录创建和权限错误处理
- **Issues Fixed**:
  1. Readiness Gate 导入错误：`types.py` → `models.py`
  2. LLM 响应解析失败：多次 JSON 解析错误（GLM API 格式问题）
  3. CodeQL Java 构建失败：`build_command` 优先级逻辑错误
  4. 报告导出权限错误：缺少目录创建和错误处理
- **Tests**: 31/31 readiness_gate + 45/45 json_parser 通过
- **Commit**: 73d4c32

## 2026-04-01

### Bug 修复: LLM 去重服务集成问题

- **Goal ID**: bugfix-llm-dedup-integration
- **Summary**: 修复 P6-17 LLM 去重功能的多个集成问题，确保跨引擎去重正常工作
- **Impact**:
  - `src/layers/l3_analysis/adjudication.py`: 添加 `api_key` 和 `base_url` 参数传递
  - `src/layers/l3_analysis/llm/openai_client.py`: 处理 GLM-5 的 `content`/`reasoning_content` 字段，添加请求超时参数支持
  - `src/layers/l3_analysis/deduplicator.py`: 使用子进程方式调用 LLM 避免异步冲突，超时增加到 180 秒
  - `src/layers/l3_analysis/models.py`: 添加 `merged_findings` 字段用于存储合并的漏洞详情
- **Root Cause**:
  - `adjudication.py` 创建 `OpenAIClient` 时未传递认证信息
  - GLM-5 推理模型使用 `reasoning_content` 字段存储推理过程，`content` 字段存储最终答案
  - 扫描框架在异步上下文中运行，`asyncio.run()` 无法嵌套调用
  - 默认超时 30 秒不足以支持 GLM-5 推理（需要 60-90 秒）
- **Fix**:
  - 从 `get_openai_config()` 获取并传递 `api_key` 和 `base_url`
  - 优先读取 `content` 字段，为空时回退到 `reasoning_content`
  - 使用子进程 + base64 编码方式调用 LLM，避免事件循环冲突
  - 默认超时从 30 秒增加到 180 秒
  - 添加 `merged_findings: list[dict[str, Any]]` 字段记录合并的漏洞详情
- **Tests**: 本地验证通过 (3 findings → 2 findings, 1 removed)
- **Security**: No secrets exposed

### Bug 修复: Readiness Gate 属性访问安全

- **Goal ID**: bugfix-readiness-gate-attr
- **Summary**: 修复 readiness_gate.py 中直接访问可能不存在的属性导致的崩溃
- **Impact**:
  - `src/layers/l3_analysis/readiness_gate.py`: 异常处理中使用安全属性访问 (getattr + fallback)
- **Root Cause**:
  - `_analyze_build_readiness` 接收 `list[BuildRecommendation]`，但异常处理假设 target 有 `name` 和 `language` 属性
  - `BuildRecommendation` 没有 `name`/`language` 属性，导致 `AttributeError`
- **Fix**:
  - 使用 `getattr(target, 'name', default_value)` 安全访问属性
  - 当 `name` 不存在时，使用 `path` 或对象的字符串表示
  - 当 `language` 不存在时，默认为 `'unknown'`
- **Tests**: 本地验证通过
- **Security**: No secrets exposed

### P6-17: 两阶段混合去重策略完成

- **Goal ID**: P6-17
- **Summary**: 实现基于位置聚类 + LLM 判断的两阶段混合去重，解决跨引擎去重失效问题
- **Impact**:
  - `src/layers/l3_analysis/deduplicator.py`: +280 行（ClusterBasedDeduplicator, LocationCluster, cluster_findings_by_location）
  - `src/layers/l3_analysis/adjudication.py`: +50 行（集成 LLM 客户端，降级到 ASTDeduplicator）
  - `tests/unit/test_l3/test_deduplicator.py`: +240 行（18 个新测试用例）
  - `tests/integration/test_deduplication.py`: 新文件（7 个集成测试）
- **Features**:
  - 位置聚类：按 file_path + line_range (容差 10 行) 分组
  - LLM 判断：对聚类内 findings 进行语义级去重判断
  - 保留策略：重复的保留 final_score 最高的，更新 related_engines
  - 降级机制：LLM 不可用时降级到 ASTDeduplicator
- **Tests**: 101 passed (deduplicator) + 54 passed (adjudication)
- **Dead Code**: not run
- **Security**: No secrets exposed

### P6-16: Readiness Gate 自动修复机制完成

- **Goal ID**: P6-16
- **Summary**: 实现 Readiness Gate 自动修复机制，尽量构建环境而非跳过检测
- **Impact**:
  - `src/layers/l3_analysis/readiness_gate.py`: Query Pack 自动下载 + RuntimeVersionManager 集成
  - `docker-compose-tun.yml`: TUN 透明代理配置（空代理变量保留用于明确禁用代理）
  - `docker-compose-china.yml`: 国内网络优化配置
  - `.env.docker.build`: Docker 构建环境变量模板
  - `Dockerfile`: 更新构建参数支持
  - `docs/docker-china-setup.md`: 国内网络环境设置指南
  - `README.md`: 新增 Docker 扫描使用指南
- **Acceptance Criteria**:
  - ✅ Readiness Gate 检测到 Query Pack 未安装时，自动尝试下载
  - ✅ Readiness Gate 检测到构建工具缺失时，尝试使用 RuntimeVersionManager 安装
  - ✅ Semgrep 在 TUN 模式下正常工作
  - ✅ 增强日志输出（`[P6-16a Auto-fix]`, `[P6-16b Auto-fix]` 标记）
- **Tests**: 31 passed (test_readiness_gate)
- **Dead Code**: not run
- **Security**: No secrets exposed (`.env` in `.gitignore`)
- **Commit**: 51f58a6

## 2026-03-30

### Bug 修复: Semgrep CLI 兼容性与类型安全

- **Goal ID**: bugfix-semgrep-cli-compat
- **Summary**: 修复 Semgrep 引擎 CLI 参数冲突和 FailedEngineInfo 类型处理问题
- **Impact**:
  - `Dockerfile`: CodeQL 版本升级 `2.24.2` → `2.25.1`
  - `src/cli/main.py`: 修复 `FailedEngineInfo` 对象/字典兼容性（3 处）
  - `src/layers/l3_analysis/engines/semgrep.py`: 修复 `--lang` 与 `--config auto` 冲突 + 添加调试日志
- **Issues Fixed**:
  - Semgrep 使用 `--config auto` 时加 `--lang` 参数导致命令失败
  - CLI 导出时 `FailedEngineInfo` dataclass 与 dict 混用导致属性访问错误
- **Tests**: 47 passed, 9 skipped (Docker 集成测试验证无回归)
- **Dead Code**: not run
- **Security**: No secrets exposed
- **Commit**: 6c32401
