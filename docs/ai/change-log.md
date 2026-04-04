# Change Log

## 2026-04-04

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
