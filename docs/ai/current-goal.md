# Current Goal

> **状态**: 已完成 ✅
> **目标**: LLM 稳定性增强 — 动态并发自适应 + 429限频修复 + JSON解析增强 + 漏洞列表服务端排序/分页
> **Goal ID**: feat-llm-stability
> **完成日期**: 2026-04-17

---

## 核心变更

### 1. 动态并发自适应 + 429 限频修复

- `concurrency.py`: 新增 `_register_rate_limit_callback()` 将并发管理器的 `report_rate_limit` 注册为 OpenAI 客户端的 429 回调
- `openai_client.py`: 新增模块级 `_on_rate_limit_callback` + `set_rate_limit_callback()`；在 429 重试时立即通知并发管理器（不再等 `__aexit__`）
- `openai_client.py`: `max_tokens` 默认值 4096 → 16384，`json_mode` 参数支持 `response_format: {"type": "json_object"}`
- `openai_client.py`: `finish_reason="length"` 现在抛出 `LLMTruncatedResponseError`（截断 JSON 不再静默传递）
- `llm_config.py`: `context_size` 默认 4096 → 8192, `max_tokens` 默认 4096 → 16384；`to_client_kwargs()` 新增 `json_mode` 字段
- `llm_config_service.py`: 构建 OpenAIClient 时传入 `json_mode`

### 2. JSON 解析增强

- `json_parser.py`: `fix_chinese_punctuation()` 重写 — 中文引号仅在 JSON 字符串外替换（防止破坏字符串边界）
- `json_parser.py`: 新增 `fix_missing_commas()` — 修复 LLM 输出中遗漏的逗号（键值对之间、数组元素之间）
- `json_parser.py`: `robust_json_loads` 管线中集成 `fix_missing_commas`
- `__init__.py`: 导出新增 `fix_missing_commas`
- 测试: 61/61 json_parser 测试通过（含 23 个新增测试）

### 3. 验证器 JSON 提取修复

- `attacker.py`, `defender.py`, `arbiter.py`: 移除手写的 `split("```json")` 代码块提取（会因嵌套 ``` 而截断），统一使用 `robust_json_loads` 的正则提取
- `adversarial.py`: `LLMRateLimitError` 现在正确传播到并发管理器的 `__aexit__`（先记录 fallback verdict 再 re-raise）

### 4. 对抗性验证超时保护

- `adversarial_service.py`: 新增 `per_finding_timeout=300s`，使用 `asyncio.wait_for` 防止单个 finding 卡死整个阶段
- 超时结果标记 `timeout: true` 而非普通 error
- 新增 `progress_callback("finding_verified")` 通知

### 5. 扫描进度 API 增强

- `scans.py`: 已完成扫描的 severity counts 改为从 Finding 表实时计算（修复旧 limit=100 缓存不准确问题）
- `scans.py`: 列表 API 批量查询 severity（一次 round-trip 替代逐条查询）
- `scans.py`: 进度 API 新增 `concurrency` 字段（从 `concurrency_update` 事件获取最新并发状态）
- `scans.py`: 阶段去重（同 phase_name 保留最新记录）
- `schemas.py`: `ScanProgressResponse` 新增 `concurrency` 字段
- `scans.py`: findings 端点新增 `engine`, `sort_field`, `sort_dir` 查询参数
- `finding.py`: Repository 支持服务端排序（severity 权重、confidence、engine）和 engine 过滤

### 6. 前端增强

- `FindingList.tsx`: 客户端排序改为服务端排序，新增 `SortHead` 可点击列头组件（severity/confidence/engine）
- `FindingList.tsx`: 分页从 ←/→ 改为数字页码（最多显示 7 页 + 省略号）
- `Findings.tsx`: 集成 `sortField/sortDir` 状态，传递给 API 和 FindingList
- `useFindings.ts`: 支持新查询参数（engine, sort_field, sort_dir）
- `useScanProgress.ts`: 支持 concurrency 状态显示
- `LiveTerminal.tsx`: 进度回调小优化
- `scans.ts`: API 类型新增 engine/sort_field/sort_dir 参数
- `models.ts`: FindingListResponse 新增 engine 字段

### 7. 进度广播增强

- `progress_broadcaster.py`: 新增并发状态事件广播（`concurrency_update`）
- `scan_orchestrator.py`: 在并发管理器调整时广播并发状态
- `scan_tasks.py`: 新增 `concurrency_update` 事件存储到 ScanEvent 表

---

## 测试结果

| 测试套件 | 结果 | 备注 |
|----------|------|------|
| test_json_parser | 61/61 ✅ | 含 23 个新增测试 |
| test_llm_client | 5/6 ✅ | 1 个预存失败（`test_is_available_without_key`） |
| test_l3 (完整) | 2131/2145 ✅ | 14 个预存失败（adjudication/deduplicator/ast_framework 等，均非本次引入） |
| test_web | 收集错误 | 3 个预存 ModuleNotFoundError（`src.web.models.project`） |

**结论**: 本次变更未引入新的测试失败。修复了 1 个由 max_tokens 默认值变更导致的测试（`test_default_init`）。

## 安全扫描

**结论: ✅ 无新增安全问题。** 所有 12 个安全发现均为预存问题。

## 死代码

本次变更未产生新的死代码。`_register_rate_limit_callback` 使用 `__import__('logging')` 模式与文件其他部分一致。

---

## 同步状态

- **同步日期**: 2026-04-17
- **路线图更新**: 新增 v1.3 里程碑
- **变更日志**: 待追加

---

## 前一目标

| 字段 | 值 |
|------|-----|
| Goal ID | web-ui-polish-batch |
| 标题 | Web UI 打磨与功能增强批次 |
| 状态 | 已完成 ✅ |
| Commit | 57a858a (最终批次) |
