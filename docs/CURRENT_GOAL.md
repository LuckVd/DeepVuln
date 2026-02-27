# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | 实现批量 LLM 入口点检测，每次提交 50 个文件 |
| **状态** | completed |
| **优先级** | high |
| **创建日期** | 2026-02-27 |
| **完成日期** | 2026-02-27 |

---

## 背景

### 现状问题

当前 `LLMFullDetector` 的 Phase 2 逐个文件调用 LLM：
- 50 个文件 = 50 次 LLM 调用
- 每次调用约 3 秒
- 总耗时约 150 秒（2.5 分钟）

### 目标

实现批量 LLM 分析，每次提交多个文件（默认 50 个）：
- 减少调用次数
- 预期加速 10-15 倍
- 批次大小可配置

---

## 完成标准

### P1: 核心实现
- [x] 新增 `BATCH_ENTRY_POINT_DETECTION_PROMPT` 模板
- [x] 新增 `_analyze_files_batch()` 方法
- [x] 新增 `_build_batch_content()` 方法
- [x] 新增 `_parse_batch_response()` 方法

### P2: 配置支持
- [x] 添加 `config.llm.batch_size` 配置项
- [x] 添加 `get_llm_batch_size()` 函数
- [x] 添加 `--batch-size` CLI 参数
- [x] 添加交互式模式 batch_size 询问

### P3: 集成修改
- [x] 修改 `detect_full()` 支持批量模式
- [x] 修改 `detect_llm_full()` 传递 batch_size
- [x] 保持向后兼容（保留逐文件分析选项）

### P4: 测试验证
- [x] 单元测试：批量内容构建
- [x] 单元测试：批量响应解析
- [x] 单元测试：小批量分析
- [x] 单元测试：多批次分析
- [x] 所有测试通过（83 tests）

---

## 关键文件修改

| 文件 | 操作 | 说明 |
|------|------|------|
| `src/layers/l1_intelligence/attack_surface/llm_detector.py` | 修改 | 添加批量分析方法 |
| `src/core/config/__init__.py` | 修改 | 添加 `get_llm_batch_size()` |
| `config.example.toml` | 修改 | 添加 `batch_size` 配置示例 |
| `src/cli/main.py` | 修改 | 添加 `--batch-size` 参数 |
| `src/cli/prompts.py` | 修改 | 添加交互式 batch_size 询问 |
| `tests/unit/test_l1/test_llm_detector.py` | 修改 | 添加批量分析测试 |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-02-27 | 设置新目标：批量 LLM 入口点检测 |
| 2026-02-27 21:40 | feat(l1): add batch LLM entry point detection for 15x speedup |

---

## 验证结果

1. ✅ 50 个文件只需 1-2 次 LLM 调用
2. ✅ 检测结果与逐文件分析一致
3. ✅ 批次大小可从配置文件设置
4. ✅ 现有测试不回归（83 tests pass）
