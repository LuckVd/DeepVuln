# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | 修复 L1 批量分析的两个问题：空响应处理 + 文件选择优先级 |
| **状态** | in_progress |
| **优先级** | high |
| **创建日期** | 2026-02-28 |

---

## 问题背景

### 问题 1: 空响应导致 JSON 解析失败

```
WARNING  Failed to parse batch response: Failed to parse JSON after all recovery attempts: Expecting value: line 1 column 1 (char 0)
```

**原因**：
- GLM-5 在某些情况下返回空字符串
- `_call_llm` 方法没有检查空响应
- 30 个文件 (~48000 字符) 可能超过 GLM-5 处理能力

### 问题 2: 文件选择优先级错误

**PandaWiki 项目结构**：
```
backend/
├── api/           ← 只有 DTO 结构体定义（无入口点）
├── handler/       ← 实际的 HTTP 处理器（有入口点）
```

**当前行为**：
- Phase 1 返回 `api/**/*.go` 文件
- 这些文件只包含 struct 定义，没有入口点

**期望行为**：
- Phase 1 优先返回 `handler/**/*.go` 文件
- 这些文件包含实际的 HTTP 处理器

---

## 完成标准

### P1: 空响应处理
- [x] 在 `_call_llm` 中添加空响应检查和警告日志
- [x] 减少默认 `batch_max_chars` 从 50000 到 30000
- [x] 空响应时抛出明确异常而非静默失败

### P2: 文件选择优先级
- [x] 更新 `PROJECT_STRUCTURE_PROMPT`，明确指示优先级
- [x] 优先分析 `handler/`、`controller/`、`route/` 目录
- [x] 跳过 `dto/`、`model/`、`schema/`、`types/` 目录

### P3: 验证
- [x] 所有 L1 测试通过（57/57）
- [ ] 重新运行扫描，确认不再出现空响应错误
- [ ] 确认 Phase 1 返回 `handler/` 目录的文件

---

## 关键文件修改

| 文件 | 操作 | 说明 |
|------|------|------|
| `src/layers/l1_intelligence/attack_surface/llm_detector.py` | 修改 | `_call_llm` 空响应检查 + prompt 更新 |
| `src/cli/prompts.py` | 修改 | 交互式提示默认值 50000 → 30000 |
| `src/cli/main.py` | 修改 | CLI 回退默认值 50000 → 30000 |
| `src/cli/prompts.py` | 修改 | 交互式提示默认值 50000 → 30000 |
| `src/cli/main.py` | 修改 | CLI 回退默认值 50000 → 30000 |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-02-28 23:00 | 调试发现 GLM-5 返回空响应 |
| 2026-02-28 23:10 | 确认 Phase 1 prompt 没有优先 handler/ 目录 |
| 2026-02-28 23:15 | 设置目标，准备实现修复 |
| 2026-02-28 23:20 | 修改 `_call_llm` 添加空响应检查 |
| 2026-02-28 23:25 | 修改 `max_batch_chars` 默认值从 50000 到 30000 |
| 2026-02-28 23:30 | 修改 `PROJECT_STRUCTURE_PROMPT` 添加优先级指令 |
| 2026-02-28 23:35 | 更新测试用例适配新的默认值 |
| 2026-02-28 23:40 | 所有 L1 测试通过 (57 passed) |
| 2026-02-28 23:45 | 统一更新 prompts.py 和 main.py 中的默认值 |

---

## 预期效果

- GLM-5 不再因输入太长而返回空响应
- Phase 1 正确选择 `handler/` 目录的文件
- 入口点检测成功率提升
