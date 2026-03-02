# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | 实现扫描并行优化：引擎并行 + 验证并行 + 对抗并行 |
| **状态** | **completed** ✅ |
| **优先级** | high |
| **创建日期** | 2026-03-03 |
| **完成日期** | 2026-03-03 |

---

## 完成标准

### P1: LLM 并发控制基础设施 ✅

- [x] **LLMConcurrencyManager 类**：全局 LLM 并发控制
  - Semaphore 限制并发数
  - 可配置 max_concurrent (默认 5)
  - 支持不同提供商的不同限制
- [x] **配置项**：`settings.llm.max_concurrent`
- [x] **全局管理器**：get_global_concurrency_manager()

### P2: 引擎级并行化 (Phase 1/2/3) ✅

- [x] **并行执行**：Semgrep、CodeQL、Agent 同时运行
- [x] **asyncio.gather**：收集各引擎结果
- [x] **错误隔离**：单个引擎失败不影响其他引擎
- [x] **进度显示**：并行执行时的进度反馈

### P3: Phase 4 验证并行化 ✅

- [x] **批量验证**：使用 asyncio.gather 并行处理 findings
- [x] **并发控制**：通过 LLMConcurrencyManager 限制
- [x] **结果聚合**：保持结果顺序

### P4: Phase 4.5 对抗验证并行化 ✅

- [x] **批量对抗验证**：并行处理多个 findings
- [x] **并发控制**：通过 LLMConcurrencyManager 限制
- [x] **错误处理**：return_exceptions=True

### P5: 测试与验证 ✅

- [x] 单元测试：21 个测试用例全部通过
- [x] 并发控制逻辑验证

---

## 变更文件

| 文件 | 操作 | 说明 |
|------|------|------|
| `src/core/llm/__init__.py` | 新建 | 模块入口 |
| `src/core/llm/concurrency.py` | 新建 | LLM 并发管理器 (~300 行) |
| `src/core/config/settings.py` | 修改 | 添加 LLMSettings 类 |
| `src/cli/main.py` | 修改 | Phase 1/2/3 并行 + Phase 4/4.5 并行 |
| `tests/unit/test_core/test_concurrency.py` | 新建 | 21 个并发控制测试 |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-03-03 | 设置目标，分析性能瓶颈 |
| 2026-03-03 | 完成 P1: LLM 并发控制基础设施 |
| 2026-03-03 | 完成 P2: 引擎级并行化 |
| 2026-03-03 | 完成 P3: Phase 4 验证并行化 |
| 2026-03-03 | 完成 P4: Phase 4.5 对抗验证并行化 |
| 2026-03-03 | 完成 P5: 21 个测试全部通过 |
| 2026-03-03 | ✅ 目标完成 |

---

## 预期收益

| 优化项 | 当前耗时 | 优化后 | 节省 |
|--------|----------|--------|------|
| Phase 1/2/3 引擎 | ~60 min | ~25 min | 35 min |
| Phase 4 验证 | ~20 min | ~3 min | 17 min |
| Phase 4.5 对抗 | ~60 min | ~10 min | 50 min |
| **总计** | **~2.4 h** | **~1 h** | **~60%** |

---

## 使用方式

### 配置并发数

```bash
# 环境变量
export DEEPVULN_LLM_MAX_CONCURRENT=10
export DEEPVULN_LLM_PROVIDER=openai
```

### 代码中使用

```python
from src.core.llm import configure_global_concurrency, get_global_concurrency_manager

# 配置全局并发管理器
configure_global_concurrency(max_concurrent=10)

# 或获取现有管理器
manager = get_global_concurrency_manager()
print(f"Max concurrent: {manager.max_concurrent}")
print(f"Stats: {manager.stats.to_dict()}")
```

---

## 风险与缓解

| 风险 | 缓解措施 |
|------|----------|
| API 限流 (429) | Semaphore + 已有重试机制 |
| 内存占用增加 | 限制最大并发数 |
| 结果顺序混乱 | 使用索引映射保持顺序 |
| 部分任务失败 | return_exceptions=True + 错误处理 |

---

## 下一步建议

1. **实际测试**：用真实项目测试并行扫描效果
2. **阈值调优**：根据实际 API 限流情况调整 max_concurrent
3. **监控统计**：添加扫描耗时统计输出
4. **CodeQL 缓存**：实现数据库缓存进一步优化
