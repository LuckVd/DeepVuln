# 当前目标

> P5-05 LLM 并发配置统一化
---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | P5-05 LLM 并发配置统一化 |
| **状态** | completed ✅ |
| **优先级** | medium |
| **创建日期** | 2026-03-09 |
| **完成日期** | 2026-03-09 |
| **所属阶段** | Phase 5 - 精度深化 |

---

## 问题背景

### 之前的问题

各模块 LLM 并发配置不一致，部分硬编码：

| 模块 | 之前 | 问题 |
|------|------|------|
| Agent | 硬编码 2 | 不读取配置 |
| 全局管理器 | 硬编码 5 | 不读取配置 |
| CLI agent 命令 | 硬编码 3 | 不读取配置 |
| 配置文件 | 7 | 被忽略 |

### 修改后

所有模块统一从 `config.local.toml` 读取 `max_concurrent`：

| 模块 | 之后 | 说明 |
|------|------|------|
| Agent | 配置值 (7) | None 时读取配置 |
| 全局管理器 | 配置值 (7) | 初始化时读取配置 |
| CLI agent 命令 | 配置值 (7) | None 时读取配置 |
| Round 4 | 配置值 (7) | 使用全局管理器 |
| 对抗式验证 | 配置值 (7) | 使用全局管理器 |

---

## 修改内容

### 1. 全局并发管理器 (`src/core/llm/concurrency.py`)

```python
# 之前
_global_manager = LLMConcurrencyManager(max_concurrent=5)

# 之后
max_concurrent = llm_config.get("max_concurrent", 7)
_global_manager = LLMConcurrencyManager(max_concurrent=max_concurrent)
```

### 2. OpenCodeAgent (`src/layers/l3_analysis/engines/opencode_agent.py`)

```python
# 之前
def __init__(self, ..., max_concurrent: int = 2, ...):

# 之后
def __init__(self, ..., max_concurrent: int | None = None, ...):
    if max_concurrent is None:
        max_concurrent = llm_config.get("max_concurrent", 7)
```

### 3. CLI agent 命令 (`src/cli/main.py`)

```python
# 之前
@click.option("--max-concurrent", type=int, default=3, ...)

# 之后
@click.option("--max-concurrent", type=int, default=None, ...)
# None 时从配置读取
```

---

## 配置说明

用户只需在 `config.local.toml` 中配置一次：

```toml
[llm]
max_concurrent = 7  # 所有 LLM 模块统一使用此值
```

---

## 测试验证

```bash
# 全局管理器读取配置
assert manager.max_concurrent == 7  ✓

# Agent 默认读取配置
assert agent.max_concurrent == 7    ✓

# Agent 显式指定仍生效
assert agent2.max_concurrent == 3   ✓
```

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-03-09 13:45 | 完成 P5-05 LLM 并发配置统一化 |
