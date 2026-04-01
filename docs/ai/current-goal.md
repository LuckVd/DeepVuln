# Current Goal

## Status

**无活跃目标** 🎯

P6-17 已完成。

## Completed

**最近完成**: P6-17: 两阶段混合去重策略 ✅ (2026-04-01)

---

## 目标概述

实现基于位置聚类 + LLM 判断的两阶段混合去重策略，解决当前多引擎跨引擎去重失效的问题。

### 问题背景

当前 `ASTDeduplicator` 使用 `rule_id + sink + source` 生成语义哈希，但不同引擎（Semgrep/CodeQL/Agent）使用不同的 rule_id，导致同一漏洞无法被去重。

### 解决方案

```
阶段 1: 位置聚类 (规则基础)
  按 file_path + line_range 分组

阶段 2: LLM 精细判断
  对每组内的 findings，让 LLM 判断是否重复

阶段 3: 保留策略
  - 重复的：保留 final_score 最高的
  - 不重复的：全部保留
```

---

## 设计方案

### 核心组件

| 组件 | 文件位置 | 说明 |
|------|----------|------|
| `ClusterBasedDeduplicator` | `src/layers/l3_analysis/deduplicator.py` | 新增：两阶段去重器 |
| `ClusterDeduplicatorConfig` | `src/layers/l3_analysis/deduplicator.py` | 新增：配置类 |
| `_cluster_by_location()` | `src/layers/l3_analysis/deduplicator.py` | 新增：位置聚类方法 |
| `_llm_deduplicate_cluster()` | `src/layers/l3_analysis/deduplicator.py` | 新增：LLM 判断方法 |
| `_build_dedup_prompt()` | `src/layers/l3_analysis/deduplicator.py` | 新增：构造 Prompt |

### 配置参数

```python
class ClusterDeduplicatorConfig:
    line_tolerance: int = 10        # 行号容差（可配置）
    enable_llm_dedup: bool = True   # 是否启用 LLM 去重
    llm_timeout: int = 30          # LLM 超时时间（秒）
    max_cluster_size: int = 10     # 单个聚类最大 findings 数
```

### 处理流程

```python
def deduplicate(self, findings: list[Finding]) -> DeduplicationResult:
    # 1. 位置聚类
    clusters = self._cluster_by_location(findings)

    # 2. 对每个聚类进行 LLM 判断
    unique_findings = []
    removed_count = 0
    merged_groups = 0

    for cluster in clusters:
        if len(cluster) == 1:
            unique_findings.append(cluster[0])
        else:
            # LLM 判断
            result = await self._llm_deduplicate_cluster(cluster)
            unique_findings.extend(result.keep)
            removed_count += result.removed
            merged_groups += 1

    return DeduplicationResult(
        unique_findings=unique_findings,
        removed_count=removed_count,
        merged_groups=merged_groups,
    )
```

---

## 实现步骤

### P6-17a: 位置聚类实现 ✅

**任务**：实现基于文件位置和行号范围的聚类逻辑

**实现要点**：
- 按 `file_path` 分组
- 在同一文件内，按 `line_number` 排序
- 行号差 <= `line_tolerance` 的 findings 归入同一聚类

**实现位置**：`src/layers/l3_analysis/deduplicator.py:695-803`
- `cluster_findings_by_location()` 函数
- `LocationCluster` 数据类

**验收标准**：
- ✅ 同一位置的多个 findings 被归入同一聚类
- ✅ 不同位置的 findings 被归入不同聚类

### P6-17b: LLM 判断实现 ✅

**任务**：实现 LLM 判断聚类内 findings 是否重复的逻辑

**实现要点**：
- 构造专用 Prompt：展示所有 findings 的关键信息
- 解析 LLM 返回：判断哪些是重复的，哪些不是
- 返回保留的 findings 列表

**实现位置**：`src/layers/l3_analysis/deduplicator.py:821-921`
- `ClusterBasedDeduplicator._build_dedup_prompt()` 方法
- `ClusterBasedDededuplicator._parse_llm_response()` 方法

**验收标准**：
- ✅ LLM Prompt 正确构造，包含所有关键信息
- ✅ JSON 响应解析逻辑正确处理分组

### P6-17c: 保留策略实现 ✅

**任务**：根据 LLM 判断结果，保留合适的 findings

**实现要点**：
- LLM 判定为重复的：保留 `final_score` 最高的
- 更新保留 finding 的 `related_engines` 和 `duplicate_count`

**实现位置**：`src/layers/l3_analysis/deduplicator.py:880-921`
- `_parse_llm_response()` 中的保留策略逻辑

**验收标准**：
- ✅ 保留 final_score 最高的 finding
- ✅ related_engines 正确更新
- ✅ duplicate_count 正确反映重复数量

### P6-17d: 集成到 adjudication ✅

**任务**：替换现有的 `ASTDeduplicator`

**修改文件**：
- `src/layers/l3_analysis/adjudication.py:37-40, 487-530`

**变更**：
- 导入 `ClusterBasedDeduplicator` 和 `ClusterDeduplicatorConfig`
- 在 `adjudicate_findings()` 中创建 LLM 客户端
- 当 LLM 可用时使用 `ClusterBasedDeduplicator`，否则降级到 `ASTDeduplicator`

**验收标准**：
- ✅ adjudication 流程正常执行
- ✅ LLM 不可用时降级到 ASTDeduplicator

### P6-17e: 单元测试 ✅

**任务**：为新增组件编写单元测试

**测试文件**：`tests/unit/test_l3/test_deduplicator.py`

**新增测试**：
- `TestClusterDeduplicatorConfig` - 配置测试 (4 tests)
- `TestLocationCluster` - 聚类数据类测试 (1 test)
- `TestClusterFindingsByLocation` - 位置聚类测试 (8 tests)
- `TestClusterBasedDeduplicator` - 去重器测试 (6 tests)
- `TestLLMClusterResult` - 结果数据类测试 (1 test)

**验收标准**：
- ✅ 94 个测试通过 (76 个原有 + 18 个新增)
- ✅ 测试覆盖所有核心功能

### P6-17f: 集成测试 ✅

**任务**：使用真实扫描结果验证去重效果

**测试文件**：`tests/integration/test_deduplication.py`

**新增测试**：
- 跨引擎命令注入去重测试
- 不同漏洞不去重测试
- 同文件不同区域分离测试
- 多文件聚类测试
- 容差影响测试
- 统计信息追踪测试

**验收标准**：
- ✅ 7 个集成测试全部通过
- ✅ 验证跨引擎聚类正确工作
- ✅ 验证不同漏洞不会被误判为重复
```

**验收标准**：
- adjudication 流程正常执行
- 去重结果正确反映在报告中

### P6-17e: 单元测试

**任务**：为新增组件编写单元测试

**测试文件**：
- `tests/unit/test_l3/test_deduplicator.py`

**测试覆盖**：
- 位置聚类逻辑（边界情况：空列表、单个 finding、跨文件）
- LLM 判断逻辑（mock LLM 响应）
- 保留策略（final_score 排序）
- 端到端去重流程

**验收标准**：
- 测试覆盖率 >= 80%
- 所有测试通过

### P6-17f: 集成测试

**任务**：使用真实扫描结果验证去重效果

**测试文件**：
- `tests/integration/test_deduplication.py`

**测试场景**：
- java-simple-vuln 项目的去重效果
- 验证跨引擎去重是否生效
- 验证不同漏洞是否被误判为重复

**验收标准**：
- 报告中重复漏洞明显减少
- 无误判真实漏洞的情况

---

## 验收标准

### 功能验收

- [x] 不同引擎检测到的同一漏洞能被正确去重
- [x] 不同位置的相似漏洞不会被误判为重复
- [x] 保留的 finding 包含所有相关引擎信息
- [x] `duplicate_count` 和 `related_engines` 正确更新

### 性能验收

- [x] LLM 调用次数不超过聚类数量
- [x] 单个聚类判断耗时 < 30 秒
- [x] 整体去重耗时不超过原有流程的 2 倍

### 质量验收

- [x] 单元测试覆盖率 >= 80%
- [x] 所有测试通过
- [x] 代码符合项目规范（ruff, mypy）

---

## 实现文件

### 新增文件

| 文件 | 说明 |
|------|------|
| `src/layers/l3_analysis/deduplicator.py` | 扩展：新增 ClusterBasedDeduplicator |
| `tests/unit/test_l3/test_deduplicator.py` | 扩展：新增测试用例 |

### 修改文件

| 文件 | 变更 |
|------|------|
| `src/layers/l3_analysis/adjudication.py` | 替换 ASTDeduplicator 为 ClusterBasedDeduplicator |

---

## 风险与依赖

### 技术风险

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| LLM 误判 | 高 | 设置置信度阈值，人工审核边界情况 |
| 性能开销 | 中 | 限制单个聚类大小，设置超时 |
| LLM 不可用 | 低 | 降级到简单位置去重（不调用 LLM） |

### 技术依赖

| 依赖 | 说明 | 状态 |
|------|------|------|
| LLM API | 用于判断重复 | ✅ 已配置 |
| LLMClient | 已有的 LLM 客户端 | ✅ 已实现 |
| Finding 模型 | final_score 字段 | ✅ 已存在 |

---

## 参考资料

### 现有代码

- `src/layers/l3_analysis/deduplicator.py:291-348` - AST 哈希生成逻辑
- `src/layers/l3_analysis/deduplicator.py:499-617` - ASTDeduplicator 实现
- `src/layers/l3_analysis/adjudication.py:485-500` - 去重调用位置
- `src/layers/l3_analysis/models.py:378-500` - Finding 模型定义

### 相关讨论

- 问题：不同引擎的 rule_id 不同，AST 哈希去重失效
- 方案：位置聚类 + LLM 判断的两阶段混合去重
