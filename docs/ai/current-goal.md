# Current Goal

## Status

**阶段**: confirm_plan
**状态**: 待确认

---

## 目标概述

**优化扫描顺序：先去重，再对抗验证**

将去重阶段移到对抗性验证之前，减少 LLM API 调用量和扫描时间。

### 问题背景

当前扫描流程：
```
Scan → Verify (191) → Adversarial (191) → Deduplicate → 182
```

191 个漏洞都经过对抗性验证，然后才去重。这意味着：
- 大量重复漏洞浪费了 LLM 调用
- 对抗性验证是最耗时的阶段（单个漏洞可能需要多轮辩论）
- Token 使用量高

### 解决方案

**调整后的流程：**
```
Scan → Verify (191) → Deduplicate → Adversarial (~150) → Final Report
```

**关键优势：**
1. ✅ `final_score` 独立于对抗验证计算（基于 codeql/reachability/taint_tracking/attack_surface）
2. ✅ 去重逻辑主要依赖 `final_score`，不受影响
3. ✅ 对抗验证结果仍可正确附加到去重后的漏洞

---

## 设计方案

### 当前流程分析

**文件位置**: `src/cli/main.py`

```python
# Line 1570: Phase 4 - LLM 验证
if llm_verify:
    result["verified_findings"] = await round_four_executor(...)

# Line 1685: Phase 4.5 - 对抗性验证 (当前在去重之前)
if adversarial and result["verified_findings"] and llm_client:
    findings_to_verify = [
        v for v in result["verified_findings"]
        if v["finding"].severity.value in ["critical", "high", "medium"]
    ]
    adversarial_results = await verify_single_adversarial(findings_to_verify)

# Line 1830-1873: Backfill 验证/对抗结果到 findings

# Line 1935: 去重和裁定 (当前在对抗验证之后)
adjudicated_findings, adjudication_summary = adjudicate_findings(
    raw_findings,
    enable_deduplication=True,
)
```

### 新流程设计

```python
# Line 1570: Phase 4 - LLM 验证 (不变)
if llm_verify:
    result["verified_findings"] = await round_four_executor(...)

# ========== 新增：先去重 ==========
# Line 1685 (新位置): 去重和裁定 (移到这里)
raw_findings = [
    item["finding"] for item in result["all_findings"]
]
deduplicated_findings, dedup_summary = adjudicate_findings(
    raw_findings,
    validate=True,
    enable_deduplication=True,
)
# 更新 result["all_findings"] 为去重后的结果
result["all_findings"] = [
    {"source": "adjudicated", "finding": f}
    for f in deduplicated_findings
]
result["verified_findings"] = [
    {"source": "adjudicated", "finding": f}
    for f in deduplicated_findings
]  # 更新 verified_findings 为去重后的结果

# Line 1820 (新位置): Phase 4.5 - 对抗性验证 (移到去重之后)
if adversarial and result["verified_findings"] and llm_client:
    # 现在对去重后的 findings 进行对抗验证
    findings_to_verify = [
        v for v in result["verified_findings"]
        if v["finding"].severity.value in ["critical", "high", "medium"]
    ]
    # 数量已减少：191 → ~150
```

### 核心变更

| 变更 | 当前 | 新位置 |
|------|------|--------|
| Adjudication/Deduplication | Line 1935 | Line 1685 (移到 Phase 4.5 之前) |
| Phase 4.5 Adversarial | Line 1685 | Line 1820 (移到去重之后) |
| Backfill verification | Line 1830 | 保持不变 (去重后仍需回填) |
| Backfill adversarial | Line 1854 | 保持不变 |

---

## 范围 (Scope)

### 包含

1. **重新排序扫描阶段**
   - 将 `adjudicate_findings()` 移到 `Phase 4.5` 之前
   - 更新 `result["verified_findings"]` 为去重后的结果

2. **更新对抗验证输入**
   - 对抗验证现在接收去重后的 findings
   - 严重度过滤逻辑保持不变

3. **保持元数据回填**
   - 验证结果回填 (Line 1830-1845)
   - 对抗结果回填 (Line 1854-1873)

4. **更新日志输出**
   - 反映新的阶段顺序
   - 显示去重前后的数量变化

### 不包含 (Out of Scope)

1. **去重算法本身的修改** - ClusterBasedDeduplicator 保持不变
2. **对抗验证逻辑的修改** - EnhancedAdversarialVerification 保持不变
3. **配置选项** - 不添加 `--legacy-order` 向后兼容选项

---

## 验收标准

### 功能验收

- [ ] 去重在对抗验证之前执行
- [ ] 对抗验证仅对去重后的漏洞进行
- [ ] 去重统计正确显示 (191 → ~150 → 对抗验证)
- [ ] 最终报告中的漏洞数量正确

### 性能验收

| 指标 | 目标值 |
|------|--------|
| 对抗验证数量 | 减少约 20-30% |
| API 调用减少 | > 20% |
| Token 节省 | > 25% |

### 质量验收

- [ ] 现有测试通过
- [ ] 使用相同输入，最终漏洞列表与当前流程一致（顺序可能不同）
- [ ] 元数据 (exploitability, adversarial_verdict) 正确附加

---

## 实现步骤

### Step 1: 重新排序扫描阶段 (main.py)

**文件**: `src/cli/main.py`

**操作**:
1. 将 `adjudicate_findings()` 调用块从 Line 1935 移到 Line 1685
2. 更新 `result["verified_findings"]` 为去重后的结果
3. 将 Phase 4.5 对抗验证块移到去重之后

**变更**:
```python
# 在 Phase 4 结束后 (Line 1682)，添加去重阶段
# P5-01e E: Deduplication and Unified Adjudication
if result["all_findings"]:
    try:
        from src.layers.l3_analysis.adjudication import adjudicate_findings

        raw_findings = [
            item["finding"] if isinstance(item, dict) and "finding" in item else item
            for item in result["all_findings"]
        ]

        # Apply deduplication and adjudication
        adjudicated_findings, adjudication_summary = adjudicate_findings(
            raw_findings,
            validate=True,
            strict_consistency=False,
            enable_deduplication=True,
        )

        # Update both all_findings and verified_findings
        dedup_wrapped = [
            {"source": "adjudicated", "finding": f}
            for f in adjudicated_findings
        ]
        result["all_findings"] = dedup_wrapped
        result["verified_findings"] = dedup_wrapped  # 关键：更新为去重后的结果

        dup_count = adjudication_summary.deduplication.get("removed_count", 0)
        logger.info(f"Cluster deduplication complete: {len(raw_findings)} -> {len(adjudicated_findings)} findings")

    except Exception as e:
        logger.warning(f"Adjudication failed: {e}")
        result["adjudication"] = {"error": str(e)}

# Phase 4.5: Adversarial Verification (现在使用去重后的 findings)
if adversarial and result["verified_findings"] and llm_client:
    # 严重度过滤逻辑保持不变，但输入数量已减少
    findings_to_verify = [
        v for v in result["verified_findings"]
        if not (v["finding"].metadata or {}).get("is_suspicious", False)
        and v["finding"].severity.value in ["critical", "high", "medium"]
    ]
```

---

### Step 2: 移除旧的去重调用位置

**文件**: `src/cli/main.py`

**操作**: 删除或注释掉 Line 1935-1981 的旧去重代码块

**原因**: 去重已在 Step 1 中移动到 Phase 4.5 之前

---

### Step 3: 更新日志输出

**文件**: `src/cli/main.py`

**操作**: 更新阶段标题和日志以反映新的顺序

```python
# Line 1570 附近
console.print("\n[bold cyan]Phase 4: Exploitability Verification (Parallel)[/]")

# Line 1685 附近 (新增)
console.print("\n[bold cyan]Phase 4.25: Deduplication and Adjudication[/]")
console.print(f"  Cluster deduplication: {len(raw_findings)} -> {len(adjudicated_findings)} findings")

# Line 1820 附近
console.print("\n[bold cyan]Phase 4.5: Adversarial Verification (Parallel)[/]")
console.print(f"  Verifying {len(findings_to_verify)} deduplicated findings")
```

---

### Step 4: 验证元数据回填

**文件**: `src/cli/main.py`

**操作**: 确认 backfill 逻辑 (Line 1830-1873) 在新顺序下仍然正常工作

**关键点**: 去重后的 findings 对象是同一个引用，所以 backfill 仍然有效

---

## 测试计划

### 单元测试

**文件**: `tests/unit/test_l3/test_scan_order.py` (新建)

**测试用例**:
```python
def test_deduplication_happens_before_adversarial():
    """验证去重在对抗验证之前执行"""
    # Mock verified_findings with duplicates
    # Run scan flow
    # Assert deduplication called before adversarial

def test_adversarial_receives_deduplicated_findings():
    """验证对抗验证接收去重后的 findings"""
    # Create 191 findings with known duplicates
    # After deduplication: 150 unique findings
    # Assert adversarial called with 150, not 191

def test_metadata_backfill_after_reorder():
    """验证元数据回填在新顺序下正常工作"""
    # Run full flow with reordering
    # Assert exploitability and adversarial_verdict correctly attached
```

### 集成测试

**文件**: `tests/integration/test_scan_order_optimization.py` (新建)

**测试场景**:
1. 使用 `java-test-app-obf` 进行完整扫描
2. 验证去重数量与之前一致 (191 → 182)
3. 验证对抗验证数量减少 (~150 vs 191)
4. 验证最终报告质量一致

---

## 风险与依赖

### 技术风险

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| 去重时缺少 adversarial 元数据 | 低 | final_score 独立计算，足够用于去重 |
| 严重度过滤基于去重后的结果 | 低 | 过滤逻辑保持不变，只是输入减少 |
| 元数据回填失效 | 低 | findings 是同一引用，回填仍然有效 |

### 技术依赖

| 依赖 | 说明 | 状态 |
|------|------|------|
| ClusterBasedDeduplicator | P6-17 已完成 | ✅ |
| EnhancedAdversarialVerification | 已实现 | ✅ |
| adjudicate_findings() | 已实现 | ✅ |

---

## 预期效果

| 指标 | 当前值 | 目标值 | 提升 |
|------|--------|--------|------|
| 对抗验证数量 | 191 | ~150 | ~25% |
| API 调用次数 | ~5000 | ~3750 | ~25% |
| Token 使用量 | 2.09M | ~1.5M | ~30% |
| 扫描时间 | ~4 小时 | ~3 小时 | ~25% |

---

## 实现文件

### 修改文件

| 文件 | 变更类型 | 变更行数估算 |
|------|----------|--------------|
| `src/cli/main.py` | 重构代码块 | ~100 行 |

### 新增文件

| 文件 | 说明 |
|------|------|
| `tests/unit/test_l3/test_scan_order.py` | 单元测试 |
| `tests/integration/test_scan_order_optimization.py` | 集成测试 |

---

## 开放问题

**请在确认前回答以下问题：**

1. 是否接受去重时无法参考 `adversarial_verdict` 的限制？
   - 影响：去重仅基于 `final_score` 和 `exploitability`（Phase 4 验证结果）
   - 缓解：`final_score` 已包含多个维度，足够准确

2. 是否需要添加配置选项来控制顺序？
   - 例如 `--scan-order: legacy|optimized`
   - 建议：不需要，直接使用优化后的顺序

3. 如果去重后某些高价值漏洞被合并，是否需要特殊处理？
   - 例如：保留被合并漏洞的 `adversarial_verdict` 作为参考
   - 建议：不需要，去重已保留 `final_score` 最高的版本
