# P6-03 详细执行规划：证据强度字段引入

> 创建时间: 2026-03-18
> 更新时间: 2026-03-18
> 状态: 规划已修正，待执行

---

## 1. 任务概述

### 1.1 目标

实现 `evidence_strength` 字段，集成防幻觉规则到验证流程，提升漏洞报告的可信度。

### 1.2 验收标准

- [ ] `EvidenceStrength` 枚举定义（strong/medium/weak/speculative）
- [ ] Finding 模型新增 `evidence_strength` 字段
- [ ] 去重后自动计算证据强度（利用 `related_engines` 信息）
- [ ] [Suspicious] 类结果强制标记为 speculative
- [ ] 防幻觉验证规则集成到验证流程
- [ ] 单元测试覆盖

### 1.3 源材料

| 来源 | 路径 | 核心内容 |
|------|------|---------|
| 防幻觉规则 | `/opt/AI/code-audit/references/core/anti_hallucination.md` | 5 条核心规则 + 验证清单 |
| 覆盖率矩阵 | `/opt/AI/code-audit/references/checklists/coverage_matrix.md` | D1-D10 维度 + 覆盖标准 |

---

## 2. 工作流分析

### 2.1 当前项目工作流

```
┌─────────────────────────────────────────────────────────────────┐
│                    DeepVuln 扫描工作流                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. 引擎扫描层 (engines/)                                        │
│     ├── SemgrepEngine.scan() → Finding[]                        │
│     ├── CodeQLEngine.scan() → Finding[]                         │
│     └── OpenCodeAgent.scan() → Finding[]                        │
│                                                                 │
│  2. 裁决层 (adjudication.py)                                     │
│     ├── apply_exploitability_override() → 按引擎设置初始状态     │
│     ├── ASTDeduplicator.deduplicate() → 设置 related_engines    │
│     │   ↑ 此时有多引擎信息                                       │
│     ├── AdjudicationConsistencyChecker → 一致性检查              │
│     └── apply_report_status() → 最终报告状态                     │
│                                                                 │
│  3. 输出层                                                       │
│     └── 报告生成                                                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 集成点选择

**选择：裁决层 - 去重之后、一致性检查之前**

```
adjudicate_findings():
    ├── apply_exploitability_override()     # 按引擎设置初始状态
    ├── ASTDeduplicator.deduplicate()       # 设置 related_engines
    ├── 【calculate_evidence_strength()】   # ← 新增：计算证据强度
    │   - 此时有 related_engines 信息
    │   - 此时有 duplicate_count 信息
    │   - 此时可访问源代码验证
    ├── AdjudicationConsistencyChecker      # 一致性检查
    └── apply_report_status()               # 最终报告状态
```

**选择理由**：

| 因素 | 说明 |
|------|------|
| 多引擎信息 | 去重后 `related_engines` 已设置，可判断多引擎印证 |
| 去重信息 | `duplicate_count` 可用，表示发现被合并次数 |
| 统一处理 | 所有引擎的 Finding 都经过此流程 |
| 性能影响 | 不影响扫描流程，只在裁决阶段额外计算 |

---

## 3. 技术设计

### 3.1 EvidenceStrength 枚举

```python
class EvidenceStrength(str, Enum):
    """
    P6-03: Evidence strength for vulnerability findings.

    Based on code-audit anti-hallucination rules and coverage matrix.
    Indicates how well the finding is supported by verifiable evidence.
    """

    STRONG = "strong"
    """
    强证据：
    - 多引擎交叉验证（len(related_engines) >= 2）
    - 或 duplicate_count >= 2（被多次发现并合并）
    - 或有完整的防幻觉验证通过 + confidence >= 0.9
    """

    MEDIUM = "medium"
    """
    中等证据：
    - 单引擎检出但置信度高（confidence >= 0.8）
    - 或 duplicate_count == 1（被合并过一次）
    - 核心验证通过
    """

    WEAK = "weak"
    """
    弱证据：
    - 单引擎检出，置信度中等（0.5 <= confidence < 0.8）
    - 无跨引擎印证
    - 需要人工验证
    """

    SPECULATIVE = "speculative"
    """
    推测性证据：
    - FindingType.SUSPICIOUS 类型
    - 或 confidence < 0.5
    - 或防幻觉验证失败
    - 可能是误报，需要重点关注
    """
```

### 3.2 防幻觉验证模型

```python
class HallucinationCheckResult(BaseModel):
    """
    防幻觉检查结果

    基于 code-audit 的 anti_hallucination.md 规则
    """

    file_exists: bool = Field(..., description="文件存在性验证（规则1）")
    code_authentic: bool = Field(default=True, description="代码真实性验证（规则2）")
    line_number_valid: bool = Field(..., description="行号有效性验证（规则3）")
    tech_stack_match: bool = Field(default=True, description="技术栈一致性验证（规则4）")

    # 详细信息
    checked_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    file_path: str = Field(..., description="被检查的文件路径")
    actual_line_count: int | None = Field(default=None, description="文件实际行数")
    reported_line: int | None = Field(default=None, description="报告的行号")

    @property
    def all_passed(self) -> bool:
        """所有验证是否通过"""
        return all([
            self.file_exists,
            self.code_authentic,
            self.line_number_valid,
            self.tech_stack_match,
        ])

    @property
    def has_failure(self) -> bool:
        """是否有验证失败"""
        return not self.all_passed

    def to_dict(self) -> dict[str, Any]:
        return {
            "all_passed": self.all_passed,
            "file_exists": self.file_exists,
            "line_number_valid": self.line_number_valid,
            "tech_stack_match": self.tech_stack_match,
        }
```

### 3.3 Finding 模型扩展

```python
# 在 Finding 类中新增字段（models.py）

class Finding(BaseModel):
    # ... 现有字段 ...

    # P6-03: Evidence strength
    evidence_strength: EvidenceStrength | None = Field(
        default=None,
        description="Evidence strength based on anti-hallucination rules",
    )
    evidence_details: dict[str, Any] | None = Field(
        default=None,
        description="Detailed evidence strength calculation breakdown",
    )
    hallucination_check: HallucinationCheckResult | None = Field(
        default=None,
        description="Anti-hallucination validation result",
    )
```

### 3.4 证据强度判定逻辑

```python
# 新文件：evidence_calculator.py

def calculate_evidence_strength(
    findings: list[Finding],
    source_path: Path,
) -> tuple[list[Finding], dict[str, int]]:
    """
    计算所有 Finding 的证据强度

    Args:
        findings: 去重后的 Finding 列表（related_engines 已设置）
        source_path: 源代码路径（用于文件验证）

    Returns:
        (updated_findings, strength_counts)
    """
    counts = {"strong": 0, "medium": 0, "weak": 0, "speculative": 0}

    for finding in findings:
        # 1. 防幻觉验证
        hallucination_check = _verify_finding(finding, source_path)
        finding.hallucination_check = hallucination_check

        # 2. 强制 speculative 条件
        if finding.type == FindingType.SUSPICIOUS:
            finding.evidence_strength = EvidenceStrength.SPECULATIVE
            finding.evidence_details = {"reason": "suspicious_type"}
            counts["speculative"] += 1
            continue

        if finding.confidence < 0.5:
            finding.evidence_strength = EvidenceStrength.SPECULATIVE
            finding.evidence_details = {"reason": "low_confidence", "confidence": finding.confidence}
            counts["speculative"] += 1
            continue

        if hallucination_check.has_failure:
            finding.evidence_strength = EvidenceStrength.SPECULATIVE
            finding.evidence_details = {"reason": "hallucination_check_failed", "check": hallucination_check.to_dict()}
            counts["speculative"] += 1
            continue

        # 3. 强证据条件
        related_engines = getattr(finding, "related_engines", []) or []
        duplicate_count = getattr(finding, "duplicate_count", 0) or 0

        if len(related_engines) >= 2:
            finding.evidence_strength = EvidenceStrength.STRONG
            finding.evidence_details = {"reason": "multi_engine", "engines": related_engines}
            counts["strong"] += 1
            continue

        if duplicate_count >= 2:
            finding.evidence_strength = EvidenceStrength.STRONG
            finding.evidence_details = {"reason": "multiple_detections", "count": duplicate_count}
            counts["strong"] += 1
            continue

        if finding.confidence >= 0.9 and hallucination_check.all_passed:
            finding.evidence_strength = EvidenceStrength.STRONG
            finding.evidence_details = {"reason": "high_confidence_verified", "confidence": finding.confidence}
            counts["strong"] += 1
            continue

        # 4. 中等证据条件
        if finding.confidence >= 0.8:
            finding.evidence_strength = EvidenceStrength.MEDIUM
            finding.evidence_details = {"reason": "high_confidence", "confidence": finding.confidence}
            counts["medium"] += 1
            continue

        if duplicate_count >= 1:
            finding.evidence_strength = EvidenceStrength.MEDIUM
            finding.evidence_details = {"reason": "merged_finding", "count": duplicate_count}
            counts["medium"] += 1
            continue

        # 5. 默认：弱证据
        finding.evidence_strength = EvidenceStrength.WEAK
        finding.evidence_details = {"reason": "default", "confidence": finding.confidence}
        counts["weak"] += 1

    return findings, counts


def _verify_finding(finding: Finding, source_path: Path) -> HallucinationCheckResult:
    """
    执行防幻觉验证

    基于code-audit anti_hallucination.md规则:
    - 规则1: 文件存在性验证
    - 规则3: 行号有效性验证
    """
    file_path = finding.location.file
    full_path = source_path / file_path

    # 规则1: 文件存在性
    file_exists = full_path.exists()

    # 规则3: 行号有效性
    line_number_valid = True
    actual_line_count = None

    if file_exists:
        try:
            content = full_path.read_text(encoding="utf-8", errors="replace")
            actual_line_count = len(content.splitlines())
            reported_line = finding.location.line
            line_number_valid = 1 <= reported_line <= actual_line_count
        except Exception:
            line_number_valid = False

    return HallucinationCheckResult(
        file_exists=file_exists,
        line_number_valid=line_number_valid,
        file_path=file_path,
        actual_line_count=actual_line_count,
        reported_line=finding.location.line,
    )
```

---

## 4. 执行步骤

### Step 1: 定义数据模型 (models.py)

**文件**: `src/layers/l3_analysis/models.py`

**任务**:
1. 添加 `EvidenceStrength` 枚举
2. 添加 `HallucinationCheckResult` 模型
3. 在 `Finding` 类添加 `evidence_strength`、`evidence_details`、`hallucination_check` 字段

**预计工作量**: ~60 行代码

---

### Step 2: 实现证据强度计算器 (evidence_calculator.py)

**文件**: `src/layers/l3_analysis/evidence_calculator.py` (新建)

**任务**:
1. 实现 `calculate_evidence_strength()` 函数
2. 实现 `_verify_finding()` 防幻觉验证函数
3. 实现证据强度判定逻辑

**预计工作量**: ~150 行代码

---

### Step 3: 集成到裁决流程 (adjudication.py)

**文件**: `src/layers/l3_analysis/adjudication.py`

**任务**:
1. 在 `adjudicate_findings()` 中，去重后、一致性检查前调用 `calculate_evidence_strength()`
2. 更新 `AdjudicationSummary` 添加 `evidence_strength` 统计字段

**修改点**:
```python
def adjudicate_findings(...) -> tuple[list[Any], AdjudicationSummary]:
    # ... 现有代码 ...

    # P4-04: Semantic Deduplication
    if enable_deduplication:
        deduplicator = ASTDeduplicator()
        dedup_result = deduplicator.deduplicate(findings)
        findings = dedup_result.unique_findings
        summary.deduplication = dedup_result.to_dict()

    # P6-03: Calculate Evidence Strength
    # 在去重后、一致性检查前计算证据强度
    from src.layers.l3_analysis.evidence_calculator import calculate_evidence_strength
    findings, strength_counts = calculate_evidence_strength(findings, source_path)
    summary.evidence_strength = strength_counts  # 新增字段

    # P4-03: Global Adjudication Consistency Check
    # ... 后续代码不变 ...
```

**预计工作量**: ~30 行代码

---

### Step 4: 更新报告输出 (reporting.py)

**文件**: `src/layers/l3_analysis/reporting.py`

**任务**:
1. 在报告生成时显示 `evidence_strength`
2. 添加证据强度统计信息

**预计工作量**: ~40 行代码

---

### Step 5: 编写单元测试

**文件**: `tests/unit/test_l3/test_evidence_calculator.py` (新建)

**测试用例**:
1. `test_suspicious_always_speculative` - Suspicious 类型强制 speculative
2. `test_low_confidence_speculative` - confidence < 0.5 强制 speculative
3. `test_hallucination_file_not_exists` - 文件不存在强制 speculative
4. `test_hallucination_line_out_of_range` - 行号超出范围强制 speculative
5. `test_multi_engine_strong` - related_engines >= 2 为 strong
6. `test_multiple_detections_strong` - duplicate_count >= 2 为 strong
7. `test_high_confidence_medium` - confidence >= 0.8 为 medium
8. `test_moderate_confidence_weak` - 默认为 weak

**预计工作量**: ~120 行代码

---

## 5. 文件变更清单

| 文件 | 操作 | 变更量 |
|------|------|--------|
| `src/layers/l3_analysis/models.py` | 修改 | +60 行 |
| `src/layers/l3_analysis/evidence_calculator.py` | 新建 | +150 行 |
| `src/layers/l3_analysis/adjudication.py` | 修改 | +30 行 |
| `src/layers/l3_analysis/reporting.py` | 修改 | +40 行 |
| `tests/unit/test_l3/test_evidence_calculator.py` | 新建 | +120 行 |

**总计**: ~400 行代码

---

## 6. 依赖关系

```
Step 1 (models.py)
    ↓ 定义 EvidenceStrength, HallucinationCheckResult, Finding 新字段
Step 2 (evidence_calculator.py) ← 依赖 Step 1 的模型定义
    ↓ 实现 calculate_evidence_strength()
Step 3 (adjudication.py) ← 调用 Step 2 的函数
    ↓ 在去重后计算证据强度
Step 4 (reporting.py) ← 使用 Step 1 的字段
    ↓ 显示证据强度
Step 5 (tests) ← 验证所有步骤
```

---

## 7. 与现有字段的关系

| 字段 | 用途 | 时机 | 来源 |
|------|------|------|------|
| `confidence` | 引擎级置信度 | 引擎扫描时 | 各引擎 |
| `related_engines` | 跨引擎印证 | 去重时 | Deduplicator |
| `duplicate_count` | 合并次数 | 去重时 | Deduplicator |
| **`evidence_strength`** | **证据强度** | **去重后** | **EvidenceCalculator** |
| `exploitability` | 可利用性评估 | Round 4 | LLM 验证 |
| `final_status` | 裁决结果 | 裁决层 | Adjudicator |
| `report_status` | 输出状态 | 报告层 | Reporting |

**evidence_strength 与现有字段的关系**:
- `confidence` → 作为证据强度计算的输入
- `related_engines` → 多引擎印证判断
- `duplicate_count` → 多次检出判断
- 与 `exploitability` 互补，不冲突
- 最终影响 `report_status` 的可信度展示

---

## 8. 风险与缓解

| 风险 | 影响 | 缓解措施 |
|------|------|---------|
| 文件验证影响性能 | 低 | 只在裁决阶段验证，不阻塞扫描 |
| 防幻觉规则过于严格 | 中 | 提供配置项允许放宽验证 |
| 与现有字段语义冲突 | 低 | 明确定义各字段职责边界 |

---

## 9. 验收检查清单

- [ ] EvidenceStrength 枚举定义正确
- [ ] HallucinationCheckResult 模型可用
- [ ] Finding 模型扩展完成
- [ ] evidence_calculator.py 实现完整
- [ ] adjudication.py 集成完成
- [ ] reporting.py 显示证据强度
- [ ] 单元测试全部通过
- [ ] 现有功能无回归

---

## 10. 时间估算

| 步骤 | 预计时间 |
|------|---------|
| Step 1: 数据模型 | 30 分钟 |
| Step 2: 证据强度计算器 | 60 分钟 |
| Step 3: 裁决流程集成 | 30 分钟 |
| Step 4: 报告输出 | 30 分钟 |
| Step 5: 单元测试 | 50 分钟 |
| **总计** | **~3.5 小时** |
