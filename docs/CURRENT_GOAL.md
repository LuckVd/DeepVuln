# 当前目标

> 单一焦点：本次会话关注的核心任务
---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | P4-04：AST Semantic Deduplication |
| **状态** | completed |
| **优先级** | P0 |
| **创建日期** | 2026-03-06 |
| **所属阶段** | Phase 4 - 裁决统一 |
| **模块层级** | L3 Analysis Layer |

---

## 目标概述

消除多个引擎或规则报告的"同一漏洞"。

**核心目标**：基于 AST + sink/source + callpath 语义进行漏洞去重，不能只用 line number 或 rule_id。

**解决问题**:
- 多引擎报告同一漏洞（Semgrep + CodeQL + AI Agent）
- 简单行号去重不准确（代码变动后失效）
- 缺乏语义级指纹机制

---

## 核心概念：FindingFingerprint

```python
@dataclass
class FindingFingerprint:
    file_path: str           # 代码文件
    function_name: str | None # AST函数节点
    sink: str                # 危险调用 (exec/eval/sql_query)
    source: str | None       # 用户输入 (request.body/query param)
    normalized_line: int     # 行号归一化
    vulnerability_type: str  # sql_injection/command_injection/xss/...
```

---

## 实现模块

### 1. 新建文件

`src/layers/l3_analysis/deduplication.py`

### 2. Fingerprint 生成函数

```python
def generate_fingerprint(finding: Finding) -> FindingFingerprint:
    # file_path: finding.location.file_path
    # function_name: finding.context.function_name (or None)
    # sink: finding.sink 或 finding.rule_id
    # source: finding.source
    # normalized_line: round(finding.location.start_line / 5) * 5
    # vulnerability_type: finding.category
```

### 3. 语义 Key

```python
def fingerprint_key(fp: FindingFingerprint) -> str:
    # key = file_path + function_name + sink + source + vulnerability_type
    # hash → sha1
```

### 4. Deduplication Engine

```python
class ASTSemanticDeduplicator:
    def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
        # 1. 建立 fingerprint map: dict[str, list[Finding]]
        # 2. 同 fingerprint → candidate duplicates
        # 3. 选择最佳 finding
```

### 5. Best Finding 选择

排序 key:
1. highest final_score
2. highest severity
3. highest confidence
4. engine priority (opencode_agent=3, codeql=2, semgrep=1)

---

## Pipeline 集成

修改 `src/pipeline/analyze_pipeline.py`:

```python
# 在 adjudication 之后
findings = adjudicate_findings(findings)
dedup_result = ASTSemanticDeduplicator().deduplicate_findings(findings)
findings = dedup_result.unique_findings

# metadata
scan_result.metadata["deduplication"] = {
    "total": dedup_result.total_findings,
    "unique": dedup_result.unique_findings,
    "removed": dedup_result.duplicates_removed,
}
```

---

## DeduplicationResult

```python
@dataclass
class DeduplicationResult:
    total_findings: int
    unique_findings: list[Finding]
    duplicates_removed: int
    duplicate_groups: list[dict]
```

---

## Metadata 保留

在被保留 finding 中增加:

```python
finding.metadata["deduplicated_from"] = [
    "semgrep.sql-injection",
    "codeql.sql-injection",
    "ai.sql-injection"
]
```

---

## 安全约束

**不能去重：**
- 不同 vulnerability_type
- 不同 file_path
- 不同 sink

例如：SQL Injection 和 Command Injection 必须保留。

---

## 单元测试

创建 `tests/unit/test_l3/test_deduplication.py`

测试用例:
- test_duplicate_same_sink
- test_duplicate_cross_engine
- test_duplicate_same_function
- test_duplicate_different_function
- test_select_highest_score
- test_metadata_preserved

**目标**: >= 60 tests

---

## 性能要求

- 算法复杂度: O(n)
- 实现方式: hash map grouping

---

## 示例

**输入:**
- Semgrep SQL injection, line 120
- CodeQL SQL injection, line 121
- AI agent SQL injection, line 119

**结果:**
- 1 finding
- metadata: `deduplicated_from: ["semgrep.sql-injection", "codeql.sql-injection", "ai.sql-injection"]`

---

## 验收标准

| 标准 | 指标 |
|------|------|
| 去重效果 | duplicates 减少 ≥ 40% |
| Pipeline | 集成完成 |
| Metadata | 统计信息完整 |
| 测试 | 60+ tests |
| 兼容性 | 所有现有 tests 通过 |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-03-06 | 开始 P4-04 AST Semantic Deduplication |
| 2026-03-06 01:45 | ✅ P4-04 完成 - 76 测试通过，Pipeline 集成完成 |
