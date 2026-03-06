# 当前目标

> 单一焦点：本次会话关注的核心任务
---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | P5-01a：整合 CodeQL 数据流结果 |
| **状态** | completed |
| **优先级** | P0 |
| **创建日期** | 2026-03-06 |
| **所属阶段** | Phase 5 - 精度深化 |
| **模块层级** | L3 Analysis Layer |
| **依赖** | P4-05 |
| **父任务** | P5-01：可利用性评估增强 |

---

## 问题背景

当前 Phase 4 可利用性评估与 CodeQL 数据流分析脱节：

| 问题 | 现状 | 影响 |
|------|------|------|
| CodeQL 数据流 | Round 2 运行，但 Phase 4 不使用 | 浪费深度分析能力 |
| 可利用性判断 | 只用正则模式匹配用户输入 | 漏报大量真实可利用漏洞 |
| 数据流信息丢失 | source/sink/path 未传递 | 无法利用精确的污点分析结果 |

**实测结果**：OWASP Juice Shop 扫描中，100% 漏洞被判定为 "not_exploitable"，但 CodeQL 已识别出完整的污点路径。

---

## 核心目标

**将 Round 2 的 CodeQL 数据流结果传递到 Phase 4 可利用性评估。**

---

## CodeQL 提供的关键信息

```python
class CodeQLDataFlowResult:
    source: TaintSource       # 污点源（用户输入位置）
    sink: TaintSink           # 污点汇聚点（漏洞位置）
    path: list[PathElement]   # 完整的数据流路径
    sanitizers: list[Sanitizer]  # 检测到的净化器
```

---

## 实现方案

### 1. 修改数据流

```
L3 Round 2 (CodeQL)
        │
        ▼ codeql_results: list[CodeQLResult]
L3 Round 4 (Exploitability)  ←── 新增参数
        │
        ▼ 使用 CodeQL 的 source/sink/path 判断可利用性
```

### 2. 修改 RoundFourExecutor

**文件**: `src/layers/l3_analysis/rounds/round_four.py`

```python
class RoundFourExecutor:
    def __init__(
        self,
        source_path: Path,
        context_builder: ContextBuilder | None = None,
        llm_client: LLMClientProtocol | None = None,
        enable_llm_assessment: bool = True,
        attack_surface_report: AttackSurfaceReport | None = None,
        codeql_results: list[CodeQLResult] | None = None,  # 新增
    ):
        self._codeql_results = codeql_results
        self._codeql_index = self._build_codeql_index(codeql_results)

    def _build_codeql_index(self, results) -> dict[str, CodeQLResult]:
        """按 file:line 索引 CodeQL 结果"""
        index = {}
        for r in results or []:
            key = f"{r.location.file}:{r.location.line}"
            index[key] = r
        return index

    def _get_codeql_dataflow(self, finding: Finding) -> CodeQLResult | None:
        """获取该漏洞的 CodeQL 数据流信息"""
        key = f"{finding.location.file}:{finding.location.line_start}"
        return self._codeql_index.get(key)
```

### 3. 修改可利用性判断逻辑

**文件**: `src/layers/l3_analysis/rounds/round_four.py`

```python
def _assess_exploitability(
    self,
    call_chain: CallChainInfo | None,
    data_flow: list[DataFlowMarker],
    finding: Finding,
) -> tuple[ExploitabilityStatus, float, str]:
    # 新增：优先使用 CodeQL 数据流结果
    codeql_flow = self._get_codeql_dataflow(finding)

    if codeql_flow and codeql_flow.has_user_source:
        # CodeQL 确认有用户输入到漏洞的数据流
        return (
            ExploitabilityStatus.EXPLOITABLE,
            0.90,  # CodeQL 确认的置信度更高
            f"CodeQL confirmed taint flow: {codeql_flow.source} → {codeql_flow.sink}"
        )

    # 原有逻辑作为 fallback
    # ...
```

### 4. 修改 CLI 传递 CodeQL 结果

**文件**: `src/cli/main.py`

```python
# 在 run_full_security_scan 中
async def run_full_security_scan(...):
    # ... Round 2 执行 CodeQL ...

    # Round 4: 传递 CodeQL 结果
    round_four = RoundFourExecutor(
        source_path=source_path,
        attack_surface_report=attack_surface_report,
        codeql_results=codeql_results,  # 新增
    )
```

---

## 新建文件

| 文件 | 用途 |
|------|------|
| 无 | 本次修改只涉及现有文件 |

---

## 修改文件

| 文件 | 改动 |
|------|------|
| `src/layers/l3_analysis/rounds/round_four.py` | 接收 CodeQL 结果 + 整合判断逻辑 |
| `src/cli/main.py` | 传递 CodeQL 结果到 Round 4 |

---

## 验收标准

| 标准 | 指标 | 状态 |
|------|------|------|
| CodeQL 整合 | CodeQL 数据流结果被利用 | ✅ 完成 |
| 可利用性精度 | 与对抗验证一致性提升至 > 60% | ⏳ 待实测验证 |
| 向后兼容 | 无 CodeQL 结果时降级正常工作 | ✅ 完成 |
| 测试覆盖 | 20+ 新测试 | ✅ 23 测试 |
| 兼容性 | 现有测试全部通过 | ✅ 1716 通过 |

---

## 设计原则

| 原则 | 实现方式 |
|------|----------|
| **可选参数** | `codeql_results=None`，不影响现有调用 |
| **渐进增强** | 有 CodeQL 结果就用，没有就降级 |
| **向后兼容** | 旧模式作为 fallback |
| **不破坏接口** | 只添加可选参数，不修改签名 |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-03-06 10:20 | feat(l3): integrate CodeQL dataflow results (5484322) |
| 2026-03-06 | 创建 P5-01a 目标 |
| 2026-03-06 | 完成 CodeQL 升级到 2.20.5 + 所有语言包下载 |
| 2026-03-06 | 完成 RoundFourExecutor 整合 CodeQL 数据流的核心代码修改 |
| 2026-03-06 15:30 | fix(l3): 修复 CONitional → CONDITIONAL typo |
| 2026-03-06 15:35 | test(l3): 添加 23 个 CodeQL 数据流集成测试 (1b8ed54) |
