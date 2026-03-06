# 当前目标

> 单一焦点：本次会话关注的核心任务
---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | P5-01：可利用性评估增强 |
| **状态** | todo |
| **优先级** | P0 |
| **创建日期** | 2026-03-06 |
| **所属阶段** | Phase 5 - 精度深化 |
| **模块层级** | L3 Analysis Layer |
| **依赖** | P4-05 |

---

## 问题背景

当前 Phase 4 可利用性评估存在以下问题：

| 问题 | 现状 | 影响 |
|------|------|------|
| 用户输入检测 | 只用正则模式匹配 | 漏报大量真实可利用漏洞 |
| 调用链分析 | 只搜索直接调用者 | 无法判断深层调用链可达性 |
| CodeQL 数据流 | 不使用 CodeQL 结果 | 浪费已有的深度分析能力 |
| L1 AST 检测 | 与入口点检测脱节 | 入口点判断不准确 |

**实测结果**：OWASP Juice Shop 扫描中，100% 漏洞被判定为 "not_exploitable"，但对抗性验证显示 53% 为 "confirmed"。

---

## 核心目标

**重构可利用性评估，实现深度整合与精确判断。**

1. 整合 CodeQL 数据流分析结果
2. 构建真正的 AST 调用图
3. 增强污点追踪能力
4. 实现多维评分系统

---

## 子任务

### P5-01a: 整合 CodeQL 数据流结果

**工作量**: 中 | **优先级**: P0 | **收益**: 高

**目标**: 将 Round 2 的 CodeQL 数据流结果传递到 Phase 4

**实现**:
```python
# 修改 RoundFourExecutor.__init__()
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

def _get_codeql_dataflow(self, finding: Finding) -> DataFlowInfo | None:
    """获取该漏洞的 CodeQL 数据流信息"""
    key = f"{finding.location.file}:{finding.location.line_start}"
    return self._codeql_index.get(key)
```

**CodeQL 提供的关键信息**:
- `source`: 污点源（用户输入位置）
- `sink`: 污点汇聚点（漏洞位置）
- `path`: 完整的数据流路径
- `sanitizers`: 检测到的净化器

---

### P5-01b: AST 调用图构建

**工作量**: 大 | **优先级**: P1 | **收益**: 高

**目标**: 基于 AST 构建函数调用图，实现可达性分析

**新建文件**: `src/layers/l3_analysis/call_graph.py`

```python
class CallGraphAnalyzer:
    """基于 AST 的调用图分析器"""

    def __init__(self, source_path: Path):
        self.source_path = source_path
        self.call_graph: dict[str, set[str]] = {}  # func -> callers
        self.entry_points: set[str] = set()

    def is_reachable_from_entry(self, target_func: str) -> tuple[bool, list[str]]:
        """检查函数是否可从入口点到达"""
        pass

    def get_call_path(self, source: str, target: str) -> list[str]:
        """获取从 source 到 target 的调用路径"""
        pass
```

---

### P5-01c: 污点追踪增强

**工作量**: 大 | **优先级**: P1 | **收益**: 高

**目标**: 增强数据流分析，支持反向追踪和净化器检测

**扩展**: `src/layers/l3_analysis/task/context_builder.py`

```python
class TaintTracker:
    """污点追踪器"""

    # 污点源定义
    TAINT_SOURCES = {
        "flask": ["request.args", "request.form", "request.json"],
        "django": ["request.GET", "request.POST", "request.body"],
        "express": ["req.body", "req.query", "req.params"],
        "spring": ["@RequestParam", "@PathVariable", "@RequestBody"],
    }

    def analyze_taint_flow(
        self,
        source_code: str,
        sink_line: int,
        language: str = "python"
    ) -> TaintResult:
        """分析从污点源到漏洞点的数据流"""
        pass
```

---

### P5-01d: 多维评分系统

**工作量**: 中 | **优先级**: P0 | **收益**: 高

**目标**: 替换二元判断为多维评分

**修改**: `src/layers/l3_analysis/rounds/round_four.py`

```python
class ExploitabilityScore:
    """可利用性评分系统"""

    def calculate(self, context: ExploitabilityContext) -> tuple[ExploitabilityStatus, float]:
        score = 0.0
        factors = []

        # 因子 1: 可达性 (0-30分)
        if context.is_entry_point:
            score += 30
        elif context.call_path_length:
            score += max(0, 30 - context.call_path_length * 5)

        # 因子 2: 用户输入 (0-40分)
        if context.codeql_confirmed_taint:
            score += 40
        elif context.has_user_input_pattern:
            score += 25

        # 因子 3: 净化器 (扣分)
        if context.sanitizers:
            score -= len(context.sanitizers) * 10

        # 因子 4: 认证要求 (扣分)
        if context.requires_auth:
            score -= 10
        if context.requires_admin:
            score -= 20

        # 映射到状态
        if score >= 60:
            return ExploitabilityStatus.EXPLOITABLE, score / 100
        elif score >= 40:
            return ExploitabilityStatus.CONDITIONAL, score / 100
        elif score >= 20:
            return ExploitabilityStatus.UNLIKELY, score / 100
        else:
            return ExploitabilityStatus.NOT_EXPLOITABLE, score / 100
```

---

## 架构整合

```
当前数据流:
L1 AttackSurfaceDetector ─────► entry_points (AST)
         │
         ▼
L3 Round 1-3 ──────────────────► findings + CodeQL results
         │
         ▼
L3 Round 4 (Exploitability) ───► 需要增强的地方
         │
         │  整合:
         │  1. entry_points (已有，需要更深度使用)
         │  2. CodeQL dataflow (新增，传递进来)
         │  3. 调用图 (新增，构建出来)
         │
         ▼
L3 Round 4.5 (Adversarial) ────► 最终裁决
```

---

## 验收标准

| 标准 | 指标 |
|------|------|
| 精度提升 | 可利用判断与对抗验证一致性 > 80% |
| CodeQL 整合 | CodeQL 数据流结果被利用 |
| 测试覆盖 | 50+ 新测试 |
| 兼容性 | 现有 192 测试全部通过 |
| 性能 | 不增加超过 20% 分析时间 |

---

## 不影响后续目标的设计原则

| 原则 | 实现方式 |
|------|----------|
| **接口稳定** | `RoundFourExecutor.__init__()` 添加可选参数 |
| **渐进增强** | CodeQL 结果可选，不影响降级运行 |
| **向后兼容** | 旧模式作为 fallback |
| **模块独立** | 调用图、污点分析作为独立文件 |
| **配置可控** | 通过配置开关控制是否启用增强功能 |

---

## 执行顺序

```
1. P5-01a (优先) - 整合 CodeQL，收益最高，工作量中
2. P5-01d (次优) - 多维评分，改进判断逻辑
3. P5-01b (后续) - 调用图，工作量大
4. P5-01c (后续) - 污点追踪，工作量大
```

---

## 新建文件

| 文件 | 用途 |
|------|------|
| `src/layers/l3_analysis/call_graph.py` | AST 调用图分析器 |
| `src/layers/l3_analysis/taint_tracker.py` | 污点追踪器 |
| `tests/unit/test_l3/test_call_graph.py` | 调用图测试 |
| `tests/unit/test_l3/test_taint_tracker.py` | 污点追踪测试 |
| `tests/unit/test_l3/test_exploitability_score.py` | 评分系统测试 |

---

## 修改文件

| 文件 | 改动 |
|------|------|
| `src/layers/l3_analysis/rounds/round_four.py` | 整合 CodeQL + 多维评分 |
| `src/layers/l3_analysis/task/context_builder.py` | 增强数据流分析 |
| `src/cli/main.py` | 传递 CodeQL 结果到 Round 4 |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-03-06 | 创建 P5-01 目标，完成设计文档 |
