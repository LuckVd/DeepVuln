# 当前目标

> 单一焦点：修复扫描编排与结果可信度问题（原则性缺陷）
---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | 修复扫描流程原则性错误与结果表达失真 |
| **状态** | in_progress |
| **优先级** | critical |
| **创建日期** | 2026-03-07 |
| **所属阶段** | Phase 5 - 精度深化 |
| **模块层级** | CLI + L3 Analysis + Round 4 |
| **依赖** | P5-01d（已完成） |
| **父任务** | P5-01：可利用性评估增强 |

---

## 问题背景

本轮架构与流程评审发现：当前系统存在“功能宣称与实际执行不一致”的编排问题，会直接影响检测结果可信度与报告可用性。

### 已确认的高影响问题

1. `--llm-verify` / `--llm-detect` / `--incremental` 在部分路径不触发 full scan。
2. `--incremental` 默认使用占位扫描器（不调用真实引擎）。
3. Full scan 中引擎失败不影响全局 `success` 判定。
4. “Exploitable Findings”统计口径错误（将 verified 混同 exploitable）。
5. `RoundFourExecutor` 存在重复方法定义（同名覆盖导致死代码）。
6. Round4 对“不确定调用链”偏向 `NOT_EXPLOITABLE`，存在假阴性风险。
7. Full scan 调 Semgrep 时未传 `tech_stack/attack_surface`，未充分使用 Rule Gating。
8. `--include-low` 在 full scan 的语义与用户预期不一致。
9. `--no-deps` 参数已暴露但未实际生效。
10. Full scan 未统一接入去重/统一裁决统计，`report_status` 展示链路未完整打通。

---

## 核心目标

**把“可运行”提升为“可置信”：修复扫描编排与结果表达的原则性问题，确保参数语义、执行路径、统计口径、成功状态、裁决输出一致。**

---

## 完整修复方案

### A. 扫描路由与参数语义一致性（P0）

**目标：** 任意启用代码分析相关参数时，必须进入 full scan 主链路。

**修复项：**
- 修复 interactive/export 路由条件：`llm_verify`、`llm_detect`、`incremental` 必须触发 `run_full_security_scan`。
- 为 `--no-deps` 定义清晰行为：  
  `false` = 代码扫描 + 依赖扫描；`true` = 仅代码扫描。
- 对 `--include-low` 统一语义：引擎过滤、验证阶段、导出统计三处一致。

**涉及文件：**
- `src/cli/main.py`

**验收：**
- 参数-路由矩阵测试全部通过（含 interactive/export/CLI 三路径）。

### B. 增量扫描可信化（P0）

**目标：** 增量模式不得再走占位逻辑。

**修复项：**
- 为 `IncrementalScanner` 注入真实扫描回调（Semgrep/CodeQL/Agent 复用 full scan 引擎能力）。
- 若真实回调不可用，明确 fail-fast 并给出降级提示，不返回“成功空结果”。

**涉及文件：**
- `src/cli/main.py`
- `src/layers/l3_analysis/incremental/scanner.py`

**验收：**
- 增量模式在有变更样本仓库中可产出真实 findings。
- 不可用场景下 `success=False` 且错误信息明确。

### C. 结果口径与成功状态修复（P0）

**目标：** 报告中的“成功/可利用”语义必须与实际一致。

**修复项：**
- 全局成功状态改为聚合判定：当请求引擎全部失败或关键阶段失败时 `success=False`。
- 重新定义“Exploitable Findings”：仅统计 exploitability/adversarial 为 exploitable 的结果。
- `verified_findings` 与 `exploitable_findings` 分离建模，避免统计混淆。

**涉及文件：**
- `src/cli/main.py`

**验收：**
- 导出文本、交互展示、统计数字三者一致。
- 构造失败场景时最终结果状态正确反映失败。

### D. Round 4 判定稳定性修复（P0）

**目标：** 降低误判和死代码风险，保证可利用性判定可解释、可复现。

**修复项：**
- 删除 `RoundFourExecutor` 重复 `_get_codeql_dataflow` 定义，保留单一实现。
- `finding.location` 判空保护完善。
- “调用链不可得”从 `NOT_EXPLOITABLE` 调整为 `NEEDS_REVIEW`（保守策略）。
- 污点追踪语言从硬编码 `python` 改为基于项目/文件检测。

**涉及文件：**
- `src/layers/l3_analysis/rounds/round_four.py`

**验收：**
- Round4 相关单测更新并通过。
- 多语言样本下状态分布合理，无异常偏向 `NOT_EXPLOITABLE`。

### E. 去重与统一报告状态接线（P1）

**目标：** Full scan 与单引擎命令保持一致的去重与最终状态汇总。

**修复项：**
- 在 full scan 汇总阶段接入统一去重流程。
- 接入 `report_status` 计算并用于统计与展示。

**涉及文件：**
- `src/cli/main.py`
- `src/layers/l3_analysis/adjudication.py`
- `src/layers/l3_analysis/reporting.py`

**验收：**
- Full scan 报告包含可追溯 `report_status` 统计。
- 重复 finding 在跨引擎结果中有效压缩。

---

## 执行顺序（强约束）

1. 先修复路由/参数语义（A）。
2. 再替换增量占位实现（B）。
3. 同步修复成功状态与统计口径（C）。
4. 修复 Round4 方法覆盖与判定偏差（D）。
5. 最后接线统一去重与 report_status（E）。

---

## 验收标准

| 标准 | 指标 |
|------|------|
| 路由一致性 | 参数-路由矩阵 100% 覆盖并通过 |
| 增量可信度 | 增量模式使用真实引擎，不再返回占位空结果 |
| 状态准确性 | `success` 与引擎执行实际状态一致 |
| 统计准确性 | `verified` / `exploitable` / `report_status` 口径一致 |
| Round4 稳定性 | 去除重复方法定义，关键判定路径可解释 |
| 测试通过率 | 新增/更新测试全部通过，现有核心测试无回归 |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-03-07 | 创建新目标：扫描编排与结果可信度修复（critical） |
| 2026-03-07 | 完成问题清单与完整修复方案定义，进入实施阶段 |
| 2026-03-07 | 发现运行时硬错误（6 项），暂停提交进入修复 |
| 2026-03-07 | 修复全部 6 项运行时硬错误，L3 测试全部通过（1067 passed） |
| 2026-03-07 | 修复问题 7：CLI 指引文案 `--base-scan` → `--base`，全部 7 项问题修复完成 |
| 2026-03-07 | 发现问题 8-9：增量回调 async 不匹配、--base 语义不一致 |
| 2026-03-07 | 修复问题 8-9，全部 9 项运行时错误修复完成，L3 测试通过（1067 passed） |

---

## 运行时硬错误（阻断提交）

> 代码审查发现的 NameError/功能失效问题，必须修复后才能提交

| # | 严重度 | 问题 | 位置 | 状态 |
|---|--------|------|------|------|------|
| 1 | **严重** | `SeverityLevel` 未导入，Semgrep 分支会 NameError | main.py:821 | ✅ 已修复 |
| 2 | **严重** | `severity_filter` 缺少 CRITICAL，最高危结果被过滤 | main.py:819-823 | ✅ 已修复 |
| 3 | **严重** | `SemgrepScanner` 类不存在，增量回调返回空结果 | main.py:540 | ✅ 已修复 |
| 4 | **严重** | `include_low` 变量未定义（应为 `include_low_severity`） | main.py:1025 | ✅ 已修复 |
| 5 | **高** | `AdjudicationSummary` 字段名与实际 API 不匹配 | main.py:1203-1207 | ✅ 已修复 |
| 6 | **中** | `l0_common` 路径错误，语言检测退化为 python | round_four.py:283 | ✅ 已修复 |
| 7 | **低** | CLI 指引显示 `--base-scan` 但实际参数是 `--base` | main.py:2362 | ✅ 已修复 |
| 8 | **严重** | 增量回调 async/await 不匹配，返回 coroutine 非 ScanResult | main.py:547 | ✅ 已修复 |
| 9 | **中** | `--base` 语义不一致，Phase 4 仍因 llm_client 存在而执行 | main.py:911 | ✅ 已修复 |

---

## 修复详情（2026-03-07）

### Fix 1: SeverityLevel 导入
```python
# main.py 添加导入
from src.layers.l3_analysis.models import SeverityLevel
```

### Fix 2: severity_filter 包含 CRITICAL
```python
severity_filter = [
    SeverityLevel.CRITICAL,  # 新增
    SeverityLevel.HIGH,
    SeverityLevel.MEDIUM,
]
```

### Fix 3: SemgrepScanner → SemgrepEngine
```python
# 增量扫描回调使用正确的引擎类
from src.layers.l3_analysis.engines.semgrep import SemgrepEngine
engine = SemgrepEngine()
result = engine.scan(source_path=project_path, files_filter=files)
```

### Fix 4: include_low → include_low_severity
```python
skip_low_severity=not include_low_severity,  # 修正变量名
```

### Fix 5: AdjudicationSummary 字段修正
```python
# 正确字段名
"duplicates_removed": adjudication_summary.deduplication.get("removed_count", 0),
"consistency_errors": adjudication_summary.conflicts_detected,
"overrides_applied": adjudication_summary.overrides_applied,
"report_status": adjudication_summary.report_status,
```

### Fix 6: l0_common → l1_intelligence
```python
# round_four.py 修正导入路径
from src.layers.l1_intelligence.tech_stack_detector.detector import TechStackDetector
```

### Fix 7: --base-scan → --base
```python
# CLI 指引文案修正
console.print("[dim]  --base         Base scan: 3 engines (Semgrep + CodeQL + Agent), no LLM[/]")
```

### Fix 8: 增量回调 async/await 不匹配
```python
# main.py:547 - 使用 asyncio.run() 调用异步 scan 方法
def scan_callback(files: list[str]) -> list[dict]:
    import asyncio
    from src.layers.l3_analysis.engines.semgrep import SemgrepEngine

    async def _run_scan():
        return await engine.scan(
            source_path=project_path,
            include_patterns=files,  # 使用 include_patterns（显式支持的参数）
        )

    result = asyncio.run(_run_scan())  # 正确调用异步方法
```

### Fix 9: --base 语义一致性
```python
# main.py:911 - Phase 4 条件只依赖 llm_verify
# 修复前：if result["all_findings"] and (llm_verify or llm_client):
# 修复后：
if result["all_findings"] and llm_verify:  # 只在显式启用 LLM 验证时执行
```
