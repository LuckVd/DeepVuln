# 当前目标

> 单一焦点：完成 P5-01e 剩余任务 C/D/E
---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | 完成结果口径、Round4 判定、去重接线三项修复 |
| **状态** | in_progress |
| **优先级** | critical |
| **创建日期** | 2026-03-07 |
| **所属阶段** | Phase 5 - 精度深化 |
| **模块层级** | CLI + L3 Analysis + Round 4 + Reporting |
| **依赖** | P5-01e A/B 已完成 |
| **父任务** | P5-01e：扫描编排一致性修复 |

---

## 已完成部分

| 任务 | 状态 | 提交 |
|------|------|------|
| A. 扫描路由与参数语义一致性 | ✅ 已完成 | 7f2743f |
| B. 增量扫描可信化 | ✅ 已完成 | 7f2743f |

---

## 待完成任务

### C. 结果口径与成功状态修复（P0）

**目标：** 报告中的"成功/可利用"语义必须与实际一致。

**修复项：**
- [ ] 全局成功状态改为聚合判定：当请求引擎全部失败或关键阶段失败时 `success=False`。
- [ ] 重新定义"Exploitable Findings"：仅统计 exploitability/adversarial 为 exploitable 的结果。
- [ ] `verified_findings` 与 `exploitable_findings` 分离建模，避免统计混淆。

**涉及文件：**
- `src/cli/main.py`

**验收：**
- 导出文本、交互展示、统计数字三者一致。
- 构造失败场景时最终结果状态正确反映失败。

---

### D. Round 4 判定稳定性修复（P0）

**目标：** 降低误判和死代码风险，保证可利用性判定可解释、可复现。

**修复项：**
- [ ] 删除 `RoundFourExecutor` 重复 `_get_codeql_dataflow` 定义，保留单一实现。
- [ ] `finding.location` 判空保护完善。
- [ ] "调用链不可得"从 `NOT_EXPLOITABLE` 调整为 `NEEDS_REVIEW`（保守策略）。
- [ ] 污点追踪语言从硬编码 `python` 改为基于项目/文件检测。

**涉及文件：**
- `src/layers/l3_analysis/rounds/round_four.py`

**验收：**
- Round4 相关单测更新并通过。
- 多语言样本下状态分布合理，无异常偏向 `NOT_EXPLOITABLE`。

---

### E. 去重与统一报告状态接线（P1）

**目标：** Full scan 与单引擎命令保持一致的去重与最终状态汇总。

**修复项：**
- [ ] 在 full scan 汇总阶段接入统一去重流程。
- [ ] 接入 `report_status` 计算并用于统计与展示。

**涉及文件：**
- `src/cli/main.py`
- `src/layers/l3_analysis/adjudication.py`
- `src/layers/l3_analysis/reporting.py`

**验收：**
- Full scan 报告包含可追溯 `report_status` 统计。
- 重复 finding 在跨引擎结果中有效压缩。

---

## 验收标准

| 标准 | 指标 |
|------|------|
| 状态准确性 | `success` 与引擎执行实际状态一致 |
| 统计准确性 | `verified` / `exploitable` / `report_status` 口径一致 |
| Round4 稳定性 | 去除重复方法定义，关键判定路径可解释 |
| 测试通过率 | 新增/更新测试全部通过，现有核心测试无回归 |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-03-07 | 创建新目标：继续完成 C/D/E 剩余任务 |
| 2026-03-07 | 前置任务 A/B 已在 7f2743f 提交中完成 |

---

## 运行时硬错误修复记录（前置）

> 以下为 7f2743f 提交中修复的运行时错误，作为本目标的前置依赖

| # | 严重度 | 问题 | 位置 | 状态 |
|---|--------|------|------|------|
| 1 | **严重** | `SeverityLevel` 未导入 | main.py:41 | ✅ 已修复 |
| 2 | **严重** | `severity_filter` 缺少 CRITICAL | main.py:824 | ✅ 已修复 |
| 3 | **严重** | `SemgrepScanner` 类不存在 | main.py:541 | ✅ 已修复 |
| 4 | **严重** | `include_low` 变量未定义 | main.py:1029 | ✅ 已修复 |
| 5 | **高** | `AdjudicationSummary` 字段名不匹配 | main.py:1207 | ✅ 已修复 |
| 6 | **中** | `l0_common` 路径错误 | round_four.py:283 | ✅ 已修复 |
| 7 | **低** | CLI 指引 `--base-scan` | main.py:2362 | ✅ 已修复 |
| 8 | **严重** | 增量回调 async/await 不匹配 | main.py:547 | ✅ 已修复 |
| 9 | **中** | `--base` 语义不一致 | main.py:911 | ✅ 已修复 |
