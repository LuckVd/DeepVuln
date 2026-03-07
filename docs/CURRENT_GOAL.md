# 当前目标

> P5-03 扫描能力完整性修复 - 12 项缺陷收敛
---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | P5-03 扫描能力完整性修复 |
| **状态** | in_progress |
| **优先级** | critical |
| **创建日期** | 2026-03-07 |
| **所属阶段** | Phase 5 - 精度深化 |
| **前置条件** | P5-02 性能优化完成 ✅ |

---

## 问题概览

| 优先级 | 数量 | 影响 |
|--------|------|------|
| P0 | 4 | 系统性漏报/功能退化 |
| P1 | 4 | 误报/可用性/覆盖率 |
| P2 | 4 | 指标失真/用户感知 |

---

## 任务清单

### P5-03a P0 级问题修复 (4 项)

#### 1. CodeQL 多语言支持 ⚠️ 未开始

| 子任务 | 描述 | 状态 |
|--------|------|------|
| 语言循环执行 | 按 `tech_result.languages` 逐语言执行 CodeQL | ⏳ 待实现 |
| 结果合并 | 多语言结果合并到单一 ScanResult | ⏳ 待实现 |
| 元数据标注 | `metadata.codeql_lang` 记录扫描语言 | ⏳ 待实现 |

**修复位置**: `src/layers/l3_analysis/engines/codeql.py`, `src/cli/main.py`

**验收标准**: python+js 样例中两种语言均产出 CodeQL 结果

---

#### 2. 增量扫描多引擎支持 ⚠️ 未开始

| 子任务 | 描述 | 状态 |
|--------|------|------|
| CodeQL 集成 | 增量回调并行接入 CodeQL | ⏳ 待实现 |
| Agent 集成 | 增量回调接入 Agent（可选） | ⏳ 待实现 |
| by_engine 输出 | 增量结果按引擎分类 | ⏳ 待实现 |

**修复位置**: `src/layers/l3_analysis/incremental/scanner.py`

**验收标准**: 同变更集下增量与全量关键规则不缺类

---

#### 3. 引擎降级状态报告 ⚠️ 未开始

| 子任务 | 描述 | 状态 |
|--------|------|------|
| requested vs executed | 对比请求引擎与实际执行引擎 | ⏳ 待实现 |
| partial_success | 部分引擎缺失时标记 | ⏳ 待实现 |
| 明确提示 | 报告中显示 `agent unavailable/skipped` | ⏳ 待实现 |

**修复位置**: `src/cli/main.py`, `src/layers/l3_analysis/models.py`

**验收标准**: 无 LLM key 请求 agent 时，报告明确 agent unavailable/skipped

---

#### 4. Rule Gating Fail-Open 保护 ⚠️ 未开始

| 子任务 | 描述 | 状态 |
|--------|------|------|
| fail-open 机制 | 攻击面检测失败时不禁用规则 | ⏳ 待实现 |
| 高置信度判断 | 仅高置信度"无 HTTP"才禁用 web 规则 | ⏳ 待实现 |
| 降级日志 | 记录降级原因到 metadata | ⏳ 待实现 |

**修复位置**: `src/core/rule_gating.py`

**验收标准**: 攻击面失败场景下 web 规则仍执行

---

### P5-03b P1 级问题修复 (4 项)

#### 5. CVE 精确匹配优化 ⚠️ 未开始

| 子任务 | 描述 | 状态 |
|--------|------|------|
| 生态+坐标匹配 | 优先 ecosystem + package 坐标精确匹配 | ⏳ 待实现 |
| 弱证据降级 | 无版本/无坐标降级为"情报提示" | ⏳ 待实现 |
| 置信度字段 | CVE 匹配结果增加 confidence 字段 | ⏳ 待实现 |

**修复位置**: `src/layers/l1_intelligence/tech_stack_detector/models.py`, `src/layers/l1_intelligence/threat_intel/`

**验收标准**: 同名组件样例误报显著下降

---

#### 6. Agent 文件限制优化 ⚠️ 未开始

| 子任务 | 描述 | 状态 |
|--------|------|------|
| --agent-max-files | CLI 参数支持自定义文件数限制 | ⏳ 待实现 |
| 风险优先排序 | 按入口点/调用链优先选择文件 | ⏳ 待实现 |
| 统计报告 | 显示实际分析文件数/总文件数 | ⏳ 待实现 |

**修复位置**: `src/layers/l3_analysis/engines/opencode_agent.py`, `src/cli/main.py`

**验收标准**: 200+ 文件项目可扩展且高风险文件优先覆盖

---

#### 7. Agent 失败统计 ⚠️ 未开始

| 子任务 | 描述 | 状态 |
|--------|------|------|
| files_failed | 统计失败文件数 | ⏳ 待实现 |
| files_analyzed | 统计成功分析文件数 | ⏳ 待实现 |
| 状态影响 | 失败率超阈值置 partial_success/failed | ⏳ 待实现 |

**修复位置**: `src/layers/l3_analysis/engines/opencode_agent.py`, `src/layers/l3_analysis/models.py`

**验收标准**: 注入 LLM 异常后，报告显示失败占比并影响总状态

---

#### 8. LLM Verify 状态分离 ⚠️ 未开始

| 子任务 | 描述 | 状态 |
|--------|------|------|
| llm_verify_requested | 记录用户请求的 LLM 验证状态 | ⏳ 待实现 |
| llm_verify_active | 记录实际启用的 LLM 验证状态 | ⏳ 待实现 |
| 报告显示 | 拆分展示两个状态 | ⏳ 待实现 |

**修复位置**: `src/cli/main.py`, `src/layers/l3_analysis/models.py`

**验收标准**: 无 key 时显示 requested=true, active=false

---

### P5-03c P2 级问题修复 (4 项)

#### 9. 攻击面 files_scanned 准确统计 ⚠️ 未开始

| 子任务 | 描述 | 状态 |
|--------|------|------|
| 真实文件数 | 记录实际分析文件数 | ⏳ 待实现 |
| 移除近似 | 不用 entry point 数近似 | ⏳ 待实现 |

**修复位置**: `src/layers/l1_intelligence/attack_surface/detector.py`

**验收标准**: 报告中扫描文件数与实际分析数一致

---

#### 10. 攻击面结果去重 ⚠️ 未开始

| 子任务 | 描述 | 状态 |
|--------|------|------|
| 去重键 | type+file+line+path+method 组合去重 | ⏳ 待实现 |
| 统计修正 | 去重后再统计 | ⏳ 待实现 |

**修复位置**: `src/layers/l1_intelligence/attack_surface/detector.py`, `src/layers/l1_intelligence/attack_surface/models.py`

**验收标准**: 重复端点不再重复计数

---

#### 11. 报告完整性展示 ⚠️ 未开始

| 子任务 | 描述 | 状态 |
|--------|------|------|
| not_exploitable 计数 | 主视图增加独立统计 | ⏳ 待实现 |
| error 计数 | 主视图增加独立统计 | ⏳ 待实现 |
| 可展开列表 | 失败/不可利用项可展开查看 | ⏳ 待实现 |

**修复位置**: `src/cli/main.py`, `src/layers/l3_analysis/reporting.py`

**验收标准**: 报告首页可见全部状态统计

---

#### 12. Gating 指标生效验证 ⚠️ 未开始

| 子任务 | 描述 | 状态 |
|--------|------|------|
| 执行层实现 | 未生效指标实现到执行层 | ⏳ 待验证 |
| 报告移除 | 或从未生效指标从报告移除 | ⏳ 待验证 |

**修复位置**: `src/core/rule_gating.py`, `src/layers/l3_analysis/engines/semgrep.py`

**验收标准**: 报告字段与实际行为一致

---

## 验收标准

| 标准 | 指标 |
|------|------|
| P0 全部修复 | 4 项 P0 问题验收通过 |
| P1 全部修复 | 4 项 P1 问题验收通过 |
| P2 全部修复 | 4 项 P2 问题验收通过 |
| 测试覆盖 | 新增/修改测试全部通过 |
| 无回归 | 现有 1880 测试不失败 |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-03-07 | 创建 P5-03 扫描能力完整性修复目标 |
| 2026-03-07 | 识别 12 项缺陷，按优先级分类 |

---

## 依赖关系

```
P5-03a (P0) ─┬─> P5-03b (P1) ─┬─> P5-03c (P2)
             │                │
             │                └─> 验收测试
             │
             └─> 可并行
```

**建议顺序**: P5-03a → P5-03b → P5-03c（P0 优先）
