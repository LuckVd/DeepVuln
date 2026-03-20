# DeepVuln 项目路线图

> 三层核心架构智能漏洞挖掘系统开发规划（高精度重构版）

---

## 项目概览

|字段|值|
|---|---|
|**名称**|DeepVuln|
|**类型**|backend|
|**描述**|三层核心架构智能漏洞挖掘系统，AI Agent 为主、SAST 工具为辅，实现攻击面驱动与可利用性优先裁决|
|**技术栈**|Python 3.10+ / LLM API (OpenAI) / Semgrep / CodeQL / Tree-sitter|

---

## 开发阶段

|阶段|目标|核心交付|状态|预计完成|
|---|---|---|---|---|
|Phase 1|基础设施搭建|L1 初版|done|2026-02|
|Phase 2|核心分析能力|L3 三引擎 + 多轮审计|done|2026-02|
|Phase 3|精度重构|Rule Gating + TechStack 重构|done|2026-03|
|Phase 4|裁决统一|Exploitability 主裁决 + 误报压制|done|2026-03-06|
|Phase 5|精度深化|可利用性评估增强 + 调用图分析|done|2026-03|
|Phase 6|报告可信度|结果边界清晰化 + 噪声治理 + 覆盖率透明|in_progress|2026-03|
|Phase 6.5|code-audit 集成|防幻觉规则 + 覆盖率矩阵 + 污点分析模板 + 漏洞验证方法论|in_progress|2026-03|

---

## Phase 6.5 详细任务：code-audit 集成

### P6-03: 证据强度字段引入（P0）

|任务|描述|依赖|状态|
|---|---|---|---|
|P6-03|证据强度字段引入（集成防幻觉规则+覆盖率矩阵）|-|done|
|P6-03a|集成防幻觉规则到 LLM 验证流程|P6-03|done|
|P6-03b|判定依据：source/sink/entry point/数据流/PoC/跨引擎印证|P6-03a|done|
|P6-03c|[Suspicious] 类结果强制标记 speculative|P6-03b|done|

**实现文件**: `src/layers/l3_analysis/models.py:EvidenceStrength`, `src/layers/l3_analysis/evidence_calculator.py`

### P6-04: conditional/informational 细分（P1）

|任务|描述|依赖|状态|
|---|---|---|---|
|P6-04|conditional/informational 细分（集成污点分析模板+验证方法论）|P6-03|done|
|P6-04a|conditional 细分：conditional-strong / conditional-weak|P6-04|done|
|P6-04b|informational 细分：not_exploitable / speculative_signal / environmental_risk|P6-04a|done|
|P6-04c|规范化污点分析报告模板（Source/Propagation/Sink/Sanitizer/Exploitability）|P6-04|done|
|P6-04d|集成漏洞验证方法论到置信度评分|P6-04c|done|

**实现文件**: `src/layers/l3_analysis/models.py:ConditionalSubtype, InformationalSubtype`, `src/layers/l3_analysis/taint_report.py`

### P6-05: 术语重命名与规则库扩展（P2）

|任务|描述|依赖|状态|
|---|---|---|---|
|P6-05|术语重命名：Verified → Processed（同时扩展规则库）|P6-04|done|
|P6-05a|扩展 Sink/Source 危险函数库|P6-05|done|
|P6-05b|集成语言检查清单到规则库（Java/Python/Go/PHP/JS/Ruby/.NET/Rust/C++）|P6-05a|done|

**实现文件**: `src/layers/l3_analysis/sinks_sources/` (Python/Java registries)

### P6-06: Agent 覆盖率统计（P3）

|任务|描述|依赖|状态|
|---|---|---|---|
|P6-06|Agent 覆盖率统计（同时设计业务逻辑检测方法论）|P6-05|done|
|P6-06a|输出统计字段：total_files/scanned_files/skipped_files|P6-06|done|
|P6-06b|设计业务逻辑检测方法论 (D9 维度)|P6-06a|done|

**实现文件**: `src/layers/l3_analysis/rounds/models.py:CoverageStats`, `src/layers/l3_analysis/methodology/`

### P6-07: 目录分类与降权策略（P3）

|任务|描述|依赖|状态|
|---|---|---|---|
|P6-07|目录分类与降权策略|P6-06|done|
|P6-07a|新增目录分类：production_code/test_code/sample_code/fixture_code/challenge_code|P6-07|done|
|P6-07b|非生产代码降权处理（score_multiplier）|P6-07a|done|
|P6-07c|配置项支持自定义目录分类和降权因子|P6-07b|done|
|P6-07d|导入 WooYun 案例库作为漏洞模式参考|P6-07|todo|

**实现文件**: `src/core/file_filtering.py:DirectoryClass, classify_directory, get_score_multiplier`, `src/layers/l3_analysis/models.py:Finding.directory_class`, `src/core/final_score.py:directory_multiplier`, `src/core/config/__init__.py:get_directory_classification_config`

### P6-08~P6-12: 覆盖率矩阵与测试

|任务|描述|依赖|状态|
|---|---|---|---|
|P6-08|多语言覆盖矩阵|P6-07|todo|
|P6-08a|language x engine x status 矩阵数据结构|P6-08|todo|
|P6-09|结果状态模型测试|P6-01|done|
|P6-10|噪声分层测试|P6-04|todo|
|P6-11|覆盖率表达测试|P6-06|todo|
|P6-12|目录分类测试|P6-07|todo|

---

## 里程碑

|里程碑|交付物|能力描述|状态|日期|
|---|---|---|---|---|
|v0.1|L1|支持源码获取、技术栈识别、攻击面探测|done|2026-02|
|v0.2|+ Semgrep|支持模式匹配扫描|done|2026-02|
|v0.2.1|+ CodeQL|支持数据流分析|done|2026-02|
|v0.2.2|+ Agent|支持 AI 驱动深度审计|done|2026-02|
|v0.3|L3 完整|三引擎 + 多轮审计|done|2026-02|
|v0.4|精度重构|Rule Gating + 语言重构|done|2026-03|
|v0.5|裁决统一|Exploitability 主导裁决|done|2026-03-06|
|v0.6|精度深化|可利用性评估增强 + 调用图分析|done|2026-03-09|
|v0.7|报告可信度|结果边界清晰 + 噪声治理 + 覆盖率透明|in_progress|2026-03|
|v0.8|企业稳定版|高精度、低误报、CI 可用|todo|-|

---

## 当前焦点

|字段|值|
|---|---|
|**阶段**|Phase 6.5 - code-audit 项目优秀实践集成|
|**当前进度**|P6-03~P6-07 已完成，P6-06b 和 P6-08 待开始|
|**下一步**|P6-06b 业务逻辑检测方法论 或 P6-08 多语言覆盖矩阵|
|**重点模块**|`src/layers/l3_analysis/`, `src/core/file_filtering.py`|
|**目标**|完成覆盖率透明化，达到 v0.7 里程碑|

---

## 风险与依赖

### 技术依赖

|类型|描述|影响|状态|
|---|---|---|---|
|依赖|LLM API|高 - Agent 核心能力|待确认|
|依赖|Semgrep CLI|中|已安装|
|依赖|CodeQL CLI|中|已安装|
|依赖|Python 3.10+|高|已确认|

### 技术风险

|类型|描述|影响|状态|缓解措施|
|---|---|---|---|---|
|风险|规则误报爆炸|高|存在|引入 Rule Gating|
|风险|CodeQL 构建/分析失败|高|存在|结构化诊断 + 降级机制 + 报告显式退化|
|风险|confirmed/不可利用冲突|高|存在|统一裁决模型|
|风险|多语言误匹配|高|存在|主语言识别|

---

## 性能目标

|指标|目标值|说明|
|---|---|---|
|单项目分析耗时|< 45min|100K LOC|
|误报率|< 20%|v0.5 目标|
|confirmed 与 exploitability 冲突|0|强制规则|
|markdown 被扫描|0|文件级过滤|
|单规则爆炸率|自动抑制|Finding Budget|

---

## 核心设计理念

1. **攻击面驱动扫描**：规则执行由项目真实特征决定
2. **Exploitability 优先裁决**：不可利用不允许标记 confirmed
3. **规则前置裁剪**：禁止规则误报爆炸
4. **语义级去重**：基于 AST 而非行号
5. **精度优先于召回**
