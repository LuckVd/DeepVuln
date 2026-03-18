# DeepVuln 项目路线图

> 三层核心架构智能漏洞挖掘系统开发规划（高精度重构版）

---

## 项目概览

|字段|值|
|---|---|
|**名称**|DeepVuln|
|**类型**|backend|
|**描述**|三层核心架构智能漏洞挖掘系统，AI Agent 为主、SAST 工具为辅，实现攻击面驱动与可利用性优先裁决|
|**技术栈**|Python 3.11+ / LLM API (OpenAI) / Semgrep / CodeQL|

---

## 目录结构

DeepVuln/  
├── src/  
│   ├── layers/                      
│   │   ├── l1_intelligence/         
│   │   └── l3_analysis/             
│   ├── core/                        
│   │   ├── config/                  
│   │   ├── logger/                  
│   │   ├── exceptions/              
│   │   └── rule_gating.py         # 新增：规则裁剪引擎  
│   ├── models/                      
│   └── cli/                         
├── rules/                           
│   ├── semgrep/                     
│   ├── codeql/                      
│   └── custom/                      
├── tests/                           
└── docs/                          

---

## 模块规划

### 按层级划分

|模块|路径|功能|优先级|
|---|---|---|---|
|L1-Intelligence|`src/layers/l1_intelligence/`|源码获取、工作空间管理、技术栈识别、代码结构解析、攻击面探测、情报同步|P0|
|Rule Gating Engine|`src/core/rule_gating.py`|规则裁剪、语言匹配、攻击面驱动控制|P0|
|L3-Analysis|`src/layers/l3_analysis/`|三引擎执行、多轮审计、裁决融合|P0|

---

### 按组件划分

|组件|所属层|路径|优先级|
|---|---|---|---|
|资产获取器|L1|`src/layers/l1_intelligence/fetcher.py`|P0|
|工作空间管理器|L1|`src/layers/l1_intelligence/workspace.py`|P0|
|技术栈识别器|L1|`src/layers/l1_intelligence/tech_stack_detector/detector.py`|P0|
|攻击面探测器|L1|`src/layers/l1_intelligence/attack_surface/`|P0|
|规则裁剪引擎|Core|`src/core/rule_gating.py`|P0|
|审计策略引擎|L3|`src/layers/l3_analysis/strategy/engine.py`|P0|
|Semgrep 引擎|L3|`src/layers/l3_analysis/engines/semgrep.py`|P0|
|CodeQL 引擎|L3|`src/layers/l3_analysis/engines/codeql.py`|P0|
|OpenCode Agent|L3|`src/layers/l3_analysis/engines/opencode_agent.py`|P0|
|多轮审计控制器|L3|`src/layers/l3_analysis/rounds/controller.py`|P0|
|Exploitability 评估执行器|L3|`src/layers/l3_analysis/rounds/round_four.py`|P0|
|主裁决与状态收敛|L3|`src/layers/l3_analysis/adjudication.py`|P0|
|去重引擎（语义级）|L3|`src/layers/l3_analysis/deduplicator.py`|P0|

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
|**Phase 6.5**|**code-audit 集成**|**防幻觉规则 + 覆盖率矩阵 + 污点分析模板 + 漏洞验证方法论**|**→ 当前阶段**|2026-03|

---

## Phase 3 详细任务：精度重构

|任务|描述|依赖|状态|
|---|---|---|---|
|P3-01|TechStackDetector 全量扫描改造|P1-06|done|
|P3-02|主语言识别（基于 LOC）|P3-01|done|
|P3-03|项目类型识别（web/api/cli/library）|P3-01|done|
|P3-04|Rule Gating Engine 实现|P3-02|done|
|P3-05|Semgrep 文件级过滤（include/exclude/lang）|P3-04|done|
|P3-06|禁止 literal 规则（AST 强制）|P3-05|done|
|P3-07|Finding Budget 误报熔断机制|P3-04|done|
|P3-08|CodeQL 失败降级策略|P2-02|done|

---

## Phase 4 详细任务：裁决统一

|任务|描述|依赖|状态|
|---|---|---|---|
|P4-01|引入统一 final_score 模型|P3-08|done|
|P4-02|Exploitability 成为主裁决权重|P4-01|done|
|P4-03|禁止 confirmed/not_exploitable 冲突|P4-02|done|
|P4-04|语义级去重（AST hash）|P2-10|done|
|P4-05|统一报告状态模型（informational/conditional/exploitable）|P4-02|done|

---

## Phase 5 详细任务：精度深化

|任务|描述|依赖|状态|
|---|---|---|---|
|P5-01|可利用性评估增强（核心重构）|P4-05|done|
|P5-01a|整合 CodeQL 数据流结果到 Phase 4|P5-01|done|
|P5-01b|AST 调用图构建与可达性分析|P5-01|done|
|P5-01c|污点追踪增强（反向追踪+净化器检测）|P5-01|done|
|P5-01d|多维评分系统（可达性+用户输入+净化器）|P5-01|done|
|P5-01e|扫描编排一致性修复（路由/状态/统计口径）|P5-01d|done|
|P5-01e-1|修复 scan 路由与参数语义一致性（llm_verify/llm_detect/incremental/no_deps）|P5-01e|done|
|P5-01e-2|增量扫描接入真实引擎回调，移除占位执行路径|P5-01e|done|
|P5-01e-3|修复 full scan 成功状态聚合与 exploitable 统计口径|P5-01e|done|
|P5-01e-4|修复 Round4 重复方法覆盖与不确定场景误判偏置|P5-01e|done|
|P5-01e-5|接入 full scan 去重与 report_status 统一统计|P5-01e|done|
|P5-02|性能优化|P5-01|done|
|P5-03|扫描能力完整性修复（12项缺陷收敛）|P5-02|done|
|P5-04|攻击面检测模式重构（静态+LLM并行）|P5-03|done|
|P5-05|LLM 并发配置统一化|P5-04|done|

---

## Phase 6 详细任务：扫描结果可信度

> 基于 Juice Shop 扫描评估，聚焦结果边界清晰化
>
> **Phase 6.5 集成说明**: P6-03~P6-07 已合并 code-audit 集成内容，详见下方 Phase 6.5 章节

### 阶段 1：结果状态模型

|任务|描述|依赖|状态|
|---|---|---|---|
|P6-01|扫描结果状态模型重构|P5-05|done|
|P6-01a|引入顶层状态：complete_success/partial_success/degraded_success/failed|P6-01|done|
|P6-01b|Failed Engines 字段结构化|P6-01a|done|
|P6-02|CodeQL 失败结构化诊断|P6-01|done|
|P6-02a|失败原因拆分：not_installed/unsupported_language/db_create_failed/build_failed/analyze_failed/timeout/pack_error|P6-02|done|
|P6-02b|多语言项目展示每种语言独立状态|P6-02a|done|

### 阶段 2：噪声治理（集成 code-audit 增强）

|任务|描述|依赖|状态|
|---|---|---|---|
|P6-03|证据强度字段引入 **[集成防幻觉规则+覆盖率矩阵]**|P6-01|todo|
|P6-03a|集成防幻觉规则到 LLM 验证流程|P6-03|todo|
|P6-03b|判定依据：source/sink/entry point/数据流/PoC/跨引擎印证|P6-03a|todo|
|P6-03c|[Suspicious] 类结果强制标记 speculative|P6-03b|todo|
|P6-04|conditional/informational 细分 **[集成污点分析模板+验证方法论]**|P6-03|todo|
|P6-04a|conditional 细分：conditional-strong / conditional-weak|P6-04|todo|
|P6-04b|informational 细分：not_exploitable / speculative_signal / environmental_risk|P6-04a|todo|
|P6-04c|规范化污点分析报告模板（Source/Propagation/Sink/Sanitizer/Exploitability）|P6-04|todo|
|P6-04d|集成漏洞验证方法论到置信度评分|P6-04c|todo|
|P6-05|术语重命名：Verified → Processed **[同时扩展规则库]**|P6-04|todo|
|P6-05a|扩展 Sink/Source 危险函数库|P6-05|todo|
|P6-05b|集成语言检查清单到规则库（Java/Python/Go/PHP/JS/Ruby/.NET/Rust/C++）|P6-05a|todo|

### 阶段 3：覆盖率透明化（集成 code-audit 增强）

|任务|描述|依赖|状态|
|---|---|---|---|
|P6-06|Agent 覆盖率统计 **[同时设计业务逻辑检测方法论]**|P6-05|todo|
|P6-06a|输出统计字段：analyzable_files_total / files_selected / files_scanned / files_failed / files_skipped_by_limit|P6-06|todo|
|P6-06b|设计业务逻辑检测方法论 (D9 维度)|P6-06a|todo|
|P6-07|目录分类与降权策略 **[同时导入 WooYun 案例库]**|P6-06|todo|
|P6-07a|新增目录分类：production_code / test_code / sample_code / fixture_code / challenge_code|P6-07|todo|
|P6-07b|非生产代码降权处理|P6-07a|todo|
|P6-07c|配置项支持排除非生产目录|P6-07b|todo|
|P6-07d|导入 WooYun 案例库作为漏洞模式参考|P6-07|todo|
|P6-08|多语言覆盖矩阵|P6-07|todo|
|P6-08a|language x engine x status 矩阵数据结构|P6-08|todo|

### 阶段 4：测试与验收

|任务|描述|依赖|状态|
|---|---|---|---|
|P6-09|结果状态模型测试|P6-01|done|
|P6-10|噪声分层测试|P6-04|todo|
|P6-11|覆盖率表达测试|P6-06|todo|
|P6-12|目录分类测试|P6-07|todo|

---

## Phase 6 验收指标

|指标|当前值（估）|目标值|
|---|---|---|
|conditional 数量|~100 条|<40 条|
|evidence_strength 字段覆盖率|0%|100%|
|Agent 覆盖率统计字段|无|6 个字段|
|目录分类支持|无|5 种类型|

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

## 风险与依赖

### 技术依赖

|类型|描述|影响|状态|
|---|---|---|---|
|依赖|LLM API|高 - Agent 核心能力|待确认|
|依赖|Semgrep CLI|中|已安装|
|依赖|CodeQL CLI|中|已安装|
|依赖|Python 3.11+|高|已确认|

---

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

## 备注

### 核心设计理念（当前版本）

1. **攻击面驱动扫描**：规则执行由项目真实特征决定
    
2. **Exploitability 优先裁决**：不可利用不允许标记 confirmed
    
3. **规则前置裁剪**：禁止规则误报爆炸
    
4. **语义级去重**：基于 AST 而非行号
    
5. **精度优先于召回**
    

---

### 开发优先级原则

1. 先解决误报爆炸，再优化性能
    
2. 当前阶段最高优先级是结果边界清晰化与噪声治理
    
3. 主语言识别是误报压制基础
    
4. 裁决统一优先于新功能开发
    

---

## 当前焦点

|字段|值|
|---|---|
|**阶段**|Phase 6.5 - code-audit 项目优秀实践集成|
|**当前进度**|P6-03 证据强度字段引入（集成防幻觉规则+覆盖率矩阵）待开始|
|**下一步**|P6-03a 集成防幻觉规则到 LLM 验证流程|
|**重点模块**|`src/layers/l3_analysis/`, `rules/`, `src/core/`|
|**目标**|提升漏洞检测精度、减少误报、规范化报告输出|

---

## Phase 6.5 详细任务：code-audit 集成

> 集成 /opt/AI/code-audit 项目的优秀实践，提升 DeepVuln 能力
>
> **注意**: 集成内容已合并到原有 P6-03~P6-07 任务中，保持任务 ID 连续性

### P6-03: 证据强度字段引入（P0 - 集成防幻觉规则+覆盖率矩阵）

|任务|描述|依赖|状态|
|---|---|---|---|
|P6-03|证据强度字段引入（集成防幻觉规则+覆盖率矩阵）|-|todo|
|P6-03a|集成防幻觉规则到 LLM 验证流程|P6-03|todo|
|P6-03b|判定依据：source/sink/entry point/数据流/PoC/跨引擎印证|P6-03a|todo|
|P6-03c|[Suspicious] 类结果强制标记 speculative|P6-03b|todo|

### P6-04: conditional/informational 细分（P1 - 集成污点分析模板+验证方法论）

|任务|描述|依赖|状态|
|---|---|---|---|
|P6-04|conditional/informational 细分（集成污点分析模板+验证方法论）|P6-03|todo|
|P6-04a|conditional 细分：conditional-strong / conditional-weak|P6-04|todo|
|P6-04b|informational 细分：not_exploitable / speculative_signal / environmental_risk|P6-04a|todo|
|P6-04c|规范化污点分析报告模板（Source/Propagation/Sink/Sanitizer/Exploitability）|P6-04|todo|
|P6-04d|集成漏洞验证方法论到置信度评分|P6-04c|todo|

### P6-05: 术语重命名（P2 - 同时扩展规则库）

|任务|描述|依赖|状态|
|---|---|---|---|
|P6-05|术语重命名：Verified → Processed（同时扩展规则库）|P6-04|todo|
|P6-05a|扩展 Sink/Source 危险函数库|P6-05|todo|
|P6-05b|集成语言检查清单到规则库（Java/Python/Go/PHP/JS/Ruby/.NET/Rust/C++）|P6-05a|todo|

### P6-06: Agent 覆盖率统计（P3 - 同时设计业务逻辑检测方法论）

|任务|描述|依赖|状态|
|---|---|---|---|
|P6-06|Agent 覆盖率统计（同时设计业务逻辑检测方法论）|P6-05|todo|
|P6-06a|输出统计字段：analyzable_files_total/files_selected/files_scanned/files_failed/files_skipped_by_limit|P6-06|todo|
|P6-06b|设计业务逻辑检测方法论 (D9 维度)|P6-06a|todo|

### P6-07: 目录分类与降权策略（P3 - 同时导入 WooYun 案例库）

|任务|描述|依赖|状态|
|---|---|---|---|
|P6-07|目录分类与降权策略（同时导入 WooYun 案例库）|P6-06|todo|
|P6-07a|新增目录分类：production_code/test_code/sample_code/fixture_code/challenge_code|P6-07|todo|
|P6-07b|非生产代码降权处理|P6-07a|todo|
|P6-07c|配置项支持排除非生产目录|P6-07b|todo|
|P6-07d|导入 WooYun 案例库作为漏洞模式参考|P6-07|todo|

### P6-08~P6-12: 覆盖率矩阵与测试（保持原计划）

|任务|描述|依赖|状态|
|---|---|---|---|
|P6-08|多语言覆盖矩阵|P6-07|todo|
|P6-08a|language x engine x status 矩阵数据结构|P6-08|todo|
|P6-09|结果状态模型测试|P6-01|done|
|P6-10|噪声分层测试|P6-04|todo|
|P6-11|覆盖率表达测试|P6-06|todo|
|P6-12|目录分类测试|P6-07|todo|
