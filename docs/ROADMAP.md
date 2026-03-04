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
│   │   ├── l2_understanding/        
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
|L1-Intelligence|`src/layers/l1_intelligence/`|源码获取、工作空间管理、情报同步|P0|
|L2-Understanding|`src/layers/l2_understanding/`|技术栈识别、代码结构解析、攻击面探测|P0|
|Rule Gating Engine|`src/core/rule_gating.py`|规则裁剪、语言匹配、攻击面驱动控制|P0|
|L3-Analysis|`src/layers/l3_analysis/`|三引擎执行、多轮审计、裁决融合|P0|

---

### 按组件划分

|组件|所属层|路径|优先级|
|---|---|---|---|
|资产获取器|L1|`l1_intelligence/fetcher.py`|P0|
|工作空间管理器|L1|`l1_intelligence/workspace.py`|P0|
|技术栈识别器（重构）|L2|`l2_understanding/tech_detector.py`|P0|
|攻击面探测器|L2|`l2_understanding/attack_surface.py`|P0|
|规则裁剪引擎|Core|`core/rule_gating.py`|P0|
|审计策略引擎|L3|`l3_analysis/strategy_engine.py`|P0|
|Semgrep 引擎（重构）|L3|`l3_analysis/engines/semgrep.py`|P0|
|CodeQL 引擎（健康管理升级）|L3|`l3_analysis/engines/codeql.py`|P0|
|OpenCode Agent|L3|`l3_analysis/engines/opencode_agent.py`|P0|
|多轮审计控制器|L3|`l3_analysis/round_controller.py`|P0|
|Exploitability 裁决器（主裁决）|L3|`l3_analysis/exploitability.py`|P0|
|去重引擎（语义级）|L3|`l3_analysis/deduplicator.py`|P0|

---

## 开发阶段

|阶段|目标|核心交付|状态|预计完成|
|---|---|---|---|---|
|Phase 1|基础设施搭建|L1 + L2 初版|done|2026-02|
|Phase 2|核心分析能力|L3 三引擎 + 多轮审计|done|2026-02|
|Phase 3|精度重构|Rule Gating + TechStack 重构|**→ 当前阶段**|-|
|Phase 4|裁决统一|Exploitability 主裁决 + 误报压制|todo|-|
|Phase 5|稳定化优化|性能优化、规则治理基础|todo|-|

---

## Phase 3 详细任务：精度重构

|任务|描述|依赖|状态|
|---|---|---|---|
|P3-01|TechStackDetector 全量扫描改造|P1-06|done|
|P3-02|主语言识别（基于 LOC）|P3-01|done|
|P3-03|项目类型识别（web/api/cli/library）|P3-01|done|
|P3-04|Rule Gating Engine 实现|P3-02|done|
|P3-05|Semgrep 文件级过滤（include/exclude/lang）|P3-04|done|
|P3-06|禁止 literal 规则（AST 强制）|P3-05|todo|
|P3-07|Finding Budget 误报熔断机制|P3-04|done|
|P3-08|CodeQL 失败降级策略|P2-02|done|

---

## Phase 4 详细任务：裁决统一

|任务|描述|依赖|状态|
|---|---|---|---|
|P4-01|引入统一 final_score 模型|P3-08|todo|
|P4-02|Exploitability 成为主裁决权重|P4-01|todo|
|P4-03|禁止 confirmed/not_exploitable 冲突|P4-02|todo|
|P4-04|语义级去重（AST hash）|P2-10|todo|
|P4-05|统一报告状态模型（informational/conditional/exploitable）|P4-02|todo|

---

## 里程碑

|里程碑|交付物|能力描述|状态|日期|
|---|---|---|---|---|
|v0.1|L1 + L2|支持源码获取、技术栈识别、攻击面探测|done|2026-02|
|v0.2|+ Semgrep|支持模式匹配扫描|done|2026-02|
|v0.2.1|+ CodeQL|支持数据流分析|done|2026-02|
|v0.2.2|+ Agent|支持 AI 驱动深度审计|done|2026-02|
|v0.3|L3 完整|三引擎 + 多轮审计|done|2026-02|
|v0.4|精度重构|Rule Gating + 语言重构|dev|-|
|v0.5|裁决统一|Exploitability 主导裁决|todo|-|
|v0.6|企业稳定版|高精度、低误报、CI 可用|todo|-|

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
|风险|CodeQL 构建失败|中|存在|降级机制|
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

### 核心设计理念（v0.4 版本）

1. **攻击面驱动扫描**：规则执行由项目真实特征决定
    
2. **Exploitability 优先裁决**：不可利用不允许标记 confirmed
    
3. **规则前置裁剪**：禁止规则误报爆炸
    
4. **语义级去重**：基于 AST 而非行号
    
5. **精度优先于召回**
    

---

### 开发优先级原则

1. 先解决误报爆炸，再优化性能
    
2. Rule Gating 是当前最高优先级
    
3. 主语言识别是误报压制基础
    
4. 裁决统一优先于新功能开发
    

---

## 当前焦点

|字段|值|
|---|---|
|**阶段**|Phase 3 - 精度重构|
|**当前进度**|Phase 3 核心任务已全部完成|
|**下一步**|P3-06 禁止 literal 规则 / Phase 4 裁决统一|
|**重点模块**|Rule Gating + File Filtering + Finding Budget + Fail-Safe|
|**目标**|三级裁剪 + 容错机制，90%+ 噪声消除|