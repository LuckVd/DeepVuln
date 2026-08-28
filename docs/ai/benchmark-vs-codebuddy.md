# 方案对标：Codebuddy Security vs DeepVuln

> **日期**: 2026-08-28
> **背景**: 用户提供了腾讯 Codebuddy Security 一次真实运行（2026-08-06，扫描 webf1 Java 靶场，32 分钟，检出 2 高危）的逆向研究报告（含 976 行执行日志、HTML 报告、源码靶场三份原始材料），要求与本项目（DeepVuln）进行方案对比并沉淀结论。
> **性质**: 对标分析文档（非代码变更）；"借鉴项"编号为 P-A1 ~ P-A4，供路线图排期参考。

---

## 〇、一句话定位差异

> **Codebuddy** 是"**攻击面切片 → 任务化 AI 审计**"的 SaaS 流水线：把仓库切成 5 个模块任务再两阶段审计，靠**编排组合**（确定性引擎锚点 + 独立复核 + 自动补丁）取胜。
>
> **DeepVuln** 是"**四轮多角色审计 + 证据门裁决**"的可部署平台：靠**可利用性优先裁决**（不可利用不允许 confirmed）和**系统化基准评测**（P/R/F1 迭代）取胜。

两者同属"确定性引擎兜底 + AI 深度审计 + 交叉验证"大框架，但**组织 AI 的方式**与**信任模型**根本不同。

---

## 一、架构编排对比

| 维度 | Codebuddy Security | DeepVuln |
|---|---|---|
| 部署形态 | 腾讯闭源 SaaS（Node.js 容器服务） | 开源自部署 Web 平台（FastAPI + Celery + React） |
| 编排器 | Pipeline 状态机（阶段顺序依赖、阶段内并行） | `ScanPipeline` 共享编排（阶段级进度广播 + checkpoint） |
| 审计组织 | **威胁建模先切 ≤5 个模块任务** → 每任务"探索+验证"两阶段 → 任务池并发(=2) | `RoundController` 四轮：候选回填 → 深度审计 → 对抗辩论 → 验证落分（finding 级编排） |
| AI 角色 | 5 组组件共用 codebuddy CLI（hy3），仅换 prompt/上下文 + verification 层 | 引擎级 agent + verification 层 attacker/defender/arbiter 三角色 |
| 确定性引擎 | Xcheck（腾讯 TCA quickscan） | Semgrep + CodeQL + AST Engine（tree-sitter） |
| 补丁 | **独立 patch 阶段，每漏洞产修复 Diff** | finding 携带 `remediation` 修复建议文本（无独立 Diff 流水线） |
| 评测 | 无系统性基准（单次案例复盘） | **benchmarks/ 体系**：mini 9 case + OWASP 150 例 + P/R/F1 基线迭代 |

---

## 二、核心机制逐项对比

### 1. 攻击面 / 威胁建模（最大的结构性差异）

| | Codebuddy | DeepVuln |
|---|---|---|
| 做法 | 威胁建模先行（Project Analysis → Threat Intel → **Attack Surface 切分**），产出 5 个带风险语义的**模块任务**（`<路径>/<组件>-<风险动词>`），任务可并行/续跑/失败隔离 | 攻击面探测（L1）产出攻击面标签 → **驱动规则门控** + FilePreFilter（call graph 可达性过滤） |
| 核心思想 | 全仓 → 5 个聚焦任务：**按模块切**，上下文 7-12K 字符，任务池并行审计 | 全仓 → 按文件过滤：**按文件筛**，剩余文件进 agent 分析 |
| 关键区别 | **任务级并行 + 失败只损失单模块 + 每任务独立 checkpoint** | 攻击面不生成"审计任务清单"，AI 审计粒度为文件/候选，无任务池并发 |

分水岭：Codebuddy 把"切攻击面"当第一等公民（先花 2 分钟 5.4K token 切模块再干活）；DeepVuln 把攻击面当**过滤器与打分维度**（规则启停、文件准入、攻击面得分），AI 侧无任务化切分。

### 2. AI 审计组织：两阶段任务模型 vs 四轮多角色

| | Codebuddy | DeepVuln |
|---|---|---|
| 结构 | 每任务 Phase1 探索（ContextStore 精简模板）→ 同位置去重 → Phase2 对抗验证 | Round1 候选回填 → Round2 深度审计 → **Round3 对抗辩论** → Round4 验证落分 |
| 去重 | 任务内 `Self-dedup: merged 1/5 same-location findings` | 两阶段混合去重（P6-17 位置聚类 + LLM 判断；P8-08e 内存级前置去重） |
| 轮次支持 | 任务内两阶段 + `--rounds=N` 跨轮追加 | 内置多轮状态机（TerminationDecider 终止决策） |
| 上下文工程 | ContextStore 三件套（project-context / threat-intel / custom-instructions），有上下文用精简模板省 token | 结构化上下文（调用链、依赖、数据流标记、AST 结构）注入 agent prompt |

DeepVuln 轮次能力 ≥ Codebuddy rounds，但 Codebuddy 的"探索/验证两阶段 + 精简模板"在单任务 token 效率上更明确。

### 3. 对抗审查（DeepVuln 论证结构更深，Codebuddy 进程隔离更强）

| | Codebuddy | DeepVuln |
|---|---|---|
| 形态 | 每 confirmed finding 起**独立进程**复核（发现者/审查者进程隔离） | verification 层 **attacker / defender / arbiter 三角色** + 多轮辩论（rebuttal 反驳机制） |
| 方法 | 证有（构建装配证据防死代码）+ 证无（防护关键词全仓 grep）+ 核查锚点表 | attacker 构造 PoC 证可利用；defender 找 sanitizer/防护；arbiter 中立裁决 + 辩论史评估 |
| 门控 | 无显式准入门槛 | **VerificationGatekeeper**：低置信+低严重级跳过对抗验证、强证据+高置信自动确认 |

互补结论：DeepVuln 可抄"每 finding 独立进程复核"（隔离度），Codebuddy 可抄"attacker/defender/arbiter + 门控准入"（论证结构）。

### 4. 交叉验证与裁决（DeepVuln 核心优势区）

| | Codebuddy | DeepVuln |
|---|---|---|
| 验证 | xcheck_verify：AI findings 与 Xcheck 编号(280/281) 按**类别**交叉映射，已确认即跳过重复验证 | 多引擎融合 + 去重仲裁 + 四轮证据累积 |
| 裁决 | **置信度两步法**：初始 90-100 → 自我证伪调整（95→92，−3 折损） | **多维度评分 + 证据门**：codeql/taint/reachability/attack_surface 加权 → `EXPLOITABLE` 须 confirming 级硬证据 |
| 信任模型 | "确定性引擎佐证"（结构性对冲幻觉） | "**可利用性优先裁决**"（不可利用 → 不许 confirmed）+ 证据分级（confirming/supporting） |

理念差异最尖锐处：Codebuddy 输出"**高可信漏洞 + 补丁**"（置信度文化）；DeepVuln 输出"**经可利用性验证的裁决**"（状态机文化）。DeepVuln 证据门防误报更硬；Codebuddy 的补丁阶段是 DeepVuln 缺失能力。

### 5. 检查点 / 续扫

| | Codebuddy | DeepVuln |
|---|---|---|
| 机制 | `audit-state.json` 每任务完成后 flush（**失败也 flush**）；`--stop-after / --resume / --continue --rounds` 三种用法 | 阶段级 checkpoint + **引擎级增量存档**（CodeQL 跑完即存档，崩溃恢复不重跑）；Celery pause/revoke 真停语义 |
| 特点 | 任务粒度恢复 + 跨轮追加 | 引擎粒度增量 + Web 生命周期管理（2026-08-28 已修 worker init_db 的 N5） |

Codebuddy"失败也推进检查点"值得 DeepVuln 学习。

### 6. 成本控制

| | Codebuddy | DeepVuln |
|---|---|---|
| 手段 | ① `--print` 非交互 + 重试(2s×2)；② ContextStore 精简模板；③ **Gate 适用性门控**（logicagent 482K token 止损）；④ cache_read 利用 | ① LLM trace 记账（`DEEPVULN_LLM_TRACE`）；② 文件级预过滤；③ VerificationGatekeeper 跳过低价值对抗验证；④ suspicious 抽离审查队列 |
| 实测 | ~610K token/次（logicagent 固定 79%，无论检出与否） | run4 9 例 mini ≈109.2K（≈12K/例），30 调用 0 错误 |

成本画像相反：Codebuddy 的固定成本大头是"专项组件判定不适用"（防更贵浪费）；DeepVuln 成本随文件/候选增长，靠过滤前置。**Gate 门控是 DeepVuln 最值得抄的设计**。

### 7. 失败处理

| | Codebuddy | DeepVuln |
|---|---|---|
| 模式 | 任务池隔离：4/5 任务失败但 1 成功出全部漏洞；**仅单调用级重试**（2s×2），无任务级重试 | 引擎级降级路径 + readiness 门控 + failed_engines 记录；P1/P4 修复体现韧性（semgrep 启动崩溃、provider 503、模型下线均兜住） |
| 教训（报告自曝） | 任务级应有完整重试/降级策略（失败模块降级给规则集或下轮重跑） | 引擎故障不阻塞主流程 |

### 8. 评测体系（DeepVuln 独有）

| | Codebuddy | DeepVuln |
|---|---|---|
| 基准 | 无（webf1 仅是被扫靶场，未作回归基准） | **benchmarks/ 全套**：mini 9 case（vuln/safe 成对 truth.json）、OWASP 150 例、run_benchmark.py selfcheck+api、compare_runs.py 跨轮对比 |
| 量化 | token/耗时/失败分布有统计，**无检出质量指标** | **P/R/F1 基线迭代**：R 0.889→1.0、safe-FP 26→0、FP 21→10，每轮修复量化回执 |
| 验收 | "webf1 检出 2 confirmed"是报告**建议**的复刻验收 | 已内化：truth.json + selfcheck + 基线对比 + 残余 FP 分类治理（N3） |

DeepVuln 把"检出质量"纳入闭环：三轮基线 Recall 100%、safe 零 FP——这是对 Codebuddy 方案最显著的超出。

---

## 三、互相可借鉴清单（供路线图排期）

### DeepVuln ← Codebuddy（借鉴项，编号 P-A1 ~ P-A4）

| # | 借鉴项 | 说人话 | 对应现状短板 |
|---|---|---|---|
| **P-A1** | **攻击面任务化切分** | 攻击面探测产出 N 个带风险语义的审计任务（`<路径>/<组件>-<风险动词>`）+ 任务池并发 + 每任务独立 checkpoint，失败只损失单模块 | DeepVuln 现为文件级过滤，无任务化调度 |
| **P-A2** | **Gate 适用性门控** | 专项检测前先判"本项目是否有必要前提"（如无认证机制则不适用越权检测），不适用立即止损 | 无跨组件适用性门控 |
| **P-A3** | **独立进程对抗复核** | 为每个 confirmed finding 起隔离进程二次复核（证有+证无+锚点表模板） | attacker/defender/arbiter 为进程内角色，隔离度弱 |
| **P-A4** | **自动补丁 Diff 阶段** | `remediation` 文本升级为"读源码 → 修复 Diff + 工作量评估"流水线阶段 | 现只有 finding.remediation 建议字段 |

### Codebuddy ← DeepVuln（反向借鉴，仅供参考）

1. **证据门裁决**：EXPLOITABLE 必须有 confirming 级硬证据（CodeQL 数据流/taint），非置信度文化
2. **三角色辩论**：attacker/defender/arbiter + rebuttal，比单进程复核论证结构更深
3. **系统化基准**：webf1 式靶场升级为 mini/OWASP 真值库 + P/R/F1 回归（回答"怎么证明系统准"）
4. **review 队列 + 逃生阀**：低置信 suspicious 条目抽离审查队列，不污染正式报告

---

## 四、结论

核心差异浓缩为三句话：

1. **AI 怎么被组织**：Codebuddy = 攻击面切片成任务池（并行、隔离、续跑）；DeepVuln = 四轮多角色状态机（候选→深度→辩论→落分）。
2. **怎么信任 AI 产出**：Codebuddy = 置信度 + 独立进程复核 + 确定性引擎佐证；DeepVuln = **可利用性裁决 + 证据门硬门槛** + 三角色辩论证伪。
3. **怎么证明自己准**：Codebuddy 靠架构设计与单次复盘；DeepVuln 靠 **P/R/F1 基准闭环**（领先一个身位）。

对 DeepVuln：最大可借鉴是 **任务化攻击面切分（P-A1）+ Gate 门控（P-A2）+ 自动补丁（P-A4）**，恰好补齐"文件级过滤、无适用性门控、补丁只有建议文本"三块短板。
对 Codebuddy：DeepVuln 的基准评测体系是现成答案。

---

## 附：原始素材

- 调研报告（用户提供）：腾讯 Codebuddy Security 逆向分析——组件构成/核心机制/复刻路线图（2026-08-06 运行实录）
- 三份原始材料：`execution-9x6K9Kf6rgeS-logs.txt`（976 行日志）、`webf1-report-2026-8-6-11-26-58.zip`（HTML 报告）、`webf1/` 源码靶场（素材位于用户侧 ~/Projects/test/，未入库）
- 本项目对照事实（本会话实测）：run4 第三轮基线（FP 21→10 / F1 0.643 / R 1.0）、N5 checkpoint 修复、scoring/verification/rounds 代码结构