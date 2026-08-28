# Project Summary

Status: Phase 19 执行中（检测基准与 P/R 评测体系，P1–P4 开放问题全关）- web-only（CLI 已移除，仅 Web 接口）

## Recent Maintenance Notes

- **2026-08-28**: **P1–P4 全部修复 + P19 增量收官**（9 个 commit：af95bb6→c8f72ee）：P1 semgrep 零 findings（HOME 不可写+相对路径双根因）/ P3 suspicious FP 切除 / P4 java-cmdi + LLM 模型迁移 deepseek-v4-flash / P2 CPG 可达性三层（UTF-8 字节错位、Servlet 识别、sink 白名单+语言专属 pattern）——三语言攻击路径全通；P19 semgrep 噪声规则剔除（run3 10/21 FP 零 TP）。**第二轮 mini 基线：TP=9/R=1.0/safe FP=0，conf≥0 F1 0.462、conf≥0.8 F1 0.692，token 135,273**。下一步：第三轮基线（重启服务量化 P19+P2 联合收益）→ owasp-subset 150 例。详见 `docs/ai/current-goal.md` 与 `change-log.md`。
- **2026-08-26/27**: benchmark 基建落地；AST 规则 7 条清零；首轮 mini 基线（R 0.889/P 0.235/F1 0.372）；P1/P3/P4 修复。
- Phase 18（已关闭 2026-08-25）：精度链路接通 + 三语言可达性补齐 + 全量体检修复，test_l3 全绿 2079/0。

## Purpose

DeepVuln 是多层（L1 情报 + L3 分析）架构的智能漏洞挖掘系统，以 AI Agent 为主、SAST 工具为辅，实现攻击面驱动与可利用性优先裁决。支持 Semgrep、CodeQL、AST Engine（tree-sitter）和 LLM Agent 四引擎联合扫描，多轮审计，增量分析。

## Core Modules

- **L1 Intelligence**: 源码获取、工作空间管理、技术栈识别、攻击面探测、威胁情报同步、构建配置分析
- **L3 Analysis**: 四引擎执行（Semgrep/CodeQL/AST Engine/Agent）+ AI 补漏逻辑漏洞检测（E5）、多轮审计、裁决融合、对抗验证、增量扫描
- **Pipeline（D1）**: `ScanPipeline` 9 阶段编排（source→engine→verify→logic_vuln→adjudication→adversarial→merge→token），含断点续扫（D3）
- **Core**: 规则裁剪引擎、误报熔断、统一评分、文件过滤
- **Web**: 唯一用户入口（`scan_orchestrator` + `pipeline` + FastAPI + Celery 异步任务，web-only，CLI 已移除）

## Tech Stack

- Python 3.10+
- LLM API (OpenAI/兼容端点)
- Semgrep (模式匹配)
- CodeQL (数据流分析)
- Tree-sitter (AST 解析)
- pytest + pytest-asyncio (测试)

## Key Boundaries

- `src/layers/l1_intelligence/` - 情报收集与工作空间
- `src/layers/l3_analysis/` - 静态分析与引擎
- `src/layers/pipeline/` - 扫描阶段编排（D1 ScanPipeline）
- `src/core/` - 基础设施与通用工具
- `src/web/` - Web 接口与扫描编排（唯一入口，web-only）
- `docs/ai/roadmap.md` - 项目路线图（事实来源）
- `docs/ai/current-goal.md` - 当前目标记录

## Recent Maintenance Notes

- Phase 18（进行中，web-only）：基于 2026-06-20 全量实现审查，修复"声称完成但生产路径未生效"的精度核心。**第一~五批均已完成并 push**（最新 `7f6c242`，本地=origin）：P0 精度链路、P1 Java/P2-Go call_graph（**三语言 py/go/java CPG 可达性端到端通**）、P4 语言收敛 + CodeQL 类型、P5 续扫完整（阶段命名统一 / resume 恢复实例状态 / 落库去重 / pause 接 revoke）、P7 可靠性（C3 git timeout / C4 baseline 覆盖 / C5 增量 import / C7 budget 排序 / 删死代码 + **C6 引擎级 checkpoint Tier1**）、P6 低风险子项（LIKELY→MEDIUM / 删 1155 行对抗死机械 / strategy_library 接进 prompts）、P8 测试真实性。全 test_l3 **2186 passed / 23 既有失败（零回归，2026-06-21 实跑确认）**。
- 剩余：**P6 硬骨头**（子项1 gatekeeper 接线需先修 5 个既有失败；子项2 `min_evidence_dimensions` 是精度/召回权衡待定）+ **P3 可达性质量**（需条件求值设计）+ C6 Tier2。安全组降级（单用户内网）、放弃 C/C++。
- 关键约束：web-only（CLI 已移除）、放弃 C/C++ 聚焦 py/go/java、安全组降级（单用户内网）、本机无 CodeQL（保引擎降级路径）。
- 环境：本机 1.9GB 内存，无 CodeQL；测试用 sqlite；LLM 走 GLM 兼容端点。
- 上一个目标：Phase 17 — AI 与静态最优结合的深化（status: completed，commit `fca0c22`；其"全部 done"结论已被 Phase 18 审查修正——多项功能实际未生效，正是 Phase 18 要接通的）。
