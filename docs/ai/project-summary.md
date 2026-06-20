# Project Summary

Status: Phase 18（精度链路接通 + 三语言可达性）- web-only（CLI 已移除，仅 Web 接口）

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

- Phase 18（进行中，web-only）：基于 2026-06-20 全量实现审查，修复"声称完成但生产路径未生效"的精度核心。已完成第一/二批 + P6-eval 并 push（代码 `4409eb4` + docs `a8eba71`，本地=origin）：P0 精度链路（四轮回填 candidate / 裁决映射属性名 / D5 confidence 同步）、P1 Java call_graph 注册、P4 语言收敛 + CodeQL 类型、P2-前置 CPG entry/callee/sink 连通、P2-Go go_builder+provider（**三语言 py/go/java CPG 可达性端到端通**）、P6-eval（critical/high 防漏报）。全 test_l3 **2195 passed / 23 既有失败（零回归）**。
- 第三批待做：P5 续扫完整（阶段命名统一 / resume 恢复实例状态 / `_finalize_results` upsert 去重 / `pause_scan` 接 revoke）；P7 可靠性（git clone 超时 / baseline 覆盖判定 / 增量 import 拼接 / budget 排序）；P3 可达性质量（需条件求值）；P6 对抗接线（gatekeeper / min_evidence_dimensions / LIKELY→MEDIUM / 1926 行 enhanced 层去留）。
- 关键约束：web-only（CLI 已移除）、放弃 C/C++ 聚焦 py/go/java、安全组降级（单用户内网）、本机无 CodeQL（保引擎降级路径）。
- 环境：本机 1.9GB 内存，无 CodeQL；测试用 sqlite；LLM 走 GLM 兼容端点。
- 上一个目标：Phase 17 — AI 与静态最优结合的深化（status: completed，commit `fca0c22`；其"全部 done"结论已被 Phase 18 审查修正——多项功能实际未生效，正是 Phase 18 要接通的）。
