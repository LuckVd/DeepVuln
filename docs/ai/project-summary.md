# Project Summary

Status: Phase 17 - web-only（CLI 已移除，仅 Web 接口）

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

- Phase 17（进行中，web-only）：已完成 D4 / Web-semgrep / D1(ScanPipeline) / D5(打分统一) / E5(AI 补漏逻辑漏洞) / D3(断点续扫 findings 持久化)，并修了 `checkpoint_service`/`phase_manager` 两个阻塞 bug；已 push origin（HEAD `8cb6277`）
- 待办：D6（CPG CFG 可达性，P3 低优先大工程）— `path_finder/finder.py` 的 `reaches_sink` 仍固定 `True`
- 环境：本机 1.9GB 内存，无 CodeQL；测试用 sqlite；LLM 走 GLM 兼容端点
- 上一个目标：Phase 16 全面质量修复（已完成，commit `87c7083`）
