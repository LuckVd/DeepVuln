# Project Summary

Status: Phase 6.5 - code-audit 集成

## Purpose

DeepVuln 是三层核心架构智能漏洞挖掘系统，以 AI Agent 为主、SAST 工具为辅，实现攻击面驱动与可利用性优先裁决。支持 Semgrep、CodeQL 和 LLM Agent 三引擎联合扫描，多轮审计，增量分析。

## Core Modules

- **L1 Intelligence**: 源码获取、工作空间管理、技术栈识别、攻击面探测、威胁情报同步
- **L3 Analysis**: 三引擎执行（Semgrep/CodeQL/Agent）、多轮审计、裁决融合、增量扫描
- **Core**: 规则裁剪引擎、误报熔断、统一评分、文件过滤
- **CLI**: 交互式命令行界面，支持 git/local/scan/intel 等子命令

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
- `src/core/` - 基础设施与通用工具
- `src/cli/` - 用户交互入口
- `docs/ROADMAP.md` - 项目真实路线图（事实来源）

## Recent Maintenance Notes

- Phase 6 完成：扫描结果状态模型、CodeQL 失败诊断
- Phase 6.5 待开始：P6-03 证据强度字段引入
- Docker 环境已强化，支持 CodeQL 执行
- 上一个目标（CodeQL 容器化稳定）已完成
