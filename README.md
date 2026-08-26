# DeepVuln

> 多层智能漏洞挖掘系统 - AI 驱动的高精度代码安全分析平台（L1 情报层 + L3 分析层 + 共享 ScanPipeline 编排）

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 🎯 项目简介

DeepVuln 是一个**多层智能漏洞挖掘系统**，以 **AI Agent 为主、SAST 工具为辅**，实现**攻击面驱动**与**可利用性优先裁决**。

> **部署形态**: 本项目为 **Web 服务**（FastAPI + Celery + React 前端），通过 Web API 提交与管理扫描。CLI 已移除。

### 核心理念

- **攻击面驱动扫描** - 规则执行由项目真实特征决定
- **可利用性优先裁决** - 不可利用不允许标记 confirmed
- **精度优先于召回** - 宁可漏报，不可误报
- **LLM 智能决策** - 让 LLM 决定最优扫描策略

---

## 🏗️ 系统架构

```
┌─────────────────────────────────────────────────────────────────┐
│                         DeepVuln 架构                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Web 服务层 (src/web)                                     │  │
│  │  • FastAPI (REST + WebSocket)  • Celery Worker            │  │
│  │  • React 前端                  • 断点续扫 checkpoint       │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              ↓                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  L1: Intelligence Layer (情报层)                          │  │
│  │  • 源码获取 • 技术栈识别 • 攻击面探测 • 威胁情报        │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              ↓                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  L3: Analysis Layer (分析层)                             │  │
│  │  ┌─────────────┬─────────────┬─────────────┬───────────┐  │  │
│  │  │  Semgrep   │   CodeQL    │  AST Engine  │  Agent   │  │  │
│  │  │  模式匹配   │  数据流分析  │  结构分析     │  AI审计   │  │  │
│  │  └─────────────┴─────────────┴─────────────┴───────────┘  │  │
│  │                          ↓                                  │  │
│  │  ┌─────────────────────────────────────────────────────┐   │  │
│  │  │  Multi-Round Adjudication (多轮裁决)            │   │  │
│  │  │  • Exploitability 评估 • 误报压制 • 去重          │   │  │
│  │  └─────────────────────────────────────────────────────┘   │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              ↓                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Reporting (报告层)                                       │  │
│  │  • 可利用性优先 • 证据质量 • 扫描透明度                │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

> **架构说明**: 扫描编排由共享的 `src/layers/pipeline/`(`ScanPipeline`) 统一驱动，
> 支持阶段级进度广播与基于检查点 (checkpoint) 的**断点续扫**；四轮多轮审计
> (Round 1-4) 通过 `RoundController` 编排；可利用性裁决采用**证据把关**
> （EXPLOITABLE 须有 CodeQL/taint/reachability 等 confirming 级硬证据）。

---

## 🔧 扫描引擎

| 引擎 | 技术 | 用途 | 状态 |
|------|------|------|------|
| **Semgrep** | 模式匹配 | 快速扫描已知漏洞模式 | ✅ |
| **CodeQL** | 数据流分析 | 污点追踪、深层语义分析 | ✅ |
| **AST Engine** | Tree-sitter | 结构级代码理解、框架误用检测 | ✅ |
| **OpenCode Agent** | LLM (GLM/GPT) | 业务逻辑分析、上下文理解 | ✅ |

### 支持的语言

- **核心支持**: Python、Go、Java（全链路：AST 规则 / CFG / CPG 可达性 / call graph）
- **AST 规则另覆盖**: JavaScript/TypeScript
- C/C++ 不在支持范围内

---

## 🚀 快速开始（Docker Compose）

### 前置要求

1. 确保 LLM API 密钥已配置（`OPENAI_API_KEY` / `OPENAI_BASE_URL`）
2. Docker 与 docker compose

### 启动 Web 服务

```bash
# 容器栈（PostgreSQL + Redis + Celery Worker + Web API）
docker compose -f docker-compose-web.yml up -d

# 或主机已有 PostgreSQL/Redis 时
docker compose -f docker-compose-web-host.yml up -d

# 健康检查
curl http://localhost:8000/api/v1/health
```

### 提交扫描

```bash
# 本地目录扫描
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-scan",
    "source_type": "local",
    "source_path": "/path/to/source",
    "scan_type": "full",
    "config": {"engines": ["semgrep", "codeql", "agent", "ast"]}
  }'

# 启动扫描
curl -X POST http://localhost:8000/api/v1/scans/{scan_id}/start

# 进度与结果
curl http://localhost:8000/api/v1/scans/{scan_id}
```

常用配置项（`config` 对象）：`engines` 引擎列表、`llm_verify` 可利用性验证、
`adversarial` 对抗验证、`llm_detect` LLM 攻击面检测。完整字段见
`src/web/models/schemas.py` 的 `ScanConfig`。

---

## 🛠️ 开发设置

### 安装依赖

```bash
git clone https://github.com/LuckVd/DeepVuln.git
cd DeepVuln

# 安装（含 web 与静态分析依赖）
pip install -e ".[web,analysis,dev]"
```

### 运行测试

```bash
# L3 分析层测试（当前基线：全绿）
python3 -m pytest tests/unit/test_l3 -q

# 全部测试
pytest
```

### 代码质量检查

```bash
# 类型检查
mypy src/

# Lint 检查
ruff check src/ --select F
```

---

## 📊 核心特性

### 1. 多轮审计与可利用性裁决

- Round 1-4 由 `RoundController` 编排（候选回填 → 深度审计 → 对抗辩论 → 验证落分）
- 统一打分链：多轮产出 `confidence/exploitability` → 裁决前计算 `final_score`
- 证据门：EXPLOITABLE 需要 confirming 级证据（CodeQL 数据流 / taint 可利用），
  单纯攻击面标签不可单独确认

### 2. 断点续扫

- 阶段级 checkpoint + 引擎级增量存档（CodeQL 跑完即存档，崩溃恢复不重跑）
- pause/revoke 语义正确：暂停真停 Celery 任务，恢复不丢引擎结果、不重复落库

### 3. AST Engine 结构分析

- **Tree-sitter** 多语言解析（Python/Go/Java/JS/TS）
- 危险 API 检测 (eval/exec/system)、加密误用 (md5/sha1)、反序列化 (pickle/yaml)
- 框架规则（Flask/Django/FastAPI/Express/Spring）+ CFG/CPG 可达性分析

### 4. AI Agent 结构化上下文

- 调用链分析 (谁调用此函数？是否入口点？)
- 依赖提取、数据流标记 (用户输入 vs 内部数据)、AST 结构信息
- 对抗辩论注入策略知识（按漏洞类型的绕过技巧 / 防御机制）

---

## 📈 里程碑

| 版本 | 能力 | 状态 |
|------|------|------|
| v0.1 - v0.8 | L1/L3 基础能力、多轮审计、精度重构、AST Engine | ✅ done |
| Phase 17-18 | 精度链路接通、三语言可达性补齐、续扫可靠性 | ✅ done |
| 体检修复 (2026-08) | 检测失效/部署/死代码清理（见 docs/ai/change-log.md） | ✅ done |
| v1.0 | 企业稳定版 | 🚧 todo |

---

## 📁 项目结构

```
DeepVuln/
├── src/
│   ├── core/                    # 跨层共享 (配置、日志、异常、共享模型)
│   ├── layers/
│   │   ├── pipeline/            # 共享扫描编排 (ScanPipeline + ScanPhase)
│   │   ├── l1_intelligence/     # L1: 情报层
│   │   │   ├── attack_surface/  #   攻击面探测
│   │   │   ├── tech_stack_detector/  # 技术栈识别
│   │   │   └── threat_intel/    #   威胁情报
│   │   └── l3_analysis/         # L3: 分析层
│   │       ├── engines/         #   Semgrep / CodeQL / Agent / ast_engine/
│   │       ├── rounds/          #   四轮审计
│   │       ├── scoring/         #   多维评分 + 证据门
│   │       ├── verification/    #   对抗验证 + gatekeeper
│   │       ├── adjudication.py  #   裁决融合
│   │       └── call_graph/ cpg 相关  # 可达性分析
│   └── web/                     # Web 服务层
│       ├── api/v1/              #   REST API
│       ├── services/            #   scan_executor / orchestrator / ...
│       ├── tasks/               #   Celery 任务
│       └── frontend/            #   React 前端
├── rules/                       # 规则文件 (semgrep / ast_query / codeql)
├── tests/                       # 测试
├── docs/                        # 文档 (含 docs/ai 工作流状态)
├── Dockerfile                   # 完整镜像（web 入口）
├── docker-compose-web.yml      # Web 容器栈
└── pyproject.toml               # 项目配置
```

---

## ⚙️ 配置

Web 服务通过环境变量配置（pydantic-settings，前缀见 `src/web/core/config.py`）：

```bash
# 数据库（注意前缀是 DEEPVULN_DB_，DATABASE_URL 不生效）
DEEPVULN_DB_URL=postgresql+asyncpg://deepvuln:deepvuln_password@localhost:5432/deepvuln

# Redis（Celery broker/backend）
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0

# LLM
OPENAI_API_KEY=your-api-key
OPENAI_BASE_URL=https://api.openai.com/v1

# 安全（JWT / API key / 限速）
DEEPVULN_SECURITY_JWT_SECRET=change-me-in-production
```

完整变量清单参考 `.env.web.example` 与 `src/web/core/config.py`。

---

## 🤝 贡献指南

欢迎贡献！请遵循以下步骤：

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

---

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

---

## 🔗 相关链接

- [项目路线图](docs/ROADMAP.md)
- [AI 工作流文档](docs/ai/)
- [更新日志](docs/CHANGELOG.md)

---

**DeepVuln** - 让漏洞挖掘更智能、更精准
