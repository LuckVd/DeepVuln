# DeepVuln

> 七层智能漏洞挖掘系统 - AI 驱动的高精度代码安全分析平台

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 🎯 项目简介

DeepVuln 是一个**多层智能漏洞挖掘系统**，以 **AI Agent 为主、SAST 工具为辅**，实现**攻击面驱动**与**可利用性优先裁决**。

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

---

## 🔧 扫描引擎

| 引擎 | 技术 | 用途 | 状态 |
|------|------|------|------|
| **Semgrep** | 模式匹配 | 快速扫描已知漏洞模式 | ✅ |
| **CodeQL** | 数据流分析 | 污点追踪、深层语义分析 | ✅ |
| **AST Engine** | 树解析器 | 结构级代码理解、框架误用检测 | ✅ |
| **OpenCode Agent** | LLM (GPT-4/GLM) | 业务逻辑分析、上下文理解 | ✅ |

### 支持的语言

- **Python**, **JavaScript/TypeScript**, **Java**, **Go**, **C/C++**
- **Ruby**, **PHP**, **C#**, **Swift**, **Kotlin**, **Rust**, **Scala**, **Lua**, **SQL**

---

## 🚀 Docker 快速开始

### 前置要求

1. 确保 LLM API 密钥已配置
2. 确保源代码目录有正确权限：
   ```bash
   chmod -R 777 /path/to/source/code
   ```

### 扫描模式

#### 1. 基础扫描 (3 引擎，无 LLM 验证)

```bash
docker run --rm \
  --network host \
  -e OPENAI_API_KEY="your-api-key" \
  -e OPENAI_BASE_URL="your-llm-endpoint" \
  -v /path/to/source:/target \
  -v /path/to/reports:/output \
  deepvuln:latest scan -p /target --base \
    --export "/output/$(date +%Y%m%d_%H%M%S)_base.txt"
```

#### 2. 完整扫描 (3 引擎 + LLM 验证 + 对抗辩论)

```bash
docker run --rm \
  --network host \
  --memory=6g \
  -e OPENAI_API_KEY="your-api-key" \
  -e OPENAI_BASE_URL="your-llm-endpoint" \
  -v /path/to/source:/target \
  -v /path/to/reports:/output \
  deepvuln:latest scan -p /target --full \
    --export "/output/$(date +%Y%m%d_%H%M%S)_full.txt" \
    --include-llm-details \
    --detailed
```

### CLI 参数

| 参数 | 说明 |
|------|------|
| `-p, --path` | 扫描目标路径 |
| `--base` | 基础扫描：Semgrep + CodeQL + Agent |
| `--full` | 完整扫描：+ LLM 验证 + 对抗辩论 |
| `--export` | 导出报告到文件 |
| `--include-llm-details` | 包含 LLM 分析详情 (去重推理、对抗裁决) |
| `--model` | LLM 模型名称 |
| `--force-codeql-all` | 强制 CodeQL 扫描所有检测到的语言 |
| `--detailed` | 输出详细漏洞信息 |
| `--skip-build` | 跳过 CodeQL 构建步骤 (降低准确率) |

---

## 🛠️ 开发设置

### 安装依赖

```bash
# 克隆仓库
git clone https://github.com/LuckVd/DeepVuln.git
cd DeepVuln

# 安装项目（开发模式）
pip install -e .[dev]

# 或使用 poetry
poetry install --with dev
```

### 运行测试

```bash
# 运行所有测试
pytest

# 运行特定测试
pytest tests/unit/test_l3/

# 查看覆盖率
pytest --cov=src --cov-report=html
```

### 代码质量检查

```bash
# 类型检查
mypy src/

# 代码格式化
ruff format src/

# Lint 检查
ruff check src/
```

---

## 📊 核心特性

### 1. LLM 智能语言决策 (Phase 7)

- 自动分析项目特征
- 智能选择最优扫描语言
- 平衡安全收益与资源消耗
- 支持时间预算机制

### 2. 前置防误报架构 (Phase 8)

| 组件 | 功能 |
|------|------|
| **FilePreFilter** | 文件级预过滤，跳过配置/测试/生成代码 |
| **StreamingValidator** | Finding 流式验证，即时过滤明显误报 |
| **InMemoryDeduplicator** | 内存级去重，同一漏洞只保留最高分 |
| **CodeQLPreFilter** | CodeQL 规则预过滤，降低泛化规则误报 |
| **VerificationGatekeeper** | 对抗验证准入门槛，节省 40% 资源 |

### 3. AST Engine 结构分析

- **Tree-sitter** 多语言解析
- **危险 API 检测** (eval/exec/system)
- **加密误用检测** (md5/sha1/DES)
- **反序列化检测** (pickle/yaml)
- **框架规则** (Flask/Django/Express/Spring)

### 4. AI Agent 结构化上下文

- 调用链分析 (谁调用此函数？是否入口点？)
- 依赖提取 (导入类/函数的实现代码)
- 数据流标记 (用户输入 vs 内部数据)
- AST 结构信息 (函数结构、变量作用域、控制流)

---

## 📈 里程碑

| 版本 | 能力 | 状态 |
|------|------|------|
| v0.1 | L1 基础能力 | ✅ done |
| v0.2 | L3 三引擎 | ✅ done |
| v0.3 | 多轮审计 | ✅ done |
| v0.4 | 精度重构 | ✅ done |
| v0.5 | 可利用性主导裁决 | ✅ done |
| v0.6 | 精度深化 | ✅ done |
| v0.7 | 报告可信度 | ✅ done |
| v0.75 | CodeQL 智能构建 | ✅ done |
| v0.8 | AST Engine + 前置防误报 | ✅ done |
| v0.9 | CPG 基础 | 🚧 todo |
| v1.0 | 企业稳定版 | 🚧 todo |

---

## 📁 项目结构

```
DeepVuln/
├── src/
│   ├── cli/                    # CLI 入口
│   ├── core/                   # 核心模块 (配置、日志、异常)
│   ├── layers/
│   │   ├── l1_intelligence/    # L1: 情报层
│   │   │   ├── attack_surface/  # 攻击面探测
│   │   │   ├── tech_stack_detector/  # 技术栈识别
│   │   │   ├── threat_intel/    # 威胁情报
│   │   │   └── workspace/       # 工作空间管理
│   │   └── l3_analysis/        # L3: 分析层
│   │       ├── engines/        # 扫描引擎
│   │       │   ├── semgrep.py
│   │       │   ├── codeql.py
│   │       │   ├── opencode_agent.py
│   │       │   └── ast_engine/  # AST 引擎
│   │       ├── decision/       # LLM 决策
│   │       ├── build/          # 构建系统
│   │       ├── pre_filter/     # 前置防误报
│   │       ├── verification/   # 对抗验证
│   │       └── adjudication/   # 裁决融合
│   └── models/                 # 数据模型
├── rules/                      # 规则文件
│   ├── semgrep/               # Semgrep 规则
│   └── ast_query/             # AST 查询规则
├── tests/                     # 测试
├── docs/                      # 文档
├── config.example.toml        # 配置示例
├── Dockerfile                 # Docker 镜像
├── docker-compose.yml         # Docker Compose
└── pyproject.toml            # 项目配置
```

---

## ⚙️ 配置

创建 `config.local.toml`:

```toml
[llm]
# LLM 提供商配置
provider = "openai"  # openai, azure, ollama, custom
model = "gpt-4"
base_url = "https://api.openai.com/v1"
api_key = "your-api-key-here"

# 并发控制
max_concurrent_requests = 5  # GLM-4.5 推荐值
timeout = 120

[scan]
# 扫描配置
timeout = 300
max_concurrent_files = 10
```

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
