# DeepVuln 项目路线图

> 七层架构智能漏洞挖掘系统开发规划

---

## 项目概览

| 字段 | 值 |
|------|-----|
| **名称** | DeepVuln |
| **类型** | backend |
| **描述** | 七层架构智能漏洞挖掘系统，AI Agent 为主、SAST 工具为辅，实现从源码到漏洞报告的全流程自动化 |
| **技术栈** | Python 3.11+ / Docker / LLM API (OpenAI) / Semgrep / CodeQL |

---

## 目录结构

```
DeepVuln/
├── src/
│   ├── layers/                    # 七层架构实现
│   │   ├── l1_intelligence/       # L1 情报与资产层
│   │   ├── l2_understanding/      # L2 项目理解层
│   │   ├── l3_analysis/           # L3 静态代码分析层
│   │   ├── l4_environment/        # L4 环境构建维护层
│   │   ├── l5_verification/       # L5 PoC验证执行层
│   │   ├── l6_fusion/             # L6 融合与决策层
│   │   └── l7_governance/         # L7 治理与知识沉淀层
│   ├── core/                      # 核心公共模块
│   │   ├── config/                # 配置管理
│   │   ├── logger/                # 日志系统
│   │   └── exceptions/            # 异常定义
│   ├── models/                    # 数据模型
│   └── cli/                       # 命令行入口
├── rules/                         # 规则库
│   ├── semgrep/                   # Semgrep 规则
│   ├── codeql/                    # CodeQL 查询
│   └── custom/                    # 自定义规则
├── templates/                     # 模板文件
│   ├── dockerfiles/               # Dockerfile 模板
│   └── reports/                   # 报告模板
├── tests/                         # 测试用例
│   ├── fixtures/                  # 测试项目
│   └── unit/                      # 单元测试
├── docs/                          # 文档
└── deploy/                        # 部署配置
```

---

## 模块规划

### 按层级划分

| 模块 | 路径 | 功能 | 优先级 |
|------|------|------|--------|
| L1-Intelligence | `src/layers/l1_intelligence/` | 源码获取、工作空间管理、情报同步 | P0 |
| L2-Understanding | `src/layers/l2_understanding/` | 技术栈识别、代码结构解析、攻击面探测 | P0 |
| L3-Analysis | `src/layers/l3_analysis/` | 审计策略、多轮审计、三引擎执行 | P0 |
| L4-Environment | `src/layers/l4_environment/` | Docker 构建、环境池管理 | P1 |
| L5-Verification | `src/layers/l5_verification/` | PoC 生成、沙箱执行、崩溃监控 | P1 |
| L6-Fusion | `src/layers/l6_fusion/` | 去重引擎、优先级排序、报告生成 | P1 |
| L7-Governance | `src/layers/l7_governance/` | 规则库管理、度量分析、反馈优化 | P2 |

### 按组件划分

| 组件 | 所属层 | 路径 | 优先级 |
|------|--------|------|--------|
| 资产获取器 | L1 | `l1_intelligence/fetcher.py` | P0 |
| 工作空间管理器 | L1 | `l1_intelligence/workspace.py` | P0 |
| 技术栈识别器 | L2 | `l2_understanding/tech_detector.py` | P0 |
| 攻击面探测器 | L2 | `l2_understanding/attack_surface.py` | P0 |
| 审计策略引擎 | L3 | `l3_analysis/strategy_engine.py` | P0 |
| Semgrep 引擎 | L3 | `l3_analysis/engines/semgrep.py` | P0 |
| CodeQL 引擎 | L3 | `l3_analysis/engines/codeql.py` | P0 |
| OpenCode Agent | L3 | `l3_analysis/engines/opencode_agent.py` | P0 |
| 多轮审计控制器 | L3 | `l3_analysis/round_controller.py` | P0 |
| Dockerfile 生成器 | L4 | `l4_environment/dockerfile_gen.py` | P1 |
| 环境池管理器 | L4 | `l4_environment/pool_manager.py` | P1 |
| PoC 生成器 | L5 | `l5_verification/poc_generator.py` | P1 |
| 沙箱执行器 | L5 | `l5_verification/sandbox.py` | P1 |
| 去重引擎 | L6 | `l6_fusion/deduplicator.py` | P1 |
| 报告生成器 | L6 | `l6_fusion/report_generator.py` | P1 |
| 规则库管理器 | L7 | `l7_governance/rule_manager.py` | P2 |
| 度量分析器 | L7 | `l7_governance/metrics.py` | P2 |

---

## 开发阶段

| 阶段 | 目标 | 核心交付 | 状态 | 预计完成 |
|------|------|----------|------|----------|
| Phase 1 | 基础设施搭建 | L1 + L2 完整实现 | done | 2026-02 |
| Phase 2 | 核心分析能力 | L3 三引擎 + 多轮审计 | todo | - |
| Phase 3 | 环境与验证 | L4 环境池 + L5 PoC 执行 | todo | - |
| Phase 4 | 结果处理 | L6 去重 + 报告生成 | todo | - |
| Phase 5 | 治理优化 | L7 规则库 + 度量 + 反馈 | todo | - |
| Phase 6 | 集成测试 | 完整流程验证、性能优化 | todo | - |

### Phase 1 详细任务：基础设施 (L1 + L2)

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P1-01 | 项目骨架搭建、配置系统 | - | done |
| P1-02 | Git Clone / 本地路径加载 | P1-01 | done |
| P1-03 | 工作空间管理（创建/清理） | P1-02 | done |
| P1-04 | 威胁情报同步接口 | P1-01 | done |
| P1-05 | Git 历史分析器 | P1-02 | done |
| P1-06 | 技术栈识别（语言/框架/中间件） | P1-02 | done |
| P1-07 | 代码结构解析（AST/调用图） | P1-06 | done |
| P1-08 | 攻击面探测器 | P1-07 | done |
| P1-09 | 安全机制提取器 | P1-07 | done |
| P1-10 | 构建配置分析器 | P1-06 | done |

### Phase 2 详细任务：核心分析 (L3)

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P2-01 | Semgrep 引擎集成 | P1-06 | todo |
| P2-02 | CodeQL 引擎集成 | P1-07 | todo |
| P2-03 | OpenCode Agent 基础框架 | P1-08 | todo |
| P2-04 | 审计策略引擎（优先级计算） | P1-08 | todo |
| P2-05 | Agent 任务分配器 | P2-04 | todo |
| P2-06 | 第一轮：攻击面侦察 | P2-01, P2-02, P2-03 | todo |
| P2-07 | 第二轮：深度追踪 | P2-06 | todo |
| P2-08 | 第三轮：关联验证 | P2-07 | todo |
| P2-09 | 轮次终止决策器 | P2-06, P2-07, P2-08 | todo |
| P2-10 | 证据链构建器 | P2-07 | todo |

### Phase 3 详细任务：环境与验证 (L4 + L5)

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P3-01 | Dockerfile 模板库 | P1-06, P1-10 | todo |
| P3-02 | Dockerfile 智能生成 | P3-01 | todo |
| P3-03 | 镜像构建与缓存 | P3-02 | todo |
| P3-04 | 容器池管理器 | P3-03 | todo |
| P3-05 | 健康检查与重建机制 | P3-04 | todo |
| P3-06 | PoC 生成器 | P2-10 | todo |
| P3-07 | 沙箱执行器 | P3-04 | todo |
| P3-08 | 崩溃/异常监控 | P3-07 | todo |
| P3-09 | 验证结果记录器 | P3-08 | todo |

### Phase 4 详细任务：结果处理 (L6)

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P4-01 | 漏洞去重引擎 | P2-10, P3-09 | todo |
| P4-02 | CVSS 优先级评分 | P4-01 | todo |
| P4-03 | 漏洞报告模板 | P4-01 | todo |
| P4-04 | 报告生成器（JSON/HTML/Markdown） | P4-02, P4-03 | todo |
| P4-05 | 修复建议生成 | P4-04 | todo |

### Phase 5 详细任务：治理优化 (L7)

| 任务 | 描述 | 依赖 | 状态 |
|------|------|------|------|
| P5-01 | 规则库存储与版本管理 | P2-01, P2-02 | todo |
| P5-02 | 规则效果评估 | P4-01 | todo |
| P5-03 | 度量指标采集 | P1~P4 | todo |
| P5-04 | 反馈优化器 | P5-02 | todo |
| P5-05 | 知识图谱存储 | P5-04 | todo |

---

## 里程碑

| 里程碑 | 交付物 | 能力描述 | 状态 | 日期 |
|--------|--------|----------|------|------|
| v0.1 | L1 + L2 | 支持源码获取、技术栈识别、攻击面探测 | done | 2026-02 |
| v0.3 | + L3 | 支持三引擎分析、多轮审计、漏洞候选 | todo | - |
| v0.5 | + L4 + L5 | 支持环境构建、PoC 生成与验证 | todo | - |
| v0.7 | + L6 | 支持去重、优先级评分、报告生成 | todo | - |
| v0.9 | 完整流程 | 七层完整集成、CLI 可用 | todo | - |
| v1.0 | + L7 | 规则库治理、度量分析、反馈闭环 | todo | - |

---

## 当前焦点

> 与 `docs/CURRENT_GOAL.md` 保持同步

| 字段 | 值 |
|------|-----|
| **阶段** | Phase 2 - 核心分析能力 |
| **目标** | （待设置） |
| **重点模块** | L3-Analysis |

---

## 风险与依赖

### 技术依赖

| 类型 | 描述 | 影响 | 状态 |
|------|------|------|------|
| 依赖 | LLM API (OpenAI/本地模型) | 高 - Agent 核心能力 | 待确认 |
| 依赖 | Docker Engine 20.10+ | 高 - L4/L5 基础设施 | 待安装 |
| 依赖 | Semgrep CLI | 中 - L3 模式匹配 | 待安装 |
| 依赖 | CodeQL CLI 2.12+ | 中 - L3 数据流分析 | 待安装 |
| 依赖 | Python 3.11+ | 高 - 运行环境 | 待确认 |

### 技术风险

| 类型 | 描述 | 影响 | 状态 | 缓解措施 |
|------|------|------|------|----------|
| 风险 | LLM API 成本控制 | 高 | 待解决 | 设置 token 上限、使用本地模型备选 |
| 风险 | Docker 环境资源消耗 | 中 | 待解决 | 容器数量限制、资源配额 |
| 鑫险 | CodeQL 数据库构建失败 | 中 | 待解决 | 降级到 Semgrep + Agent 方案 |
| 风险 | PoC 执行逃逸风险 | 高 | 待解决 | 严格沙箱隔离、网络隔离 |

---

## 性能目标

| 指标 | 目标值 | 说明 |
|------|--------|------|
| 单项目分析耗时 | < 60min | 100K LOC 项目 |
| Agent 并行数 | 5 | 可配置 |
| 容器池大小 | 10 | 可配置 |
| 验证成功率 | > 60% | 确认漏洞 / 候选漏洞 |
| 误报率 | < 40% | L3 优化目标 |

---

## 备注

### 核心设计理念

1. **AI Agent 为主，SAST 工具为辅**：OpenCode Agent 承担深度审计，Semgrep/CodeQL 负责快速模式匹配
2. **攻击面驱动**：所有分析方向由项目实际特征动态决定
3. **多轮递进**：侦察→深度→关联，逐层降低漏报率
4. **环境与验证分离**：L4 保障环境稳定性，L5 专注漏洞验证
5. **闭环反馈**：验证结果反哺规则库和审计策略

### 开发优先级原则

1. 先跑通最小流程，再优化各环节
2. L3 Agent 能力是核心竞争力，优先投入
3. L4/L5 可先做简化版，后续迭代
4. L7 属于锦上添花，最后实现
