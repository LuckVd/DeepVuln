# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | Round 2 真正的 CodeQL 数据流分析：自定义查询生成 + 路径追踪 + SARIF 解析 + Sanitizer 识别 |
| **状态** | completed |
| **优先级** | critical |
| **创建日期** | 2026-03-03 |
| **完成日期** | 2026-03-03 |

---

## 完成标准

### P0: 自定义 CodeQL 查询生成 ✅ 完成

- [x] **查询模板系统**：为不同漏洞类型生成 CodeQL 查询
- [x] **Source/Sink 定义**：基于 Finding 自动定义 TaintTracking source/sink
- [x] **查询参数化**：支持文件路径、函数名、变量名等参数注入

### P1: CodeQL 路径追踪执行 ✅ 完成

- [x] **调用 CodeQL CLI**：执行 `database analyze` 运行自定义查询
- [x] **TaintTracking 配置**：生成完整的污点追踪配置
- [x] **路径查询执行**：获取 source → sink 的完整路径

### P2: SARIF 解析增强 ✅ 完成

- [x] **codeFlows 解析**：从 SARIF 提取完整数据流路径
- [x] **threadFlows 处理**：解析多线程流路径
- [x] **路径节点提取**：提取每个路径节点的位置、变量、表达式

### P3: Sanitizer 识别 ✅ 完成

- [x] **净化函数检测**：识别路径中的 sanitize 调用
- [x] **净化效果评估**：判断 sanitizer 是否有效阻断污点传播
- [x] **has_effective_sanitizer 标记**：更新 DataFlowPath 状态

### P4: Round 2 集成 ✅ 完成

- [x] **改造 _trace_dataflow**：使用真实 CodeQL 结果替代推断
- [x] **is_complete 判定**：基于实际路径完整性设置
- [x] **置信度更新**：根据数据流分析结果调整候选漏洞置信度

### P5: 测试验证 ✅ 完成

- [x] **单元测试**：新增组件的测试覆盖 (59 个新测试)
- [x] **集成测试**：端到端数据流分析验证
- [ ] **真实项目测试**：在已知漏洞项目上验证 (需要 CodeQL 环境)

---

## 技术方案

### 架构设计

```
┌─────────────────────────────────────────────────────────────────┐
│                   Round 2 数据流分析架构                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐    │
│  │  Query       │ ──▶ │  CodeQL      │ ──▶ │  SARIF       │    │
│  │  Generator   │     │  Executor    │     │  Parser      │    │
│  │              │     │              │     │              │    │
│  │ • 模板系统   │     │ • CLI 调用   │     │ • codeFlows  │    │
│  │ • Source定义 │     │ • 查询执行   │     │ • 路径节点   │    │
│  │ • Sink定义   │     │ • 结果获取   │     │ • Sanitizer  │    │
│  └──────────────┘     └──────────────┘     └──────────────┘    │
│          │                   │                   │              │
│          └───────────────────┼───────────────────┘              │
│                              │                                  │
│                              ▼                                  │
│                    ┌──────────────────┐                        │
│                    │  DataFlowPath    │                        │
│                    │                  │                        │
│                    │ • 完整路径节点   │                        │
│                    │ • Sanitizer 列表 │                        │
│                    │ • is_complete    │                        │
│                    └──────────────────┘                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 核心组件

| 组件 | 路径 | 职责 |
|------|------|------|
| QueryGenerator | `l3_analysis/codeql/query_generator.py` | CodeQL 查询模板生成 |
| CodeQLDataflowExecutor | `l3_analysis/codeql/executor.py` | CodeQL CLI 执行封装 |
| SARIFParser | `l3_analysis/codeql/sarif_parser.py` | SARIF 输出解析增强 |
| SanitizerDetector | `l3_analysis/codeql/sanitizer_detector.py` | Sanitizer 检测和评估 |
| DataflowAnalyzer | `l3_analysis/rounds/dataflow_analyzer.py` | 数据流分析协调器 |

---

## 变更文件

| 文件 | 操作 | 说明 |
|------|------|------|
| `src/layers/l3_analysis/codeql/__init__.py` | 新增 | CodeQL 工具模块入口 |
| `src/layers/l3_analysis/codeql/query_generator.py` | 新增 | CodeQL 查询生成器 |
| `src/layers/l3_analysis/codeql/executor.py` | 新增 | CodeQL 执行器 |
| `src/layers/l3_analysis/codeql/sarif_parser.py` | 新增 | SARIF 解析增强 |
| `src/layers/l3_analysis/codeql/sanitizer_detector.py` | 新增 | Sanitizer 检测器 |
| `src/layers/l3_analysis/rounds/dataflow_analyzer.py` | 新增 | 数据流分析协调器 |
| `src/layers/l3_analysis/rounds/round_two.py` | 修改 | 改造 _trace_dataflow |
| `tests/unit/test_l3/test_codeql_dataflow.py` | 新增 | 数据流分析测试 (59 个测试) |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-03-03 | 设置目标：Round 2 CodeQL 数据流分析 |
| 2026-03-03 | 完成 QueryGenerator - 支持多语言查询模板生成 |
| 2026-03-03 | 完成 SARIFParser - codeFlows 完整路径解析 |
| 2026-03-03 | 完成 CodeQLDataflowExecutor - CLI 执行封装 |
| 2026-03-03 | 完成 SanitizerDetector - 多语言 sanitizer 检测 |
| 2026-03-03 | 完成 DataflowAnalyzer - 协调器整合所有组件 |
| 2026-03-03 | 改造 Round 2 - 集成真实数据流分析 |
| 2026-03-03 | 编写单元测试 - 59 个新测试全部通过 |
| 2026-03-03 | ✅ 目标完成 - 626 个测试全部通过 |

---

## 预期收益

| 指标 | 当前 | 目标 | 提升 |
|------|------|------|------|
| 数据流路径完整性 | 仅 2 节点 | 完整路径 | 路径可见性 100% |
| is_complete 准确率 | 0% (永远 False) | >90% | +90% |
| Sanitizer 检测 | 无 | 自动识别 | 新增能力 |
| 漏洞验证准确率 | ~60% | >85% | +25% |

---

## 备注

- 基于 Round 1 Finding 生成针对性的 CodeQL 查询
- 利用 CodeQL 的 TaintTracking 配置实现真正的数据流追踪
- 解析 SARIF 中的 codeFlows 获取完整路径节点
- 识别路径中的 sanitizer 调用并评估有效性
- 支持 Python、Java、JavaScript、Go 四种语言
- 当 CodeQL 不可用时自动回退到推断分析
