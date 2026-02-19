# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | P2-07 多轮审计 - 第二轮深度追踪 |
| **状态** | completed |
| **优先级** | high |
| **创建日期** | 2026-02-20 |
| **完成日期** | 2026-02-20 |

---

## 背景说明

第二轮审计专注于对第一轮识别的候选漏洞进行深度分析。它利用 Agent 的深度审计能力和 CodeQL 的数据流分析，追踪从 source 到 sink 的完整数据流路径。

**核心功能**：
1. **数据流追踪**：从用户输入追踪到敏感 sink
2. **污点分析**：识别不可信数据的传播路径
3. **跨函数分析**：追踪跨函数/跨文件的调用链
4. **证据增强**：为候选漏洞补充代码证据

**设计理念**：
- 深度优先：对高置信度候选进行完整分析
- 证据驱动：收集足够的代码证据支持判断
- 可追溯：记录完整的数据流路径

---

## 完成标准

### Phase 1: 数据流模型
- [x] 创建 `DataFlowPath` 模型
- [x] 创建 `TaintSource` 和 `TaintSink` 模型
- [x] 创建 `DeepAnalysisResult` 结果模型

### Phase 2: 第二轮执行器
- [x] 创建 `RoundTwoExecutor` 类
- [x] 集成 CodeQL 数据流分析
- [x] 集成 Agent 深度审计
- [x] 实现数据流路径提取

### Phase 3: 污点分析器
- [ ] 创建 `TaintAnalyzer` 类 (可选优化)
- [ ] 实现污点传播追踪 (可选优化)
- [ ] 实现净化函数检测 (可选优化)

### Phase 4: 集成与测试
- [x] 集成到模块导出
- [x] 单元测试覆盖 (65 tests)
- [x] 与第一轮结果串联

---

## 技术实现

### 已创建文件

- `src/layers/l3_analysis/rounds/dataflow.py` - 数据流模型
  - SourceType, SinkType, SanitizerType 枚举
  - TaintSource, TaintSink, Sanitizer, PathNode 模型
  - DataFlowPath, DeepAnalysisResult 模型

- `src/layers/l3_analysis/rounds/round_two.py` - 第二轮执行器
  - RoundTwoExecutor 类
  - CodeQL 数据流分析集成
  - Agent 深度审计集成
  - 置信度更新逻辑

### 已修改文件

- `src/layers/l3_analysis/rounds/__init__.py` - 导出新类
- `tests/unit/test_l3/test_rounds.py` - 新增 28 个测试用例

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-02-20 | 设置新目标：P2-07 多轮审计 - 第二轮深度追踪 |
| 2026-02-20 | 完成 Phase 1：创建 dataflow.py 数据流模型 |
| 2026-02-20 | 完成 Phase 2：创建 round_two.py 第二轮执行器 |
| 2026-02-20 | 完成 Phase 4：集成模块导出、65 个单元测试全部通过 |

---

## 下一步

P2-08: 第三轮关联验证 (Correlation Verification)

<options>
<option>提交 P2-07 代码</option>
<option>继续实现 P2-08</option>
<option>更新 ROADMAP.md</option>
</options>