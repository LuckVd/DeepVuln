# Current Goal

## Status

**阶段**: Phase 8 - AST Engine 与代码图构建
**状态**: P8-05 已完成，等待下一个目标
**同步日期**: 2026-04-04

---

## 已完成目标

### P8-05: 与 Call Graph 桥接

**状态**: ✅ 已完成
**完成日期**: 2026-04-04
**测试结果**: 58/58 测试通过

#### 交付物

**实现文件**:
- `src/layers/l3_analysis/engines/ast_engine/graph/bridge.py` - GraphBridge 类
- `src/layers/l3_analysis/engines/ast_engine/graph/unified.py` - UnifiedGraphQuery 类

**测试文件**:
- `tests/unit/test_l3/test_ast_graph/test_bridge.py` - 14 个单元测试
- `tests/unit/test_l3/test_ast_graph/test_unified.py` - 18 个单元测试
- `tests/integration/test_graph_bridge_e2e.py` - 3 个集成测试

#### 功能

**GraphBridge** (跨图导航):
- `find_containing_function()` - AST 节点 → 包含它的 CallNode
- `find_ast_nodes_in_function()` - CallNode → 函数体内的所有 ASTNode
- `trace_to_sink()` - 从入口点到 sink 的完整路径

**UnifiedGraphQuery** (统一查询):
- `find_all_sinks()` - 查找所有危险 sink
- `find_reachable_sinks()` - 从入口点找到所有可达的危险 sink
- `get_function_context()` - 获取某个位置的完整上下文
- `get_attack_paths()` - 获取到目标位置的完整攻击路径

**支持模式**:
- code_injection: eval, exec, compile
- command_injection: system, popen, subprocess
- sql_injection: execute, executemany
- path_traversal: open, Path.open
- deserialization: pickle.load, yaml.load
- weak_crypto: md5, sha1, DES

#### 设计决策

- **选项 A**: 保持简单图结构，基于 tree-sitter 父子关系
- **完全准确**: 向上遍历 parent_id 找到包含函数
- **无需修改**: 利用已有 AST Graph 结构

---

### P8-04: AST Graph Builder (选项 A)

**状态**: ✅ 已完成
**完成日期**: 2026-04-04
**测试结果**: 23/23 单元测试通过

---

### P8-03: 结构型漏洞检测器

**状态**: ✅ 已完成
**提交**: `5492dac`
**完成日期**: 2026-04-04

---

### P8-02: AST Engine 核心架构与基础设施

**状态**: ✅ 已完成
**提交**: `d303fa5`
**完成日期**: 2026-04-04

---

## 后续任务预览

| 任务 | 优先级 | 依赖 | 说明 |
|------|--------|------|------|
| P8-06 | P1 | P8-04 ✅ | AI Agent 结构化上下文 |
| P8-07 | P2 | P8-03 ✅ | 规则库扩展 |
| P8-08 | P3 | P8-05 | CPG 基础（Phase 2）|
