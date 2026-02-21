# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | 漏洞判断准确度改进 (P0+P1+P3) |
| **状态** | completed |
| **优先级** | high |
| **创建日期** | 2026-02-21 |
| **完成日期** | 2026-02-21 |

---

## 背景说明

在对 Apache Dubbo 进行安全扫描时，发现 LLM Agent 存在以下问题：

1. **上下文不足** - 只发送单个文件，无法看到调用链
2. **缺少数据流分析** - 没有追踪参数来源，误判攻击者可控性
3. **缺少可利用性验证** - 高估漏洞严重程度

**改进方案**：
- **P0**: 增强 Prompt 模板 - 立即生效
- **P1**: 增强 Context Builder - 提供更多上下文
- **P3**: 添加 Round 4 可利用性验证 - 过滤误报

---

## 完成标准

### P0: 增强 Prompt 模板
- [x] 修改 `security_audit.py` 的 System Prompt
- [x] 添加攻击面分析指南
- [x] 添加数据流分析指南
- [x] 添加可利用性评估指南
- [x] 添加严重程度校准规则

### P1: 增强 Context Builder
- [x] 添加调用链分析功能 (`analyze_call_chain`)
- [x] 添加依赖代码提取功能 (`extract_dependencies`)
- [x] 添加数据流标记功能 (`analyze_data_flow`)
- [x] 更新 Prompt 构建逻辑 (`build_enhanced_context`)

### P3: 添加 Round 4 可利用性验证
- [x] 创建 `RoundFourExecutor` 类
- [x] 实现攻击路径分析
- [x] 实现数据来源验证
- [x] 实现严重程度校准
- [x] 集成到多轮审计流程

---

## 实现详情

### P0: 修改文件
- `src/layers/l3_analysis/prompts/security_audit.py`
  - 添加 "Exploitability Assessment" 章节
  - 添加攻击面、数据源、利用条件分析指南
  - 添加严重程度校准规则
  - 添加新字段: `attack_surface`, `user_controlled`, `exploitation_conditions`

### P1: 修改文件
- `src/layers/l3_analysis/task/context_builder.py`
  - 新增 `CallChainInfo` 数据类
  - 新增 `DataFlowMarker` 数据类
  - 新增 `analyze_call_chain()` 方法
  - 新增 `analyze_data_flow()` 方法
  - 新增 `extract_dependencies()` 方法
  - 新增 `build_enhanced_context()` 方法
- `src/layers/l3_analysis/engines/opencode_agent.py`
  - 更新为使用增强版 Context Builder

### P3: 新增/修改文件
- `src/layers/l3_analysis/rounds/round_four.py` (新建 ~500 行)
  - `ExploitabilityStatus` 枚举
  - `SeverityAdjustment` 模型
  - `ExploitabilityResult` 模型
  - `RoundFourExecutor` 类
    - `execute()` - 主执行方法
    - `_verify_exploitability()` - 验证单个漏洞
    - `_assess_exploitability()` - 评估可利用性
    - `_calculate_severity_adjustment()` - 计算严重程度调整
    - `_apply_verification_result()` - 应用验证结果
- `src/layers/l3_analysis/rounds/__init__.py` (更新导出)

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-02-21 | 设置新目标：漏洞判断准确度改进 |
| 2026-02-21 | 完成 P0: 增强 Prompt 模板 |
| 2026-02-21 | 完成 P1: 增强 Context Builder |
| 2026-02-21 | 完成 P3: 添加 Round 4 可利用性验证 |
| 2026-02-21 | 所有组件测试通过 |

---

## 预期效果

使用改进后的扫描器重新扫描 Dubbo 项目，预期：

| 漏洞 | 原判定 | 新判定 | 原因 |
|------|--------|--------|------|
| 路径遍历 | MEDIUM | INFO/LOW | 无外部入口点，参数来自配置 |
| 时序攻击 | MEDIUM | LOW | RPC 内部调用，网络延迟远大于时间差 |
| 弱签名算法 | MEDIUM | 误报 | 实际使用 HMAC-SHA256 |

---

## 下一步

1. 运行完整测试套件验证
2. 重新扫描 Dubbo 项目验证改进效果
3. 考虑实现 L5 完整验证层 (PoC 生成 + 沙箱执行)
