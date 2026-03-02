# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | 增强 Agent 漏洞发现能力 |
| **状态** | completed |
| **优先级** | high |
| **创建日期** | 2026-03-02 |
| **完成日期** | 2026-03-02 |

---

## 问题背景

### 问题：Agent 漏洞发现能力不足

**现象**：
- 三次扫描均未发现任何漏洞
- Prompt 设计过于保守，所有发现被降级为 INFO/LOW
- 缺乏具体漏洞模式指导
- 单文件分析，无法追踪跨文件数据流

**解决方案**：
1. 添加漏洞模式库（具体特征 + Sink + Sanitizer）
2. 引入攻击者视角 Prompt
3. 添加可疑代码标记机制
4. 实现两阶段分析模式

---

## 完成标准

### P1: 漏洞模式库 (Vulnerability Patterns)
- [x] 添加 SQL Injection 模式（patterns, sinks, sanitizers）
- [x] 添加 XSS 模式
- [x] 添加 Command Injection 模式
- [x] 添加 Path Traversal 模式
- [x] 添加 SSRF 模式
- [x] 添加 Deserialization 模式
- [x] 在 Prompt 中引用模式库

### P2: 攻击者视角 Prompt (Attacker Perspective)
- [x] 添加 ATTACKER_PERSPECTIVE 常量
- [x] 融入 System Prompt
- [x] 引导 Agent 从攻击者角度思考

### P3: 可疑代码标记机制 (Suspicious Code)
- [x] 修改输出 JSON 格式，添加 `suspicious_code` 字段
- [x] 修改 `_parse_llm_response` 解析逻辑
- [x] 在 CLI 报告中展示可疑代码

### P4: 验证测试
- [x] 用已知漏洞项目测试（如 OWASP Juice Shop）
- [x] 确认 Agent 能发现至少 1 个真实漏洞
- [x] 对比优化前后的发现数量

---

## 关键文件

| 文件 | 操作 | 说明 |
|------|------|------|
| `src/layers/l3_analysis/prompts/security_audit.py` | 修改 | 添加漏洞模式库和攻击者视角 |
| `src/layers/l3_analysis/engines/opencode_agent.py` | 修改 | 解析可疑代码输出 |
| `src/cli/main.py` | 修改 | 展示可疑代码 |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-03-02 | 设置目标 |
| 2026-03-02 10:12 | ✅ P1 完成：漏洞模式库 (6 种漏洞类型，含 patterns/sinks/sanitizers) |
| 2026-03-02 10:12 | ✅ P2 完成：攻击者视角 Prompt 融入 System Prompt |
| 2026-03-02 10:12 | ✅ P3 部分完成：Agent 解析 suspicious_code 功能实现 |
| 2026-03-02 11:30 | ✅ P3 完成：CLI 展示可疑代码 (交互式/详细视图/报告导出) |
| 2026-03-02 12:00 | ✅ P4 完成：OWASP Juice Shop 测试，发现 50+ 确认漏洞 + 78 可疑代码 |
| 2026-03-02 12:00 | 🐛 修复 Bug：路径过滤逻辑错误导致所有文件被跳过 (target 目录) |

---

## 预期效果

- Agent 能发现更多可疑代码 ✅
- 报告中显示"需要人工审查"的代码 ✅
- 漏洞发现数量增加（从 0 到 N）✅ **0 → 50+ 确认漏洞 + 78 可疑代码**
- 为 L5 验证层提供更多候选 ✅

---

## 测试结果 (OWASP Juice Shop)

### 优化前
- Agent 发现：**0** 个漏洞
- 可疑代码：**0** 个

### 优化后
- Agent 发现：**50+** 个确认漏洞
- 可疑代码：**78** 个
- 漏洞类型覆盖：SQL 注入、XSS、路径遍历、SSRF、弱密码哈希、硬编码密钥等

### 发现的真实漏洞示例
1. **SQL Injection** - `routes/search.ts:21` - 用户输入直接拼接到 SQL 查询
2. **Path Traversal** - `rsn/rsnUtil.ts:102` - seePatch 函数路径遍历
3. **Stored XSS** - `models/product.ts:48` - 产品描述存储型 XSS
4. **Weak Password Hashing** - `models/user.ts:70` - 使用不安全的哈希库

---

## 后续优化 (P2 优先级)

- 跨文件数据流追踪
- 两阶段分析模式（检测 → 评估）
- 数据流摘要传递
