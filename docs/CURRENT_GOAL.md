# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | 实现 L3.5 对抗验证层 |
| **状态** | completed |
| **优先级** | high |
| **创建日期** | 2026-03-02 |
| **完成日期** | 2026-03-02 |

---

## 问题背景

### 问题：漏洞候选缺乏验证，误报率可能较高

**现象**：
- L3 Agent 发现的漏洞未经验证，仅为 LLM 的判断
- 可疑代码需要人工审查，缺乏自动化筛选
- Phase 4 的 LLM 验证是对 Semgrep/CodeQL 发现的验证，不针对 Agent

**解决方案**：
引入对抗验证层（L3.5），通过三角色对抗分析验证漏洞候选：
1. **攻击者角色**：构造 PoC，证明漏洞可利用
2. **防御者角色**：检查防御措施，证明漏洞不可利用
3. **仲裁者角色**：综合判定，输出最终结论

---

## 完成标准

### P1: 攻击者角色 (Attacker Role)
- [x] 设计攻击者 Prompt（构造 PoC、分析攻击路径）
- [x] 实现 `AttackerVerifier` 类
- [x] 输出攻击论证（payload、前置条件、成功率）

### P2: 防御者角色 (Defender Role)
- [x] 设计防御者 Prompt（检查 sanitizer、数据流阻断）
- [x] 实现 `DefenderVerifier` 类
- [x] 输出防御论证（防御措施、误报理由）

### P3: 仲裁者角色 (Arbiter Role)
- [x] 设计仲裁者 Prompt（评估双方论据）
- [x] 实现 `ArbiterVerifier` 类
- [x] 定义判定结果：CONFIRMED / FALSE_POSITIVE / NEEDS_REVIEW / CONDITIONAL

### P4: 对抗流程集成
- [x] 实现 `AdversarialVerifier` 主控制器
- [x] 集成到 L3 扫描流程（Agent 发现后调用）
- [x] 添加配置项控制是否启用对抗验证

### P5: 测试验证
- [ ] 用 OWASP Juice Shop 测试对抗验证效果
- [ ] 对比启用/禁用对抗验证的误报率
- [ ] 记录典型对抗对话案例

---

## 关键文件

| 文件 | 操作 | 说明 |
|------|------|------|
| `src/layers/l3_analysis/verification/__init__.py` | 新建 | 模块初始化 |
| `src/layers/l3_analysis/verification/models.py` | 新建 | 数据模型定义 |
| `src/layers/l3_analysis/verification/adversarial.py` | 新建 | 对抗验证主控制器 |
| `src/layers/l3_analysis/verification/attacker.py` | 新建 | 攻击者角色 |
| `src/layers/l3_analysis/verification/defender.py` | 新建 | 防御者角色 |
| `src/layers/l3_analysis/verification/arbiter.py` | 新建 | 仲裁者角色 |
| `src/layers/l3_analysis/prompts/adversarial.py` | 新建 | 三角色 Prompt |
| `src/cli/main.py` | 修改 | 添加 --adversarial 选项 |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-03-02 12:30 | 设置目标 |
| 2026-03-02 13:00 | 完成 P1-P4 实现 |
| 2026-03-02 13:30 | 完成 CLI 集成，P5 待测试 |

---

## 预期效果

- 漏洞候选经过对抗验证，降低误报率
- 产生可解释的验证过程（攻防对话）
- 为 L5 PoC 验证层提供高质量候选
- 最终判定结果包含置信度

---

## 架构设计

```
L3 Agent 发现漏洞候选
         ↓
┌─────────────────────────────────────┐
│         L3.5 对抗验证层              │
│                                     │
│  ┌──────────┐     ┌──────────┐      │
│  │ 攻击者    │ ←→ │ 防御者    │      │
│  │ Attacker │     │ Defender │      │
│  └────┬─────┘     └────┬─────┘      │
│       │                │            │
│       └───────┬────────┘            │
│               ↓                     │
│       ┌──────────┐                  │
│       │ 仲裁者    │                  │
│       │ Arbiter  │                  │
│       └────┬─────┘                  │
│            ↓                        │
│   CONFIRMED / FALSE_POSITIVE /      │
│   NEEDS_REVIEW / CONDITIONAL        │
└─────────────────────────────────────┘
         ↓
    L5 PoC 验证层（仅 CONFIRMED）
```

---

## 判定标准

| 结果 | 条件 |
|------|------|
| CONFIRMED | 攻击者成功构造 PoC，防御者无法反驳 |
| FALSE_POSITIVE | 防御者证明存在有效缓解措施 |
| NEEDS_REVIEW | 双方论据相当，需人工审查 |
| CONDITIONAL | 在特定条件下可利用 |

---

## 使用方式

```bash
# 启用对抗验证扫描
deepvuln scan -p /path/to/project --full --adversarial

# 完整扫描 + LLM 验证 + 对抗验证
deepvuln scan -p . --full --llm-verify --adversarial
```

---

## 下一步

- [ ] 用 OWASP Juice Shop 实际测试对抗验证效果
- [ ] 收集典型对抗对话案例
- [ ] 优化 Prompt 提高准确度
