# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | 优化对抗验证层：Prompt优化 + 按需多轮对抗 |
| **状态** | **completed** ✅ |
| **优先级** | high |
| **创建日期** | 2026-03-02 |
| **完成日期** | 2026-03-02 |

---

## 完成标准

### P1: Prompt 优化 ✅

- [x] **Few-Shot 示例**：为攻击者、防御者、仲裁者各添加 2-4 个高质量示例
- [x] **上下文增强**：传递完整调用链、入口点签名、数据流节点
- [x] **角色专业化**：攻击者=渗透测试思维，防御者=代码审计思维，仲裁者=安全研究思维
- [x] **链式思考**：添加 5 步分析步骤引导
- [x] **置信度校准**：明确定义 0-1 分 5 档置信度

### P2: 按需多轮对抗机制 ✅

- [x] **触发条件**：
  - `verdict == NEEDS_REVIEW`
  - 或 `|attacker_strength - defender_strength| < 0.2`
  - 或 `confidence < 0.6`
- [x] **反驳机制**：
  - `AttackerVerifier.rebut(defender_argument)` - 攻击者反驳防御者
  - `DefenderVerifier.rebut(attacker_argument)` - 防御者反驳攻击者
- [x] **循环控制**：
  - 最多 3 轮（可配置）
  - 达到明确判定时提前终止
- [x] **仲裁者增强**：
  - 接收所有轮次的辩论历史
  - 基于完整上下文做最终判断

### P3: 测试验证 ✅

- [x] 单元测试：模型和配置 (`test_adversarial_models.py`)
- [x] 单元测试：各角色 Verifier (`test_adversarial_verifiers.py`)
- [x] 集成测试：多轮对抗流程 (`test_adversarial_multiround.py`)
- [x] 端到端测试：完整场景 (`test_adversarial_e2e.py`)

---

## 变更文件

| 文件 | 操作 | 行数 |
|------|------|------|
| `src/layers/l3_analysis/prompts/adversarial.py` | 重写 | 1229 行 |
| `src/layers/l3_analysis/verification/models.py` | 重写 | 430 行 |
| `src/layers/l3_analysis/verification/adversarial.py` | 重写 | 672 行 |
| `src/layers/l3_analysis/verification/attacker.py` | 重写 | 298 行 |
| `src/layers/l3_analysis/verification/defender.py` | 重写 | 428 行 |
| `src/layers/l3_analysis/verification/arbiter.py` | 重写 | 477 行 |
| `tests/unit/test_l3/test_adversarial_models.py` | 新建 | 400+ 行 |
| `tests/unit/test_l3/test_adversarial_verifiers.py` | 新建 | 600+ 行 |
| `tests/unit/test_l3/test_adversarial_multiround.py` | 新建 | 500+ 行 |
| `tests/unit/test_l3/test_adversarial_e2e.py` | 新建 | 500+ 行 |
| `tests/unit/test_l3/conftest_adversarial.py` | 新建 | 300+ 行 |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-03-02 | 设置目标 |
| 2026-03-02 | 完成 P1 Prompt 优化 |
| 2026-03-02 | 完成 P2 多轮对抗机制 |
| 2026-03-02 | 完成 P3 测试验证 |
| 2026-03-02 | ✅ 目标完成 |

---

## 关键改进

### 1. Prompt 优化

- **Few-Shot 示例**：每个角色 2-4 个高质量示例，展示好的输出格式
- **角色专业化**：
  - 攻击者 = 渗透测试专家思维
  - 防御者 = 代码审计专家思维
  - 仲裁者 = 安全研究专家思维
- **链式思考**：5 步分析流程引导
- **置信度校准**：0.9-1.0 Definitive / 0.7-0.9 Strong / 0.5-0.7 Moderate / 0.3-0.5 Weak / 0.0-0.3 Speculative

### 2. 多轮对抗机制

```
Round 1: analyze() → evaluate()
    ↓ (if NEEDS_REVIEW / strength_diff < 0.2 / confidence < 0.6)
Round 2: rebut() → evaluate()
    ↓ (if still uncertain)
Round 3: rebut() → evaluate()
    ↓ (max rounds reached)
Return final verdict
```

### 3. 新增配置

```python
AdversarialVerifierConfig:
  max_rounds: int = 3              # 最大轮次
  parallel_analysis: bool = True   # 首轮并行
  sequential_rebuttal: bool = True # 反驳顺序执行
  trigger_conditions: TriggerConditions  # 触发条件
```

### 4. 新增模型

- `DebateRound` - 单轮辩论记录
- `TriggerConditions` - 触发条件配置
- `VerificationResult.debate_rounds` - 所有轮次历史
- `VerificationResult.max_rounds_reached` - 是否达到最大轮数

---

## 下一步建议

1. **实际测试**：用真实漏洞样本测试多轮对抗效果
2. **性能优化**：考虑 LLM 调用缓存、并行优化
3. **对比评估**：对比单轮 vs 多轮的判断准确度
4. **阈值调优**：根据实际效果调整触发条件阈值
