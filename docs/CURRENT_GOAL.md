# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | P4-03：全局裁决一致性与冲突禁止机制 |
| **状态** | pending |
| **优先级** | P0 |
| **创建日期** | 2026-03-05 |
| **所属阶段** | Phase 4 - 裁决统一 |

---

## 目标概述

建立 Global Adjudication Consistency Layer，确保同一漏洞不能出现状态冲突，exploitability 与 final_status 必须一致，多引擎结果不能互相矛盾。

**核心目标**：系统进入"强一致裁决模式"，不输出逻辑矛盾的报告，deterministic。

---

## 约束条件

| 约束 | 说明 |
|------|------|
| 可新建 | `src/layers/l3_analysis/consistency.py` |
| 可修改 | `src/layers/l3_analysis/adjudication.py`, `src/layers/l3_analysis/strategy_engine.py`, `models.py` |
| 禁止修改 | final_score 计算逻辑、exploitability 计算逻辑、Rule Gating、File Filtering、Finding Budget、CodeQL Health |

---

## 禁止行为

- [x] ❌ 不允许静默修正
- [x] ❌ 不允许自动合并冲突
- [x] ❌ 不允许降级而不报错
- [x] ❌ 不允许忽略冲突
- [x] ❌ 必须显式抛出异常

---

## 完成标准

### 1️⃣ 异常类型（必须）

```python
class GlobalAdjudicationError(Exception):
    """全局裁决一致性错误"""
    pass
```

- [ ] 实现 `GlobalAdjudicationError` 异常类

### 2️⃣ 全局一致性检查器（必须）

创建 `src/layers/l3_analysis/consistency.py`:

```python
class AdjudicationConsistencyChecker:
    def validate_findings(self, findings: list):
        """
        执行全局一致性检查
        """
```

- [ ] 创建 consistency.py 模块
- [ ] 实现 AdjudicationConsistencyChecker 类
- [ ] 实现 validate_findings() 方法

### 3️⃣ 五条强制规则（必须）

| 规则 | 条件 | 错误类型 |
|------|------|----------|
| 规则 1 | exploitability != final_status | GlobalAdjudicationError |
| 规则 2 | 同 ID 的 EXPLOITABLE + NOT_EXPLOITABLE | GlobalAdjudicationError |
| 规则 3 | 同 ID 跨引擎状态冲突 | GlobalAdjudicationError |
| 规则 4 | 状态等级逆向升级 | GlobalAdjudicationError |
| 规则 5 | final_status 为空 | GlobalAdjudicationError |

#### 规则 1：Exploitability 与 FinalStatus 必须一致

```python
if exploitability == "NOT_EXPLOITABLE" and final_status != "NOT_EXPLOITABLE":
    raise GlobalAdjudicationError(...)
```

- [ ] 实现 exploitability 与 final_status 一致性检查

#### 规则 2：禁止同 ID 状态并存

```python
# 同一 logical_vuln_id 不能同时存在 EXPLOITABLE 和 NOT_EXPLOITABLE
```

- [ ] 实现同 ID 状态冲突检测

#### 规则 3：禁止跨引擎状态冲突

```python
# Semgrep → EXPLOITABLE, Agent → NOT_EXPLOITABLE (同一 ID)
# 必须抛异常
```

- [ ] 实现跨引擎状态冲突检测

#### 规则 4：状态等级不允许逆向升级

```python
# 状态等级: NOT_EXPLOITABLE < CONDITIONAL < EXPLOITABLE
# 同一 ID 必须统一到最高级别
```

- [ ] 实现状态等级检查
- [ ] 定义状态等级常量

#### 规则 5：禁止 final_status 为空

```python
if finding.final_status is None:
    raise GlobalAdjudicationError(...)
```

- [ ] 实现 final_status 空值检查

### 4️⃣ 统一 ID 规则（必须）

在 models.py 中确保：

```python
logical_vuln_id: str | None = None
```

生成规则：
```python
hash(rule_id + file_path + normalized_sink)
```

- [ ] 确认 Finding 有 logical_vuln_id 字段
- [ ] 实现统一的 ID 生成逻辑

### 5️⃣ Strategy Engine 集成（必须）

```python
# 在 adjudicate_findings() 之后
# 在排序之前
# 在输出之前
AdjudicationConsistencyChecker().validate_findings(findings)
```

- [ ] 在 adjudicate_findings() 后调用一致性检查
- [ ] 确保排序之前执行
- [ ] 确保输出之前执行

### 6️⃣ Metadata 记录（必须）

```json
{
  "consistency_check": {
    "checked": true,
    "error": null,
    "findings_checked": 100,
    "conflicts_found": 0
  }
}
```

- [ ] 存储 checked 状态
- [ ] 存储 error 信息（如有）
- [ ] 存储 findings_checked 数量

---

## 变更文件

| 文件 | 操作 | 说明 |
|------|------|------|
| `src/layers/l3_analysis/consistency.py` | 新建 | 全局一致性检查模块 |
| `src/layers/l3_analysis/adjudication.py` | 修改 | 集成一致性检查 |
| `src/layers/l3_analysis/strategy_engine.py` | 修改 | 调用一致性检查 |
| `src/layers/l3_analysis/models.py` | 修改 | 添加 logical_vuln_id |

---

## 实现优先级

| 优先级 | 功能 |
|--------|------|
| P0 | GlobalAdjudicationError |
| P0 | AdjudicationConsistencyChecker |
| P0 | 规则 1-5 实现 |
| P1 | logical_vuln_id 字段 |
| P1 | Strategy Engine 集成 |
| P2 | Metadata 记录 |

---

## 实现顺序

1. 创建 `src/layers/l3_analysis/consistency.py` 模块
2. 实现 GlobalAdjudicationError 异常
3. 实现 AdjudicationConsistencyChecker 类
4. 实现五条强制规则
5. 添加 logical_vuln_id 字段到 Finding
6. 在 Strategy Engine 中集成
7. 添加 Metadata 记录
8. 添加单元测试（40+）

---

## 测试要求

### 新增测试（40+）

| 测试 | 说明 |
|------|------|
| exploitability 与 final_status 冲突 | 规则 1 |
| 同 ID 跨引擎冲突 | 规则 2 + 3 |
| 状态等级冲突 | 规则 4 |
| final_status 为空 | 规则 5 |
| 正常情况不抛异常 | 基本功能 |
| logical_vuln_id 生成 | ID 统一性 |
| 批量检查 | 性能 |
| Metadata 记录 | 结果验证 |

---

## 验收清单

- [ ] 不存在 confirmed / not_exploitable 并存
- [ ] 同 logical_vuln_id 状态完全一致
- [ ] exploitability 与 final_status 不可能冲突
- [ ] 系统进入"强一致裁决模式"
- [ ] 所有测试通过（40+ 新测试）
- [ ] 显式抛出异常（不静默处理）

---

## 预期效果

实现后系统会：
- **强一致性** - 同一漏洞 ID 状态完全一致
- **冲突禁止** - 不允许逻辑矛盾
- **确定性** - deterministic 输出
- **可追溯** - metadata 记录检查结果
- **显式错误** - 冲突必须抛异常

---

## 设计原则

**本阶段是：**
- ✅ 全局一致性校验
- ✅ 冲突禁止机制
- ✅ 强一致裁决

**本阶段不是：**
- ❌ 修改评分逻辑
- ❌ 自动合并冲突
- ❌ 静默修正错误

---

## 与 P4-01/P4-02 的关系

| P4-01 | P4-02 | P4-03 |
|-------|-------|-------|
| final_score | final_status | 一致性校验 |
| 加权计算 | 裁决覆盖 | 冲突禁止 |
| 排序基础 | 状态决策 | 强一致性 |

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-03-05 | 设置目标：全局裁决一致性 |
| - | （待更新） |

---

## 备注

- 此任务是 Phase 4 的第三个任务
- 依赖 P4-01 的 final_score 和 P4-02 的 final_status
- 核心是建立全局一致性校验层
- 系统将进入"强一致裁决模式"
- 完成后 DeepVuln 将不输出逻辑矛盾的报告
