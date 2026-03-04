# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | P3-06：禁止 literal 规则（AST 强制语义匹配） |
| **状态** | completed |
| **优先级** | P1 |
| **创建日期** | 2026-03-05 |
| **完成日期** | 2026-03-05 |
| **所属阶段** | Phase 3 - 精度重构 |

---

## 目标概述

禁止仅基于字符串匹配（literal matching）的规则参与扫描。所有规则必须基于 AST 结构、使用 pattern-either + metavariable、或使用 Semgrep 的模式语义匹配。不能允许 `pattern: "eval("` 这种简单字符串规则。

**核心目标**：精度优先于召回，彻底消除 literal 规则导致的误报爆炸。

---

## 约束条件

| 约束 | 说明 |
|------|------|
| 只允许新建 | `src/core/rule_ast_validator.py` |
| 只允许修改 | `src/layers/l3_analysis/engines/semgrep.py` |
| 禁止修改 | Rule Gating、File Filtering、Finding Budget、CLI、Agent、CodeQL、TechStack、Rule Pack 文件 |

---

## 完成标准

### 1️⃣ RuleValidationStatus 枚举（必须）✅

```python
class RuleValidationStatus(str, Enum):
    VALID = "valid"
    LITERAL_ONLY = "literal_only"
    INVALID_STRUCTURE = "invalid_structure"
```

- [x] 实现 `RuleValidationStatus` 枚举
- [x] 定义三种状态类型

### 2️⃣ RuleValidationResult 数据结构（必须）✅

```python
@dataclass
class RuleValidationResult:
    rule_id: str
    status: RuleValidationStatus
    reason: str
    pattern_count: int = 0
    has_metavariable: bool = False
    has_structure: bool = False
```

- [x] 实现 `RuleValidationResult` 数据类
- [x] `rule_id` 字段
- [x] `status` 字段
- [x] `reason` 字段

### 3️⃣ 判定为 LITERAL_ONLY 的情况（必须）✅

满足**任意一条**即判定为 `LITERAL_ONLY`：

| 条件 | 说明 |
|------|------|
| 仅包含 `pattern: "some_string"` | 纯字符串匹配 |
| 没有使用 metavariable（如 `$X`） | 无变量绑定 |
| 没有使用 `pattern-either` | 无多模式选择 |
| 没有使用 `patterns:` | 无组合逻辑 |
| 没有使用 `pattern-inside` | 无上下文约束 |
| 没有 AST 结构特征 | 无 function call、assignment 等 |

- [x] 检测纯字符串 pattern
- [x] 检测 metavariable 使用
- [x] 检测 pattern-either/patterns/pattern-inside
- [x] 检测 AST 结构特征

### 4️⃣ 判定为 VALID 的情况（必须）✅

满足**任意一条**即 `VALID`：

| 条件 | 说明 |
|------|------|
| 使用 metavariable（`$X`） | 有变量绑定 |
| 使用 `pattern-either` | 多模式选择 |
| 使用 `patterns:` | 组合逻辑 |
| 使用 `pattern-inside` | 上下文约束 |
| 使用 `pattern-regex` + 结构约束 | 正则 + 结构 |
| 包含 AST 结构关键字 | function call、assignment 等 |

- [x] metavariable 检测
- [x] pattern-either 检测
- [x] patterns 检测
- [x] pattern-inside 检测
- [x] AST 结构关键字检测

### 5️⃣ 规则过滤集成（必须）✅

在 Semgrep 执行前进行规则过滤：

```python
validator = RuleASTValidator()
valid_rules = []
invalid_rules = []

for rule in loaded_rules:
    result = validator.validate_rule(rule)
    if result.status == RuleValidationStatus.VALID:
        valid_rules.append(rule)
    else:
        invalid_rules.append(result.rule_id)

# 禁止 invalid_rules 进入执行
```

- [x] 在规则加载后执行验证
- [x] 过滤 LITERAL_ONLY 规则
- [x] 只使用 VALID 规则执行扫描

### 6️⃣ 执行策略（必须）✅

| 策略 | 行为 |
|------|------|
| literal-only 规则 | 不加载，不执行 |
| 错误处理 | 不报错，静默跳过 |
| 主流程 | 不影响，继续执行 |
| 日志记录 | 记录禁用规则 ID |

- [x] 静默跳过无效规则
- [x] 不抛异常
- [x] 不影响主流程

### 7️⃣ Metadata 记录（必须）✅

在 `ScanResult.metadata` 中新增：

```json
{
  "ast_validation": {
    "disabled_literal_rules": ["rule.id.1", "rule.id.2"],
    "validated_count": 150,
    "rejected_count": 23,
    "rejection_rate": "13.3%"
  }
}
```

- [x] 存储禁用规则列表
- [x] 存储验证通过数量
- [x] 存储拒绝数量
- [x] 计算拒绝率

---

## AST 结构关键字

检测以下 AST 结构特征表示规则有语义：

| 类别 | 关键字示例 |
|------|-----------|
| 函数调用 | `$FUNC(...)`, `func(...)` |
| 赋值语句 | `$X = ...`, `var = ...` |
| 类定义 | `class $CLASS` |
| 函数定义 | `function $FUNC`, `def $FUNC` |
| 导入语句 | `import $X`, `require($X)` |
| 条件语句 | `if (...)`, `while (...)` |
| 方法调用 | `$OBJ.method(...)` |
| 属性访问 | `$OBJ.property` |
| 操作符 | `+`, `-`, `*`, `/`, `==`, `!=` |

---

## Metavariable 模式

检测正则匹配：

```python
METAVARIABLE_PATTERN = r'\$[A-Z_][A-Z0-9_]*'
```

示例：
- `$X` ✅
- `$VAR` ✅
- `$FUNCTION_NAME` ✅
- `$X123` ✅

---

## 禁止行为

- [x] ❌ 不允许直接删除 rule 文件
- [x] ❌ 不允许修改 rule pack 文件内容
- [x] ❌ 不允许改变 CLI
- [x] ❌ 不允许抛异常
- [x] ❌ 不允许影响主流程

---

## 变更文件

| 文件 | 操作 | 说明 |
|------|------|------|
| `src/core/rule_ast_validator.py` | 新建 | AST 规则校验模块 |
| `src/layers/l3_analysis/engines/semgrep.py` | 修改 | 集成规则校验 |
| `tests/unit/test_core/test_rule_ast_validator.py` | 新建 | 34 个单元测试 |

---

## 实现优先级

| 优先级 | 功能 | 状态 |
|--------|------|------|
| P0 | RuleValidationStatus 枚举 | ✅ |
| P0 | RuleValidationResult 数据结构 | ✅ |
| P0 | LITERAL_ONLY 检测逻辑 | ✅ |
| P0 | VALID 检测逻辑 | ✅ |
| P1 | Semgrep 集成 | ✅ |
| P1 | Metadata 记录 | ✅ |
| P2 | 详细拒绝原因 | ✅ |

---

## 实现顺序

1. ✅ 创建 RuleASTValidator 类
2. ✅ 实现 metavariable 检测
3. ✅ 实现 AST 结构检测
4. ✅ 实现 pattern-either/patterns 检测
5. ✅ 集成到 Semgrep 执行流程
6. ✅ 添加 metadata 记录

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-03-05 | 设置目标：禁止 literal 规则 |
| 2026-03-05 | 完成 RuleASTValidator 实现 |
| 2026-03-05 | 完成 Semgrep 集成 |
| 2026-03-05 | 添加 34 个单元测试，全部通过 |
| 2026-03-05 | 全部 1392 测试通过 |

---

## 验收清单

- [x] 纯字符串规则不会执行
- [x] 注释中的字符串不会触发规则
- [x] 文档中的字符串不会触发规则
- [x] metadata 正确记录禁用规则数量
- [x] 主流程不受影响
- [x] 不抛异常
- [x] 不修改 rule pack 文件

---

## 预期效果

实现后系统会：
- **精度提升** - 消除 literal 规则误报
- **注释免疫** - 代码注释不触发规则
- **文档免疫** - 文档字符串不触发规则
- **语义匹配** - 只执行 AST 语义规则
- **可追溯** - 完整记录禁用规则

---

## Phase 3 完成状态

当 P3-06 完成后：

| 功能 | 状态 |
|------|------|
| 规则裁剪 (Rule Gating) | ✅ |
| 文件裁剪 (File Filtering) | ✅ |
| 结果熔断 (Finding Budget) | ✅ |
| CodeQL 降级 (Fail-Safe) | ✅ |
| AST 强制 (Literal Ban) | ✅ |

**Phase 3 全部任务完成！**

---

## 备注

- 此任务确保只有语义规则参与扫描
- 与 Rule Gating、File Filtering 配合使用
- Literal 规则是误报的主要来源之一
- 精度优先于召回是 v0.4 的核心理念
- 禁用的规则可通过 metadata 追溯
