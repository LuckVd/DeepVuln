# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | P3-08：CodeQL 失败降级策略（Fail-Safe Degradation） |
| **状态** | completed |
| **优先级** | P1 |
| **创建日期** | 2026-03-04 |
| **完成日期** | 2026-03-04 |
| **所属阶段** | Phase 3 - 精度重构 |

---

## 目标概述

当 CodeQL 出现数据库构建失败、编译失败、CLI 报错、超时、无支持语言、内存溢出、子进程异常等情况时，自动降级为 Semgrep + Agent 方案，而不是中断扫描流程。

**核心目标**：CodeQL 可失败但系统稳定，主流程永不中断。

---

## 约束条件

| 约束 | 说明 |
|------|------|
| 只允许新建 | `src/core/codeql_health.py` |
| 只允许修改 | `src/layers/l3_analysis/engines/codeql.py` |
| 禁止修改 | Rule Gating、File Filtering、Finding Budget、CLI、Agent、Semgrep、TechStack |

---

## 完成标准

### 1️⃣ CodeQLStatus 枚举（必须）

```python
class CodeQLStatus(str, Enum):
    SUCCESS = "success"
    BUILD_FAILED = "build_failed"
    QUERY_FAILED = "query_failed"
    TIMEOUT = "timeout"
    UNSUPPORTED_LANGUAGE = "unsupported_language"
    RESOURCE_ERROR = "resource_error"
    SUBPROCESS_ERROR = "subprocess_error"
    NOT_INSTALLED = "not_installed"
    DATABASE_ERROR = "database_error"
```

- [x] 实现 `CodeQLStatus` 枚举
- [x] 定义所有状态类型

### 2️⃣ CodeQLHealthResult 数据结构（必须）

```python
@dataclass
class CodeQLHealthResult:
    status: CodeQLStatus
    message: str
    duration: float
    fallback_triggered: bool
    error_details: dict | None
```

- [x] 实现 `CodeQLHealthResult` 数据类
- [x] `status` 字段
- [x] `message` 字段
- [x] `duration` 字段
- [x] `fallback_triggered` 字段

### 3️⃣ 构建失败容错（必须）

**捕获异常**：
- `subprocess.CalledProcessError` → BUILD_FAILED
- `subprocess.TimeoutExpired` → TIMEOUT
- `MemoryError` → RESOURCE_ERROR
- `OSError` → SUBPROCESS_ERROR

- [x] 数据库构建异常捕获
- [x] 返回健康状态而非抛异常
- [x] 记录错误详情

### 4️⃣ 查询执行失败容错（必须）

**捕获异常**：
- `subprocess.CalledProcessError` → QUERY_FAILED
- `subprocess.TimeoutExpired` → TIMEOUT
- `json.JSONDecodeError` → QUERY_FAILED

- [x] 查询执行异常捕获
- [x] SARIF 解析异常捕获
- [x] 返回健康状态而非抛异常

### 5️⃣ 超时控制（必须）

| 操作 | 默认超时 |
|------|----------|
| 数据库构建 | 1800s (30min) |
| 查询执行 | 600s (10min) |
| 单个查询 | 300s (5min) |

- [x] 数据库构建超时控制
- [x] 查询执行超时控制
- [x] 超时自动降级

### 6️⃣ 语言支持判断（必须）

- [x] 语言支持检测
- [x] 不支持时跳过执行
- [x] 记录 UNSUPPORTED_LANGUAGE 状态

### 7️⃣ 降级行为（必须）

- [x] 失败时返回空结果
- [x] success=False
- [x] metadata 记录健康状态
- [x] 不抛异常

### 8️⃣ 健康状态记录（必须）

- [x] 存储执行状态
- [x] 存储耗时
- [x] 存储错误信息
- [x] 存储 fallback 标志

### 9️⃣ 禁止行为（必须保证）

- [x] ❌ 不允许 raise 未捕获异常
- [x] ❌ 不允许终止主流程
- [x] ❌ 不允许影响 Semgrep 执行
- [x] ❌ 不允许影响 Agent 执行
- [x] ❌ 不允许返回 None

---

## 三层容错架构

| 层级 | 场景 | 行为 |
|------|------|------|
| 构建层 | 数据库构建失败 | 降级 + 记录 |
| 查询层 | 查询执行失败 | 降级 + 记录 |
| 资源层 | 超时/内存溢出 | 降级 + 记录 |

---

## 错误类型映射

| 异常类型 | 状态 | 降级 |
|----------|------|------|
| `CalledProcessError` (build) | BUILD_FAILED | ✅ |
| `CalledProcessError` (query) | QUERY_FAILED | ✅ |
| `TimeoutExpired` | TIMEOUT | ✅ |
| `MemoryError` | RESOURCE_ERROR | ✅ |
| `OSError` | SUBPROCESS_ERROR | ✅ |
| 语言不支持 | UNSUPPORTED_LANGUAGE | ✅ |

---

## 变更文件

| 文件 | 操作 | 说明 |
|------|------|------|
| `src/core/codeql_health.py` | 新建 | CodeQL 健康管理模块 |
| `src/layers/l3_analysis/engines/codeql.py` | 修改 | 集成 Fail-Safe 包装 |

---

## 实现优先级

| 优先级 | 功能 |
|--------|------|
| P0 | 异常捕获包装 |
| P0 | 超时控制 |
| P0 | 健康状态记录 |
| P1 | UNSUPPORTED_LANGUAGE 判断 |
| P1 | metadata 集成 |
| P2 | 详细错误信息 |

---

## 实现顺序

1. ✅ 创建 CodeQLStatus 和 CodeQLHealthResult
2. ✅ 实现异常捕获包装器
3. ✅ 添加超时控制
4. ✅ 实现语言支持判断
5. ✅ 集成 metadata 记录

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-03-04 | 设置目标：CodeQL 失败降级策略 |
| 2026-03-04 | 创建 CodeQLHealthManager 和 CodeQLHealthResult |
| 2026-03-04 | 集成到 CodeQLEngine.scan() |
| 2026-03-04 | 所有测试通过（1358 passed） |
| 2026-03-04 | 任务完成 |

---

## 验收清单

- [x] CodeQL 构建失败不会中断扫描
- [x] CodeQL 查询失败不会中断扫描
- [x] 超时自动降级
- [x] 语言不支持时跳过执行
- [x] metadata 正确记录健康状态
- [x] Semgrep + Agent 始终可执行
- [x] 主流程不会抛异常
- [x] 返回值始终是 ScanResult

---

## 预期效果

实现后系统会：
- **永不中断** - CodeQL 失败不影响整体扫描
- **优雅降级** - 自动切换到 Semgrep + Agent
- **状态可追溯** - 完整记录失败原因
- **超时可控** - 避免无限等待
- **资源安全** - 内存溢出时自动降级

---

## Phase 3 完成状态

当 P3-08 完成后：

| 功能 | 状态 |
|------|------|
| 规则裁剪 (Rule Gating) | ✅ |
| 文件裁剪 (File Filtering) | ✅ |
| 结果熔断 (Finding Budget) | ✅ |
| CodeQL 降级 (Fail-Safe) | ✅ |

**Phase 3 全部任务完成！**

---

## 备注

- 此任务确保 CodeQL 的不稳定性不会影响整体系统
- 与 Rule Gating、File Filtering、Finding Budget 配合使用
- Fail-Safe 机制是生产环境可用的关键保障
- 降级后 Semgrep + Agent 仍可提供完整的安全扫描能力
