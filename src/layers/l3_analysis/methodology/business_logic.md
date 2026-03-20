# Business Logic Security Detection Methodology

> P6-06b: D9 维度业务逻辑漏洞检测方法论
> 基于 code-audit 项目的 Control-driven 审计模型
> 版本: 1.0.0

## 概述

业务逻辑漏洞是一类特殊的安全问题：它们不是"危险代码"的存在，而是"安全控制的缺失"。传统的 Sink-driven 方法（搜索危险函数 → 追踪数据流）无法有效检测这类漏洞，因为 Grep 无法搜索"不存在的代码"。

**核心原则**: D9 漏洞是"缺失的安全控制"，需要 **Control-driven** 审计方法。

---

## 双轨审计模型

| 轨道 | 适用维度 | 核心逻辑 | 输入 |
|------|---------|---------|------|
| **Sink-driven** | D1, D4, D5, D6 | 搜索危险函数 → 追踪输入 → 验证无防护 | Sink 模式列表 |
| **Control-driven** | **D3, D9** | 枚举操作 → 验证控制存在 → **缺失=漏洞** | 端点-权限矩阵 |
| **Config-driven** | D2, D7, D8, D10 | 搜索配置 → 对比安全基线 | 配置文件列表 |

**关键区别**:
- Sink-driven: 搜索"存在的危险代码"
- Control-driven: 搜索"应存在但缺失的安全控制"

---

## D9 漏洞子类型

### 1. IDOR / 资源归属校验

**定义**: 用户可以访问或操作不属于他们的资源。

**检测方法**:
```
1. 搜索: findById|getById|selectById|get_object_or_404|findOne
2. 对每个调用:
   a. 返回值是否与当前用户比对？
   b. 查询条件是否包含用户/租户标识？
   c. 无归属校验 + 端点可由普通用户访问 → IDOR 候选
3. 覆盖范围: 全部 CRUD 端点（不止 read，包括 delete/copy/export）
```

**判定规则**:
- findById 后无归属校验 + 端点可由普通用户访问 = **High (IDOR/水平越权)**

### 2. Mass Assignment

**定义**: 攻击者通过修改请求参数绑定到实体类的敏感字段。

**检测方法**:
```
1. 搜索: @RequestBody|@ModelAttribute 绑定的实体类
2. 对每个绑定:
   a. 实体类是否有 @JsonIgnore / @JsonProperty(access=READ_ONLY) 标注敏感字段？
   b. 是否使用 DTO 隔离（而非直接绑定 Entity）？
   c. 无隔离 + 实体含 role/isAdmin/status/siteId 等字段 → Mass Assignment 候选
```

**判定规则**:
- @RequestBody 直接绑定含权限字段的实体 = **High (Mass Assignment)**

### 3. 状态机完整性

**定义**: 多步骤流程中的状态转换缺少前置条件验证。

**检测方法**:
```
1. 识别多步骤流程: Grep status|state|step|phase 字段
2. 对每个流程:
   a. 每步是否验证前置状态？
   b. 能否跳步？能否回退到已完成步骤？
   c. 状态转换是否在事务内？
```

**判定规则**:
- 无状态验证 + 可跳过步骤 = **High (流程绕过)**

### 4. 竞态条件

#### 4a. TOCTOU (Time-of-Check Time-of-Use)

```
搜索: if.*exists|if.*check|if.*find → 后续紧跟写操作
检查与操作之间是否有事务锁/行级锁/乐观锁
无锁 + 影响业务状态 → TOCTOU 候选
```

#### 4b. Lost Update

```
搜索: save|update|put 端点
检查是否有版本号/ETag/乐观锁(@Version)
无版本控制 + 多用户可编辑同一资源 → Lost Update 候选
```

#### 4c. 非线程安全共享状态

```
搜索: HashMap|ArrayList|SimpleDateFormat 用于类字段
Controller/Service 是单例 → 多线程共享 → 线程安全候选
```

**判定规则**:
- 无锁的状态修改 + 影响业务状态 = **High (竞态条件)**

### 5. 数据导出与批量操作

**定义**: 导出/批量操作缺少范围限制或权限控制。

**检测方法**:
```
1. 搜索: export|download|batch|bulk 端点
2. 检查:
   a. 导出范围是否受限于当前用户/租户？
   b. 能否通过参数篡改导出其他租户数据？
```

**判定规则**:
- 批量导出无范围限制 + 多租户场景 = **Medium (数据泄露)**

### 6. 多租户/多站点隔离

**定义**: 跨租户数据访问或操作缺少隔离检查。

**检测方法**:
```
1. 搜索: 查询条件是否强制包含租户/站点标识
2. 检查: 能否通过篡改 siteId/tenantId 参数跨站操作？
```

**判定规则**:
- 跨租户查询无隔离 = **High (数据泄露)**

---

## 审计执行流程

### Phase 1: 端点枚举

```
输出: 端点-权限矩阵
{
  端点路径,
  HTTP方法,
  认证要求,
  权限注解,
  资源归属校验,
  敏感类型 (数据修改/数据访问/资金操作/批量操作)
}
```

### Phase 2: D9 子类型检测

对矩阵中每个端点执行:

| 步骤 | 检测内容 |
|------|---------|
| Step 1 | IDOR / 资源归属校验 |
| Step 2 | Mass Assignment 防护 |
| Step 3 | 状态机完整性 |
| Step 4 | 并发安全 |
| Step 5 | 数据导出与批量操作 |
| Step 6 | 多租户/多站点隔离 |

### Phase 3: 覆盖率评估

```
端点审计率 = endpoints_audited / total_endpoints

Control-driven 覆盖标准:
- deep 模式: 端点审计率 ≥ 50%
- standard 模式: 端点审计率 ≥ 30%
- 至少 3 种资源类型执行了 CRUD 权限一致性对比
```

---

## 风险评级矩阵

| 漏洞类型 | 严重性 | 利用难度 | 检测难度 |
|----------|--------|----------|----------|
| IDOR/水平越权 | High | 低 | 中 |
| Mass Assignment | High | 中 | 低 |
| 状态机绕过 | High | 中 | 高 |
| 竞态条件 | High | 中 | 高 |
| 批量导出泄露 | Medium | 高 | 中 |
| 多租户隔离 | High | 中 | 中 |

---

## 防幻觉规则

D9 审计特别需要注意避免误报:

1. **必须验证端点存在**: 使用 Glob/Read 确认文件和代码真实存在
2. **必须读取控制代码**: 不能假设"应该有权限检查"，必须实际读取并确认
3. **区分公开接口**: 登录/注册/健康检查等公开接口不需要授权
4. **理解业务上下文**: 某些操作可能故意不检查归属（如管理员操作）

**核心原则**: 宁可漏报，不可误报。

---

## 参考

- `/opt/AI/code-audit/references/security/business_logic.md`
- `/opt/AI/code-audit/references/core/phase2_deep_methodology.md` (Phase 2.6)
- `/opt/AI/code-audit/references/checklists/coverage_matrix.md` (D9 维度)
