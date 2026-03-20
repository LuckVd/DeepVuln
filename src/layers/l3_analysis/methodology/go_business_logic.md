# Go Business Logic Detection Patterns

> P6-06b: Go 业务逻辑漏洞检测模式
> 适用于: Go 1.x, Gin, Echo, Fiber, net/http
> 版本: 1.0.0

---

## 框架控制实现对照表

| 控制类型 | Gin | Echo | Fiber | net/http |
|----------|-----|------|-------|----------|
| **认证控制** | 中间件 `AuthRequired()` | 中间件 `middleware.JWT` | 中间件 | 手动检查 |
| **授权控制** | 中间件 + 手动检查 | 中间件 + 手动检查 | 中间件 | 手动检查 |
| **资源所有权** | `userID == resource.OwnerID` | 手动检查 | 手动检查 | 手动检查 |
| **输入验证** | `binding.ShouldBind` | `echo.Bind` | `fiber.BodyParser` | 手动解析 |
| **并发控制** | 事务 + `SELECT FOR UPDATE` | 同左 | 同左 | 同左 |
| **审计日志** | 中间件 | 中间件 | 中间件 | 手动 |

---

## D9.1: IDOR / 资源归属校验

### 检测模式

```go
// 危险模式: 直接使用用户输入的 ID 查询，无归属检查
func (h *Handler) GetOrder(c *gin.Context) {
    id := c.Param("id")
    var order Order
    if err := h.db.First(&order, id).Error; err != nil {
        c.JSON(404, gin.H{"error": "not found"})
        return
    }
    c.JSON(200, order)  // ❌ 无归属校验，任何人可访问
}

// 安全模式: 添加归属校验
func (h *Handler) GetOrder(c *gin.Context) {
    userID := c.GetString("user_id")  // 从认证中间件获取
    id := c.Param("id")

    var order Order
    if err := h.db.First(&order, id).Error; err != nil {
        c.JSON(404, gin.H{"error": "not found"})
        return
    }

    if order.UserID != userID {  // ✓ 归属校验
        c.JSON(403, gin.H{"error": "forbidden"})
        return
    }

    c.JSON(200, order)
}

// 安全模式: 查询时自动过滤
func (h *Handler) GetOrder(c *gin.Context) {
    userID := c.GetString("user_id")
    id := c.Param("id")

    var order Order
    if err := h.db.Where("id = ? AND user_id = ?", id, userID).First(&order).Error; err != nil {
        c.JSON(404, gin.H{"error": "not found"})  // ✓ 自动归属过滤
        return
    }
    c.JSON(200, order)
}
```

### Grep 命令

```bash
# 查找可能的 IDOR 点
grep -rn "\.First\|\.Find\|\.Where" --include="*.go" | grep -v "user_id\|userID\|owner"

# 检查是否有归属校验
grep -A 10 "\.First(&\|\.Find(&" handlers/*.go | grep -E "userID|owner|user_id"

# 查找带 ID 参数的路由
grep -rn ":id\|/id/\|Param.*id" --include="*.go"
```

---

## D9.2: Mass Assignment

### 检测模式

```go
// 危险模式: 直接绑定结构体
type User struct {
    ID       uint   `json:"id"`
    Username string `json:"username"`
    Email    string `json:"email"`
    Role     string `json:"role"`     // ❌ 敏感字段，用户可注入
    IsAdmin  bool   `json:"is_admin"` // ❌ 敏感字段
}

func (h *Handler) CreateUser(c *gin.Context) {
    var user User
    if err := c.ShouldBindJSON(&user); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }
    h.db.Create(&user)  // ❌ 用户可设置 role 和 is_admin
    c.JSON(200, user)
}

// 安全模式: 使用 DTO 隔离
type CreateUserRequest struct {
    Username string `json:"username" binding:"required"`
    Email    string `json:"email" binding:"required,email"`
    Password string `json:"password" binding:"required,min=8"`
    // role, is_admin 不在此结构体中
}

func (h *Handler) CreateUser(c *gin.Context) {
    var req CreateUserRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    user := User{
        Username: req.Username,
        Email:    req.Email,
        Password: hashPassword(req.Password),
        Role:     "user",      // ✓ 服务端设置默认值
        IsAdmin:  false,       // ✓ 服务端设置默认值
    }
    h.db.Create(&user)
    c.JSON(200, user)
}

// 安全模式: 使用 struct tag 限制
type User struct {
    ID       uint   `json:"id" gorm:"primaryKey"`
    Username string `json:"username"`
    Email    string `json:"email"`
    Role     string `json:"-"`              // ✓ JSON 忽略
    IsAdmin  bool   `json:"-"`              // ✓ JSON 忽略
}
```

### Grep 命令

```bash
# 查找结构体绑定
grep -rn "ShouldBind\|BindJSON\|Bind\|Parse" --include="*.go"

# 查找可能的风险字段
grep -rn "Role.*string\|IsAdmin.*bool\|Status.*string" --include="*.go" models/

# 检查是否使用 DTO
grep -rn "Request\|DTO\|Input" --include="*.go" | grep "struct"
```

---

## D9.3: 状态机完整性

### 检测模式

```go
// 危险模式: 无状态验证
func (h *Handler) ShipOrder(c *gin.Context) {
    id := c.Param("id")
    var order Order
    if err := h.db.First(&order, id).Error; err != nil {
        c.JSON(404, gin.H{"error": "not found"})
        return
    }

    order.Status = "shipped"  // ❌ 未检查当前状态
    h.db.Save(&order)
    c.JSON(200, order)
}

// 安全模式: 状态转换验证
var validTransitions = map[string][]string{
    "created":  {"paid", "cancelled"},
    "paid":     {"shipped", "cancelled"},
    "shipped":  {"delivered"},
    "cancelled": {},
    "delivered": {},
}

func canTransition(from, to string) bool {
    allowed, exists := validTransitions[from]
    if !exists {
        return false
    }
    for _, s := range allowed {
        if s == to {
            return true
        }
    }
    return false
}

func (h *Handler) ShipOrder(c *gin.Context) {
    id := c.Param("id")

    tx := h.db.Begin()
    var order Order
    if err := tx.Set("gorm:query_option", "FOR UPDATE").First(&order, id).Error; err != nil {
        tx.Rollback()
        c.JSON(404, gin.H{"error": "not found"})
        return
    }

    if !canTransition(order.Status, "shipped") {  // ✓ 状态验证
        tx.Rollback()
        c.JSON(400, gin.H{"error": "invalid state transition"})
        return
    }

    order.Status = "shipped"
    order.ShippedAt = time.Now()
    tx.Save(&order)
    tx.Commit()

    c.JSON(200, order)
}
```

### Grep 命令

```bash
# 查找状态字段
grep -rn "Status.*string\|State.*string" --include="*.go" models/

# 查找状态变更
grep -rn "\.Status\s*=\|\.State\s*=" --include="*.go"

# 检查是否有状态验证
grep -rn "if.*Status\|if.*state\|canTransition\|validTransition" --include="*.go"
```

---

## D9.4: 竞态条件

### TOCTOU 检测

```go
// 危险模式: Check-Then-Act 竞态
func (h *Handler) Withdraw(c *gin.Context) {
    userID := c.GetString("user_id")
    amount := c.Query("amount")

    var account Account
    h.db.First(&account, "user_id = ?", userID)

    balance, _ := strconv.ParseFloat(account.Balance, 64)
    withdrawAmount, _ := strconv.ParseFloat(amount, 64)

    if balance < withdrawAmount {  // Check
        c.JSON(400, gin.H{"error": "insufficient funds"})
        return
    }
    // ... 竞态窗口 ...
    account.Balance = fmt.Sprintf("%.2f", balance-withdrawAmount)  // Act
    h.db.Save(&account)  // ❌ 余额可能已被修改

    c.JSON(200, account)
}

// 安全模式: 事务 + 行锁
func (h *Handler) Withdraw(c *gin.Context) {
    userID := c.GetString("user_id")
    amount := c.Query("amount")

    tx := h.db.Begin()

    var account Account
    if err := tx.Set("gorm:query_option", "FOR UPDATE").First(&account, "user_id = ?", userID).Error; err != nil {
        tx.Rollback()
        c.JSON(404, gin.H{"error": "account not found"})
        return
    }

    balance, _ := strconv.ParseFloat(account.Balance, 64)
    withdrawAmount, _ := strconv.ParseFloat(amount, 64)

    if balance < withdrawAmount {
        tx.Rollback()
        c.JSON(400, gin.H{"error": "insufficient funds"})
        return
    }

    account.Balance = fmt.Sprintf("%.2f", balance-withdrawAmount)
    tx.Save(&account)
    tx.Commit()  // ✓ 事务提交

    c.JSON(200, account)
}
```

### Lost Update 检测

```go
// 危险模式: 无版本控制
func (h *Handler) UpdateProfile(c *gin.Context) {
    userID := c.GetString("user_id")
    var req UpdateProfileRequest
    c.ShouldBindJSON(&req)

    var profile Profile
    h.db.First(&profile, "user_id = ?", userID)

    profile.Name = req.Name  // ❌ 可能覆盖其他用户的更新
    h.db.Save(&profile)

    c.JSON(200, profile)
}

// 安全模式: 乐观锁
type Profile struct {
    ID        uint   `gorm:"primaryKey"`
    UserID    string
    Name      string
    Version   int    `gorm:"version"`  // ✓ 乐观锁版本号
    UpdatedAt time.Time
}

func (h *Handler) UpdateProfile(c *gin.Context) {
    userID := c.GetString("user_id")
    var req UpdateProfileRequest
    c.ShouldBindJSON(&req)
    expectedVersion := c.GetHeader("If-Match")  // 客户端提供版本

    var profile Profile
    if err := h.db.First(&profile, "user_id = ?", userID).Error; err != nil {
        c.JSON(404, gin.H{"error": "not found"})
        return
    }

    if fmt.Sprintf("%d", profile.Version) != expectedVersion {
        c.JSON(409, gin.H{"error": "concurrent modification"})  // ✓ 版本冲突
        return
    }

    profile.Name = req.Name
    h.db.Save(&profile)  // GORM 会自动更新 Version

    c.JSON(200, profile)
}
```

### 线程安全检测

```go
// 危险模式: 全局可变状态
var cache = make(map[string]interface{})  // ❌ 非线程安全

func GetCached(key string) interface{} {
    return cache[key]  // 竞态条件
}

// 安全模式: 使用 sync.Map 或加锁
var cache sync.Map  // ✓ 线程安全

func GetCached(key string) interface{} {
    value, ok := cache.Load(key)
    if !ok {
        return nil
    }
    return value
}

// 或使用互斥锁
var (
    cacheMu sync.RWMutex
    cache   = make(map[string]interface{})
)

func GetCached(key string) interface{} {
    cacheMu.RLock()
    defer cacheMu.RUnlock()
    return cache[key]
}
```

### Grep 命令

```bash
# 查找 Check-Then-Act 模式
grep -rn "if.*balance\|if.*count\|if.*Balance" --include="*.go" -A 5

# 查找全局可变状态
grep -rn "^var\s\+\w\+\s\+=\s\+make\|^var\s\+\w\+\s\+=\s\+map" --include="*.go"

# 检查是否有锁机制
grep -rn "sync.Mutex\|sync.RWMutex\|sync.Map\|FOR UPDATE\|tx\.Begin" --include="*.go"
```

---

## D9.5: 数据导出与批量操作

### 检测模式

```go
// 危险模式: 无范围限制的导出
func (h *Handler) ExportUsers(c *gin.Context) {
    var users []User
    h.db.Find(&users)  // ❌ 导出所有用户
    c.JSON(200, users)
}

// 安全模式: 限制导出范围
func (h *Handler) ExportUsers(c *gin.Context) {
    userID := c.GetString("user_id")
    userRole := c.GetString("user_role")

    if userRole != "admin" {
        c.JSON(403, gin.H{"error": "forbidden"})
        return
    }

    organizationID := c.GetString("organization_id")
    var users []User
    h.db.Where("organization_id = ?", organizationID).Find(&users)  // ✓ 限制范围
    c.JSON(200, users)
}
```

### Grep 命令

```bash
# 查找导出端点
grep -rn "export\|Export\|download\|Download" --include="*.go"

# 检查导出范围限制
grep -B 5 -A 10 "export\|Export" handlers/*.go | grep "Where\|organization\|tenant"
```

---

## D9.6: 多租户隔离

### 检测模式

```go
// 危险模式: 无租户过滤
func (h *Handler) GetDocuments(c *gin.Context) {
    var documents []Document
    h.db.Find(&documents)  // ❌ 跨租户数据泄露
    c.JSON(200, documents)
}

// 安全模式: 强制租户过滤
func (h *Handler) GetDocuments(c *gin.Context) {
    tenantID := c.GetString("tenant_id")

    var documents []Document
    h.db.Where("tenant_id = ?", tenantID).Find(&documents)  // ✓ 租户隔离
    c.JSON(200, documents)
}

// 安全模式: 使用中间件自动注入租户条件
func TenantMiddleware(db *gorm.DB) gin.HandlerFunc {
    return func(c *gin.Context) {
        tenantID := c.GetString("tenant_id")
        c.Set("db", db.Scopes(func(d *gorm.DB) *gorm.DB {
            return d.Where("tenant_id = ?", tenantID)
        }))
        c.Next()
    }
}
```

### Grep 命令

```bash
# 查找多租户字段
grep -rn "tenant\|Tenant\|organization\|Organization" --include="*.go"

# 检查查询是否包含租户过滤
grep -rn "tenant_id\|organization_id" --include="*.go" | grep "Where"

# 检查中间件
grep -rn "func.*Middleware\|TenantMiddleware" --include="*.go"
```

---

## 控制验证清单

```markdown
## Go 端点 D9 验证

| 端点 | IDOR检查 | Mass Assignment | 状态验证 | 竞态安全 | 结果 |
|------|---------|-----------------|---------|---------|------|
| GET /api/orders/:id | □ | N/A | N/A | N/A | |
| POST /api/orders | N/A | □ | □ | □ | |
| PUT /api/orders/:id | □ | □ | □ | □ | |
| DELETE /api/orders/:id | □ | N/A | □ | □ | |
| GET /api/export | □ | N/A | N/A | N/A | |
```

---

## 参考

- 通用方法论: `methodology/business_logic.md`
- code-audit Go 参考: `/opt/AI/code-audit/references/languages/go.md`
