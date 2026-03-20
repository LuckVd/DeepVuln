# Java Business Logic Detection Patterns

> P6-06b: Java 业务逻辑漏洞检测模式
> 适用于: Java 8+, Spring Boot, Spring MVC, Spring Security
> 版本: 1.0.0

---

## 框架控制实现对照表

| 控制类型 | Spring 实现方式 | 检查方法 |
|----------|-----------------|----------|
| **认证控制** | `@PreAuthorize("isAuthenticated()")`, SecurityFilter | 检查注解或 Filter 链 |
| **授权控制** | `@PreAuthorize("hasRole('X')")`, `@Secured`, `@RequiresPermissions` | 检查权限注解 |
| **资源所有权** | `entity.getOwnerId().equals(currentUserId)` | 检查 Service/Repository 代码 |
| **输入验证** | `@Valid`, `@NotNull`, `@Size`, Validator | 检查验证注解 |
| **并发控制** | `@Transactional` + `@Lock`, `SELECT FOR UPDATE` | 检查事务和锁 |
| **审计日志** | `@Audit` 注解, AOP, Spring Data Auditing | 检查日志切面 |

---

## D9.1: IDOR / 资源归属校验

### 检测模式

```java
// 危险模式: 直接使用用户输入的 ID 查询，无归属检查
@GetMapping("/orders/{id}")
public Order getOrder(@PathVariable Long id) {
    return orderRepository.findById(id).orElseThrow();  // ❌ 无归属校验
}

// 安全模式: 添加归属校验
@GetMapping("/orders/{id}")
public Order getOrder(@PathVariable Long id, @AuthenticationPrincipal User user) {
    Order order = orderRepository.findById(id).orElseThrow();
    if (!order.getUserId().equals(user.getId())) {  // ✓ 归属校验
        throw new AccessDeniedException("Not your order");
    }
    return order;
}

// 安全模式: 使用 Spring Data 自动过滤
public interface OrderRepository extends JpaRepository<Order, Long> {
    @Query("SELECT o FROM Order o WHERE o.id = :id AND o.userId = :userId")
    Optional<Order> findByIdAndUserId(@Param("id") Long id, @Param("userId") Long userId);
}
```

### Grep 命令

```bash
# 查找可能的 IDOR 点
grep -rn "findById\|getById\|findOne\|getOne" --include="*.java"

# 检查是否有归属校验
grep -A 10 "findById" Controller.java | grep -E "userId|owner|createdBy|equals"

# 查找带 ID 参数的路由
grep -rn "@GetMapping.*{id}\|@PathVariable.*id" --include="*.java"
```

---

## D9.2: Mass Assignment

### 检测模式

```java
// 危险模式: 直接绑定实体类
@PostMapping("/users")
public User createUser(@RequestBody User user) {  // ❌ 用户可注入 role, isAdmin 等字段
    return userRepository.save(user);
}

// 安全模式: 使用 DTO 隔离
public class UserCreateDTO {
    private String username;
    private String email;
    private String password;
    // role, isAdmin 等敏感字段不在此 DTO 中
}

@PostMapping("/users")
public User createUser(@Valid @RequestBody UserCreateDTO dto) {
    User user = new User();
    user.setUsername(dto.getUsername());
    user.setEmail(dto.getEmail());
    user.setPassword(passwordEncoder.encode(dto.getPassword()));
    user.setRole(Role.USER);  // ✓ 服务端设置默认角色
    return userRepository.save(user);
}

// 安全模式: 使用 @JsonIgnore 标记只读字段
@Entity
public class User {
    @JsonIgnore  // ✓ JSON 序列化时忽略
    @Column(nullable = false)
    private String role = "USER";

    @JsonProperty(access = JsonProperty.Access.READ_ONLY)  // ✓ 只读
    private Boolean isAdmin = false;
}
```

### Grep 命令

```bash
# 查找 @RequestBody 绑定的实体类
grep -rn "@RequestBody\s*\w\+\s*\w\+" --include="*.java" -A 1

# 检查实体类是否有敏感字段保护
grep -rn "@JsonIgnore\|@JsonProperty.*READ_ONLY" --include="*.java"

# 查找可能的风险字段
grep -rn "role\|isAdmin\|isSuperuser\|status\|siteId" --include="*.java" Entity.java
```

---

## D9.3: 状态机完整性

### 检测模式

```java
// 危险模式: 无状态验证
@PostMapping("/orders/{id}/ship")
public Order shipOrder(@PathVariable Long id) {
    Order order = orderRepository.findById(id).orElseThrow();
    order.setStatus(OrderStatus.SHIPPED);  // ❌ 未检查当前状态
    return orderRepository.save(order);
}

// 安全模式: 状态转换验证
public enum OrderStatus {
    CREATED, PAID, SHIPPED, DELIVERED, CANCELLED;

    private static final Map<OrderStatus, Set<OrderStatus>> TRANSITIONS = Map.of(
        CREATED, Set.of(PAID, CANCELLED),
        PAID, Set.of(SHIPPED, CANCELLED),
        SHIPPED, Set.of(DELIVERED)
    );

    public boolean canTransitionTo(OrderStatus target) {
        return TRANSITIONS.getOrDefault(this, Set.of()).contains(target);
    }
}

@PostMapping("/orders/{id}/ship")
@Transactional
public Order shipOrder(@PathVariable Long id) {
    Order order = orderRepository.findByIdWithLock(id).orElseThrow();  // ✓ 悲观锁

    if (!order.getStatus().canTransitionTo(OrderStatus.SHIPPED)) {  // ✓ 状态验证
        throw new InvalidStateException("Cannot ship from " + order.getStatus());
    }

    order.setStatus(OrderStatus.SHIPPED);
    order.setShippedAt(Instant.now());
    return orderRepository.save(order);
}
```

### Grep 命令

```bash
# 查找状态字段
grep -rn "Status\s*status\|State\s*state" --include="*.java" -A 2

# 查找状态变更
grep -rn "\.setStatus\|\.setState\|\.status\s*=" --include="*.java" -A 2

# 检查是否有状态验证
grep -rn "if.*status\|if.*state\|canTransition\|isValidTransition" --include="*.java"
```

---

## D9.4: 竞态条件

### TOCTOU 检测

```java
// 危险模式: Check-Then-Act 竞态
@PostMapping("/accounts/{id}/withdraw")
public Account withdraw(@PathVariable Long id, @RequestParam BigDecimal amount) {
    Account account = accountRepository.findById(id).orElseThrow();

    if (account.getBalance().compareTo(amount) < 0) {  // Check
        throw new InsufficientFundsException();
    }
    // ... 竞态窗口 ...
    account.setBalance(account.getBalance().subtract(amount));  // Act
    return accountRepository.save(account);  // ❌ 余额可能已被修改
}

// 安全模式: 悲观锁
@PostMapping("/accounts/{id}/withdraw")
@Transactional
public Account withdraw(@PathVariable Long id, @RequestParam BigDecimal amount) {
    Account account = accountRepository.findByIdWithLock(id).orElseThrow();  // ✓ SELECT FOR UPDATE

    if (account.getBalance().compareTo(amount) < 0) {
        throw new InsufficientFundsException();
    }

    account.setBalance(account.getBalance().subtract(amount));
    return accountRepository.save(account);
}

// Repository 中的锁方法
public interface AccountRepository extends JpaRepository<Account, Long> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT a FROM Account a WHERE a.id = :id")
    Optional<Account> findByIdWithLock(@Param("id") Long id);
}
```

### Lost Update 检测

```java
// 危险模式: 无版本控制
@PutMapping("/profiles/{id}")
public Profile updateProfile(@PathVariable Long id, @RequestBody ProfileDTO dto) {
    Profile profile = profileRepository.findById(id).orElseThrow();
    profile.setName(dto.getName());  // ❌ 可能覆盖其他用户的更新
    return profileRepository.save(profile);
}

// 安全模式: 乐观锁
@Entity
public class Profile {
    @Id
    private Long id;

    private String name;

    @Version  // ✓ JPA 乐观锁
    private Long version;
}

@PutMapping("/profiles/{id}")
public Profile updateProfile(
    @PathVariable Long id,
    @RequestBody ProfileDTO dto,
    @RequestHeader("If-Match") Long expectedVersion  // ✓ 客户端提供版本
) {
    Profile profile = profileRepository.findById(id).orElseThrow();

    if (!profile.getVersion().equals(expectedVersion)) {
        throw new ConcurrentModificationException();  // ✓ 版本冲突
    }

    profile.setName(dto.getName());
    return profileRepository.save(profile);
}
```

### 线程安全检测

```java
// 危险模式: Controller 级别的可变状态
@RestController
public class UserController {
    private Map<Long, User> cache = new HashMap<>();  // ❌ Spring 单例，多线程共享

    @GetMapping("/users/{id}")
    public User getUser(@PathVariable Long id) {
        return cache.computeIfAbsent(id, userRepository::findById);
    }
}

// 安全模式: 使用线程安全结构
@RestController
public class UserController {
    private final ConcurrentHashMap<Long, User> cache = new ConcurrentHashMap<>();  // ✓ 线程安全

    @GetMapping("/users/{id}")
    public User getUser(@PathVariable Long id) {
        return cache.computeIfAbsent(id, k -> userRepository.findById(k).orElseThrow());
    }
}
```

### Grep 命令

```bash
# 查找 Check-Then-Act 模式
grep -rn "if.*balance\|if.*count\|if.*getBalance" --include="*.java" -A 5

# 查找类级别可变状态
grep -rn "private.*Map\|private.*List\|private.*Set" --include="*.java" Controller.java

# 检查是否有锁机制
grep -rn "@Lock\|@Version\|select_for_update\|PESSIMISTIC" --include="*.java"
```

---

## D9.5: 数据导出与批量操作

### 检测模式

```java
// 危险模式: 无范围限制的导出
@GetMapping("/users/export")
public List<User> exportUsers() {
    return userRepository.findAll();  // ❌ 导出所有用户
}

// 安全模式: 限制导出范围
@GetMapping("/users/export")
@PreAuthorize("hasRole('ADMIN')")
public List<User> exportUsers(@AuthenticationPrincipal User currentUser) {
    if (!currentUser.hasPermission("user:export")) {
        throw new AccessDeniedException("No export permission");
    }

    // ✓ 仅导出当前用户所属组织的数据
    return userRepository.findByOrganizationId(currentUser.getOrganizationId());
}
```

### Grep 命令

```bash
# 查找导出端点
grep -rn "@GetMapping.*export\|@GetMapping.*download" --include="*.java"

# 检查导出范围限制
grep -B 5 -A 10 "export" Controller.java | grep "organization\|tenant\|filter"
```

---

## D9.6: 多租户隔离

### 检测模式

```java
// 危险模式: 无租户过滤
@Service
public class DocumentService {
    public List<Document> getAllDocuments() {
        return documentRepository.findAll();  // ❌ 跨租户数据泄露
    }
}

// 安全模式: 强制租户过滤
@Service
public class DocumentService {
    @Autowired
    private TenantContext tenantContext;

    public List<Document> getAllDocuments() {
        return documentRepository.findByTenantId(tenantContext.getCurrentTenantId());  // ✓ 租户隔离
    }

    public Document createDocument(Document document) {
        document.setTenantId(tenantContext.getCurrentTenantId());  // ✓ 自动设置租户
        return documentRepository.save(document);
    }
}

// 使用 Hibernate Filter 实现自动租户过滤
@Entity
@FilterDef(name = "tenantFilter", parameters = @ParamDef(name = "tenantId", type = Long.class))
@Filter(name = "tenantFilter", condition = "tenant_id = :tenantId")
public class Document {
    // ...
}
```

### Grep 命令

```bash
# 查找多租户字段
grep -rn "tenant\|organization\|siteId\|companyId" --include="*.java"

# 检查查询是否包含租户过滤
grep -rn "findBy.*Tenant\|findBy.*Organization" --include="*.java"

# 检查 Hibernate Filter
grep -rn "@FilterDef\|@Filter" --include="*.java"
```

---

## 权限注解一致性检查

### 检测模式

```java
// 危险模式: CRUD 权限不一致
@RestController
@RequestMapping("/api/users")
public class UserController {

    @PreAuthorize("hasRole('ADMIN')")  // ✓ 有权限
    @GetMapping
    public List<User> listUsers() { ... }

    @GetMapping("/{id}")  // ❌ 无权限注解
    public User getUser(@PathVariable Long id) { ... }

    @PreAuthorize("hasRole('ADMIN')")  // ✓ 有权限
    @PostMapping
    public User createUser(@RequestBody UserDTO dto) { ... }

    @PutMapping("/{id}")  // ❌ 无权限注解
    public User updateUser(@PathVariable Long id, @RequestBody UserDTO dto) { ... }

    @DeleteMapping("/{id}")  // ❌ 无权限注解
    public void deleteUser(@PathVariable Long id) { ... }
}
```

### Grep 命令

```bash
# 检查 Controller 中所有端点的权限注解
grep -rn "@.*Mapping\|@PreAuthorize\|@Secured\|@RequiresPermissions" --include="*Controller.java" -B 1

# 找出无权限注解的端点
grep -rn "@.*Mapping" --include="*Controller.java" | grep -v "@PreAuthorize"
```

---

## 控制验证清单

```markdown
## Java 端点 D9 验证

| 端点 | IDOR检查 | Mass Assignment | 状态验证 | 竞态安全 | 权限一致 | 结果 |
|------|---------|-----------------|---------|---------|---------|------|
| GET /api/orders/{id} | □ | N/A | N/A | N/A | □ | |
| POST /api/orders | N/A | □ | □ | □ | □ | |
| PUT /api/orders/{id} | □ | □ | □ | □ | □ | |
| DELETE /api/orders/{id} | □ | N/A | □ | □ | □ | |
| GET /api/export | □ | N/A | N/A | N/A | □ | |
```

---

## 参考

- 通用方法论: `methodology/business_logic.md`
- code-audit Java 参考: `/opt/AI/code-audit/references/languages/java.md`
