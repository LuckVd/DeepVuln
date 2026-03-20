# Python Business Logic Detection Patterns

> P6-06b: Python 业务逻辑漏洞检测模式
> 适用于: Python 2.x / 3.x, Flask, Django, FastAPI, Tornado
> 版本: 1.0.0

---

## 框架控制实现对照表

| 控制类型 | Django | Flask | FastAPI |
|----------|--------|-------|---------|
| **认证控制** | `@login_required`, `IsAuthenticated` | `@login_required`, Flask-Login | `Depends(get_current_user)` |
| **授权控制** | `@permission_required`, DRF Permissions | `@roles_required`, Flask-Principal | `Security(scopes=[])` |
| **资源所有权** | `obj.owner == request.user` | 手动检查 | 手动检查 |
| **输入验证** | Django Forms, DRF Serializers | WTForms, Marshmallow | Pydantic Models |
| **并发控制** | `select_for_update()`, F()表达式 | SQLAlchemy with_for_update | SQLAlchemy锁 |
| **审计日志** | django-auditlog, signals | 自定义装饰器 | 中间件 |

---

## D9.1: IDOR / 资源归属校验

### 检测模式

#### Django/DRF

```python
# 危险模式: 直接使用用户输入的 ID 查询，无归属检查
def get_object(self):
    return MyModel.objects.get(id=self.kwargs['pk'])  # ❌ 无归属校验

# 安全模式: 添加归属校验
def get_object(self):
    obj = MyModel.objects.get(id=self.kwargs['pk'])
    if obj.owner != self.request.user:  # ✓ 归属校验
        raise PermissionDenied()
    return obj

# 或使用 QuerySet 过滤
def get_queryset(self):
    return MyModel.objects.filter(owner=self.request.user)  # ✓ 自动过滤
```

#### Flask

```python
# 危险模式
@app.route('/api/order/<int:order_id>')
def get_order(order_id):
    order = Order.query.get(order_id)  # ❌ 无归属校验
    return jsonify(order.to_dict())

# 安全模式
@app.route('/api/order/<int:order_id>')
@login_required
def get_order(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id:  # ✓ 归属校验
        abort(403)
    return jsonify(order.to_dict())
```

#### FastAPI

```python
# 危险模式
@router.get("/orders/{order_id}")
async def get_order(order_id: int):
    order = await Order.get(order_id)  # ❌ 无归属校验
    return order

# 安全模式
@router.get("/orders/{order_id}")
async def get_order(
    order_id: int,
    current_user: User = Depends(get_current_user)
):
    order = await Order.get_or_404(order_id)
    if order.user_id != current_user.id:  # ✓ 归属校验
        raise HTTPException(403)
    return order
```

### Grep 命令

```bash
# 查找可能的 IDOR 点
grep -rn "\.get\s*(\|\.filter\s*(\|get_object_or_404\|query\.get" --include="*.py"

# 检查是否有归属校验
grep -A 10 "\.get\s*(" views.py | grep -E "user|owner|created_by"

# 查找带 ID 参数的路由
grep -rn "@app\.route.*<.*>\|@router\.get.*{" --include="*.py"
```

---

## D9.2: Mass Assignment

### 检测模式

#### Django

```python
# 危险模式: 直接使用用户输入创建对象
def create_user(request):
    user = User.objects.create(**request.POST)  # ❌ 用户可控制所有字段
    return JsonResponse({'id': user.id})

# 安全模式: 使用表单/序列化器验证
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email']  # ✓ 仅允许安全字段
        read_only_fields = ['is_staff', 'is_superuser']  # ✓ 敏感字段只读

def create_user(request):
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return JsonResponse(serializer.data, status=201)
```

#### Flask

```python
# 危险模式
@app.route('/api/user', methods=['POST'])
def create_user():
    user = User(**request.json)  # ❌ 用户可注入 is_admin=True
    db.session.add(user)
    db.session.commit()
    return jsonify(user.to_dict())

# 安全模式
@app.route('/api/user', methods=['POST'])
def create_user():
    allowed_fields = ['username', 'email', 'password']  # ✓ 白名单
    data = {k: v for k, v in request.json.items() if k in allowed_fields}
    user = User(**data)
    db.session.add(user)
    db.session.commit()
    return jsonify(user.to_dict())
```

#### FastAPI

```python
# 安全模式: 使用 Pydantic 模型隔离
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    # is_admin 不在模型中 → 无法注入

@router.post("/users")
async def create_user(user_in: UserCreate):
    user = await User.create(**user_in.dict())
    return user
```

### Grep 命令

```bash
# 查找可能的 Mass Assignment
grep -rn "\*\*request\.\|**request\[" --include="*.py"

# 查找 Model.objects.create 和 save
grep -rn "\.create\s*(\|\.save\s*(" --include="*.py" -A 2

# 检查是否使用 Serializer/Form
grep -rn "Serializer\|Form\|validate" --include="*.py"
```

---

## D9.3: 状态机完整性

### 检测模式

```python
# 危险模式: 无状态验证
def ship_order(order_id):
    order = Order.objects.get(id=order_id)
    order.status = 'shipped'  # ❌ 未检查当前状态
    order.save()

# 安全模式: 状态转换验证
VALID_TRANSITIONS = {
    'pending': ['paid', 'cancelled'],
    'paid': ['shipped', 'refunded'],
    'shipped': ['delivered'],
    'cancelled': [],
    'refunded': [],
}

def ship_order(order_id):
    order = Order.objects.select_for_update().get(id=order_id)  # ✓ 加锁

    if order.status not in ['paid']:  # ✓ 前置状态检查
        raise InvalidStateError(f"Cannot ship from {order.status}")

    if order.status not in VALID_TRANSITIONS.get(order.status, []):
        raise InvalidStateError("Invalid transition")

    order.status = 'shipped'
    order.shipped_at = timezone.now()
    order.save()
```

### Grep 命令

```bash
# 查找状态字段
grep -rn "status\s*=\|state\s*=" --include="*.py" -B 2 -A 5

# 查找状态变更
grep -rn "\.status\s*=\|\.state\s*=" --include="*.py" -A 2

# 检查是否有状态验证
grep -rn "if.*status\|if.*state" --include="*.py"
```

---

## D9.4: 竞态条件

### TOCTOU 检测

```python
# 危险模式: Check-Then-Act 竞态
def transfer_money(from_id, to_id, amount):
    from_account = Account.objects.get(id=from_id)
    if from_account.balance < amount:  # Check
        raise InsufficientFundsError()
    # ... 竞态窗口 ...
    from_account.balance -= amount  # Act
    from_account.save()  # ❌ 余额可能已被其他请求修改

# 安全模式: 原子操作
def transfer_money(from_id, to_id, amount):
    with transaction.atomic():
        from_account = Account.objects.select_for_update().get(id=from_id)  # ✓ 行锁
        if from_account.balance < amount:
            raise InsufficientFundsError()
        from_account.balance -= amount
        from_account.save()

        to_account = Account.objects.select_for_update().get(id=to_id)
        to_account.balance += amount
        to_account.save()
```

### Lost Update 检测

```python
# 危险模式: 无版本控制
def update_profile(user_id, data):
    user = User.objects.get(id=user_id)
    user.name = data['name']  # ❌ 可能覆盖其他用户的更新
    user.save()

# 安全模式: 乐观锁
def update_profile(user_id, data, expected_version):
    user = User.objects.get(id=user_id)
    if user.version != expected_version:  # ✓ 版本检查
        raise ConcurrentModificationError()
    user.name = data['name']
    user.version += 1
    user.save()
```

### 线程安全检测

```python
# 危险模式: 类级别的可变状态
class MyView(View):
    cache = {}  # ❌ 多线程共享，竞态条件

    def get(self, request):
        self.cache[request.user.id] = request.GET
        return JsonResponse(self.cache)

# 安全模式: 使用线程安全结构或局部变量
from threading import Lock

class MyView(View):
    _cache = {}
    _lock = Lock()

    def get(self, request):
        with self._lock:  # ✓ 加锁
            self._cache[request.user.id] = request.GET
        return JsonResponse(self._cache)
```

### Grep 命令

```bash
# 查找 Check-Then-Act 模式
grep -rn "if.*balance\|if.*count\|if.*exists" --include="*.py" -A 5 | grep -v "select_for_update"

# 查找类级别可变状态
grep -rn "^\s*\w*\s*=\s*{\|^\s*\w*\s*=\s*\[" --include="*.py" views.py

# 检查是否有锁机制
grep -rn "select_for_update\|@transaction\|Lock\|with.*lock" --include="*.py"
```

---

## D9.5: 数据导出与批量操作

### 检测模式

```python
# 危险模式: 无范围限制的导出
@app.route('/api/users/export')
@login_required
def export_users():
    users = User.objects.all()  # ❌ 导出所有用户
    return export_to_csv(users)

# 安全模式: 限制导出范围
@app.route('/api/users/export')
@login_required
def export_users():
    if not current_user.has_permission('user:export'):
        abort(403)

    # ✓ 仅导出当前用户所属组织的数据
    users = User.objects.filter(organization=current_user.organization)
    return export_to_csv(users)
```

### Grep 命令

```bash
# 查找导出端点
grep -rn "export\|download\|csv\|excel" --include="*.py"

# 检查导出范围
grep -B 5 -A 10 "def export" --include="*.py" | grep "filter\|organization\|tenant"
```

---

## D9.6: 多租户隔离

### 检测模式

```python
# 危险模式: 无租户过滤
class DocumentViewSet(viewsets.ModelViewSet):
    def get_queryset(self):
        return Document.objects.all()  # ❌ 跨租户数据泄露

# 安全模式: 强制租户过滤
class DocumentViewSet(viewsets.ModelViewSet):
    def get_queryset(self):
        return Document.objects.filter(
            tenant=self.request.user.tenant  # ✓ 租户隔离
        )

    def perform_create(self, serializer):
        serializer.save(tenant=self.request.user.tenant)  # ✓ 自动设置租户
```

### Grep 命令

```bash
# 查找多租户字段
grep -rn "tenant\|organization\|site_id\|company" --include="*.py"

# 检查查询是否包含租户过滤
grep -rn "\.filter\|\.get" --include="*.py" | grep "tenant\|organization"
```

---

## 控制验证清单

```markdown
## Python 端点 D9 验证

| 端点 | IDOR检查 | Mass Assignment | 状态验证 | 竞态安全 | 结果 |
|------|---------|-----------------|---------|---------|------|
| GET /api/order/{id} | □ | N/A | N/A | N/A | |
| POST /api/order | N/A | □ | □ | □ | |
| PUT /api/order/{id} | □ | □ | □ | □ | |
| DELETE /api/order/{id} | □ | N/A | □ | □ | |
| GET /api/export | □ | N/A | N/A | N/A | |
```

---

## 参考

- 通用方法论: `methodology/business_logic.md`
- code-audit Python 参考: `/opt/AI/code-audit/references/languages/python.md`
