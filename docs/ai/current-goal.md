# Current Goal

> **状态**: 设计确认中
> **目标**: JWT 登录认证系统 — 默认账户 admin/deepvuln + 首次登录强制改密
> **Goal ID**: feat-jwt-auth
> **创建日期**: 2026-04-17

---

## 需求描述

为 DeepVuln Web 平台实现登录认证系统：
- 默认账户 `admin` / `deepvuln`，服务启动时自动种子
- 首次登录强制修改密码
- JWT Token 认证，保留现有 API Key 并行
- 仅单用户模式（admin），无需多用户/注册

---

## 技术选型

| 项目 | 选择 | 理由 |
|------|------|------|
| Token 机制 | JWT (HS256) | 无状态，适配前后端分离架构 |
| 密码哈希 | passlib[bcrypt] | 行业标准 |
| JWT 库 | python-jose[cryptography] | FastAPI 生态主流 |
| 前端状态 | React Context + localStorage | 项目已有 Context 模式 |
| 单用户 | 仅 admin，启动时种子 | 最小化实现 |

---

## 后端设计

### 1. 新增文件

| 文件 | 用途 |
|------|------|
| `src/web/models/user.py` | User ORM 模型 |
| `src/web/services/auth_service.py` | 认证服务（登录/改密/JWT验证/种子） |
| `src/web/api/v1/auth.py` | 认证 API 路由 |

### 2. User 模型 (`user.py`)

```
users 表:
  id              Integer PK
  username        String(50) UNIQUE NOT NULL
  password_hash   String(255) NOT NULL
  must_change_password  Boolean DEFAULT TRUE
  is_active       Boolean DEFAULT TRUE
  created_at      DateTime
  updated_at      DateTime
```

### 3. Auth Service (`auth_service.py`)

| 方法 | 功能 |
|------|------|
| `authenticate(db, username, password)` | 验证用户名密码，返回 user 或 None |
| `create_access_token(user_id)` | 生成 JWT（含 must_change_password 声明） |
| `verify_token(token)` | 解码验证 JWT，返回 payload 或 None |
| `change_password(db, user_id, new_password)` | 更新密码哈希，清除 must_change_password |
| `seed_default_user(db)` | 检查 admin 是否存在，不存在则创建 |

### 4. Auth API (`auth.py`)

| 端点 | 方法 | 认证 | 功能 |
|------|------|------|------|
| `/auth/login` | POST | 无 | 登录，返回 JWT + must_change_password |
| `/auth/change-password` | POST | JWT | 修改密码 |
| `/auth/me` | GET | JWT | 获取当前用户信息 |
| `/auth/logout` | POST | JWT | 前端清除 token（无服务端操作） |

### 5. 安全依赖扩展 (`security.py`)

新增 `get_current_user` 依赖：
- 从 `Authorization: Bearer <token>` 提取 JWT
- 验证 token，查库获取用户
- 用于保护需要登录的端点

认证优先级：JWT Bearer > API Key > 无认证

### 6. 配置扩展 (`config.py` SecuritySettings)

```
jwt_secret: str = "deepvuln-jwt-secret-change-in-production"
jwt_algorithm: str = "HS256"
jwt_expire_minutes: int = 1440  # 24h
auth_enabled: bool = True  # 总开关，False 时跳过所有认证
```

### 7. 启动种子 (`main.py` lifespan)

在 `init_db()` 之后调用 `seed_default_user()`，确保 admin 用户存在。

### 8. 依赖安装

```
pip install python-jose[cryptography] passlib[bcrypt]
```

---

## 前端设计

### 1. 新增文件

| 文件 | 用途 |
|------|------|
| `src/api/auth.ts` | 认证 API 调用 |
| `src/contexts/AuthContext.tsx` | 认证状态管理 |
| `src/pages/Login.tsx` | 登录页面（赛博风格） |
| `src/components/auth/AuthGuard.tsx` | 路由守卫 |
| `src/components/auth/ChangePasswordModal.tsx` | 强制改密弹窗 |

### 2. AuthContext

- `token` / `user` / `mustChangePassword` 状态
- `login(username, password)` / `logout()` / `changePassword(newPassword)`
- token 存 localStorage，初始化时自动恢复

### 3. 登录页 (`Login.tsx`)

- 深色赛博风格，与现有 UI 一致
- Username + Password 输入框
- 登录按钮 + 错误提示
- 全屏布局（不显示侧边栏）

### 4. 路由守卫 (`AuthGuard.tsx`)

- 包裹所有 AppLayout 子路由
- 无 token → 重定向 /login
- mustChangePassword → 弹出 ChangePasswordModal
- 未激活 → 提示错误

### 5. 路由更新 (`App.tsx`)

```
/login          → LoginPage（无需认证）
/               → AuthGuard → AppLayout
                  /dashboard, /scans, /settings ...
```

### 6. Axios 拦截器更新 (`client.ts`)

- 请求拦截器：从 localStorage 读取 token，注入 `Authorization: Bearer <token>`
- 响应拦截器：401 时清除 token 并跳转 /login

### 7. AppLayout 更新

- 侧边栏底部添加用户名 + 退出按钮

---

## 实现步骤

### Phase 1: 后端基础
1. 安装依赖 `python-jose[cryptography] passlib[bcrypt]`
2. 创建 `src/web/models/user.py` — User ORM 模型
3. 扩展 `SecuritySettings` — JWT 配置项
4. 创建 `src/web/services/auth_service.py` — 认证核心逻辑
5. 创建 `src/web/api/v1/auth.py` — 认证 API 端点
6. 扩展 `security.py` — `get_current_user` 依赖
7. 更新 `main.py` — 启动时种子默认用户
8. 注册路由到 `api.py`

### Phase 2: 前端
9. 创建 `api/auth.ts` — 认证 API 调用
10. 创建 `contexts/AuthContext.tsx` — 认证状态
11. 更新 `api/client.ts` — 注入 token 拦截器
12. 创建 `pages/Login.tsx` — 登录页面
13. 创建 `components/auth/AuthGuard.tsx` — 路由守卫
14. 创建 `components/auth/ChangePasswordModal.tsx` — 改密弹窗
15. 更新 `App.tsx` — 集成路由守卫
16. 更新 `AppLayout.tsx` — 用户信息 + 退出

### Phase 3: 测试
17. 编写后端测试 `tests/unit/test_web/test_auth.py`
18. 手动验证前端流程

---

## 测试策略

### 后端单元测试

| 测试用例 | 验证 |
|----------|------|
| `test_seed_creates_admin` | 种子创建 admin 用户 |
| `test_seed_idempotent` | 重复种子不报错 |
| `test_authenticate_success` | 正确密码返回 user |
| `test_authenticate_wrong_password` | 错误密码返回 None |
| `test_create_and_verify_token` | JWT 创建和验证 |
| `test_login_endpoint_success` | POST /auth/login 200 |
| `test_login_endpoint_wrong_password` | POST /auth/login 401 |
| `test_change_password` | 改密后旧密码失效 |
| `test_change_password_clears_flag` | 改密后 must_change_password=False |
| `test_me_endpoint_authenticated` | GET /auth/me 200 |
| `test_me_endpoint_unauthenticated` | GET /auth/me 401 |

### 前端验证

- 登录流程：输入凭据 → 获取 token → 跳转 dashboard
- 首次登录：mustChangePassword=true → 弹出改密弹窗
- Token 注入：后续请求 Authorization 头正确
- 401 处理：token 过期 → 清除 → 跳转 /login
- 退出：清除 token → 跳转 /login

---

## 修改文件清单

### 新增
- `src/web/models/user.py`
- `src/web/services/auth_service.py`
- `src/web/api/v1/auth.py`
- `src/web/frontend/src/api/auth.ts`
- `src/web/frontend/src/contexts/AuthContext.tsx`
- `src/web/frontend/src/pages/Login.tsx`
- `src/web/frontend/src/components/auth/AuthGuard.tsx`
- `src/web/frontend/src/components/auth/ChangePasswordModal.tsx`
- `tests/unit/test_web/test_auth.py`

### 修改
- `src/web/core/config.py` — SecuritySettings 增加 JWT 配置
- `src/web/core/security.py` — 增加 get_current_user 依赖
- `src/web/api/v1/api.py` — 注册 auth 路由
- `src/web/models/__init__.py` — 导出 User 模型
- `src/web/main.py` — 启动时种子默认用户
- `src/web/frontend/src/api/client.ts` — 注入 JWT 拦截器
- `src/web/frontend/src/App.tsx` — 集成 AuthGuard + Login 路由
- `src/web/frontend/src/components/layout/AppLayout.tsx` — 退出按钮

### 依赖
- `requirements.txt` — 新增 python-jose[cryptography] passlib[bcrypt]
