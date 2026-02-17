# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | P1-08: 攻击面探测器 (Attack Surface Detector) |
| **状态** | completed |
| **优先级** | high |
| **创建日期** | 2026-02-17 |
| **完成日期** | 2026-02-17 |

---

## 背景说明

攻击面探测器是 Phase 2 (L3 核心分析) 的关键前置模块。它负责自动识别项目的安全边界和潜在攻击入口，为后续的漏洞分析提供目标定位。

**当前问题**：
- 只能检测依赖和技术栈，无法识别代码中的攻击入口
- Phase 2 的审计策略引擎需要攻击面信息来制定审计策略
- 没有 Attack Surface 数据，Agent 无法聚焦分析

---

## 完成标准

### Phase 1: HTTP 入口点检测
- [x] 识别常见框架路由（Gin, Echo, Spring, Flask, FastAPI）
- [x] 提取 HTTP 方法、路径、处理函数
- [x] 检测路径参数和查询参数

### Phase 2: RPC 入口点检测
- [x] gRPC 服务定义解析（.proto 文件）
- [x] Dubbo 服务接口识别
- [x] Thrift IDL 解析

### Phase 3: 其他入口点检测
- [x] 消息队列消费者（Kafka, RabbitMQ, Redis）
- [x] 定时任务入口（Cron, Celery, Spring @Scheduled）
- [x] 支持多语言（Java, Python, Go）

### Phase 4: 输出与集成
- [x] 生成 Attack Surface Markdown 报告
- [x] 单元测试覆盖（34 个测试）
- [x] CLI 集成到扫描显示（scan_display.py）

---

## 技术方案

### 模块结构

```
src/layers/l1_intelligence/attack_surface/
├── __init__.py
├── detector.py           # 主探测器
├── http_detector.py      # HTTP 入口点检测
├── rpc_detector.py       # RPC 入口点检测
├── mq_detector.py        # 消息队列检测
├── models.py             # 数据模型
└── patterns/             # 框架特定模式
    ├── go/
    │   ├── gin.py
    │   └── echo.py
    ├── java/
    │   ├── spring.py
    │   └── dubbo.py
    └── python/
        ├── flask.py
        └── django.py
```

### 数据模型

```python
class EntryPoint(BaseModel):
    """攻击入口点"""
    type: str              # http, rpc, mq, cron, file
    method: str | None     # GET, POST, etc.
    path: str              # /api/users/{id}
    handler: str           # 处理函数/方法名
    file: str              # 定义文件
    line: int              # 行号
    auth_required: bool    # 是否需要认证
    params: list[str]      # 参数列表
    metadata: dict         # 额外元数据

class AttackSurface(BaseModel):
    """攻击面报告"""
    source_path: str
    entry_points: list[EntryPoint]
    http_endpoints: int
    rpc_services: int
    mq_consumers: int
    cron_jobs: int
    file_inputs: int
```

### 检测策略

#### Go (Gin 框架)

```go
// 模式匹配
r.GET("/users/:id", getUser)      → GET /users/{id}
r.POST("/login", loginHandler)    → POST /login
```

#### Java (Spring Boot)

```java
// 注解检测
@GetMapping("/api/users/{id}")    → GET /api/users/{id}
@PostMapping("/login")            → POST /login
@RequestMapping(value = "/api", method = RequestMethod.GET)
```

#### Python (Flask)

```python
# 装饰器检测
@app.route('/users/<int:id>')    → GET /users/{id}
@app.post('/login')              → POST /login
```

---

## 关联文件

### 需要新建
- `src/layers/l1_intelligence/attack_surface/__init__.py`
- `src/layers/l1_intelligence/attack_surface/detector.py`
- `src/layers/l1_intelligence/attack_surface/models.py`
- `src/layers/l1_intelligence/attack_surface/http_detector.py`
- `tests/unit/test_attack_surface/`

### 需要修改
- `src/layers/l1_intelligence/__init__.py` - 导出新模块

### 依赖
- `src/layers/l1_intelligence/tech_stack_detector/` - 获取框架信息

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-02-17 | 设置新目标：P1-08 攻击面探测器 |
| 2026-02-17 | Phase 1 完成：HTTP 入口点检测（Gin, Echo, Spring, Flask, FastAPI） |
| 2026-02-17 | 创建模块结构：models.py, detector.py, http_detector.py |
| 2026-02-17 | 添加单元测试：20 个测试全部通过 |
| 2026-02-17 | Phase 2 完成：RPC 入口点检测（Dubbo, gRPC, Thrift） |
| 2026-02-17 | 改进 Spring 检测器支持多行注解 |
| 2026-02-17 | 使用 Dubbo 项目验证：发现 1 Dubbo + 10 gRPC 服务 |
| 2026-02-17 | Phase 3 完成：MQ 消费者 + 定时任务检测（Kafka, RabbitMQ, Redis, Celery, Cron） |
| 2026-02-17 | Phase 4 完成：Markdown 报告生成 + 集成测试 |
| 2026-02-17 | 单元测试增加到 34 个 |
| 2026-02-17 | CLI 集成完成：attack surface 显示到 scan_display.py |

---

## 备注

### 优先支持的框架

| 语言 | 框架 | 优先级 |
|------|------|--------|
| Go | Gin | P0 |
| Go | Echo | P1 |
| Java | Spring Boot | P0 |
| Java | Dubbo | P1 |
| Python | Flask | P0 |
| Python | FastAPI | P1 |
| Python | Django | P2 |

### 后续扩展

- OpenAPI/Swagger 规范解析
- GraphQL 端点检测
- WebSocket 入口检测
- CLI 参数入口检测
