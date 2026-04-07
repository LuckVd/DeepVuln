# DeepVuln Frontend

DeepVuln 智能漏洞挖掘系统的 Web 前端界面。

## 技术栈

- React 18 + TypeScript
- Vite 5
- Ant Design 5
- React Router 6
- Zustand (状态管理)
- React Query (数据获取)
- Axios (HTTP 客户端)

## 开发

### 安装依赖

```bash
cd src/web/frontend
npm install
```

### 启动开发服务器

```bash
npm run dev
```

访问 http://localhost:5173

### 构建生产版本

```bash
npm run build
```

## 环境变量

复制 `.env.example` 到 `.env` 并根据需要修改：

```bash
cp .env.example .env
```

- `VITE_API_BASE_URL`: API 基础路径（默认: `/api/v1`）
- `VITE_WS_HOST`: WebSocket 主机（默认: `localhost:8000`）

## API 认证

前端通过 `X-API-Key` 请求头进行认证。

在浏览器控制台设置 API Key：

```javascript
localStorage.setItem('deepvuln_api_key', 'your-api-key-here')
```

## 功能

- ✅ 项目管理（列表、创建、删除）
- ✅ 扫描管理（列表、详情、筛选）
- ✅ 实时进度更新（WebSocket + 轮询降级）
- ✅ 扫描控制（暂停、继续、取消）

## 目录结构

```
src/
├── api/           # API 客户端
├── components/    # 组件
├── hooks/         # 自定义 Hooks
├── pages/         # 页面组件
├── stores/        # 状态管理
├── types/         # TypeScript 类型
└── utils/         # 工具函数
```
