# Current Goal: Web 前端重构 (UI/UX 升级)

> **目标 ID**: P16-web-frontend-refactor
> **目标**: 参考 DeepAudit 设计，重构 Web 前端，提供赛博朋克风格的专业安全审计界面
> **阶段**: Phase 16 - in-progress
> **状态**: 进行中

---

## 问题概述

当前前端存在的问题：

| # | 问题 | 严重性 | 影响范围 |
|---|------|--------|----------|
| 1 | UI 设计普通 | 🟡 中 | 使用 Ant Design 默认样式，缺乏特色 |
| 2 | 组件依赖大库 | 🟡 中 | Ant Design 体积大，定制困难 |
| 3 | 无国际化 | 🟢 低 | 仅支持中文 |
| 4 | 无主题切换 | 🟢 低 | 只有一种主题 |
| 5 | 轮询更新 | 🟡 中 | 使用定时轮询而非流式更新 |
| 6 | 页面简单 | 🟡 中 | 只有 3 个页面，功能单一 |

---

## 参考设计：DeepAudit

DeepAudit 前端特点：
- **赛博朋克终端风格**: 深色背景 + 霓虹光效 + 像素字体
- **自建组件库**: 基于 Radix UI 无头组件
- **国际化支持**: i18next 框架
- **流式交互**: 实时展示 Agent 输出
- **完善架构**: features/ 模块 + 自建 UI 组件库

---

## 实施策略：最小原型迭代

### 迭代 1: 基础设施 + 一页可用 ✅

**目标**: 搭建基础，改造一个页面验证效果

- 安装核心依赖 (Radix UI + 工具库)
- 配置赛博朋克主题 (Tailwind)
- 创建基础 UI 组件 (Button, Card, Badge)
- 重构 **Scans 页面** 作为示例

**验收**: 扫描列表页面使用新样式和组件

---

### 迭代 2: 完善布局 + 仪表盘

**目标**: 完善应用布局，新增仪表盘

- 创建主布局 (MainLayout + Sidebar + Header)
- 创建仪表盘页面 (统计卡片 + 图表)
- 主题切换功能

**验收**: 完整的应用布局，新的仪表盘页面

---

### 迭代 3: 流式交互 + 漏洞页面

**目标**: 实现实时更新，完善核心页面

- 流式 API 支持 (WebSocket / SSE)
- 重构扫描详情页 (实时进度展示)
- 重构漏洞页面 (新组件 + 代码高亮)

**验收**: 实时更新的扫描详情，新风格的漏洞页面

---

### 迭代 4: 国际化 + 完善

**目标**: 添加多语言支持，完善细节

- i18next 配置
- 中英文语言包
- 语言切换器
- 细节优化

**验收**: 支持中英文切换

---

## 技术选型

```diff
# 保留
- React 18.2.0
- TypeScript 5.2.2
- Vite 5.0.8
- React Router 6.21.1
- Axios 1.6.5
- Tailwind CSS 3.4.1
- React Query 5.17.0
- react-syntax-highlighter 15.5.0

# 移除
- antd 5.12.8
- @ant-design/icons 5.2.6
- zustand 4.4.7 (用 Context API 替代)

# 新增
+ @radix-ui/react-* (无头组件)
+ class-variance-authority (组件变体)
+ clsx + tailwind-merge (样式合并)
+ lucide-react (图标)
+ i18next + react-i18next (国际化)
+ next-themes (主题系统)
+ eventsource-parser (流式处理)
+ sonner (Toast 通知)
+ recharts (图表)
```

---

## 目录结构 (新)

```
src/web/frontend/src/
├── app/
│   ├── providers.tsx       # 全局 Provider
│   ├── routes.tsx          # 集中式路由
│   └── App.tsx
├── components/
│   ├── ui/                 # 自建 UI 组件库
│   │   ├── button.tsx
│   │   ├── card.tsx
│   │   ├── badge.tsx
│   │   └── ...
│   ├── layout/
│   │   ├── MainLayout.tsx
│   │   ├── Sidebar.tsx
│   │   └── Header.tsx
│   └── theme/
│       └── ThemeToggle.tsx
├── features/
│   ├── scans/
│   │   ├── api.ts
│   │   └── hooks.ts
│   └── findings/
│       ├── api.ts
│       └── hooks.ts
├── pages/
│   ├── Dashboard.tsx       # 新增
│   ├── Scans.tsx
│   ├── ScanDetail.tsx
│   └── Findings.tsx
└── shared/
    ├── api/
    │   └── client.ts
    └── utils/
        └── cn.ts
```

---

## 赛博朋克主题配色

```css
/* 核心配色 */
--bg-primary: #0a0e0a;      /* 主背景 */
--bg-secondary: #111a11;    /* 次级背景 */
--accent-cyan: #00ffea;     /* 青色霓虹 */
--accent-orange: #ff6b00;   /* 橙色霓虹 */
--text-primary: #e0e0e0;    /* 主文本 */
--text-dim: #808080;        /* 暗文本 */
--border-neon: #00ffea40;   /* 霓虹边框 */
```

---

## 验收标准

### 迭代 1
- [x] 核心依赖安装完成
- [ ] 赛博朋克主题配置完成
- [ ] Button, Card, Badge 组件创建
- [ ] Scans 页面使用新组件

### 迭代 2
- [ ] 主布局组件创建
- [ ] 仪表盘页面创建
- [ ] 主题切换功能

### 迭代 3
- [ ] 流式 API 支持
- [ ] 扫描详情页重构
- [ ] 漏洞页面重构

### 迭代 4
- [ ] i18next 配置
- [ ] 中英文语言包
- [ ] 语言切换器

---

## 当前迭代：迭代 1 - 基础设施 + 一页可用

### 任务列表

- [ ] P16-01: 安装核心依赖
- [ ] P16-02: 配置赛博朋克主题
- [ ] P16-03a: 创建 Button, Card, Badge 组件
- [ ] P16-04: 重构 Scans 页面
