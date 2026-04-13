# Current Goal

> **状态**: 等待下一个目标
> **上次同步**: Web 前端增强 + 安全修复 (2026-04-13)

使用 `/ai-goal` 开始新目标。

---

## Feat Record: 2026-04-12 扫描详情页面增强

### 需求描述
用户反馈扫描详情页面（如扫描 #0090）显示信息不够详细，需要：
1. 显示完整的扫描选项配置
2. 显示扫描目标信息
3. 修复主进度条显示不准确问题
4. 引擎执行详情可点击展开，显示每个引擎的时间、发现漏洞数、Token 使用量

### 实现方案
1. 新增 Collapsible 组件（基于 @radix-ui/react-collapsible）
2. 修改 ScanDetail.tsx：
   - 修复主进度条使用实时 progress 数据
   - 添加"扫描目标"卡片显示源路径、分支
   - 添加"扫描配置"可折叠卡片显示所有配置参数
3. 修改 ScanProgress.tsx：
   - 将引擎状态改为可展开的卡片列表
   - 每个引擎卡片点击展开显示耗时、发现数、Token

### 修改文件
- `src/web/frontend/src/components/ui/collapsible.tsx`: 新增可折叠组件
- `src/web/frontend/src/components/ui/index.ts`: 导出 Collapsible 组件
- `src/web/frontend/src/pages/ScanDetail.tsx`: 添加扫描配置/目标卡片，修复进度条
- `src/web/frontend/src/components/scan/ScanProgress.tsx`: 引擎详情可展开
- `src/web/frontend/src/i18n/translations.ts`: 添加相关翻译

### 验证结果
- 类型检查通过（仅剩已存在的无关错误）
- 所有新增功能正常工作
- Collapsible 组件正常展开/收起
- 引擎卡片正确显示详情数据

## Feat Record: 2026-04-12 终端风格实时进度窗口

### 需求描述
在扫描详情页面新增终端风格的实时进度窗口，参考 DeepAudit 实现，注意性能优化（仅当前页面激活）。

### 实现方案
1. 新建 LiveTerminal 组件（终端 UI + 扫描线效果 + 闪烁光标）
2. 复用全局 WS client 单例注册事件监听器（不创建额外 WS 连接）
3. 将 WS 事件（phase_start/complete, finding_new, progress, scan_complete/failed）格式化为终端日志
4. 性能优化：LogLine 用 React.memo、progress 事件 300ms 节流、日志上限 200 条、自动滚动可中断

### 修改文件
- `src/web/frontend/src/components/scan/LiveTerminal.tsx`: 新建终端风格实时进度组件
- `src/web/frontend/src/components/scan/index.ts`: 导出 LiveTerminal
- `src/web/frontend/src/pages/ScanDetail.tsx`: 集成 LiveTerminal，传入 scanId/scanStatus/wsState

### 验证结果
- TypeScript 全项目零错误编译通过
- 组件在扫描运行中显示实时日志、闪烁光标
- 扫描完成后显示退出状态
- 离开页面时 WS 监听器自动清理

## Feat Record: 2026-04-12 终端实时进度详细化

### 需求描述
LiveTerminal 终端窗口显示内容太少，需要展示所有阶段的详细信息：攻击面检测结果、引擎扫描进度、对抗性辩论内容等。

### 实现方案
1. **后端增强 WS 事件数据**：
   - `broadcast_phase_complete` 新增 `result` 参数，传递语言/框架/文件数/引擎列表/去重/Token等详情
   - 新增 `ScanEventBroadcaster.broadcast_event()` 通用方法
   - 新增 `ProgressBroadcaster.broadcast_event()` 桥接方法
   - 修复 `_adversarial_progress_callback` 使用 `asyncio.create_task` 调用 async 方法
   - 增强对抗性回调数据（finding_title, vuln_type, severity, file_path）
2. **前端增强 LiveTerminal**：
   - 阶段开始时显示描述文字
   - 阶段完成时解析 result 展示详情（语言/框架/攻击面/文件数/引擎/去重/Token/成本）
   - 引擎启动/完成解析 progress message 为格式化日志
   - 新增 `adversarial_round` 事件监听，展示辩论轮次、角色、内容、置信度
   - 漏洞发现使用 emoji 图标区分严重等级
   - 日志上限提升至 500 条

### 修改文件
- `src/web/api/websocket.py`: `broadcast_phase_complete` 新增 result 参数；新增 `broadcast_event` 方法
- `src/web/services/progress_broadcaster.py`: `on_phase_complete` 传递 result；新增 `broadcast_event` 方法
- `src/web/services/scan_orchestrator.py`: 修复 `_adversarial_progress_callback` 使用 `asyncio.create_task`
- `src/web/services/adversarial_service.py`: 增强回调数据（finding_title, vuln_type, severity, file_path）
- `src/web/frontend/src/types/websocket.ts`: 新增 `adversarial_round` 事件类型
- `src/web/frontend/src/components/scan/LiveTerminal.tsx`: 全面增强日志展示

### 验证结果
- Python 后端模块导入正常
- TypeScript 全项目零错误
- 后端 API 单元测试 9/9 passed
- `adversarial_round` 事件现在能正确通过 WS 推送到前端

## Feat Record: 2026-04-12 LiveTerminal WS 修复 + 详细内容增强

### 需求描述
LiveTerminal 终端窗口只能显示 2 条初始日志，无法接收任何实时 WS 事件。根因是 Celery Worker 和 FastAPI 分属不同进程，内存中的 ConnectionManager 无法跨进程通信。修复后进一步要求更详细的终端内容，包括对抗性辩论角色/内容/置信度、漏洞发现详情、L1 技术栈检测结果等。

### 实现方案

#### Bugfix: WebSocket 事件无法到达前端（3个问题）

1. **进程隔离问题**: Celery Worker 的 `ConnectionManager` 是空的内存单例。修复方案：Redis Pub/Sub 桥接。
   - `websocket.py` `ConnectionManager` 增加 Redis publish/subscribe 支持
   - `main.py` lifespan 中启动/停止 Redis subscriber

2. **Vite 不代理 WS**: `vite.config.ts` 缺少 `ws: true`，前端 WS 升级请求未转发到后端

3. **useWebSocket 循环断连**: `options` 依赖每次渲染都变，导致 useEffect cleanup 调用 `disconnect()` 但 reconnect useEffect 不重跑。修复：用 `useRef` 存 options，事件订阅 effect 只跑一次

#### Feat: LiveTerminal 详细内容增强

1. **adversarial_service.py**: 从 `VerificationResult.debate_rounds` 提取真实辩论数据（attacker/defender/judge），广播完整的 claim、evidence、strength、verdict
2. **scan_orchestrator.py**: L1 准备阶段增加 `primary_language`、`total_files`、`file_counts`；`on_scan_complete` 传递实际 token 数
3. **progress_broadcaster.py**: `on_scan_complete` 接受 `tokens_used` 参数
4. **LiveTerminal.tsx**: 增强漏洞发现显示（标题+引擎+位置+描述）、对抗性辩论详情（角色标签+claim+evidence+strength）、L1 结果详情（语言分布+文件数）

### 修改文件
- `src/web/api/websocket.py`: 添加 Redis Pub/Sub 桥接（publish + subscribe loop）
- `src/web/main.py`: lifespan 启动/停止 Redis subscriber
- `src/web/frontend/vite.config.ts`: 添加 `ws: true`
- `src/web/frontend/src/hooks/useWebSocket.ts`: 修复循环断连 bug，用 ref 存 options
- `src/web/services/adversarial_service.py`: 从 VerificationResult 提取真实辩论轮次
- `src/web/services/scan_orchestrator.py`: 增强 L1 result 数据，传递 tokens_used
- `src/web/services/progress_broadcaster.py`: on_scan_complete 接受 tokens_used
- `src/web/frontend/src/components/scan/LiveTerminal.tsx`: 增强漏洞/辩论/阶段日志展示

### 验证结果
- Python 后端模块导入正常
- TypeScript 编译通过（无新增错误）
- 扫描 #104 WS 事件成功接收：阶段详情、引擎启停、Token 统计、扫描完成摘要均正常显示
- 对抗性辩论内容需再次扫描验证（本次修复前 session.rounds 为空）
