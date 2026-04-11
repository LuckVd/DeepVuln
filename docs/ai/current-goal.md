# Current Goal: 配置系统迁移 - 从 config.local.toml 到数据库

> **目标 ID**: P18-config-migration
> **目标**: 移除 config.local.toml，所有配置迁移到前端设置
> **阶段**: Phase 18 - complete
> **状态**: 已完成 ✅
> **完成日期**: 2026-04-11

---

## 同步总结

**实施步骤**: 全部完成 ✅
- P18-01: 数据库模型创建 ✅
- P18-02: 后端 API 开发 ✅
- P18-03: 扫描任务集成 ✅
- P18-04: 前端 UI 开发 ✅
- P18-05: 清理旧代码 ✅

**测试结果**: passed ✅

**安全注意**: ⚠️ config.local.toml 文件仍需手动清理（包含硬编码密钥）

**文档更新**: roadmap.md, change-log.md 已同步

---

---

## 问题概述

当前系统存在配置分散的问题：

| 问题 | 严重性 | 影响 |
|------|--------|------|
| LLM 配置分离 | 🔴 高 | 前端配置不生效，扫描仍用 config.local.toml |
| 配置来源混乱 | 🟡 中 | 配置文件、环境变量、数据库混用 |
| 用户无法配置 | 🟡 中 | 扫描参数、API Key 等需要修改配置文件 |

---

## 功能需求

### 核心功能

1. **LLM 配置从数据库读取**
   - Agent 扫描使用 `agent_scan` 类型配置
   - 对抗性验证使用 `verification` 类型配置
   - 移除对 config.local.toml 的依赖

2. **系统配置表 (system_settings)**
   - 扫描配置：timeout, max_concurrent_files
   - 威胁情报：github_token, nvd_api_key
   - 支持前端 CRUD

3. **前端设置页面扩展**
   - 扫描配置卡片
   - API Key 配置卡片
   - 连接测试功能

### 技术选型

| 组件 | 技术 |
|------|------|
| 存储 | PostgreSQL + 新表 |
| 后端 | FastAPI + SQLAlchemy |
| 前端 | React + TypeScript |

---

## 实施步骤

### P18-01: 数据库模型创建
- [ ] 创建 `system_settings` 表
- [ ] `SystemSetting` 模型定义
- [ ] `SystemSettingRepository` 仓储类
- [ ] Alembic 迁移脚本

### P18-02: 后端 API 开发
- [ ] 系统配置 CRUD 端点 (`/api/v1/system-settings`)
- [ ] LLM 配置获取服务（支持按类型获取）
- [ ] 配置验证服务

### P18-03: 扫描任务集成
- [ ] 修改 `scan_tasks.py` 从数据库获取 LLM 配置
- [ ] 修改 `opencode_agent.py` 支持传入 LLM 客户端
- [ ] 对抗性验证使用正确的配置类型

### P18-04: 前端 UI 开发
- [ ] 扫描配置卡片组件
- [ ] API Key 配置卡片组件
- [ ] 设置页面布局调整

### P18-05: 清理旧代码
- [ ] 移除 `get_llm_config()` 中的 config.local.toml 读取
- [ ] 更新 CLI 命令使用数据库配置
- [ ] 更新文档

---

## 数据模型

### system_settings 表结构

```sql
CREATE TABLE system_settings (
    id SERIAL PRIMARY KEY,
    key VARCHAR(255) UNIQUE NOT NULL,
    value TEXT,
    category VARCHAR(50),  -- scan, threat_intel, etc.
    description TEXT,
    updated_at TIMESTAMP DEFAULT NOW()
);
```

### 预设配置项

| key | category | 默认值 | 描述 |
|-----|----------|--------|------|
| scan.timeout | scan | 300 | 扫描超时时间（秒） |
| scan.max_concurrent_files | scan | 10 | 最大并发扫描文件数 |
| threat_intel.github_token | threat_intel | | GitHub Token |
| threat_intel.nvd_api_key | threat_intel | | NVD API Key |

---

## API 设计

### 系统配置端点

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | `/api/v1/system-settings` | 获取所有系统配置 |
| PUT | `/api/v1/system-settings` | 批量更新系统配置 |

### LLM 配置获取（新增）

| 方法 | 路径 | 描述 |
|------|------|------|
| GET | `/api/v1/llm-configs/type/{config_type}` | 获取指定类型的默认配置 |

---

## 验收标准

- [ ] 扫描任务使用数据库中的 LLM 配置
- [ ] Agent 扫描使用 agent_scan 类型配置
- [ ] 对抗性验证使用 verification 类型配置
- [ ] 前端可以修改扫描参数和 API Key
- [ ] 移除 config.local.toml 依赖
- [ ] API 配置支持连接测试
