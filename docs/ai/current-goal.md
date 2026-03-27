# Current Goal

## Status

Completed - 2026-03-27

## Goal

P8-01: 多版本运行时环境管理器

## Summary

实现运行时版本自动检测、安装和切换能力。当 DeepVuln 检测到项目需要特定语言版本（如 Java 8、Python 3.9）时，自动安装正确的运行时环境后再执行构建，解决环境版本不匹配导致的构建失败问题。

## Result

### 已完成实现

| 步骤 | 描述 | 状态 |
|------|------|------|
| S1 | 创建 `src/layers/l3_analysis/build/runtime/` 目录结构 | ✅ 完成 |
| S2 | 实现 `RuntimeRegistry` 运行时版本注册表 | ✅ 完成 |
| S3 | 实现 `RuntimeInstaller` 基础框架和 Java 安装器 | ✅ 完成 |
| S4 | 实现 `RuntimeSwitcher` 环境变量切换 | ✅ 完成 |
| S5 | 实现 `RuntimeVersionManager` 统一管理 | ✅ 完成 |
| S6 | 修改 `ProvisionPolicy` 添加 AUTO_INSTALL | ✅ 完成 |
| S7 | 修改 `ReadinessGate` 集成版本管理器 | ✅ 完成 |
| S12 | 单元测试覆盖 | ✅ 完成 (29 tests) |

### 新增文件

| 文件 | 描述 |
|------|------|
| `src/layers/l3_analysis/build/runtime/__init__.py` | 模块入口 |
| `src/layers/l3_analysis/build/runtime/models.py` | 数据模型 |
| `src/layers/l3_analysis/build/runtime/registry.py` | 版本注册表 |
| `src/layers/l3_analysis/build/runtime/installer.py` | 安装器框架 |
| `src/layers/l3_analysis/build/runtime/switcher.py` | 版本切换器 |
| `src/layers/l3_analysis/build/runtime/manager.py` | 统一管理器 |
| `tests/unit/test_l3/test_runtime/` | 单元测试 |

### 修改文件

| 文件 | 修改内容 |
|------|----------|
| `src/layers/l3_analysis/build/tool_resolver.py` | 添加 `ProvisionPolicy.AUTO_INSTALL` |
| `src/layers/l3_analysis/build/__init__.py` | 添加 `get_runtime_manager()` 导出 |
| `src/layers/l3_analysis/readiness_gate.py` | 集成 `RuntimeVersionManager` |

### 支持的运行时版本

| 语言 | 支持版本 | 下载来源 |
|------|----------|----------|
| Java | 8, 11, 17, 21 | Eclipse Temurin |
| Python | 3.8, 3.9, 3.10, 3.11, 3.12 | Miniconda |
| Node.js | 16, 18, 20 | nodejs.org |
| Go | 1.20, 1.21, 1.22 | go.dev |

### 测试结果

```
tests/unit/test_l3/test_runtime/ - 29 passed, 1 warning
```

## Known Issues

- Docker 镜像需要更新以支持运行时下载（网络访问、/opt/runtimes 目录权限）
- Python 使用 Miniconda，首次安装可能需要较长时间
- 运行时下载依赖网络，国内可能需要配置镜像源

## Next Steps

- S8-S10: 实现 Python/Node.js/Go 安装器的额外测试
- S11: 修改 Dockerfile 支持动态安装
- S13: 集成测试：Java 8 项目
- S14: 更新文档

## Next Recommended

- P7-11b 系列: Docker 集成测试（验证多版本运行时功能）
- 更新 Docker 镜像以支持运行时动态安装
