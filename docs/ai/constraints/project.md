# Project Constraints

## 代码约定

- 使用 Python 3.10+ 语法特性
- 类型注解必须完整（mypy strict 模式）
- 使用 ruff 进行 lint 和 format
- 行宽上限 100 字符

## 架构约定

- L1 层负责情报收集、工作空间管理、攻击面探测
- L3 层负责静态分析、引擎执行、裁决融合
- 跨层调用只能单向：L3 → L1 → Core
- 规则文件放在 `rules/` 目录下

## 测试约定

- 单元测试放在 `tests/unit/`
- 集成测试放在 `tests/integration/`
- 使用 pytest-asyncio 处理异步测试
- 测试命名：`test_<module>_<scenario>`

## 安全约束

- LLM API 密钥通过环境变量配置
- 敏感信息不得硬编码
- 扫描结果不得包含用户密钥或凭证

## 工作流约定

- 项目真实路线图在 `docs/ROADMAP.md`
- `docs/ai/roadmap.md` 是工作流副本，需要同步
- 当前目标在 `docs/CURRENT_GOAL.md` 记录
