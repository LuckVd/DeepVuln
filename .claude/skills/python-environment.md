# Python Environment Skill

> 使用 uv 管理 Python 虚拟环境和依赖

---

## 核心要求

**本项目使用 uv 作为 Python 包管理器，所有 Python 相关操作必须通过 uv 执行。**

---

## 环境规范

### 包管理器

| 工具 | 用途 | 命令前缀 |
|------|------|----------|
| **uv** | 包管理、虚拟环境 | `uv <command>` |
| **uv run** | 在虚拟环境中执行命令 | `uv run <command>` |
| **uv pip** | pip 兼容命令 | `uv pip <command>` |

### 禁止使用

| 命令 | 原因 | 替代方案 |
|------|------|----------|
| `pip install` | 不经过 uv 管理 | `uv pip install` 或 `uv add` |
| `python` | 可能使用错误环境 | `uv run python` |
| `pytest` | 可能使用错误环境 | `uv run pytest` |
| `pip freeze` | 不包含 uv 锁定信息 | `uv pip freeze` |

---

## 常用命令

### 依赖管理

```bash
# 同步依赖（根据 pyproject.toml 和 uv.lock）
uv sync

# 添加新依赖
uv add <package-name>

# 添加开发依赖
uv add --dev <package-name>

# 安装单个包（不修改 pyproject.toml）
uv pip install <package-name>

# 查看已安装包
uv pip show <package-name>

# 冻结依赖
uv pip freeze
```

### 运行命令

```bash
# 运行 Python 脚本
uv run python <script.py>

# 运行测试
uv run pytest

# 运行测试（带覆盖率）
uv run pytest --cov=src tests/

# 运行类型检查
uv run mypy src/

# 运行代码检查
uv run ruff check src/

# 运行 Semgrep
uv run semgrep --config auto <path>
```

### 项目入口

```bash
# 运行 CLI
uv run deepvuln <command>
```

---

## 依赖配置文件

| 文件 | 用途 |
|------|------|
| `pyproject.toml` | 项目元数据和依赖定义 |
| `uv.lock` | 锁定的依赖版本（自动生成） |

---

## 添加新依赖的流程

1. **编辑 pyproject.toml**（推荐用于项目依赖）
   ```toml
   dependencies = [
       "new-package>=1.0.0",
   ]
   ```
   然后运行 `uv sync`

2. **或使用 uv add**（自动更新 pyproject.toml）
   ```bash
   uv add new-package
   ```

3. **或临时安装**（不修改配置）
   ```bash
   uv pip install new-package
   ```

---

## 已安装的核心工具

| 工具 | 版本 | 用途 |
|------|------|------|
| **semgrep** | 1.86.0 | 静态安全扫描 (需要 WSL/Docker) |
| **pytest** | - | 单元测试 |
| **ruff** | - | 代码格式化和检查 |
| **mypy** | - | 类型检查 |

### Semgrep Windows 平台限制

⚠️ **重要**：Semgrep 的核心引擎 (`semgrep-core`) 是 Linux ELF 二进制文件，在 Windows 上无法直接运行。

**解决方案**：

1. **使用 WSL (推荐)**
   ```bash
   # 在 WSL 中安装 Semgrep
   wsl
   pip install semgrep
   semgrep --version
   ```

2. **使用 Docker**
   ```bash
   docker run --rm -v "${PWD}:/src" returntocorp/semgrep semgrep scan --config auto
   ```

3. **使用官方安装脚本 (PowerShell)**
   ```powershell
   powershell -c "irm https://semgrep.dev/install.ps1 | iex"
   ```

**在 DeepVuln 中的处理**：
- `SemgrepEngine` 会自动检测运行环境
- Windows 环境下会尝试通过 WSL 调用 Semgrep
- 如果不可用，会跳过 Semgrep 扫描并记录警告

---

## 错误处理

### "command not found"

如果遇到命令找不到，确保使用 `uv run`：

```bash
# 错误
semgrep --version

# 正确
uv run semgrep --version
```

### 依赖冲突

```bash
# 重新同步依赖
uv sync --reinstall
```

### 锁定文件问题

```bash
# 重新生成锁定文件
uv lock --upgrade
uv sync
```

---

## CI/CD 集成

在 CI 环境中使用 uv：

```yaml
# GitHub Actions 示例
- name: Install uv
  run: pip install uv

- name: Sync dependencies
  run: uv sync

- name: Run tests
  run: uv run pytest
```

---

## 最佳实践

1. **始终使用 uv run**：确保在正确的虚拟环境中执行
2. **提交 uv.lock**：确保团队和 CI 使用相同版本
3. **定期更新**：`uv lock --upgrade` 获取安全补丁
4. **检查依赖树**：`uv pip show <package>` 查看依赖关系

---

## 检查清单

在执行任何 Python 操作前，确认：

- [ ] 使用 `uv run` 前缀
- [ ] 依赖已通过 `uv sync` 同步
- [ ] 新依赖已添加到 `pyproject.toml`
- [ ] 不直接使用 `pip` 或 `python` 命令
