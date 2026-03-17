# DeepVuln Docker 使用指南

本文档介绍如何使用 Docker 运行 DeepVuln 漏洞扫描平台，并确保容器内具备 CodeQL 所需的常见构建环境。

## 快速开始

### 1. 构建镜像

```bash
# 克隆仓库
git clone https://github.com/LuckVd/DeepVuln.git
cd DeepVuln

# 构建 Docker 镜像（首次构建较慢，需下载 CodeQL 与多语言工具链）
docker build -t deepvuln:latest .
```

### 2. 基本使用

```bash
# 扫描本地代码目录
docker run --rm \
    -v /path/to/your/code:/target \
    -e OPENAI_API_KEY=your-api-key \
    deepvuln:latest scan -p /target

# 查看帮助
docker run --rm deepvuln:latest --help

# 查看版本
docker run --rm deepvuln:latest --version
```

## 配置方式

### 方式一：环境变量

```bash
docker run --rm \
    -v ./your-project:/target \
    -e OPENAI_API_KEY=sk-xxx \
    -e OPENAI_BASE_URL=https://api.openai.com/v1 \
    deepvuln:latest scan -p /target --full
```

### 方式二：配置文件

```bash
# 创建配置文件
cat > config.local.toml << EOF
[llm]
provider = "openai"
model = "gpt-4"

[llm.openai]
api_key = "your-api-key"
base_url = "https://api.openai.com/v1"
EOF

# 使用配置文件运行
docker run --rm \
    -v ./your-project:/target \
    -v ./config.local.toml:/app/config.local.toml \
    deepvuln:latest scan -p /target --full
```

## 扫描模式

### Semgrep 快速扫描

```bash
docker run --rm \
    -v ./code:/target \
    -e OPENAI_API_KEY=xxx \
    deepvuln:latest scan -p /target --engines semgrep
```

### CodeQL 深度分析

```bash
# Go 项目
docker run --rm \
    -v ./go-project:/target \
    -e OPENAI_API_KEY=xxx \
    deepvuln:latest codeql -p /target --language go

# Java 项目
docker run --rm \
    -v ./java-project:/target \
    -e OPENAI_API_KEY=xxx \
    deepvuln:latest codeql -p /target --language java

# Python 项目
docker run --rm \
    -v ./python-project:/target \
    -e OPENAI_API_KEY=xxx \
    deepvuln:latest codeql -p /target --language python
```

### Agent AI 分析

```bash
docker run --rm \
    -v ./code:/target \
    -e OPENAI_API_KEY=xxx \
    deepvuln:latest agent -p /target
```

### 完整扫描（所有引擎）

```bash
docker run --rm \
    -v ./code:/target \
    -e OPENAI_API_KEY=xxx \
    deepvuln:latest scan -p /target --full
```

## 输出报告

```bash
# 主 scan 命令导出完整文本报告
docker run --rm \
    -v ./code:/target \
    -v ./reports:/reports \
    -e OPENAI_API_KEY=xxx \
    deepvuln:latest scan -p /target --full --export /reports/full-report.txt

# Semgrep 子命令导出 JSON 报告
docker run --rm \
    -v ./code:/target \
    -v ./reports:/reports \
    deepvuln:latest semgrep -p /target --auto -f json -o /reports/semgrep-report.json

# Agent 子命令导出 Markdown 报告
docker run --rm \
    -v ./code:/target \
    -v ./reports:/reports \
    -e OPENAI_API_KEY=xxx \
    deepvuln:latest agent -p /target --format markdown -o /reports/agent-report.md
```

## Docker Compose

对于复杂场景，推荐使用 Docker Compose：

```bash
# 设置环境变量
export OPENAI_API_KEY=your-api-key
export TARGET_PATH=/path/to/your/code

# 运行扫描
docker-compose run --rm deepvuln scan -p /target --full

# 后台运行 worker
docker-compose --profile worker up -d
```

如果你需要自定义 Debian 镜像源、下载备选源或宿主机代理：

```bash
export APT_MIRROR=http://mirrors.aliyun.com/debian
export GO_DOWNLOAD_URL=https://mirrors.aliyun.com/golang/go1.22.0.linux-amd64.tar.gz
export CODEQL_DOWNLOAD_URL=https://your-mirror.example.com/codeql/codeql-linux64.zip
export HTTP_PROXY=http://host.docker.internal:7890
export HTTPS_PROXY=http://host.docker.internal:7890
export NO_PROXY=localhost,127.0.0.1,host.docker.internal
export PRELOAD_CODEQL_PACKS=false
docker-compose build --no-cache
```

## 预装环境

镜像包含以下组件：

| 组件 | 版本 | 用途 |
|------|------|------|
| Python | 3.12 | 运行 DeepVuln |
| Go | 1.22 | Go 项目构建 |
| Node.js / npm | Debian package | JS/TS 项目依赖与构建 |
| Java JDK | 21 | Java 项目构建 |
| Maven | Debian package | Java 构建工具 |
| Gradle | Debian package | Java 构建工具 |
| GCC / G++ / Clang / Make | Debian package | C/C++ 项目构建 |
| .NET SDK | 8.0 | C# 项目构建 |
| Ruby | Debian package | Ruby 项目分析 |
| CodeQL CLI | 2.24.2 | 静态分析引擎 |
| CodeQL query packs | 可选预下载 | 减少首次运行失败 |
| Semgrep | latest | 快速扫描引擎 |

## 容器化 CodeQL 约束

- 容器已经预装常见工具链，但项目本身如果需要私有依赖源、私有 Maven 仓库、特定 Node 版本或自定义 build script，仍需在运行时额外挂载配置。
- CodeQL 数据库缓存目录在容器内固定为 `/tmp/codeql_cache`，Compose 已将其持久化。
- CodeQL 查询包缓存目录在容器内固定为 `/home/deepvuln/.codeql`，Compose 已将其持久化。
- Swift/macOS 专属构建链不在当前 Linux 镜像支持范围内。
- Go 下载源可通过 `GO_DOWNLOAD_URL` 覆盖。
- CodeQL CLI 下载源可通过 `CODEQL_DOWNLOAD_URL` 覆盖。
- CodeQL query packs 默认不在 Compose 构建阶段预下载；如需预热可设置 `PRELOAD_CODEQL_PACKS=true`。
- 如需使用宿主机代理，应使用 `host.docker.internal`，不要使用 `127.0.0.1`。

## 推荐用法

对于 CodeQL 重度场景，优先通过容器执行，而不是依赖宿主机零散安装：

```bash
docker-compose run --rm deepvuln scan -p /target --full
```

针对 Java / Go / C# 项目，先验证容器内工具链：

```bash
docker-compose run --rm deepvuln bash -lc "java -version && mvn -version && gradle -version && go version && dotnet --info && codeql version"
```

## 支持的语言

| 语言 | Semgrep | CodeQL | Agent |
|------|---------|--------|-------|
| Python | ✅ | ✅ | ✅ |
| JavaScript | ✅ | ✅ | ✅ |
| TypeScript | ✅ | ✅ | ✅ |
| Go | ✅ | ✅ | ✅ |
| Java | ✅ | ✅ | ✅ |
| C/C++ | ✅ | ✅ | ✅ |
| C# | ✅ | ✅ | ✅ |
| Ruby | ✅ | ✅ | ✅ |
| PHP | ✅ | ❌ | ✅ |

## CI/CD 集成

### GitHub Actions

```yaml
name: DeepVuln Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    container:
      image: deepvuln:latest

    steps:
      - uses: actions/checkout@v4

      - name: Run DeepVuln Scan
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          deepvuln scan -p /github/workspace --engines semgrep --engines agent --export report.txt

      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: report.txt
```

### GitLab CI

```yaml
deepvuln-scan:
  image:
    name: deepvuln:latest
    entrypoint: [""]
  stage: security
  script:
    - python -m src.cli.main scan -p /builds/$CI_PROJECT_PATH --engines semgrep --engines agent --export report.txt
  variables:
    OPENAI_API_KEY: $OPENAI_API_KEY
  artifacts:
    paths:
      - report.txt
    expire_in: 1 week
```

### Jenkins Pipeline

```groovy
pipeline {
    agent {
        docker {
            image 'deepvuln:latest'
        }
    }
    environment {
        OPENAI_API_KEY = credentials('openai-api-key')
    }
    stages {
        stage('Security Scan') {
            steps {
                sh 'python -m src.cli.main scan -p $WORKSPACE --engines semgrep --engines agent --export report.txt'
            }
        }
    }
}
```

## 资源配置

### 推荐配置

| 项目规模 | CPU | 内存 | 磁盘 |
|----------|-----|------|------|
| 小型 (<10k LOC) | 2 | 4GB | 10GB |
| 中型 (10k-100k LOC) | 4 | 8GB | 20GB |
| 大型 (>100k LOC) | 8 | 16GB | 50GB |

### 限制资源

```bash
docker run --rm \
    --cpus=4 \
    --memory=8g \
    -v ./code:/target \
    -e OPENAI_API_KEY=xxx \
    deepvuln:latest scan -p /target --full
```

## 故障排除

### 常见问题

**1. CodeQL 构建失败**

```bash
# 检查项目是否需要特殊构建命令
docker run --rm -it deepvuln:latest /bin/bash
cd /target
go build ./...  # 或 mvn compile, npm install 等
```

**2. 内存不足**

```bash
# 增加内存限制
docker run --rm --memory=16g ...
```

**3. API 超时**

```bash
# 通过挂载配置文件调整 [scan].timeout 或 [llm].timeout
docker run --rm \
    -v ./code:/target \
    -v ./config.local.toml:/app/config.local.toml:ro \
    deepvuln:latest scan -p /target
```

### 调试模式

```bash
# 显示更详细的扫描报告
docker run --rm \
    -v ./code:/target \
    -e OPENAI_API_KEY=xxx \
    deepvuln:latest scan -p /target --full --detailed
```

## 更新镜像

```bash
# 拉取最新代码
git pull origin main

# 重新构建镜像
docker build -t deepvuln:latest --no-cache .

# 或使用 docker-compose
docker-compose build --no-cache
```

## 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件
