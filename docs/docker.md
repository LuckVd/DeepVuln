# DeepVuln Docker 使用指南

本文档介绍如何使用 Docker 运行 DeepVuln 漏洞扫描平台。

## 快速开始

### 1. 构建镜像

```bash
# 克隆仓库
git clone https://github.com/LuckVd/DeepVuln.git
cd DeepVuln

# 构建 Docker 镜像（首次构建约 10-15 分钟）
docker build -t deepvuln:latest .
```

### 2. 基本使用

```bash
# 扫描本地代码目录
docker run --rm \
    -v /path/to/your/code:/target \
    -e OPENAI_API_KEY=your-api-key \
    deepvuln:latest /target

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
    deepvuln:latest /target --full
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
    deepvuln:latest /target --full
```

## 扫描模式

### Semgrep 快速扫描

```bash
docker run --rm \
    -v ./code:/target \
    -e OPENAI_API_KEY=xxx \
    deepvuln:latest /target --engines semgrep
```

### CodeQL 深度分析

```bash
# Go 项目
docker run --rm \
    -v ./go-project:/target \
    -e OPENAI_API_KEY=xxx \
    deepvuln:latest /target --engines codeql --language go

# Java 项目
docker run --rm \
    -v ./java-project:/target \
    -e OPENAI_API_KEY=xxx \
    deepvuln:latest /target --engines codeql --language java

# Python 项目
docker run --rm \
    -v ./python-project:/target \
    -e OPENAI_API_KEY=xxx \
    deepvuln:latest /target --engines codeql --language python
```

### Agent AI 分析

```bash
docker run --rm \
    -v ./code:/target \
    -e OPENAI_API_KEY=xxx \
    deepvuln:latest /target --engines agent
```

### 完整扫描（所有引擎）

```bash
docker run --rm \
    -v ./code:/target \
    -e OPENAI_API_KEY=xxx \
    deepvuln:latest /target --full
```

## 输出报告

```bash
# 导出 JSON 报告
docker run --rm \
    -v ./code:/target \
    -v ./reports:/reports \
    -e OPENAI_API_KEY=xxx \
    deepvuln:latest /target --output /reports/report.json

# 导出 Markdown 报告
docker run --rm \
    -v ./code:/target \
    -v ./reports:/reports \
    -e OPENAI_API_KEY=xxx \
    deepvuln:latest /target --output /reports/report.md --format markdown
```

## Docker Compose

对于复杂场景，推荐使用 Docker Compose：

```bash
# 设置环境变量
export OPENAI_API_KEY=your-api-key
export TARGET_PATH=/path/to/your/code

# 运行扫描
docker-compose run --rm deepvuln /target --full

# 后台运行 worker
docker-compose --profile worker up -d
```

## 预装环境

镜像包含以下组件：

| 组件 | 版本 | 用途 |
|------|------|------|
| Python | 3.12 | 运行 DeepVuln |
| Go | 1.22 | Go 项目构建 |
| Node.js | 20 | JS/TS 项目分析 |
| Java JDK | 17 | Java 项目构建 |
| Maven | latest | Java 构建工具 |
| Gradle | latest | Java 构建工具 |
| CodeQL CLI | 2.16.0 | 静态分析引擎 |
| Semgrep | latest | 快速扫描引擎 |

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
          deepvuln /github/workspace --engines semgrep,agent --output report.json

      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: report.json
```

### GitLab CI

```yaml
deepvuln-scan:
  image:
    name: deepvuln:latest
    entrypoint: [""]
  stage: security
  script:
    - python -m src.cli.main /builds/$CI_PROJECT_PATH --engines semgrep,agent
  variables:
    OPENAI_API_KEY: $OPENAI_API_KEY
  artifacts:
    paths:
      - report.json
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
                sh 'python -m src.cli.main $WORKSPACE --engines semgrep,agent'
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
    deepvuln:latest /target --full
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
# 使用更长的超时时间
docker run --rm -e SCAN_TIMEOUT=600 ...
```

### 调试模式

```bash
# 启用详细日志
docker run --rm \
    -v ./code:/target \
    -e OPENAI_API_KEY=xxx \
    -e LOG_LEVEL=DEBUG \
    deepvuln:latest /target --verbose
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
