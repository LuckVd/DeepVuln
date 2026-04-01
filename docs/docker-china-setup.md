# DeepVuln Docker 国内网络环境配置指南

## 问题背景

在国内网络环境下使用 Docker 扫描 Java 项目时，常遇到以下问题：
1. Maven 依赖下载超时
2. 构建工具（Gradle/Maven）无法下载插件
3. 某些包通过代理访问时出现 HTTPS 证书错误

## 解决方案

### 方案概述

1. **构建阶段**：使用国内镜像 + 可选代理
2. **运行阶段**：配置 Maven/Gradle 使用国内镜像源

### 快速开始

#### 1. 配置构建环境变量

```bash
# 复制配置模板
cp .env.docker.build .env.docker.build.local

# 如果需要使用代理（可选）
# 编辑 .env.docker.build.local，设置：
# BUILD_HTTP_PROXY=http://host.docker.internal:7890
# BUILD_HTTPS_PROXY=http://host.docker.internal:7890
```

#### 2. 构建 Docker 镜像

```bash
# 方式一：使用国内优化版配置（推荐）
docker-compose -f docker-compose-china.yml build

# 方式二：直接构建（需要手动设置 build-args）
docker build \
  --build-arg APT_MIRROR=https://mirrors.tuna.tsinghua.edu.cn/debian \
  --build-arg CODEQL_DOWNLOAD_FALLBACK_URL=https://ghproxy.net/https://github.com/... \
  --build-arg PRELOAD_CODEQL_PACKS=false \
  -t deepvuln:latest .
```

#### 3. 运行扫描

```bash
# 设置环境变量
export OPENAI_API_KEY=your-key
export OPENAI_BASE_URL=https://open.bigmodel.cn/api/paas/v4

# 扫描 Java 项目
export TARGET_PATH=/opt/projects/benchmark/Qbenchmark/env_validation/java-simple-vuln
docker-compose -f docker-compose-china.yml run --rm deepvuln scan -p /target --base

# 或直接指定目录
docker-compose -f docker-compose-china.yml run --rm \
  -v /opt/projects/benchmark/Qbenchmark/env_validation/java-simple-vuln:/target:ro \
  deepvuln scan -p /target --base
```

## 配置详解

### Maven 镜像配置

项目已预配置 `docker-config/maven/settings.xml`，使用阿里云镜像：

- 阿里云 Central: `https://maven.aliyun.com/repository/central`
- 阿里云 Spring: `https://maven.aliyun.com/repository/spring`
- 阿里云 Public: `https://maven.aliyun.com/repository/public`

### Gradle 镜像配置

如需扫描 Gradle 项目，在项目根目录创建 `init.gradle`：

```groovy
allprojects {
    repositories {
        maven { url 'https://maven.aliyun.com/repository/public/' }
        maven { url 'https://maven.aliyun.com/repository/spring/' }
        maven { url 'https://maven.aliyun.com/repository/central/' }
        maven { url 'https://maven.aliyun.com/repository/gradle-plugin/' }
    }
    buildscript {
        repositories {
            maven { url 'https://maven.aliyun.com/repository/public/' }
            maven { url 'https://maven.aliyun.com/repository/gradle-plugin/' }
        }
    }
}
```

### 代理配置

#### 如果宿主机代理运行在 7890 端口

```bash
# 在 .env.docker.build.local 中设置
BUILD_HTTP_PROXY=http://host.docker.internal:7890
BUILD_HTTPS_PROXY=http://host.docker.internal:7890
BUILD_NO_PROXY=localhost,127.0.0.1,::1,10.*,192.168.*,172.16.*,mirrors.tuna.tsinghua.edu.cn,pypi.tuna.tsinghua.edu.cn,ghproxy.net,goproxy.cn
```

#### 如果使用 SOCKS5 代理（7891 端口）

Docker 构建时 SOCKS5 支持有限，建议使用 HTTP 代理端口。

## 常见问题

### Q: 构建时还是下载失败

A: 检查以下几点：
1. 确认 `docker-cache/` 目录有缓存的 go 和 codeql 文件
2. 如果使用代理，确认代理允许 Docker 容器访问
3. 尝试设置 `PRELOAD_CODEQL_PACKS=false` 跳过预加载

### Q: Maven 依赖下载仍然很慢

A: 确认 settings.xml 已正确挂载到容器内：

```bash
docker-compose -f docker-compose-china.yml run --rm deepvuln cat /home/deepvuln/.m2/settings.xml
```

### Q: HTTPS 证书错误

A: 这通常是国内镜像源走了代理导致的。解决方法：
1. 确保 `NO_PROXY` 包含所有国内镜像域名
2. 或直接不设置代理，使用 fallback 镜像

## 目录结构

```
DeepVuln/
├── .env.docker.build          # 构建环境变量模板
├── .env.docker.build.local    # 本地构建配置（不提交）
├── docker-compose-china.yml   # 国内优化版 docker-compose
├── docker-config/
│   └── maven/
│       └── settings.xml       # Maven 阿里云镜像配置
└── docker-cache/              # 本地下载缓存
    ├── go1.22.0.linux-amd64.tar.gz
    └── codeql-linux64.zip
```

## 运行时代理设置

如果扫描时需要下载运行时依赖（如 Python 包、npm 包），可以设置运行时代理：

```bash
# 在 docker-compose-china.yml 的 environment 中添加
RUNTIME_HTTP_PROXY=http://host.docker.internal:7890
RUNTIME_HTTPS_PROXY=http://host.docker.internal:7890
```

或在命令行中覆盖：

```bash
docker-compose -f docker-compose-china.yml run --rm \
  -e HTTP_PROXY=http://host.docker.internal:7890 \
  -e HTTPS_PROXY=http://host.docker.internal:7890 \
  deepvuln scan -p /target --base
```
