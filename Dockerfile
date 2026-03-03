# DeepVuln Docker Image
# 多语言漏洞扫描平台 - 包含所有分析引擎依赖
#
# 构建命令:
#   docker build -t deepvuln:latest .
#
# 运行命令:
#   docker run --rm -v /path/to/code:/target -e OPENAI_API_KEY=xxx deepvuln:latest /target

# =============================================================================
# Stage 1: Builder - 安装构建工具和下载依赖
# =============================================================================
FROM python:3.12-slim AS builder

# 设置环境变量
ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# 配置国内镜像源（阿里云）
RUN sed -i 's|deb.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources

# 安装基础构建工具
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    gnupg \
    ca-certificates \
    git \
    unzip \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# 安装 Go 1.22（使用国内镜像）
ENV GOLANG_VERSION=1.22.0
ARG HTTP_PROXY
ARG HTTPS_PROXY
RUN wget -e use_proxy=yes -e https_proxy=${HTTPS_PROXY:-http://host.docker.internal:7890} \
    https://go.dev/dl/go${GOLANG_VERSION}.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go${GOLANG_VERSION}.linux-amd64.tar.gz \
    && rm go${GOLANG_VERSION}.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
ENV PATH="${GOPATH}/bin:${PATH}"

# 安装 Node.js 20（使用镜像）
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# 安装 Java JDK 21
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-21-jdk \
    maven \
    gradle \
    && rm -rf /var/lib/apt/lists/*
ENV JAVA_HOME="/usr/lib/jvm/java-21-openjdk-amd64"
ENV PATH="${JAVA_HOME}/bin:${PATH}"

# 下载 CodeQL CLI（使用代理）- 使用最新稳定版
# 查询包 1.5.6 需要 CodeQL 2.24.2+
ENV CODEQL_VERSION=2.24.2
ARG HTTPS_PROXY
RUN mkdir -p /opt/codeql \
    && curl -x ${HTTPS_PROXY:-http://host.docker.internal:7890} -L \
    "https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.zip" \
    -o /tmp/codeql.zip \
    && unzip /tmp/codeql.zip -d /opt/codeql \
    && rm /tmp/codeql.zip
ENV PATH="/opt/codeql/codeql:${PATH}"

# 下载 CodeQL 查询包（使用代理）
# 注意：CodeQL 使用 HTTPS_PROXY 环境变量
ARG HTTPS_PROXY
ENV HTTPS_PROXY=${HTTPS_PROXY:-http://host.docker.internal:7890}
RUN codeql pack download codeql/go-queries \
    && codeql pack download codeql/java-queries \
    && codeql pack download codeql/python-queries \
    && codeql pack download codeql/javascript-queries \
    && codeql pack download codeql/cpp-queries \
    && codeql pack download codeql/ruby-queries \
    && codeql pack download codeql/csharp-queries

# 复制项目文件并安装 Python 依赖
WORKDIR /build
COPY pyproject.toml uv.lock* ./
RUN pip install uv && uv sync --no-dev

# =============================================================================
# Stage 2: Runtime - 最终运行镜像
# =============================================================================
FROM python:3.12-slim AS runtime

# 设置环境变量
ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV PYTHONUNBUFFERED=1

# 配置国内镜像源（阿里云）
RUN sed -i 's|deb.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources

# 安装运行时依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    ca-certificates \
    libc6-dev \
    build-essential \
    make \
    && rm -rf /var/lib/apt/lists/*

# 从 builder 复制 Go
COPY --from=builder /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
ENV PATH="${GOPATH}/bin:${PATH}"
RUN mkdir -p ${GOPATH} && chmod -R 777 ${GOPATH}

# 从 builder 复制 Node.js
COPY --from=builder /usr/bin/node /usr/bin/node
COPY --from=builder /usr/lib/node_modules /usr/lib/node_modules
RUN ln -s /usr/lib/node_modules/npm/bin/npm-cli.js /usr/bin/npm \
    && ln -s /usr/lib/node_modules/npm/bin/npx-cli.js /usr/bin/npx

# 从 builder 复制 Java
COPY --from=builder /usr/lib/jvm/java-21-openjdk-amd64 /usr/lib/jvm/java-21-openjdk-amd64
ENV JAVA_HOME="/usr/lib/jvm/java-21-openjdk-amd64"
ENV PATH="${JAVA_HOME}/bin:${PATH}"

# 从 builder 复制 Maven 和 Gradle
COPY --from=builder /usr/share/maven /usr/share/maven
ENV MAVEN_HOME="/usr/share/maven"
ENV PATH="${MAVEN_HOME}/bin:${PATH}"
COPY --from=builder /usr/share/gradle /usr/share/gradle
ENV GRADLE_HOME="/usr/share/gradle"
ENV PATH="${GRADLE_HOME}/bin:${PATH}"

# 从 builder 复制 CodeQL
COPY --from=builder /opt/codeql /opt/codeql
ENV PATH="/opt/codeql/codeql:${PATH}"
ENV CODEQL_HOME="/opt/codeql"

# 从 builder 复制 CodeQL 查询包（下载到 root 用户目录）
COPY --from=builder /root/.codeql /home/deepvuln/.codeql

# 创建非 root 用户
RUN useradd -m -s /bin/bash deepvuln \
    && mkdir -p /app /target /home/deepvuln/.cache \
    && chown -R deepvuln:deepvuln /app /target /home/deepvuln /home/deepvuln/.codeql

# 复制 Python 虚拟环境
COPY --from=builder /build/.venv /app/.venv
ENV PATH="/app/.venv/bin:${PATH}"
ENV VIRTUAL_ENV="/app/.venv"
ENV PYTHONPATH="/app"

# 安装 Semgrep（使用 uv）
RUN pip install uv && uv pip install --python /app/.venv/bin/python semgrep

# 复制项目代码
WORKDIR /app
COPY --chown=deepvuln:deepvuln . .

# 设置工作目录
WORKDIR /target

# 切换到非 root 用户
USER deepvuln

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "print('healthy')" || exit 1

# 默认入口点
ENTRYPOINT ["python", "-m", "src.cli.main"]
CMD ["--help"]
