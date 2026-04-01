# DeepVuln Docker Image
# Multi-language security scanning runtime with CodeQL-oriented toolchains.

FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV PYTHONUNBUFFERED=1
ENV GOPATH=/go
ENV CODEQL_VERSION=2.25.1
ENV CODEQL_HOME=/opt/codeql
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
ENV MAVEN_HOME=/usr/share/maven
ENV GRADLE_HOME=/usr/share/gradle
ENV DOTNET_ROOT=/usr/share/dotnet
ENV PATH=/root/.local/bin:/app/.venv/bin:/usr/local/go/bin:/go/bin:/opt/codeql/codeql:/usr/share/maven/bin:/usr/share/gradle/bin:/usr/share/dotnet:${JAVA_HOME}/bin:${PATH}

ARG APT_MIRROR=
ARG HTTP_PROXY=
ARG HTTPS_PROXY=
ARG NO_PROXY=
ARG GO_DOWNLOAD_URL=https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
ARG GO_DOWNLOAD_FALLBACK_URL=https://dl.google.com/go/go1.22.0.linux-amd64.tar.gz
ARG CODEQL_DOWNLOAD_URL=
ARG CODEQL_DOWNLOAD_FALLBACK_URL=https://ghproxy.net/https://github.com/github/codeql-cli-binaries/releases/download/v2.25.1/codeql-linux64.zip
ARG DOWNLOAD_CONNECT_TIMEOUT=15
ARG DOWNLOAD_MAX_TIME=90
ARG CODEQL_DOWNLOAD_MAX_TIME=1800
ARG PRELOAD_CODEQL_PACKS=true

RUN if [ -n "${APT_MIRROR}" ]; then \
        sed -i "s|http://deb.debian.org/debian|${APT_MIRROR}|g" /etc/apt/sources.list.d/debian.sources && \
        sed -i "s|http://security.debian.org/debian-security|${APT_MIRROR}|g" /etc/apt/sources.list.d/debian.sources; \
    fi

RUN env -u HTTP_PROXY -u HTTPS_PROXY -u NO_PROXY -u http_proxy -u https_proxy -u no_proxy \
    apt-get update \
    && env -u HTTP_PROXY -u HTTPS_PROXY -u NO_PROXY -u http_proxy -u https_proxy -u no_proxy \
        apt-get install -y --no-install-recommends \
        bash \
        build-essential \
        ca-certificates \
        clang \
        curl \
        gcc \
        g++ \
        git \
        gnupg \
        libc6-dev \
        libicu-dev \
        make \
        nodejs \
        npm \
        openjdk-21-jdk \
        ruby-full \
        unzip \
        wget \
        xz-utils \
    # Install Maven and Gradle for Java builds (CodeQL database creation)
    && env -u HTTP_PROXY -u HTTPS_PROXY -u NO_PROXY -u http_proxy -u https_proxy -u no_proxy \
        apt-get install -y \
        maven \
        gradle \
    && rm -rf /var/lib/apt/lists/*

# Fix OpenJDK 21 security config file (Debian Trixie bug: file is a broken symlink)
RUN mkdir -p /etc/java-21-openjdk/security \
    && if [ -L "${JAVA_HOME}/conf/security/java.security" ] && [ ! -e "${JAVA_HOME}/conf/security/java.security" ]; then \
        echo '# OpenJDK 21 Security Configuration (minimal)' > /etc/java-21-openjdk/security/java.security \
        && echo 'security.provider.1=SUN' >> /etc/java-21-openjdk/security/java.security \
        && echo 'security.provider.2=SunRsaSign' >> /etc/java-21-openjdk/security/java.security \
        && echo 'security.provider.3=SunEC' >> /etc/java-21-openjdk/security/java.security \
        && echo 'security.provider.4=SunJSSE' >> /etc/java-21-openjdk/security/java.security \
        && echo 'security.provider.5=SunJCE' >> /etc/java-21-openjdk/security/java.security \
        && echo 'security.provider.6=SunPKCS11' >> /etc/java-21-openjdk/security/java.security \
        && echo 'security.useSystemPropertiesFile=false' >> /etc/java-21-openjdk/security/java.security; \
    fi

RUN mkdir -p /etc/apt/keyrings \
    && env -u HTTP_PROXY -u HTTPS_PROXY -u NO_PROXY -u http_proxy -u https_proxy -u no_proxy \
        curl -fsSL https://packages.microsoft.com/keys/microsoft.asc \
        | gpg --dearmor -o /etc/apt/keyrings/microsoft.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/debian/12/prod bookworm main" \
        > /etc/apt/sources.list.d/microsoft-prod.list \
    && env -u HTTP_PROXY -u HTTPS_PROXY -u NO_PROXY -u http_proxy -u https_proxy -u no_proxy \
        apt-get update \
    && env -u HTTP_PROXY -u HTTPS_PROXY -u NO_PROXY -u http_proxy -u https_proxy -u no_proxy \
        apt-get install -y --no-install-recommends dotnet-sdk-8.0 \
    && rm -rf /var/lib/apt/lists/*

# Optional: Use pre-downloaded cache files if available
COPY docker-cache/ /tmp/docker-cache/

RUN set -eu; \
    if [ -f "/tmp/docker-cache/go1.22.0.linux-amd64.tar.gz" ]; then \
        echo "Using cached Go archive"; \
        cp /tmp/docker-cache/go1.22.0.linux-amd64.tar.gz /tmp/go.tar.gz; \
    else \
        fetch() { \
            url="$1"; \
            if [ -z "$url" ]; then \
                return 1; \
            fi; \
            echo "Attempting download: $url"; \
            wget -q \
                --tries=1 \
                --dns-timeout="${DOWNLOAD_CONNECT_TIMEOUT}" \
                --connect-timeout="${DOWNLOAD_CONNECT_TIMEOUT}" \
                --read-timeout="${DOWNLOAD_MAX_TIME}" \
                "$url" -O /tmp/go.tar.gz; \
        }; \
        fetch_with_proxy() { \
            url="$1"; \
            if [ -z "$url" ] || [ -z "${HTTP_PROXY}" ] || [ -z "${HTTPS_PROXY}" ]; then \
                return 1; \
            fi; \
            echo "Attempting download via proxy: $url"; \
            env HTTP_PROXY="${HTTP_PROXY}" HTTPS_PROXY="${HTTPS_PROXY}" NO_PROXY="${NO_PROXY}" \
                wget -q \
                    --tries=1 \
                    --dns-timeout="${DOWNLOAD_CONNECT_TIMEOUT}" \
                    --connect-timeout="${DOWNLOAD_CONNECT_TIMEOUT}" \
                    --read-timeout="${DOWNLOAD_MAX_TIME}" \
                    "$url" -O /tmp/go.tar.gz; \
        }; \
        fetch "${GO_DOWNLOAD_URL}" \
        || fetch "${GO_DOWNLOAD_FALLBACK_URL}" \
        || fetch_with_proxy "${GO_DOWNLOAD_URL}" \
        || fetch_with_proxy "${GO_DOWNLOAD_FALLBACK_URL}"; \
    fi; \
    tar -C /usr/local -xzf /tmp/go.tar.gz; \
    rm /tmp/go.tar.gz

RUN set -eu; \
    if [ -n "${CODEQL_DOWNLOAD_URL}" ]; then \
        codeql_url="${CODEQL_DOWNLOAD_URL}"; \
    else \
        codeql_url="https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.zip"; \
    fi; \
    codeql_fallback_url="${CODEQL_DOWNLOAD_FALLBACK_URL}"; \
    mkdir -p /opt/codeql; \
    if [ -f "/tmp/docker-cache/codeql-linux64.zip" ]; then \
        echo "Using cached CodeQL archive"; \
        cp /tmp/docker-cache/codeql-linux64.zip /tmp/codeql.zip; \
    else \
        fetch() { \
            url="$1"; \
            if [ -z "$url" ]; then \
                return 1; \
            fi; \
            echo "Attempting download: $url"; \
            curl -fsSL \
                --connect-timeout "${DOWNLOAD_CONNECT_TIMEOUT}" \
                --max-time "${CODEQL_DOWNLOAD_MAX_TIME}" \
                --retry 0 \
                "$url" -o /tmp/codeql.zip; \
        }; \
        fetch_with_proxy() { \
            url="$1"; \
            if [ -z "$url" ] || [ -z "${HTTP_PROXY}" ] || [ -z "${HTTPS_PROXY}" ]; then \
                return 1; \
            fi; \
            echo "Attempting download via proxy: $url"; \
            env HTTP_PROXY="${HTTP_PROXY}" HTTPS_PROXY="${HTTPS_PROXY}" NO_PROXY="${NO_PROXY}" \
                curl -fsSL \
                    --connect-timeout "${DOWNLOAD_CONNECT_TIMEOUT}" \
                    --max-time "${CODEQL_DOWNLOAD_MAX_TIME}" \
                    --retry 0 \
                    "$url" -o /tmp/codeql.zip; \
        }; \
        fetch "${codeql_url}" \
        || fetch "${codeql_fallback_url}" \
        || fetch_with_proxy "${codeql_url}" \
        || fetch_with_proxy "${codeql_fallback_url}"; \
    fi; \
    unzip -q /tmp/codeql.zip -d /opt/codeql; \
    rm /tmp/codeql.zip

WORKDIR /app
COPY pyproject.toml requirements.txt uv.lock* ./

COPY . /app

# Configure PyPI mirror for better connectivity in China
RUN env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy -u no_proxy \
    python -m pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple \
    && env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy -u no_proxy \
    python -m pip config set global.trusted-host pypi.tuna.tsinghua.edu.cn

# Install uv using official installer (may need proxy for GitHub releases)
# Falls back to pip install if official installer fails
RUN set -eu; \
    install_uv() { \
        curl -LsSf https://astral.sh/uv/install.sh | sh; \
    }; \
    install_uv_with_proxy() { \
        if [ -n "${HTTP_PROXY}" ] && [ -n "${HTTPS_PROXY}" ]; then \
            env HTTP_PROXY="${HTTP_PROXY}" HTTPS_PROXY="${HTTPS_PROXY}" NO_PROXY="${NO_PROXY}" \
                curl -LsSf https://astral.sh/uv/install.sh | sh; \
        else \
            return 1; \
        fi; \
    }; \
    install_uv || install_uv_with_proxy || \
    (env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy -u no_proxy \
        python -m pip install --no-cache-dir --upgrade pip && \
     env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy -u no_proxy \
        python -m pip install --no-cache-dir uv)

# Create venv and install Python dependencies using PyPI mirror
# uv is installed to ~/.local/bin by official installer
RUN env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy -u no_proxy \
    uv venv /app/.venv \
    && env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy -u no_proxy \
        uv pip install --python /app/.venv/bin/python -e ".[analysis]" semgrep

RUN useradd -m -s /bin/bash deepvuln \
    && mkdir -p /target /tmp/codeql_cache /home/deepvuln/.cache /home/deepvuln/.codeql /go /opt/runtimes \
    && chown -R deepvuln:deepvuln /app /target /tmp/codeql_cache /home/deepvuln /go /opt/runtimes

USER deepvuln
ENV HOME=/home/deepvuln
WORKDIR /app

RUN if [ "${PRELOAD_CODEQL_PACKS}" = "true" ]; then \
        PACKS="codeql/go-queries codeql/java-queries codeql/python-queries codeql/javascript-queries codeql/cpp-queries codeql/ruby-queries codeql/csharp-queries"; \
        for pack in $$PACKS; do \
            if [ -n "${HTTP_PROXY}" ] && [ -n "${HTTPS_PROXY}" ]; then \
                env HTTP_PROXY="${HTTP_PROXY}" HTTPS_PROXY="${HTTPS_PROXY}" NO_PROXY="${NO_PROXY}" \
                    codeql pack download $$pack; \
            else \
                codeql pack download $$pack; \
            fi; \
        done; \
    fi

WORKDIR /target

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import shutil; assert shutil.which('codeql'); print('healthy')" || exit 1

ENTRYPOINT ["python", "-m", "src.cli.main"]
CMD ["--help"]
