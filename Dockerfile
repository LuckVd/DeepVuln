# DeepVuln Docker Image
# Multi-language security scanning runtime with CodeQL-oriented toolchains.

FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV PYTHONUNBUFFERED=1
ENV GOPATH=/go
ENV CODEQL_VERSION=2.24.2
ENV CODEQL_HOME=/opt/codeql
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
ENV MAVEN_HOME=/usr/share/maven
ENV GRADLE_HOME=/usr/share/gradle
ENV DOTNET_ROOT=/usr/share/dotnet
ENV PATH=/app/.venv/bin:/usr/local/go/bin:/go/bin:/opt/codeql/codeql:/usr/share/maven/bin:/usr/share/gradle/bin:/usr/share/dotnet:${JAVA_HOME}/bin:${PATH}

ARG APT_MIRROR=
ARG HTTP_PROXY=
ARG HTTPS_PROXY=
ARG NO_PROXY=
ARG GO_DOWNLOAD_URL=https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
ARG GO_DOWNLOAD_FALLBACK_URL=https://dl.google.com/go/go1.22.0.linux-amd64.tar.gz
ARG CODEQL_DOWNLOAD_URL=
ARG CODEQL_DOWNLOAD_FALLBACK_URL=https://ghproxy.net/https://github.com/github/codeql-cli-binaries/releases/download/v2.24.2/codeql-linux64.zip
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
        maven \
        gradle \
        nodejs \
        npm \
        openjdk-21-jdk \
        ruby-full \
        unzip \
        wget \
    && rm -rf /var/lib/apt/lists/*

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

RUN set -eu; \
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
    unzip -q /tmp/codeql.zip -d /opt/codeql; \
    rm /tmp/codeql.zip

WORKDIR /app
COPY pyproject.toml requirements.txt uv.lock* ./

COPY . /app

RUN python -m pip install --no-cache-dir uv \
    && uv venv /app/.venv \
    && uv pip install --python /app/.venv/bin/python -e ".[analysis]" semgrep

RUN useradd -m -s /bin/bash deepvuln \
    && mkdir -p /target /tmp/codeql_cache /home/deepvuln/.cache /home/deepvuln/.codeql /go \
    && chown -R deepvuln:deepvuln /app /target /tmp/codeql_cache /home/deepvuln /go

USER deepvuln
ENV HOME=/home/deepvuln
WORKDIR /app

RUN if [ "${PRELOAD_CODEQL_PACKS}" = "true" ]; then \
        env HTTP_PROXY="${HTTP_PROXY}" HTTPS_PROXY="${HTTPS_PROXY}" NO_PROXY="${NO_PROXY}" \
            codeql pack download codeql/go-queries \
        && env HTTP_PROXY="${HTTP_PROXY}" HTTPS_PROXY="${HTTPS_PROXY}" NO_PROXY="${NO_PROXY}" \
            codeql pack download codeql/java-queries \
        && env HTTP_PROXY="${HTTP_PROXY}" HTTPS_PROXY="${HTTPS_PROXY}" NO_PROXY="${NO_PROXY}" \
            codeql pack download codeql/python-queries \
        && env HTTP_PROXY="${HTTP_PROXY}" HTTPS_PROXY="${HTTPS_PROXY}" NO_PROXY="${NO_PROXY}" \
            codeql pack download codeql/javascript-queries \
        && env HTTP_PROXY="${HTTP_PROXY}" HTTPS_PROXY="${HTTPS_PROXY}" NO_PROXY="${NO_PROXY}" \
            codeql pack download codeql/cpp-queries \
        && env HTTP_PROXY="${HTTP_PROXY}" HTTPS_PROXY="${HTTPS_PROXY}" NO_PROXY="${NO_PROXY}" \
            codeql pack download codeql/ruby-queries \
        && env HTTP_PROXY="${HTTP_PROXY}" HTTPS_PROXY="${HTTPS_PROXY}" NO_PROXY="${NO_PROXY}" \
            codeql pack download codeql/csharp-queries; \
    fi

WORKDIR /target

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import shutil; assert shutil.which('codeql'); print('healthy')" || exit 1

ENTRYPOINT ["python", "-m", "src.cli.main"]
CMD ["--help"]
