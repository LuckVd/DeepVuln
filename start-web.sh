#!/bin/bash
# DeepVuln Web 服务启动脚本
# 用于在主机上启动 Web API 和 Celery Worker

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 设置环境变量（PYTHONPATH 以脚本所在目录为准，不再硬编码他人机器路径）
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="$SCRIPT_DIR:${PYTHONPATH:-}"
# 代码只读 DEEPVULN_DB_* 前缀（audit B3：DATABASE_URL 从未生效）
export DEEPVULN_DB_URL="${DEEPVULN_DB_URL:-postgresql+asyncpg://deepvuln:deepvuln_password@localhost:5432/deepvuln}"
export CELERY_BROKER_URL="redis://localhost:6379/0"
export CELERY_RESULT_BACKEND="redis://localhost:6379/0"
export OPENAI_API_KEY="${OPENAI_API_KEY:-}"
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-https://api.lkeap.cloud.tencent.com/coding/v3}"

# 检查依赖
check_dependencies() {
    echo -e "${YELLOW}检查依赖...${NC}"

    # 检查 PostgreSQL
    if ! pg_isready -q 2>/dev/null; then
        echo -e "${RED}PostgreSQL 未运行，请先启动 PostgreSQL${NC}"
        exit 1
    fi

    # 检查 Redis
    if ! redis-cli ping >/dev/null 2>&1; then
        echo -e "${RED}Redis 未运行，请先启动 Redis${NC}"
        exit 1
    fi

    echo -e "${GREEN}依赖检查完成${NC}"
}

# 初始化数据库
init_database() {
    echo -e "${YELLOW}检查数据库...${NC}"

    # 检查数据库是否存在
    if ! sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw deepvuln; then
        echo -e "${YELLOW}创建数据库...${NC}"
        sudo -u postgres createdb deepvuln
    fi

    # 运行迁移 (从 migrations 目录)
    echo -e "${YELLOW}运行数据库迁移...${NC}"
    (cd migrations && alembic upgrade head) || echo -e "${YELLOW}迁移已完成或失败${NC}"
}

# 启动服务
start_services() {
    echo -e "${YELLOW}启动服务...${NC}"

    # 停止现有进程
    pkill -f "celery.*scan_tasks" || true
    pkill -f "uvicorn.*web.main" || true
    sleep 2

    # 创建日志目录
    mkdir -p logs

    # 启动 Celery Worker
    echo -e "${GREEN}启动 Celery Worker...${NC}"
    nohup /usr/bin/python3.12 -m celery -A src.web.tasks.scan_tasks worker -l info -Q scan --concurrency=2 \
        > logs/celery.log 2>&1 </dev/null &
    CELERY_PID=$!
    echo $CELERY_PID > logs/celery.pid

    # 启动 Web API
    echo -e "${GREEN}启动 Web API...${NC}"
    nohup /usr/bin/python3.12 -m uvicorn src.web.main:app --host 0.0.0.0 --port 8000 \
        > logs/web-api.log 2>&1 </dev/null &
    API_PID=$!
    echo $API_PID > logs/web-api.pid

    sleep 3

    # 检查服务状态
    if ps -p $CELERY_PID > /dev/null && ps -p $API_PID > /dev/null; then
        echo -e "${GREEN}服务启动成功！${NC}"
        echo -e "Celery Worker PID: $CELERY_PID"
        echo -e "Web API PID: $API_PID"
        echo -e "Web API 地址: http://localhost:8000"
        echo -e "API 文档: http://localhost:8000/docs"
        echo ""
        echo -e "查看日志:"
        echo -e "  tail -f logs/celery.log"
        echo -e "  tail -f logs/web-api.log"
        echo ""
        echo -e "停止服务:"
        echo -e "  kill \$(cat logs/celery.pid) \$(cat logs/web-api.pid)"
        echo -e "  或: pkill -f 'celery.*scan_tasks'; pkill -f 'uvicorn.*web.main'"
    else
        echo -e "${RED}服务启动失败，请检查日志${NC}"
        exit 1
    fi
}

# 主流程
main() {
    cd /opt/projects/DeepVuln
    check_dependencies
    init_database
    start_services
}

main
