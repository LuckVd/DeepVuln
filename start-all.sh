#!/bin/bash
# DeepVuln Complete Startup Script
# Starts PostgreSQL, Redis, Celery Worker, and Web Service

set -e

PROJECT_DIR="/opt/projects/DeepVuln"
cd "$PROJECT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "  DeepVuln 完整服务启动脚本"
echo "=========================================="
echo ""

# Activate virtual environment
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
    echo -e "${GREEN}✓${NC} 虚拟环境已激活"
else
    echo -e "${RED}✗${NC} 虚拟环境不存在，请先创建: python -m venv .venv"
    exit 1
fi

# Check PostgreSQL
echo -n "检查 PostgreSQL..."
if docker ps | grep -q deepvuln-postgres; then
    echo -e " ${GREEN}运行中${NC}"
else
    echo -e " ${YELLOW}未运行，请先启动 docker-compose${NC}"
    echo "  运行: docker-compose up -d postgres redis"
fi

# Check Redis
echo -n "检查 Redis..."
if docker ps | grep -q deepvuln-redis; then
    echo -e " ${GREEN}运行中${NC}"
else
    echo -e " ${YELLOW}未运行，请先启动 docker-compose${NC}"
fi

# Set API Key
export DEEPVULN_API_KEYS="${DEEPVULN_API_KEYS:-dev-test-key-2024}"
export PYTHONPATH="$PROJECT_DIR:$PYTHONPATH"

echo ""
echo "启动服务..."
echo ""

# Function to cleanup background processes
cleanup() {
    echo ""
    echo "正在停止服务..."
    kill $CELERY_PID 2>/dev/null || true
    echo -e "${GREEN}✓${NC} Celery Worker 已停止"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Start Celery Worker
echo -e "${GREEN}启动 Celery Worker...${NC}"
celery -A src.web.core.celery_app worker \
    --loglevel=info \
    --pool=solo \
    --concurrency=1 \
    -Q scan &
CELERY_PID=$!

sleep 2

# Check if Celery is running
if ps -p $CELERY_PID > /dev/null; then
    echo -e "${GREEN}✓${NC} Celery Worker 已启动 (PID: $CELERY_PID)"
else
    echo -e "${RED}✗${NC} Celery Worker 启动失败"
    exit 1
fi

# Start Web Service
echo ""
echo -e "${GREEN}启动 Web 服务...${NC}"
python -m uvicorn src.web.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --reload &
WEB_PID=$!

sleep 2

# Check if Web Service is running
if ps -p $WEB_PID > /dev/null; then
    echo -e "${GREEN}✓${NC} Web 服务已启动 (PID: $WEB_PID)"
else
    echo -e "${RED}✗${NC} Web 服务启动失败"
    kill $CELERY_PID
    exit 1
fi

echo ""
echo "=========================================="
echo -e "${GREEN}所有服务已成功启动!${NC}"
echo "=========================================="
echo ""
echo "服务地址:"
echo "  - Web API:     http://localhost:8000"
echo "  - API 文档:    http://localhost:8000/docs"
echo "  - 前端开发:    http://localhost:5173 (需单独启动)"
echo ""
echo "按 Ctrl+C 停止所有服务"
echo ""

# Wait for any process to exit
wait
