#!/bin/bash
# =============================================================
# SecAgentX 开发环境一键启动脚本
# =============================================================
# 使用方式:
#   chmod +x scripts/start_dev.sh
#   ./scripts/start_dev.sh [--with-frontend]
# =============================================================

set -e

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

echo "=================================="
echo "  SecAgentX 开发环境启动"
echo "=================================="

# ─── 1. 检查 .env ───
if [ ! -f .env ]; then
    echo "[WARN] .env 文件不存在，从 .env.example 复制..."
    cp .env.example .env
    echo "[WARN] 请编辑 .env 填入 API Key 后重新运行"
    exit 1
fi

# ─── 2. 安装 Python 依赖 ───
echo "[1/4] 安装 Python 依赖..."
pip install -r requirements.txt -q 2>/dev/null || pip install -r requirements.txt

# ─── 3. 初始化数据库 ───
echo "[2/4] 初始化数据库..."
python3 -c "
from backend.main import init_db
init_db()
print('数据库初始化完成')
"

# ─── 4. 创建基础目录 ───
echo "[3/4] 创建运行时目录..."
mkdir -p data exports logs data/blacklist

# ─── 5. 启动服务 ───
echo "[4/4] 启动 SecAgentX API 服务..."
echo ""
echo "   ╔══════════════════════════════════════╗"
echo "   ║  API:  http://localhost:8000          ║"
echo "   ║  API:  http://localhost:8000/docs     ║"
echo "   ║  健康: http://localhost:8000/api/health║"
echo "   ╚══════════════════════════════════════╝"
echo ""

if [ "$1" == "--with-frontend" ]; then
    echo "[INFO] 同时启动前端开发服务器..."
    echo "   ║  前端: http://localhost:3000          ║"
    (cd frontend && npm install --silent && npm run dev) &
    python3 -m backend.interface.api_server
else
    python3 -m backend.interface.api_server
fi

