#!/bin/bash
# SecAgentX 零人工干预模式启动脚本
# 启动 API 服务（含 AutoIngestor + AutoPatrol + AutoEscalation）

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

echo "═════════════════════════════════════════════"
echo "  SecAgentX - 零人工干预模式"
echo "═════════════════════════════════════════════"

# 检查 .env
if [ ! -f .env ]; then
    echo "[!] .env 文件不存在，正在从 .env.example 复制..."
    if [ -f .env.example ]; then
        cp .env.example .env
        echo "[!] 请编辑 .env 填入 API Key 后重新运行"
        exit 1
    fi
fi

# 检查 config.yaml
if [ ! -f config.yaml ]; then
    echo "[!] config.yaml 不存在，将使用默认配置"
fi

# 检查依赖
echo "[*] 检查 Python 依赖..."
python3 -c "import fastapi, uvicorn, yaml, httpx" 2>/dev/null || {
    echo "[*] 安装 Python 依赖..."
    pip install -r requirements.txt
}

echo "[*] 启动 SecAgentX API 服务 (零人工干预模式)..."
echo "    Webhook: POST /webhook/alert"
echo "    API:     http://localhost:8000"
echo "    WebSocket: ws://localhost:8000/ws/chat (统一入口)"
echo ""

python -m backend.interface.api_server

