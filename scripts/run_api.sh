#!/bin/bash
set -euo pipefail

# ============================================================
# SecAgentX API Server 启动脚本
# ============================================================

cd "$(dirname "$0")/.."

echo "=== SecAgentX 启动前检查 ==="

# 1. 检查 Python 版本
PYTHON_VERSION=$(python3 --version 2>&1 | grep -oP '\d+\.\d+')
if (( $(echo "$PYTHON_VERSION < 3.9" | bc -l) )); then
    echo "[ERROR] Python 3.9+ required (found $PYTHON_VERSION)"
    exit 1
fi
echo "[OK] Python $(python3 --version)"

# 2. 检查 .env 文件
if [ ! -f .env ]; then
    echo "[ERROR] .env 文件不存在！请从 .env.example 复制并配置 API Key"
    echo "  cp .env.example .env"
    exit 1
fi
echo "[OK] .env 文件存在"

# 3. 检查关键依赖
python3 -c "
import importlib, sys
required = ['fastapi', 'uvicorn', 'httpx', 'yaml', 'dotenv']
missing = [pkg for pkg in required if not importlib.util.find_spec(pkg)]
if missing:
    print(f'[ERROR] 缺少依赖: {missing}')
    print('请执行: pip install -r requirements.txt')
    sys.exit(1)
print('[OK] 核心依赖检查通过')
"

# 4. 检查 API Key 配置（只检查是否存在，不打印值）
for key in DEEPSEEK_API_KEY QWEN_API_KEY; do
    if grep -q "^${key}=" .env 2>/dev/null; then
        val=$(grep "^${key}=" .env | cut -d= -f2)
        if [ -n "$val" ] && [ "$val" != "your-${key,,}-here" ]; then
            echo "[OK] $key 已配置"
        else
            echo "[WARN] $key 未配置或为默认值"
        fi
    else
        echo "[WARN] $key 未在 .env 中设置"
    fi
done

# 5. 创建运行时目录
mkdir -p data logs

# 6. 检查端口占用
PORT="${SECAGENTX_PORT:-8000}"
if ss -tlnp "sport = :$PORT" 2>/dev/null | grep -q ":$PORT"; then
    echo "[WARN] 端口 $PORT 已被占用，尝试其他端口"
fi

echo "=== 启动 SecAgentX API Server ==="
echo "  端口: $PORT"
echo "  日志: logs/secagentx.log"
echo ""

# 使用 exec 确保信号正确传递
exec uvicorn backend.interface.api_server:app \
    --host "${SECAGENTX_HOST:-0.0.0.0}" \
    --port "${SECAGENTX_PORT:-8000}" \
    --log-level "${SECAGENTX_LOG_LEVEL:-info}" \
    --workers 1 \
    --timeout-keep-alive 65 \
    --no-access-log

