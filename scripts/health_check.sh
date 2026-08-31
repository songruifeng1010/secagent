#!/bin/bash
# =============================================================
# SecAgentX 运行健康检查脚本（运维工具）
#
# 用法:
#   ./scripts/health_check.sh          # 完整检查
#   ./scripts/health_check.sh --quick  # 快速检查（仅关键项）
#   ./scripts/health_check.sh --json   # JSON 输出（供监控系统使用）
# =============================================================
set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

API="${SECAGENTX_HEALTH_URL:-http://127.0.0.1:8000}"
QUICK=0
JSON=0
for arg in "$@"; do
  [ "$arg" = "--quick" ] && QUICK=1
  [ "$arg" = "--json" ] && JSON=1
done

PASS=0
FAIL=0
WARN=0
RESULTS=()

check() {
  local name="$1" status="$2" detail="$3"
  if [ "$status" = "ok" ]; then
    PASS=$((PASS+1))
    RESULTS+=("{\"check\":\"$name\",\"status\":\"ok\",\"detail\":\"$detail\"}")
  elif [ "$status" = "warn" ]; then
    WARN=$((WARN+1))
    RESULTS+=("{\"check\":\"$name\",\"status\":\"warn\",\"detail\":\"$detail\"}")
  else
    FAIL=$((FAIL+1))
    RESULTS+=("{\"check\":\"$name\",\"status\":\"fail\",\"detail\":\"$detail\"}")
  fi
}

# ─── 1. 后端进程 ───
PID=$(pgrep -f "backend.interface.api_server" | head -1)
if [ -n "$PID" ]; then
  check "backend_process" "ok" "PID=$PID"
else
  check "backend_process" "fail" "进程未运行"
fi

# ─── 2. API 健康检查 ───
HEALTH=$(curl -s -m 5 "$API/api/health" 2>/dev/null)
if echo "$HEALTH" | grep -q '"status":"ok"'; then
  DB_STATUS=$(echo "$HEALTH" | grep -o '"database":"[^"]*"' | cut -d'"' -f4)
  EVENTS=$(echo "$HEALTH" | grep -o '"database_events":[0-9]*' | cut -d: -f2)
  check "api_health" "ok" "db=$DB_STATUS events=$EVENTS"
elif [ -z "$HEALTH" ]; then
  check "api_health" "fail" "API 无响应"
else
  check "api_health" "fail" "API 状态异常: ${HEALTH:0:80}"
fi

# ─── 3. 前端 ───
FRONT=$(curl -s -m 5 -o /dev/null -w "%{http_code}" "$API/" 2>/dev/null)
if [ "$FRONT" = "200" ]; then
  check "frontend" "ok" "HTTP 200"
else
  check "frontend" "warn" "HTTP $FRONT"
fi

# ─── 4. 数据库文件 ───
if [ -f "data/secagentx.db" ]; then
  DB_SIZE=$(du -h data/secagentx.db | cut -f1)
  check "database_file" "ok" "$DB_SIZE"
else
  check "database_file" "fail" "data/secagentx.db 不存在"
fi

# ─── 5. 磁盘空间 ───
DISK_USED=$(df -h . | tail -1 | awk '{print $5}' | tr -d '%')
if [ "$DISK_USED" -lt 80 ]; then
  check "disk_space" "ok" "使用 ${DISK_USED}%"
elif [ "$DISK_USED" -lt 90 ]; then
  check "disk_space" "warn" "使用 ${DISK_USED}% (接近阈值)"
else
  check "disk_space" "fail" "使用 ${DISK_USED}% (磁盘紧张)"
fi

# ─── 6. 日志错误扫描（最近 100 条） ───
if [ "$QUICK" = "0" ]; then
  if [ -f "logs/secagentx.log" ]; then
    ERR_COUNT=$(tail -100 logs/secagentx.log | grep -c '"level": "ERROR"' || true)
    if [ "$ERR_COUNT" -eq 0 ]; then
      check "log_errors" "ok" "最近100条日志无ERROR"
    else
      check "log_errors" "warn" "最近100条日志有 $ERR_COUNT 条ERROR"
    fi
  fi
fi

# ─── 7. ML 模型 ───
if ls model/threat_model_*.joblib >/dev/null 2>&1; then
  ML_MODEL=$(ls -t model/threat_model_*.joblib | head -1 | xargs basename)
  check "ml_model" "ok" "$ML_MODEL"
else
  check "ml_model" "warn" "未找到模型文件"
fi

# ─── 8. 防火墙后端 ───
FW_BACKEND=$(grep "^FIREWALL_BACKEND=" .env 2>/dev/null | cut -d= -f2)
check "firewall_backend" "ok" "${FW_BACKEND:-未配置}"

# ─── 9. 端口监听 ───
if ss -tln | grep -q ":8000 "; then
  check "port_8000" "ok" "监听中"
else
  check "port_8000" "fail" "8000 端口未监听"
fi

# ─── 输出 ───
if [ "$JSON" = "1" ]; then
  echo "{"
  echo "  \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
  echo "  \"summary\": {\"pass\": $PASS, \"warn\": $WARN, \"fail\": $FAIL},"
  echo "  \"checks\": ["
  for i in "${!RESULTS[@]}"; do
    comma=","
    [ $i -eq $(( ${#RESULTS[@]} - 1 )) ] && comma=""
    echo "    ${RESULTS[$i]}$comma"
  done
  echo "  ]"
  echo "}"
else
  echo "======================================"
  echo "  SecAgentX 健康检查报告"
  echo "======================================"
  for r in "${RESULTS[@]}"; do
    name=$(echo "$r" | grep -o '"check":"[^"]*"' | cut -d'"' -f4)
    status=$(echo "$r" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
    detail=$(echo "$r" | grep -o '"detail":"[^"]*"' | cut -d'"' -f4)
    icon="✅"; [ "$status" = "warn" ] && icon="⚠️"; [ "$status" = "fail" ] && icon="❌"
    printf "  %s %-18s %s\n" "$icon" "$name" "$detail"
  done
  echo "--------------------------------------"
  echo "  结果: $PASS 通过 | $WARN 警告 | $FAIL 失败"
  [ "$FAIL" -gt 0 ] && exit 1 || exit 0
fi

