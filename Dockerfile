# =============================================================
# SecAgentX - 多阶段 Docker 构建（生产优化版）
# =============================================================

# --- Stage 1: 构建前端 ---
FROM node:24-alpine AS frontend-builder

WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
# Vite 与 Vue 插件属于构建期 devDependencies；仅最终 Python 镜像保持精简。
RUN npm ci
COPY frontend/ ./
RUN npm run build

# --- Stage 2: 运行后端（含前端静态文件） ---
FROM python:3.11-slim

# 安全：创建非 root 用户
RUN groupadd -r secagentx && useradd -r -g secagentx -d /app -s /sbin/nologin secagentx

WORKDIR /app

# 安装 Python 依赖（无系统依赖需要，所有包均有预编译 wheel）
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# 复制后端代码
COPY backend/ ./backend/
COPY config.yaml ./
COPY knowledge_data/ ./knowledge_data/
COPY scripts/ ./scripts/

# 从 Stage 1 复制构建好的前端文件
COPY --from=frontend-builder /app/dist/ ./frontend/dist/

# 创建运行时目录并设置权限
RUN mkdir -p data exports logs .jwt_secret && \
    chown -R secagentx:secagentx /app

USER secagentx

EXPOSE 8000

# 健康检查
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/api/health/ready', timeout=5).raise_for_status()" || exit 1

# 使用 exec 格式确保信号正确传递
CMD ["python", "-m", "uvicorn", "backend.interface.api_server:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
