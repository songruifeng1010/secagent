"""
SecAgentX 认证模块 — JWT Bearer Token
"""
import os
import uuid
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from .refresh_sessions import (
    RefreshSession,
    RefreshTokenInvalid,
    RefreshTokenReuseDetected,
    refresh_token_store,
)

# JWT 密钥优先级（安全加固 v2）:
#   1. 环境变量 SECAGENTX_JWT_SECRET（推荐生产使用）
#   2. 本地文件 data/.jwt_secret（自动生成，开发使用）
_SECRET_FILE = "data/.jwt_secret"


def _load_or_create_secret() -> str:
    # 优先从环境变量读取（生产环境推荐）
    env_secret = os.getenv("SECAGENTX_JWT_SECRET", "")
    if env_secret and len(env_secret) >= 32:
        return env_secret

    # 次优：从持久化文件读取
    if os.path.exists(_SECRET_FILE):
        with open(_SECRET_FILE, "r") as f:
            return f.read().strip()

    # 最后：自动生成
    secret = hashlib.sha256(os.urandom(64)).hexdigest()
    os.makedirs(os.path.dirname(_SECRET_FILE) or ".", exist_ok=True)
    # 权限：仅所有者可读写
    fd = os.open(_SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(secret)
    return secret


JWT_SECRET = _load_or_create_secret()
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("SECAGENTX_JWT_ACCESS_EXPIRE_MINUTES", "30"))  # 30 分钟
REFRESH_TOKEN_EXPIRE_MINUTES = int(os.getenv("SECAGENTX_JWT_REFRESH_EXPIRE_MINUTES", "1440"))  # 24 小时

security_scheme = HTTPBearer(auto_error=False)
WEB_ACCESS_COOKIE = "secagentx_access"
WEB_REFRESH_COOKIE = "secagentx_refresh"
WEB_CSRF_COOKIE = "secagentx_csrf"


class TokenData(BaseModel):
    sub: str
    role: str = "viewer"
    token_version: int = 0
    exp: Optional[str] = None


class LoginBody(BaseModel):
    username: str
    password: str


def create_access_token(sub: str, role: str = "admin", token_version: int = 0) -> str:
    """创建 JWT 访问令牌（短时效，30分钟）"""
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": sub,
        "role": role,
        "ver": token_version,
        "type": "access",
        "exp": expire.timestamp(),
        "iat": datetime.now(timezone.utc).timestamp(),
        "jti": uuid.uuid4().hex,
    }
    import jwt as pyjwt
    return pyjwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_refresh_token(
    sub: str,
    role: str = "admin",
    token_version: int = 0,
    family_id: Optional[str] = None,
    register: bool = True,
) -> str:
    """创建 JWT 刷新令牌（长时效，24小时）

    刷新令牌仅用于换取新的访问令牌，不直接授权 API 调用。
    """
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    jti = uuid.uuid4().hex
    family_id = family_id or uuid.uuid4().hex
    payload = {
        "sub": sub,
        "role": role,
        "ver": token_version,
        "type": "refresh",
        "exp": expire.timestamp(),
        "iat": now.timestamp(),
        "jti": jti,
        "family_id": family_id,
    }
    import jwt as pyjwt
    token = pyjwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    if register:
        refresh_token_store.register(
            RefreshSession(
                jti=jti,
                family_id=family_id,
                user_id=sub,
                issued_at=now.timestamp(),
                expires_at=expire.timestamp(),
            )
        )
    return token


def _decode_token(token: str) -> dict:
    """解码 JWT，返回 payload（不区分 token type）"""
    import jwt as pyjwt
    return pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


def rotate_refresh_token(token: str) -> tuple[str, str, int]:
    """轮换一次性刷新令牌，并使用用户的实时角色和 token version。"""
    payload = _decode_token(token)
    if payload.get("type") != "refresh":
        raise RefreshTokenInvalid("需要 refresh token")

    sub = payload.get("sub")
    jti = payload.get("jti")
    family_id = payload.get("family_id")
    if not sub or not jti or not family_id:
        raise RefreshTokenInvalid("刷新令牌缺少必要声明")

    from .rbac import get_user_manager

    user = get_user_manager().get_user(sub)
    if not user or not user.enabled:
        raise RefreshTokenInvalid("用户不存在或已禁用")
    if int(payload.get("ver", -1)) != user.token_version:
        raise RefreshTokenInvalid("用户权限或凭据已变更，请重新登录")

    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    new_jti = uuid.uuid4().hex
    new_session = RefreshSession(
        jti=new_jti,
        family_id=family_id,
        user_id=sub,
        issued_at=now.timestamp(),
        expires_at=expire.timestamp(),
    )
    refresh_token_store.rotate(jti, new_session)

    import jwt as pyjwt

    new_payload = {
        "sub": sub,
        "role": user.role,
        "ver": user.token_version,
        "type": "refresh",
        "exp": expire.timestamp(),
        "iat": now.timestamp(),
        "jti": new_jti,
        "family_id": family_id,
    }
    new_refresh = pyjwt.encode(new_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    new_access = create_access_token(sub, user.role, user.token_version)
    return new_access, new_refresh, ACCESS_TOKEN_EXPIRE_MINUTES * 60


def revoke_refresh_token_family(token: str) -> None:
    """撤销 refresh token 所属会话族；无效令牌按幂等注销处理。"""
    try:
        payload = _decode_token(token)
        family_id = payload.get("family_id")
        if payload.get("type") == "refresh" and family_id:
            refresh_token_store.revoke_family(family_id)
    except Exception:
        return


def validate_live_token_data(token: TokenData) -> TokenData:
    """重新校验长连接中的令牌时效与实时用户状态。"""
    if token.exp and float(token.exp) <= datetime.now(timezone.utc).timestamp():
        raise HTTPException(status_code=401, detail="访问令牌已过期")

    from .rbac import get_user_manager

    user = get_user_manager().get_user(token.sub)
    if not user or not user.enabled:
        raise HTTPException(status_code=401, detail="用户不存在或已禁用")
    if token.token_version != user.token_version:
        raise HTTPException(status_code=401, detail="用户权限或凭据已变更，请重新登录")
    token.role = user.role
    return token


async def verify_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    request: Request = None,
) -> TokenData:
    """验证 Bearer 或 Web HttpOnly Cookie 中的访问令牌。"""
    if credentials is None and request is not None:
        cookie_token = request.cookies.get(WEB_ACCESS_COOKIE, "")
        if cookie_token:
            credentials = HTTPAuthorizationCredentials(
                scheme="bearer", credentials=cookie_token
            )
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="缺少认证令牌",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        import jwt as pyjwt
        payload = _decode_token(credentials.credentials)
        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="仅访问令牌可用于 API 请求",
                headers={"WWW-Authenticate": "Bearer"},
            )
        sub = payload.get("sub")
        if not sub:
            raise HTTPException(status_code=401, detail="令牌缺少用户标识")

        token_data = TokenData(
            sub=sub,
            role=payload.get("role", "viewer"),
            token_version=int(payload.get("ver", -1)),
            exp=str(payload.get("exp", "")),
        )
        return validate_live_token_data(token_data)
    except HTTPException:
        raise
    except Exception as e:
        err_msg = str(e)
        if "expired" in err_msg.lower():
            raise HTTPException(status_code=401, detail="访问令牌已过期，请使用 refresh token 刷新")
        raise HTTPException(status_code=401, detail=f"无效令牌: {err_msg}")


def require_role(role: str):
    """权限控制装饰器"""
    async def checker(token: TokenData = Depends(verify_token)):
        if token.role != role and token.role != "admin":
            raise HTTPException(status_code=403, detail=f"需要 {role} 权限")
        return token
    return checker


# ─── 开放端点路径前缀 ───
# 注意: 跨区域联邦 API 在生产环境中应通过 VPC/内网访问
#
# 联邦同步接口（/api/federation/events, /api/federation/blacklist）
# 由 verify_federation_request（Peer Token）单独保护，需绕过 JWT 中间件。
# 联邦状态/仪表盘接口（/api/federation/status, /api/federation/dashboard）
# 需要 JWT 认证，不在此处列出。
OPEN_API_PATHS = {
    "/api/health",
    "/api/health/live",
    "/api/health/ready",
    "/api/metrics",
    "/api/auth/login",
    "/api/auth/refresh",
    "/api/auth/web/login",
    "/api/auth/web/refresh",
    "/api/auth/web/logout",
    "/api/federation/events",      # 联邦事件同步（Peer Token 保护）
    "/api/federation/blacklist",   # 联邦黑名单同步（Peer Token 保护）
    "/docs",
    "/openapi.json",
    "/redoc",
}


async def get_bearer_token_from_request(request) -> Optional[HTTPAuthorizationCredentials]:
    """从请求头提取 Bearer Token"""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return HTTPAuthorizationCredentials(
            scheme="bearer", credentials=auth[7:]
        )
    return None


def is_open_path(path: str) -> bool:
    """判断路径是否为开放路径（无需认证）"""
    if path in OPEN_API_PATHS:
        return True
    if path.startswith("/docs/") or path.startswith("/redoc/"):
        return True
    # 前端静态资源跳过
    if path.startswith("/assets/") or path == "/" or path.startswith("/favicon"):
        return True
    return False
