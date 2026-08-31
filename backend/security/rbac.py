"""
RBAC 权限管理 — 基于角色的访问控制

角色体系:
  - admin:     全部权限（管理用户/系统配置/封禁/审计）
  - operator:  运营权限（查看事件/封禁/解封/审计）
  - analyst:   分析权限（查看事件/Agent/审计，不可封禁）
  - viewer:    只读权限（基础查看）

用户存储: 使用配置文件中 users 列表 + 数据库持久化
"""
import os
import json
import hashlib
import hmac
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("secagentx.rbac")

KNOWN_INSECURE_ADMIN_PASSWORDS = {
    "admin",
    "password",
    "changeme",
    "secagentx_2026",
    "secagentx_prod_2026!",
}


class AdminBootstrapError(RuntimeError):
    """管理员初始凭据缺失或不安全。"""

# ─── 权限定义 ───

PERMISSIONS = {
    "events:read",       # 查看安全事件
    "events:write",      # 更新/处置事件
    "events:export",     # 导出事件数据
    "firewall:block",    # 封禁 IP
    "firewall:unblock",  # 解封 IP
    "firewall:view",     # 查看封禁列表
    "agents:read",       # 查看 Agent 状态
    "audit:read",        # 查看审计日志
    "admin:users",       # 管理用户
    "admin:config",      # 管理系统配置
    "dashboard:view",    # 查看仪表盘
    "knowledge:read",    # 查询知识库 (MITRE/CVE)
}

# ─── 角色-权限映射 ───

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin": PERMISSIONS.copy(),

    "operator": {
        "events:read", "events:write", "events:export",
        "firewall:block", "firewall:unblock", "firewall:view",
        "agents:read",
        "audit:read",
        "dashboard:view",
        "knowledge:read",
    },

    "analyst": {
        "events:read",
        "firewall:view",
        "agents:read",
        "audit:read",
        "dashboard:view",
        "knowledge:read",
    },

    "viewer": {
        "events:read",
        "dashboard:view",
        "knowledge:read",
    },
}

# ─── 用户模型 ───

@dataclass
class User:
    username: str
    password_hash: str
    role: str = "viewer"
    enabled: bool = True
    display_name: str = ""
    created_at: str = ""
    updated_at: str = ""
    token_version: int = 0

    def has_permission(self, permission: str) -> bool:
        """检查用户是否拥有指定权限"""
        perms = ROLE_PERMISSIONS.get(self.role, set())
        return permission in perms

    def has_any_permission(self, *permissions: str) -> bool:
        """检查用户是否拥有任一指定权限"""
        perms = ROLE_PERMISSIONS.get(self.role, set())
        return any(p in perms for p in permissions)

    def to_dict(self) -> dict:
        """序列化（不含密码 hash）"""
        return {
            "username": self.username,
            "role": self.role,
            "enabled": self.enabled,
            "display_name": self.display_name or self.username,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


# ─── 用户管理器 ───

class UserManager:
    """用户管理器 — 加载/保存/验证用户"""

    def __init__(self, users_file: str = None):
        self._users_file = users_file or os.getenv(
            "SECAGENTX_USERS_FILE", "data/users.json"
        )
        self._users: dict[str, User] = {}
        self._load()

    # ═══════════════════ 公开接口 ═══════════════════

    def authenticate(self, username: str, password: str) -> Optional[User]:
        """验证用户名密码，成功返回 User 对象，失败返回 None"""
        user = self._users.get(username)
        if not user or not user.enabled:
            return None
        if self._verify_password(password, user.password_hash):
            # v3.1 兼容迁移：旧版无盐 SHA-256 仅允许用于一次登录验证，
            # 成功后立即升级为 bcrypt 并使既有令牌失效。
            if not user.password_hash.startswith(("$2a$", "$2b$", "$2y$")):
                user.password_hash = self._hash_password(password)
                user.token_version += 1
                user.updated_at = datetime.now(timezone.utc).isoformat()
                self._save()
                self._revoke_refresh_sessions(username)
                logger.info("用户密码已自动迁移到 bcrypt: %s", username)
            return user
        return None

    def get_user(self, username: str) -> Optional[User]:
        """获取用户（不含密码 hash）"""
        user = self._users.get(username)
        return user if user else None

    def list_users(self) -> list[dict]:
        """列出所有用户（不含密码 hash）"""
        return [u.to_dict() for u in self._users.values()]

    def create_user(self, username: str, password: str, role: str = "viewer",
                    display_name: str = "", enabled: bool = True) -> User:
        """创建用户"""
        if username in self._users:
            raise ValueError(f"用户已存在: {username}")
        if role not in ROLE_PERMISSIONS:
            raise ValueError(f"无效角色: {role}，可用: {', '.join(ROLE_PERMISSIONS.keys())}")
        now = datetime.now(timezone.utc).isoformat()
        user = User(
            username=username,
            password_hash=self._hash_password(password),
            role=role,
            enabled=enabled,
            display_name=display_name or username,
            created_at=now,
            updated_at=now,
        )
        self._users[username] = user
        self._save()
        logger.info("创建用户: %s (role=%s)", username, role)
        return user

    def update_user(self, username: str, role: str = None,
                    enabled: bool = None, display_name: str = None,
                    password: str = None) -> Optional[User]:
        """更新用户信息"""
        user = self._users.get(username)
        if not user:
            return None
        invalidates_tokens = False
        if role is not None:
            if role not in ROLE_PERMISSIONS:
                raise ValueError(f"无效角色: {role}")
            invalidates_tokens = invalidates_tokens or role != user.role
            user.role = role
        if enabled is not None:
            invalidates_tokens = invalidates_tokens or enabled != user.enabled
            user.enabled = enabled
        if display_name is not None:
            user.display_name = display_name
        if password:
            user.password_hash = self._hash_password(password)
            invalidates_tokens = True
        if invalidates_tokens:
            user.token_version += 1
        user.updated_at = datetime.now(timezone.utc).isoformat()
        self._save()
        if invalidates_tokens:
            self._revoke_refresh_sessions(username)
        logger.info("更新用户: %s (role=%s, enabled=%s)", username, user.role, user.enabled)
        return user

    def delete_user(self, username: str) -> bool:
        """删除用户（禁止删除 admin 用户）"""
        if username == "admin":
            raise ValueError("不能删除 admin 用户")
        if username in self._users:
            del self._users[username]
            self._save()
            self._revoke_refresh_sessions(username)
            logger.info("删除用户: %s", username)
            return True
        return False

    # ═══════════════════ 内部方法 ═══════════════════

    def _hash_password(self, password: str) -> str:
        """使用 bcrypt 对密码进行不可逆哈希；生产运行不允许弱降级。"""
        import bcrypt
        return bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

    def _verify_password(self, password: str, stored_hash: str) -> bool:
        """验证密码"""
        if stored_hash.startswith(("$2a$", "$2b$", "$2y$")):
            import bcrypt
            return bcrypt.checkpw(
                password.encode("utf-8"), stored_hash.encode("utf-8")
            )
        # 仅用于把 v3.0 及更早版本的用户透明迁移到 bcrypt。
        legacy_hash = hashlib.sha256(password.encode()).hexdigest()
        return hmac.compare_digest(legacy_hash, stored_hash)

    def _revoke_refresh_sessions(self, username: str) -> None:
        """撤销用户刷新会话；token version 同时保证旧令牌立即失效。"""
        try:
            from .refresh_sessions import refresh_token_store
            refresh_token_store.revoke_user(username)
        except Exception:
            logger.exception("撤销用户刷新会话失败: %s", username)

    def _load(self):
        """从文件加载用户，并同步 admin 密码"""
        self._users = {}
        if not os.path.exists(self._users_file):
            self._ensure_admin_exists()
            return
        try:
            with open(self._users_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for entry in data:
                try:
                    user = User(
                        username=entry["username"],
                        password_hash=entry["password_hash"],
                        role=entry.get("role", "viewer"),
                        enabled=entry.get("enabled", True),
                        display_name=entry.get("display_name", ""),
                        created_at=entry.get("created_at", ""),
                        updated_at=entry.get("updated_at", ""),
                        token_version=int(entry.get("token_version", 0)),
                    )
                    self._users[user.username] = user
                except (KeyError, ValueError) as e:
                    logger.warning("用户数据加载跳过: %s", e)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logger.warning("用户文件加载失败: %s", e)

        # 确保 admin 用户存在（_ensure_admin_exists 内部会同步密码）
        self._ensure_admin_exists()

    def _validate_admin_plaintext(self, password: str) -> None:
        if len(password) < 12:
            raise AdminBootstrapError("SECAGENTX_PASSWORD 至少需要 12 个字符")
        if password.strip().lower() in KNOWN_INSECURE_ADMIN_PASSWORDS:
            raise AdminBootstrapError("SECAGENTX_PASSWORD 使用了已知的不安全默认值")

    def _validate_admin_hash(self, password_hash: str) -> None:
        is_bcrypt = password_hash.startswith(("$2a$", "$2b$", "$2y$"))
        if not is_bcrypt:
            raise AdminBootstrapError(
                "SECAGENTX_PASSWORD_HASH 必须是 bcrypt hash；"
                "旧 SHA-256 用户将在密码登录后自动迁移"
            )
        if any(self._verify_password(value, password_hash)
               for value in KNOWN_INSECURE_ADMIN_PASSWORDS):
            raise AdminBootstrapError("SECAGENTX_PASSWORD_HASH 对应已知的不安全默认密码")

    def _sync_admin_from_env(self):
        """从环境变量同步 admin 用户密码 hash。

        每次加载用户文件时调用，确保:
        1. .env 中 SECAGENTX_PASSWORD_HASH 变更后 admin 能登录
        2. 密码明文/ hash 任一更新都生效
        """
        if "admin" not in self._users:
            return
        env_hash = os.getenv("SECAGENTX_PASSWORD_HASH", "")
        env_plain = os.getenv("SECAGENTX_PASSWORD", "")
        user = self._users["admin"]

        # hash 优先: 如果环境变量有 hash，用它覆盖
        if env_hash:
            self._validate_admin_hash(env_hash)
            if user.password_hash != env_hash:
                user.password_hash = env_hash
                user.token_version += 1
                user.updated_at = datetime.now(timezone.utc).isoformat()
                self._save()
                self._revoke_refresh_sessions("admin")
                logger.debug("admin 密码已从 SECAGENTX_PASSWORD_HASH 同步")
            return

        # 无 hash 但有明文 → 重新 hash 后更新
        if env_plain:
            self._validate_admin_plaintext(env_plain)
            if not self._verify_password(env_plain, user.password_hash):
                user.password_hash = self._hash_password(env_plain)
                user.token_version += 1
                user.updated_at = datetime.now(timezone.utc).isoformat()
                self._save()
                self._revoke_refresh_sessions("admin")
                logger.debug("admin 密码已从 SECAGENTX_PASSWORD 同步")
            return

        if any(self._verify_password(value, user.password_hash)
               for value in KNOWN_INSECURE_ADMIN_PASSWORDS):
            raise AdminBootstrapError(
                "检测到 admin 仍在使用已知默认密码；请配置 SECAGENTX_PASSWORD 或 HASH"
            )
        logger.debug("未配置 SECAGENTX_PASSWORD/HASH，沿用已有安全凭据")

    def _ensure_admin_exists(self):
        """确保 admin 用户存在（不存在时用环境变量创建）"""
        if "admin" not in self._users:
            env_hash = os.getenv("SECAGENTX_PASSWORD_HASH", "")
            env_plain = os.getenv("SECAGENTX_PASSWORD", "")
            if env_hash:
                self._validate_admin_hash(env_hash)
                password_hash = env_hash
            elif env_plain:
                self._validate_admin_plaintext(env_plain)
                password_hash = self._hash_password(env_plain)
            else:
                raise AdminBootstrapError(
                    "首次启动必须配置 SECAGENTX_PASSWORD（至少 12 字符）"
                    "或 SECAGENTX_PASSWORD_HASH"
                )
            now = datetime.now(timezone.utc).isoformat()
            self._users["admin"] = User(
                username="admin",
                password_hash=password_hash,
                role="admin",
                enabled=True,
                display_name="Administrator",
                created_at=now,
                updated_at=now,
            )
            self._save()
            logger.info("自动创建 admin 用户")
        else:
            # 已存在则同步密码（确保 .env 变更生效）
            self._sync_admin_from_env()

    def _save(self):
        """保存用户到文件"""
        os.makedirs(os.path.dirname(self._users_file) or ".", exist_ok=True)
        data = []
        for user in self._users.values():
            data.append({
                "username": user.username,
                "password_hash": user.password_hash,
                "role": user.role,
                "enabled": user.enabled,
                "display_name": user.display_name,
                "created_at": user.created_at,
                "updated_at": user.updated_at,
                "token_version": user.token_version,
            })
        with open(self._users_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


# 全局单例
_user_manager: Optional[UserManager] = None


def get_user_manager() -> UserManager:
    """获取全局用户管理器单例"""
    global _user_manager
    if _user_manager is None:
        _user_manager = UserManager()
    return _user_manager


def enforce_permission(token, permission: str, manager: UserManager = None) -> User:
    """按数据库中的实时用户状态检查权限，不信任 JWT 内的历史角色声明。"""
    from fastapi import HTTPException

    mgr = manager or get_user_manager()
    user = mgr.get_user(token.sub)
    if not user or not user.enabled:
        raise HTTPException(status_code=403, detail="用户不存在或已禁用")
    if not user.has_permission(permission):
        raise HTTPException(
            status_code=403,
            detail=f"权限不足: 需要 {permission} 权限 (当前角色: {user.role})",
        )
    return user


def require_permission(permission: str):
    """FastAPI 依赖：检查当前用户是否有指定权限

    用法:
        @app.get("/api/events")
        async def list_events(token: TokenData = Depends(verify_token),
                               _=Depends(require_permission("events:read"))):
            ...
    """
    from fastapi import Depends
    from .auth import verify_token, TokenData

    async def checker(token: TokenData = Depends(verify_token)):
        enforce_permission(token, permission)
        return token
    return checker
