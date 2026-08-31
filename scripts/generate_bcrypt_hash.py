#!/usr/bin/env python3
"""
生成 bcrypt 密码哈希 — 用于 SecAgentX 生产环境密码配置

用法:
    python scripts/generate_bcrypt_hash.py
    # 输入密码，输出 hash 字符串

然后复制输出到 .env 文件:
    SECAGENTX_PASSWORD_HASH=$2b$12$...
"""

import getpass
import sys

try:
    import bcrypt
except ImportError:
    print("需要安装 bcrypt: pip install bcrypt")
    sys.exit(1)


def main():
    print("=" * 50)
    print("  SecAgentX bcrypt 密码哈希生成器")
    print("=" * 50)

    password = getpass.getpass("输入密码: ")
    confirm = getpass.getpass("再次输入密码: ")

    if password != confirm:
        print(" 两次密码不一致！")
        sys.exit(1)

    if len(password) < 8:
        print(" 密码长度至少 8 位！")
        sys.exit(1)

    # 生成 bcrypt hash (cost factor = 12，安全性和性能的平衡)
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)

    print("\n" + "=" * 50)
    print("  密码哈希生成成功!")
    print("=" * 50)
    print(f"\n在 .env 文件中配置:\n")
    print(f"  SECAGENTX_USERNAME=admin")
    print(f"  SECAGENTX_PASSWORD_HASH={hashed.decode('utf-8')}")
    print(f"\n  # 移除旧版明文配置:")
    print(f"  # SECAGENTX_PASSWORD=xxx\n")
    print("=" * 50)


if __name__ == "__main__":
    main()

