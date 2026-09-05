"""检查 Git 暂存区是否包含不应发布的大文件或本地训练产物。

该检查只查看已纳入 Git 索引的文件，不会删除工作区中的数据集、模型或临时文件。
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


MAX_FILE_BYTES = 95 * 1024 * 1024


def staged_paths() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "-z"],
        check=True,
        stdout=subprocess.PIPE,
    )
    return [Path(item) for item in result.stdout.decode("utf-8").split("\0") if item]


def blocked_reason(path: Path) -> str | None:
    normalized = path.as_posix().lower()
    if normalized.startswith("dataset/") and path.suffix.lower() in {".csv", ".txt", ".zip"}:
        return "训练数据集应由使用者按 dataset/README.md 下载"
    if normalized.startswith("model/") and path.suffix.lower() in {".joblib", ".pkl", ".pickle"}:
        return "离线模型制品不应直接进入源码仓库"
    if normalized.startswith((".test-temp", ".pytest-", "test-runtime")):
        return "本地测试临时目录"
    if path.name.lower() in {".env", ".env.local", ".env.production"}:
        return "环境变量文件可能包含密钥"
    return None


def main() -> int:
    errors: list[str] = []
    for path in staged_paths():
        absolute = Path.cwd() / path
        if absolute.exists() and absolute.stat().st_size > MAX_FILE_BYTES:
            errors.append(f"{path}: 文件大于 95 MB")
        reason = blocked_reason(path)
        if reason:
            errors.append(f"{path}: {reason}")

    if errors:
        print("发布预检失败：以下文件不应进入 GitHub：", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print("发布预检通过：暂存区没有发现超大文件、训练数据或本地模型制品。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
