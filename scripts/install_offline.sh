#!/usr/bin/env bash
set -euo pipefail

WHEELHOUSE="${1:-./wheelhouse}"

command -v pipx >/dev/null 2>&1 || {
  echo "未找到 pipx。请先安装 pipx，或使用 Python 虚拟环境离线安装。" >&2
  exit 1
}

shopt -s nullglob
wheels=("$WHEELHOUSE"/secagentx-*.whl)
if [[ ${#wheels[@]} -ne 1 ]]; then
  echo "${WHEELHOUSE} 中没有找到 secagentx wheel。请先在联网机器执行：python -m pip download -d wheelhouse secagentx" >&2
  exit 1
fi
wheel="${wheels[0]}"

echo "使用离线包安装 $(basename "$wheel") ..."
pipx install --pip-args "--no-index --find-links='$(cd "$WHEELHOUSE" && pwd)'" "$wheel"
echo "安装完成。运行：secagentx chat"
