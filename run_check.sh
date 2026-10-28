#!/usr/bin/env bash
# ==============================================================================
# run_check.sh — Debian 13 手动执行 / Crontab 定时调度包装脚本
# ==============================================================================

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

if [[ ! -f "$PROJECT_DIR/.env" ]]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 提示: 未找到 .env，请先执行 cp .env.example .env 并填写配置。" >&2
fi

chmod +x bin/sing-box bin/xray 2>/dev/null || true

if [[ -x "$PROJECT_DIR/.venv/bin/python" ]]; then
    PYTHON_EXEC="$PROJECT_DIR/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_EXEC="$(command -v python3)"
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 错误: 未找到 Python3，请先执行 install_debian.sh 或创建 .venv。" >&2
    exit 1
fi

echo "[$(date '+%Y-%m-%d %H:%M:%S')] 🚀 开始执行节点连通性与 AI 深度检测任务..."
"$PYTHON_EXEC" main.py "$@"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✅ 任务成功执行完毕。"
