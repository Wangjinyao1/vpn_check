#!/usr/bin/env bash
# ==============================================================================
# install_debian.sh — Debian 13 一键安装脚本
# ==============================================================================
# 功能：
#   1. 安装 Python / Git / 解压等系统依赖
#   2. 创建虚拟环境并安装 requirements.txt
#   3. 下载 Linux 版 Xray-core 与 Sing-box 内核到 bin/
#   4. 生成 .env（若不存在）并收紧权限
#   5. 安装 systemd 服务与定时器（默认每 2 小时巡检一次）
#
# 用法：
#   sudo bash install_debian.sh
#   sudo bash install_debian.sh --project-dir /opt/vpn_check --no-timer
#   REPO_URL=https://github.com/<owner>/<repo>.git sudo -E bash install_debian.sh
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/main.py" ]]; then
    DEFAULT_PROJECT_DIR="$SCRIPT_DIR"
else
    DEFAULT_PROJECT_DIR="/opt/vpn_check"
fi
PROJECT_DIR="${PROJECT_DIR:-$DEFAULT_PROJECT_DIR}"
REPO_URL="${REPO_URL:-}"
ENABLE_TIMER=1
SERVICE_NAME="vpn-check"

log()  { printf '\033[32m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[warn]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project-dir) PROJECT_DIR="${2:?缺少目录参数}"; shift 2 ;;
        --no-timer) ENABLE_TIMER=0; shift ;;
        --repo) REPO_URL="${2:?缺少仓库地址}"; shift 2 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) fail "未知参数: $1" ;;
    esac
done

[[ $EUID -eq 0 ]] || fail "请使用 root 或 sudo 执行"

log "安装系统依赖 ..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip git curl unzip tar ca-certificates

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)
        XRAY_ASSET="Xray-linux-64.zip"
        SB_ARCH="amd64"
        ;;
    aarch64|arm64)
        XRAY_ASSET="Xray-linux-arm64-v8a.zip"
        SB_ARCH="arm64"
        ;;
    *) fail "暂不支持的架构: $ARCH" ;;
esac

# ---------- 获取项目代码 ----------
if [[ -f "$PROJECT_DIR/main.py" ]]; then
    log "检测到已有项目目录: $PROJECT_DIR"
elif [[ -n "$REPO_URL" ]]; then
    log "克隆仓库到 $PROJECT_DIR ..."
    mkdir -p "$(dirname "$PROJECT_DIR")"
    git clone --depth 1 "$REPO_URL" "$PROJECT_DIR"
else
    fail "目录 $PROJECT_DIR 不存在且未提供 REPO_URL；请在仓库目录内执行，或设置 REPO_URL"
fi
cd "$PROJECT_DIR"

# ---------- Python 环境 ----------
log "创建虚拟环境并安装依赖 ..."
python3 -m venv .venv
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -r requirements.txt

# ---------- 下载内核 ----------
mkdir -p bin
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

if [[ ! -x bin/xray ]]; then
    log "下载 Xray-core ($ARCH) ..."
    if curl -fsSL -o "$TMP_DIR/xray.zip" "https://github.com/XTLS/Xray-core/releases/latest/download/$XRAY_ASSET"; then
        unzip -oq "$TMP_DIR/xray.zip" xray -d bin
        chmod +x bin/xray
    else
        warn "Xray-core 下载失败，可稍后手动放入 bin/xray"
    fi
fi

if [[ ! -x bin/sing-box ]]; then
    log "下载 Sing-box ($ARCH) ..."
    SB_TAG="${SINGBOX_VERSION:-}"
    if [[ -z "$SB_TAG" ]]; then
        SB_TAG="$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest \
            | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])' 2>/dev/null || true)"
    fi
    # 避免 GitHub API 限流导致安装中断，回退到已验证版本
    SB_TAG="${SB_TAG:-v1.13.16}"
    SB_VER="${SB_TAG#v}"
    SB_URL="https://github.com/SagerNet/sing-box/releases/download/${SB_TAG}/sing-box-${SB_VER}-linux-${SB_ARCH}.tar.gz"
    if curl -fsSL -o "$TMP_DIR/sing-box.tar.gz" "$SB_URL"; then
        tar -xzf "$TMP_DIR/sing-box.tar.gz" -C "$TMP_DIR"
        install -m 0755 "$TMP_DIR/sing-box-${SB_VER}-linux-${SB_ARCH}/sing-box" bin/sing-box
    else
        warn "Sing-box 下载失败，可稍后手动放入 bin/sing-box"
    fi
fi

[[ -x bin/xray || -x bin/sing-box ]] || fail "未获得任何代理内核，请检查网络后重试"

# ---------- 配置文件 ----------
if [[ ! -f .env ]]; then
    cp .env.example .env
    chmod 600 .env
    warn "已生成 .env，请编辑后填入订阅链接与数据库配置：nano $PROJECT_DIR/.env"
else
    chmod 600 .env
    log "沿用已有 .env（权限已收紧为 600）"
fi

# ---------- systemd 定时巡检 ----------
if [[ $ENABLE_TIMER -eq 1 ]]; then
    log "安装 systemd 服务与定时器（每 2 小时）..."
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=VPN Check node health and Gemini availability inspection
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=${PROJECT_DIR}
ExecStart=${PROJECT_DIR}/.venv/bin/python ${PROJECT_DIR}/main.py --quiet
Nice=10

[Install]
WantedBy=multi-user.target
EOF

    cat > "/etc/systemd/system/${SERVICE_NAME}.timer" <<EOF
[Unit]
Description=Run VPN Check every 2 hours

[Timer]
OnBootSec=5min
OnUnitActiveSec=2h
Persistent=true
RandomizedDelaySec=5min

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now "${SERVICE_NAME}.timer"
    log "定时器已启用：systemctl status ${SERVICE_NAME}.timer"
    log "立即执行一次：systemctl start ${SERVICE_NAME}.service"
else
    log "已跳过 systemd 定时器安装（--no-timer）"
fi

chmod +x run_check.sh 2>/dev/null || true

log "安装完成。"
log "  1) 编辑配置: nano ${PROJECT_DIR}/.env"
log "  2) 手动巡检: ${PROJECT_DIR}/run_check.sh -q"
log "  3) 查看日志: tail -f ${PROJECT_DIR}/run_log.log"
