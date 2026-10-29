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
#   sudo GH_PROXY=https://ghproxy.net/ bash install_debian.sh
#   sudo bash install_debian.sh --project-dir /opt/vpn_check --no-timer
#   sudo REPO_URL=https://github.com/<owner>/<repo>.git bash install_debian.sh
#
# 环境变量：
#   REPO_URL        项目仓库地址（默认本仓库，作用于自动克隆）
#   GH_PROXY        GitHub 加速前缀（如 https://ghproxy.net/），作用于 clone 与内核下载
#   SINGBOX_VERSION Sing-box 版本标签（默认取最新，失败回退 v1.13.16）
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/main.py" ]]; then
    DEFAULT_PROJECT_DIR="$SCRIPT_DIR"
else
    DEFAULT_PROJECT_DIR="/opt/vpn_check"
fi
PROJECT_DIR="${PROJECT_DIR:-$DEFAULT_PROJECT_DIR}"
REPO_URL="${REPO_URL:-https://github.com/Wangjinyao1/vpn_check.git}"
GH_PROXY="${GH_PROXY:-}"
ENABLE_TIMER=1
SERVICE_NAME="vpn-check"

if [[ -n "$GH_PROXY" && "$GH_PROXY" != */ ]]; then
    GH_PROXY="$GH_PROXY/"
fi

log()  { printf '\033[32m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[warn]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

gh_url() {
    # 为 GitHub 地址拼接加速前缀；未配置 GH_PROXY 或非 GitHub 地址时原样返回
    if [[ -n "$GH_PROXY" && ( "$1" == https://github.com/* || "$1" == https://api.github.com/* || "$1" == https://raw.githubusercontent.com/* ) ]]; then
        printf '%s%s' "$GH_PROXY" "$1"
    else
        printf '%s' "$1"
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project-dir) PROJECT_DIR="${2:?缺少目录参数}"; shift 2 ;;
        --no-timer) ENABLE_TIMER=0; shift ;;
        --repo) REPO_URL="${2:?缺少仓库地址}"; shift 2 ;;
        -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
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

# ---------- 临时目录 ----------
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# ---------- 获取项目代码 ----------
if [[ -f "$PROJECT_DIR/main.py" ]]; then
    log "检测到已有项目目录: $PROJECT_DIR"
else
    if [[ -d "$PROJECT_DIR" && -n "$(find "$PROJECT_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
        if [[ -d "$PROJECT_DIR/.git" && ! -e "$PROJECT_DIR/main.py" ]]; then
            warn "检测到不完整的克隆目录，清理后重试: $PROJECT_DIR"
            rm -rf "$PROJECT_DIR"
        else
            fail "目录 $PROJECT_DIR 非空且未找到 main.py，请清理后重试，或用 --project-dir 指定其他目录"
        fi
    fi

    if [[ -n "$REPO_URL" ]]; then
        CLONE_URL="$(gh_url "$REPO_URL")"
        log "获取项目代码到 $PROJECT_DIR ..."
        log "  git 来源: $CLONE_URL"
        mkdir -p "$(dirname "$PROJECT_DIR")"
        if git clone --depth 1 "$CLONE_URL" "$PROJECT_DIR"; then
            log "git clone 完成"
        else
            warn "git clone 失败，改用源码压缩包（不依赖 git 协议）..."
            rm -rf "$PROJECT_DIR"
            ARCHIVE_OK=0
            if [[ "$REPO_URL" == https://github.com/* ]]; then
                for BRANCH in main master; do
                    ARCHIVE_URL="$(gh_url "${REPO_URL%.git}/archive/refs/heads/${BRANCH}.tar.gz")"
                    log "  尝试: $ARCHIVE_URL"
                    if curl -fsSL --connect-timeout 15 --retry 2 -o "$TMP_DIR/project.tar.gz" "$ARCHIVE_URL"; then
                        ARCHIVE_OK=1
                        break
                    fi
                done
            fi
            if [[ $ARCHIVE_OK -eq 1 ]]; then
                mkdir -p "$PROJECT_DIR"
                if ! tar -xzf "$TMP_DIR/project.tar.gz" -C "$PROJECT_DIR" --strip-components=1; then
                    fail "源码压缩包解压失败: $TMP_DIR/project.tar.gz"
                fi
                warn "已通过源码压缩包安装（无 .git 目录，后续更新可重新执行本脚本）"
            fi
            [[ -f "$PROJECT_DIR/main.py" ]] || fail "无法获取项目代码：git clone 与压缩包下载均失败，请检查网络或改用 README 的离线部署方式"
        fi
    else
        fail "目录 $PROJECT_DIR 不存在且未提供 REPO_URL；请在仓库目录内执行，或设置 REPO_URL"
    fi
fi
cd "$PROJECT_DIR"

# ---------- Python 环境 ----------
log "创建虚拟环境并安装依赖 ..."
python3 -m venv .venv
if ! .venv/bin/pip install --quiet --upgrade pip; then
    warn "pip 升级失败，继续使用当前版本"
fi
if ! .venv/bin/pip install --quiet -r requirements.txt; then
    fail "Python 依赖安装失败：若无法访问 PyPI，请使用 sudo env PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple bash $0"
fi

# ---------- 下载内核 ----------
mkdir -p bin

if [[ ! -x bin/xray ]]; then
    XRAY_URL="$(gh_url "https://github.com/XTLS/Xray-core/releases/latest/download/$XRAY_ASSET")"
    log "下载 Xray-core ($ARCH) ..."
    log "  来源: $XRAY_URL"
    if curl -fsSL --connect-timeout 15 --retry 2 -o "$TMP_DIR/xray.zip" "$XRAY_URL"; then
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
        SB_TAG="$(curl -fsSL --connect-timeout 10 --max-time 20 \
            "$(gh_url https://api.github.com/repos/SagerNet/sing-box/releases/latest)" \
            | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])' 2>/dev/null || true)"
    fi
    # 避免 GitHub API 限流或不可达导致安装中断，回退到已验证版本
    SB_TAG="${SB_TAG:-v1.13.16}"
    SB_VER="${SB_TAG#v}"
    SB_URL="$(gh_url "https://github.com/SagerNet/sing-box/releases/download/${SB_TAG}/sing-box-${SB_VER}-linux-${SB_ARCH}.tar.gz")"
    log "  来源: $SB_URL"
    if curl -fsSL --connect-timeout 15 --retry 2 -o "$TMP_DIR/sing-box.tar.gz" "$SB_URL"; then
        tar -xzf "$TMP_DIR/sing-box.tar.gz" -C "$TMP_DIR"
        install -m 0755 "$TMP_DIR/sing-box-${SB_VER}-linux-${SB_ARCH}/sing-box" bin/sing-box
    else
        warn "Sing-box 下载失败，可稍后手动放入 bin/sing-box"
    fi
fi

[[ -x bin/xray || -x bin/sing-box ]] || fail "未获得任何代理内核：请检查网络（可设置 GH_PROXY），或手动把 Linux 内核放入 $PROJECT_DIR/bin/"

# ---------- 配置文件 ----------
if [[ ! -f .env ]]; then
    cp .env.example .env
    chmod 600 .env
    warn "已生成 .env，请编辑后填入订阅链接与 Gemini Cookie：nano $PROJECT_DIR/.env"
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
