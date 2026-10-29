# VPN Check & Passwall Optimizer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Debian%2013%20%7C%20Windows-lightgrey.svg)](./install_debian.sh)
[![Version](https://img.shields.io/badge/Version-9.02-brightgreen.svg)](#changelog)
[![GitHub stars](https://img.shields.io/github/stars/Wangjinyao1/vpn_check?style=social)](https://github.com/Wangjinyao1/vpn_check)

> 面向中国大陆网络环境的机场节点质量评估工具：用真实代理内核逐节点建隧道，按 OpenWrt-Passwall 规则分级，验证 Google / Gemini / Grok 可达性与 Gemini 真实提问能力，并导出可直接落地的 Passwall 配置。

**关键词**：`机场测速` `节点可用性` `Passwall` `Xray` `Sing-box` `Reality` `Hysteria2` `AnyTLS` `Gemini 地区封锁`

---

## 📑 目录

- [项目目的](#goals)
- [核心特性](#features)
- [检测原理](#principles)
- [项目架构与目录结构](#architecture)
- [快速开始](#quickstart)
- [命令行参数](#cli)
- [Debian 13 部署与定时任务](#deploy)
- [配置参考（.env）](#config)
- [Passwall 导出产物](#export)
- [单元测试与验证](#testing)
- [上传 GitHub 前的保密性审查](#security)
- [版本迭代](#changelog)
- [常见问题](#faq)
- [贡献指南](#contributing)
- [免责声明](#disclaimer)
- [开源参考与致谢](#thanks)
- [License](#license)

---

<a id="goals"></a>

## 🎯 项目目的

从多个机场订阅中筛出**自己真正可用**的节点：

1. 节点能否稳定出海（不是只“握手成功”）
2. Google / Gemini / Grok 三个关键站点是否可访问
3. Gemini 是否被地区封锁（“**Gemini 目前不支持你所在的地区。敬请期待！**”）
4. 配置登录凭据时，Gemini 能否**真实提问并收到回答**
5. 最终生成可粘贴到 OpenWrt Passwall 的节点列表、Base64 订阅与 UCI 一键导入脚本

**适用场景**

- 自用机场订阅节点太多，想知道哪些真的能上网、哪些能稳定访问 AI 服务
- 使用 OpenWrt + Passwall，需要可直接导入的节点 / 订阅 / UCI 脚本
- 需要区分 Gemini 的「网页可访问」「地区封锁」「真实提问可用」三种状态
- 希望结果只保存在本地（无数据库、无外部依赖）

**不适用**：商业转售、批量压测、共享账号滥用，或任何违反服务条款的用途。

---

<a id="features"></a>

## ✨ 核心特性

- **真实内核隧道**：Xray-core / Sing-box 在本地随机高位端口建立 SOCKS5 隧道，逐节点实测。
- **Passwall 三级连通分级**：🟢 代理通 / 🟡 仅直连 / 🔴 无网络，判定顺序与 Passwall 探针一致。
- **三网页可用性**：Google（`www.google.com/?hl=zh_CN`）、Gemini（`gemini.google.com/app`）、Grok（`grok.com`）。
  - Google / Grok 使用浏览器指纹访问，HTTP 层有响应即判定“链路可达”（403/429 为站点风控页，不代表代理不可用）。
  - Gemini 由深度检测独立判定“可用 / 地区封锁 / 不可达”。
- **Gemini 双引擎判据**：
  - 免登录：解析 Google 前端特性开关 `45631641` 与 GeoIP 三位地区码（对齐 `xykt/RegionRestrictionCheck`）。
  - 登录提问：配置 `GEMINI_1PSID` 后调用 `StreamGenerate` 发起真实问答，验证模型是否可用（对齐 `MatinSenPai/Gemini-Config-Checker`）。
- **出海落地识别**：Cloudflare trace 获取落地 IP，归属地走进程内缓存，未命中时 ipinfo 回源。
- **全协议解析**：VLESS（Reality/Vision）、VMess、Trojan、Shadowsocks（SIP002/2022/插件）、Hysteria2（端口跳跃/混淆）、AnyTLS。
- **订阅配额识别**：解析 `Subscription-Userinfo`，展示节余流量与到期时间。
- **Passwall 原生导出**：节点链接、Base64 订阅、Gemini 可访问清单、Gemini 提问成功清单、UCI 导入脚本。
- **零数据库**：不依赖 MySQL / Redis / SQLite，结果只落本地报告与 Passwall 导出，部署即用。
- **纯 CLI / One-Shot**：适配 Cron / systemd timer，日志单文件 3MB 封顶。
- **配置集中**：阈值、探针、超时全部集中在 `core/config.py`，敏感项仅从 `.env` 读取。
- **失败可归类**：`TIMEOUT` / `TLS_ERROR` / `PROXY_CONNECT_FAIL` 等失败码，便于批量排查与统计。
- **纯函数可测**：解析、判定与内核配置生成均有单元测试覆盖。

---

<a id="principles"></a>

## 🔬 检测原理

```text
订阅源 ──► 拉取/Base64 解码 ──► 协议解析 ──► 连接指纹跨订阅去重
                                                      │
                                                      ▼
                                    按协议选择内核（Xray / Sing-box）
                                                      │
                                    本地 SOCKS5 隧道（随机端口）
                                                      │
                     ┌────────────────────────────────┴──────────────────────────┐
                     ▼                                                           ▼
        国际主探针 Google generate_204                            失败后回退国内探针
                     │                                                           │
              成功 ──► 🟢 代理通                                    成功 ──► 🟡 仅直连
                     │                                              失败 ──► 🔴 无网络
                     ▼
        三网页探测 + 落地 IP/归属地 + Gemini 地区判定 + 可选提问验证
                     │
                     ▼
        终端看板 + 报告归档 + Passwall 导出
```

### 连通分级（对齐 Passwall）

| 级别 | 含义 | 判定条件 |
| --- | --- | --- |
| 🟢 Level 0 | 代理通 | 国际探针（Google / Gstatic / Cloudflare / YouTube）任一返回 200/204 |
| 🟡 Level 1 | 仅直连 | 国际探针全失败，但国内探针任一可达 |
| 🔴 Level 2 | 无网络 | 国内外探针全部失败，或内核启动失败 |

### 探针清单（对齐 Passwall）

| 类型 | 探针 | 目标地址 |
| --- | --- | --- |
| 国际 | Google204 | `https://www.google.com/generate_204` |
| 国际 | Gstatic204 | `https://www.gstatic.com/generate_204` |
| 国际 | Cloudflare | `https://cp.cloudflare.com/` |
| 国际 | YouTube204 | `https://www.youtube.com/generate_204` |
| 国内 | MIUI_CN | `https://connect.rom.miui.com/generate_204` |
| 国内 | HiCloud_CN | `https://connectivitycheck.platform.hicloud.com/generate_204` |
| 国内 | VIVO_CN | `https://wifi.vivo.com.cn/generate_204` |
| 国内 | Baidu | `https://www.baidu.com` |

默认 `HEAD` 请求、`PROBE_TIMEOUT=6s`，仅 `200/204` 视为通过；可用 `PROBE_METHOD=GET` 切换方法。

### Gemini 判定顺序

1. `generativelanguage.googleapis.com/v1beta/models` 连通性探针（200/400/403 均视为到达 Google 网关）
2. AI Studio 重定向 / `available-regions` 封锁页判定
3. Gemini Web App：地区码属于 `CHN/RUS/IRN/PRK/...` → 直接封锁；命中中英文封锁文案 → 封锁；特性开关为 `false` → 封锁
4. 以上通过且配置了 Cookie → 提交提问并解析流式回复，输出 `回答成功 / 提问受阻 / 未测`

### Gemini 三态结果

| 状态 | 判定依据 | 结果字段 |
| --- | --- | --- |
| 网页可访问 | Web App 返回正常页面，且未命中封锁特征 | `gemini_status=ok`、`gemini_ok=true` |
| 地区封锁 | GeoIP 地区码命中黑名单、页面命中中英文封锁文案，或特性开关为 `false` | `region_blocked=true`，导出 Gemini 清单时排除 |
| 真实提问可用 | 配置 Cookie 后 `StreamGenerate` 返回 200 且解析出回复 | `chat_ok=true`（`false` 为提问受阻，`null` 为未测） |

### 失败码（`fail_code`）

| 失败码 | 含义 |
| --- | --- |
| `DOMESTIC_ONLY` | 🟡 仅直连：国内探针可达、国际探针全失败 |
| `TIMEOUT` | 探针超时 |
| `CONN_REFUSED` | 目标拒绝连接 |
| `CONN_RESET` | 连接被重置 / 管道中断 |
| `TLS_ERROR` | TLS 握手或证书异常 |
| `DNS_ERROR` | 域名解析失败 |
| `PROXY_CONNECT_FAIL` | SOCKS5 隧道不通（内核未真正代理流量） |
| `KERNEL_START` | 内核启动失败（含降级后仍失败） |
| `NO_KERNEL` | 未找到可用内核二进制 |
| `PIPELINE_ERROR` | 探测流程内部异常 |
| `UNREACHABLE` | 其他不可达 |

---

<a id="architecture"></a>

## 🏗️ 项目架构与目录结构

```text
vpn_check/
├── main.py                    # CLI 入口：编排拉取 → 探测 → 报告 → 导出
├── net_check.py               # 兼容旧入口，转发 main.main()
├── install_debian.sh          # Debian 13 一键安装（依赖/内核/venv/systemd timer）
├── run_check.sh               # Linux 手动/定时执行包装脚本
├── requirements.txt           # PySocks / curl_cffi
├── core/
│   ├── config.py              # 统一配置中心（.env 解析、探针规则、路径、超时）
│   ├── models.py              # 领域模型（ProxyNode / SiteProbe / GeminiVerdict / NodeResult）
│   ├── parsers.py             # 分享链接解析与连接指纹去重
│   ├── subscription.py        # 订阅拉取、配额解析、跨订阅汇总
│   ├── engine.py              # Xray / Sing-box 配置生成与隧道生命周期
│   ├── netprobe.py            # SOCKS5 HTTP 探针、落地 IP 探测
│   ├── checker.py             # 探测管道、三级分级、并发调度
│   ├── gemini.py              # Gemini 地区封锁与提问验证
│   ├── ip_location.py         # IP 归属地（进程缓存 + ipinfo 回源）
│   ├── exporter.py            # Passwall 链接 / Base64 / UCI 导出
│   ├── report.py              # 终端决策看板
│   └── logging_setup.py       # run_log.log（单文件 3MB）
├── tests/test_core.py         # 解析 / 配置 / 导出 / Gemini 判据单元测试
├── bin/                       # 内核二进制（不提交，安装脚本自动下载）
├── export/                    # Passwall 导出产物（含节点凭据，禁止提交）
├── .github/
│   └── copilot-instructions.md # 项目记忆：开发规范、结构约定与验证要求
├── .temp/                     # temp_* 运行时配置与内核日志（禁止提交）
├── .env                       # 敏感配置（禁止提交）
├── .env.example               # 脱敏配置模板
└── run_log.log                # 运行日志（禁止提交）
```

### 运行阶段与模块

| 阶段 | 模块 | 职责 |
| --- | --- | --- |
| 1. 拉取 | `core/subscription.py` | 并发拉取订阅、解析配额、跨订阅汇总 |
| 2. 解析 | `core/parsers.py` + `core/models.py` | 分享链接 → `ProxyNode`，按连接指纹去重 |
| 3. 建隧道 | `core/engine.py` | 生成 Xray / Sing-box 配置，启停 SOCKS5 隧道 |
| 4. 探测 | `core/netprobe.py` + `core/checker.py` | 国际 / 国内探针、网页探测、并发调度 |
| 5. 判定 | `core/gemini.py` + `core/ip_location.py` | Gemini 三态判定、落地 IP 与归属地 |
| 6. 输出 | `core/report.py` / `core/exporter.py` | 终端看板、报告归档、Passwall 导出 |

<a id="kernel"></a>

### 内核选择策略

| 协议 / 场景 | 首选内核 | 说明 |
| --- | --- | --- |
| VLESS / VMess / Trojan | Xray | 支持 Reality、Vision、WS、gRPC、XHTTP、HTTPUpgrade、mKCP |
| Shadowsocks | Xray | 标准加密；带 SIP003 插件时切 Sing-box |
| Hysteria2 | Sing-box | QUIC、端口跳跃、salamander 混淆 |
| AnyTLS | Sing-box | ≥1.13.16 自动启用 `client_metadata` |

内核启动失败时按配置自动切换备用内核（`ENABLE_CORE_FALLBACK=1`），并在结果中标记降级。

---

<a id="quickstart"></a>

## 🚀 快速开始

### 1. 环境要求

| 项目 | 要求 | 说明 |
| --- | --- | --- |
| Python | 3.10+ | 使用 `dataclasses` 与 `from __future__ import annotations` |
| 操作系统 | Debian 13 / Ubuntu 22.04+ / Windows 10+ | Linux 推荐部署在 VPS 或软路由旁路主机 |
| 代理内核 | `bin/xray` + `bin/sing-box` | Windows 为 `xray.exe` / `sing-box.exe` |
| Python 依赖 | `PySocks` / `curl_cffi` | `pip install -r requirements.txt` |
| 网络 | 可访问 GitHub 与订阅地址 | 订阅直连失败时可配置本地代理 |

### 2. 获取代码与安装依赖

```bash
git clone https://github.com/Wangjinyao1/vpn_check.git
cd vpn_check

# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

```powershell
# Windows PowerShell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

> Debian 13 可直接使用一键安装脚本，自动完成依赖、内核、`.env` 与 systemd 定时器，见 [Debian 13 部署](#deploy)。
>
> 服务器无法直连 GitHub 时，请使用该章节的「方式 D：离线部署」。

### 3. 准备内核二进制

程序不在运行期下载内核，请提前放入 `bin/`（避免巡检时依赖外网可用性）：

```bash
mkdir -p bin

# Xray-core：按架构选择 Xray-linux-64.zip / Xray-linux-arm64-v8a.zip
curl -fsSL -o /tmp/xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
unzip -oq /tmp/xray.zip xray -d bin && chmod +x bin/xray

# Sing-box：Linux amd64 示例（v1.13.16，可按 Releases 最新标签替换）
curl -fsSL -o /tmp/sing-box.tar.gz https://github.com/SagerNet/sing-box/releases/download/v1.13.16/sing-box-1.13.16-linux-amd64.tar.gz
tar -xzf /tmp/sing-box.tar.gz -C /tmp
install -m 0755 /tmp/sing-box-1.13.16-linux-amd64/sing-box bin/sing-box
```

Windows 用户从官方 Releases 下载 `Xray-windows-64.zip` 与 `sing-box-windows-amd64.zip`，解压后将 `xray.exe`、`sing-box.exe` 放入 `bin\`。

验证内核可用：

```bash
bin/xray version
bin/sing-box version
```

同一台机器同时存在两个内核时，程序会按协议自动选择，详见 [内核选择策略](#kernel)。

### 4. 配置 `.env`

```powershell
# Windows
Copy-Item .env.example .env
notepad .env
```

```bash
# Linux / macOS
cp .env.example .env
nano .env
```

最小配置只需订阅源（支持 1~10 组，至少 1 组）：

```ini
SUBSCRIBE_name_1=机场名称
SUBSCRIBE_URL_1=https://example.com/api/v1/client/subscribe?token=your_token
```

常用可选项：

| 变量 | 作用 |
| --- | --- |
| `GEMINI_1PSID` / `GEMINI_1PSIDTS` | 启用 Gemini 真实提问验证 |
| `SUBSCRIPTION_PROXY` | 订阅直连失败时依次尝试的本地代理 |
| `GEMINI_CHAT_QUESTION` / `GEMINI_CHAT_EXPECT` | 自定义提问内容与期望答案 |

完整变量说明见 [配置参考](#config)。

### 5. 运行

```powershell
# 完整巡检：拉取 → 隧道 → 探测 → Gemini → 报告 → 导出
python main.py

# 调试：仅测 3 个节点，跳过 Gemini 提问
python main.py --limit 3 --skip-gemini-chat

# 只测 VLESS，20 并发，控制台只看可用节点
python main.py --protocol vless --workers 20 --ok-only

# 静默模式（Cron / systemd 友好）
python main.py --quiet
```

运行结束后会得到：

| 产物 | 默认路径 | 说明 |
| --- | --- | --- |
| 终端看板 | stdout | 总览、可用节点榜、订阅质量、失败原因 |
| 报告归档 | `test_results.txt` | 与终端看板内容一致，可用 `--report-file` 改写 |
| Passwall 导出 | `export/` | 节点链接、Gemini 可访问 / 提问成功清单、Base64 订阅、UCI 脚本 |
| 运行日志 | `run_log.log` | 单文件 3MB 封顶，不产生备份文件 |

终端输出示例（实际结果随订阅与网络环境变化）：

```text
==================================================================
  🌐 VPN Node Evaluator & Passwall Optimizer v9.02
  严格遵循 OpenWrt-Passwall、Gemini-Config-Checker 与项目开发规范
==================================================================
📡 [1/3] 拉取订阅（共 2 个订阅源）...
  ✅ 机场A                获取  86 节点（  3.2s，节余流量: 128.4 GB）
🚀 [2/3] 启动内核隧道探测（42 节点，10 并发）...
 [ 12/ 42] 🟢 代理通 | 香港-Reality | 23ms | 203.0.113.8 (JP Tokyo Tokyo) | Gemini:JPN
📋 [3/3] 汇总测试报告 ...
✨ 总计 42 | 🟢 代理通 31 | 🤖 Gemini 可用 18 | 💬 提问成功 9
```

---

<a id="cli"></a>

## 🧭 命令行参数

```bash
python main.py [options]
```

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--limit N` | `0`（不限） | 仅测试前 N 个节点，调试用 |
| `--filter KW` | 空 | 按节点名称关键字过滤（区分大小写） |
| `--protocol LIST` | 空 | 仅测试指定协议，逗号分隔，如 `vless,anytls` |
| `--workers N` | `10` | 并发线程数；实际取值受 `MAX_WORKERS`（默认 32）与节点总数约束 |
| `--skip-gemini` | 关闭 | 跳过 Gemini 深度检测（仍探测网页可达性） |
| `--skip-gemini-chat` | 关闭 | Gemini 仅测地区封锁，不发起提问 |
| `--no-export` | 关闭 | 不导出 Passwall 配置 |
| `--ok-only` | 关闭 | 控制台仅展示总览与可用节点榜 |
| `--quiet`, `-q` | 关闭 | 静默模式，仅输出最终摘要 |
| `--report-file PATH` | `test_results.txt` | 报告归档路径 |
| `--export-dir PATH` | `export/` | Passwall 导出目录 |
| `--version` | — | 显示版本号 |
| `-h`, `--help` | — | 显示帮助 |

> `main.py` 与兼容入口 `net_check.py` 等价，后者仅为保留旧调用方式。

---

<a id="deploy"></a>

## 🖥️ Debian 13 部署与定时任务

### 一键安装（两条命令）

```bash
# 能直连 GitHub
curl -fsSL https://raw.githubusercontent.com/Wangjinyao1/vpn_check/main/install_debian.sh -o /tmp/install_debian.sh
sudo bash /tmp/install_debian.sh

# 无法直连 GitHub：用加速镜像下载脚本，并让脚本也走镜像
curl -fsSL https://ghproxy.net/https://raw.githubusercontent.com/Wangjinyao1/vpn_check/main/install_debian.sh -o /tmp/install_debian.sh
sudo GH_PROXY=https://ghproxy.net/ bash /tmp/install_debian.sh
```

> 脚本在未提供 `REPO_URL` 时会**默认获取本仓库**到 `/opt/vpn_check`，因此只需下载脚本即可安装；
> `GH_PROXY` 会同时作用于仓库获取与 Xray / Sing-box 内核下载。
>
> 若镜像不支持 git 协议（例如 `GnuTLS, handshake failed`），脚本会**自动回退到源码压缩包**（`archive/refs/heads/main.tar.gz`，仅用 curl + tar），无需 git。
>
> 内核下载会强制 HTTP/1.1，并按 `GH_PROXY → gh-proxy.com → ghfast.top → ghproxy.net → 直连` 的顺序自动重试，规避镜像 502 / HTTP/2 断流。

根目录的 [`install_debian.sh`](./install_debian.sh) 会自动完成：

1. 安装 `python3` / `python3-venv` / `git` / `curl` / `unzip` 等系统依赖
2. 创建 `.venv` 并安装 `requirements.txt`
3. 下载 Xray-core 与 Sing-box 到 `bin/`
4. 初始化 `.env`（若不存在）并将权限收紧为 `600`
5. 安装 `vpn-check.service` 与 `vpn-check.timer`（默认每 2 小时巡检）

### 方式 A：已克隆仓库（推荐）

```bash
git clone https://github.com/Wangjinyao1/vpn_check.git /opt/vpn_check
cd /opt/vpn_check
sudo bash install_debian.sh
```

> 脚本会自动识别所在目录；若项目不在脚本同级目录，可用 `--project-dir` 指定。
> 若 `git clone` 卡住或超时，说明主机无法直连 GitHub，请改用 [方式 D](#deploy)。

### 方式 B：已下载脚本 + 自动克隆项目

脚本必须先存在于本机（`REPO_URL` 只负责克隆项目，**不能替代脚本文件本身**）：

```bash
# 先把 install_debian.sh 下载或上传到 /tmp 后执行
sudo bash /tmp/install_debian.sh --project-dir /opt/vpn_check

# GitHub 不可达时
sudo GH_PROXY=https://ghproxy.net/ bash /tmp/install_debian.sh --project-dir /opt/vpn_check

# 自定义仓库地址
sudo REPO_URL=https://github.com/<owner>/<repo>.git bash /tmp/install_debian.sh
```

> 在空目录直接执行 `bash install_debian.sh` 会报
> `bash: install_debian.sh: No such file or directory`。

### 方式 C：远程脚本直装（需可访问 GitHub Raw）

```bash
curl -fsSL https://raw.githubusercontent.com/Wangjinyao1/vpn_check/main/install_debian.sh -o /tmp/install_debian.sh
sudo bash /tmp/install_debian.sh
```

> `raw.githubusercontent.com` 在中国大陆常被 DNS 污染或阻断，表现为
> `curl: (28) Connection timed out`。可改用镜像下载并让脚本走镜像（执行前请先核对脚本内容）：
>
> ```bash
> curl -fsSL https://ghproxy.net/https://raw.githubusercontent.com/Wangjinyao1/vpn_check/main/install_debian.sh -o /tmp/install_debian.sh
> head -22 /tmp/install_debian.sh
> sudo GH_PROXY=https://ghproxy.net/ bash /tmp/install_debian.sh
> ```

### 方式 D：离线部署（GitHub 不可达时最可靠）

在**能访问 GitHub 的电脑**上打包仓库（`git archive` 只收录已跟踪文件，自动排除 `.env`、`export/`、`bin/`）：

```bash
git clone https://github.com/Wangjinyao1/vpn_check.git
cd vpn_check
git archive --format=tar.gz -o ../vpn_check.tar.gz HEAD
```

把压缩包与 **Linux 内核**一起上传到服务器：

```powershell
scp .\vpn_check.tar.gz root@<服务器IP>:/root/
scp .\bin\xray .\bin\sing-box root@<服务器IP>:/root/
```

在服务器上解压、放入内核并安装：

```bash
mkdir -p /opt/vpn_check
tar -xzf /root/vpn_check.tar.gz -C /opt/vpn_check
mkdir -p /opt/vpn_check/bin
install -m 0755 /root/xray /root/sing-box /opt/vpn_check/bin/
cd /opt/vpn_check
sudo bash install_debian.sh          # 检测到 bin/ 内核后会自动跳过下载
```

若 PyPI 也不可达，可指定国内镜像后再安装依赖：

```bash
sudo env PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple bash install_debian.sh
```

> 内核也可从任意能联网的机器下载后上传：`Xray-linux-64.zip`、
> `sing-box-1.13.16-linux-amd64.tar.gz`，架构必须与服务器一致（常见为 x86_64）。

### 部署常见报错

| 报错 | 原因 | 处理 |
| --- | --- | --- |
| `bash: install_debian.sh: No such file or directory` | 当前目录没有脚本（未 clone / 未下载） | 先按方式 A / B / C / D 把脚本放到本机 |
| `curl: (28) Connection timed out ... raw.githubusercontent.com` | 无法直连 GitHub Raw（大陆网络常见） | 用方式 D，或镜像 / 代理 |
| `fatal: unable to access 'https://github.com/...'` | github.com 不可达 | 设置 `GH_PROXY=https://ghproxy.net/` 重试，或用方式 D |
| `GnuTLS, handshake failed: The TLS connection was non-properly terminated` | 镜像不转发 git 协议 | 脚本会自动改用源码压缩包；也可手动下载 `archive/refs/heads/main.tar.gz` 解压 |
| `curl: (92) HTTP/2 stream ... INTERNAL_ERROR` 或 `curl: (22) ... 502` | 镜像对大文件支持不稳定 | 脚本已强制 HTTP/1.1 并自动切换备用镜像；仍失败可手动上传 `bin/` 内核 |
| `Could not find a version that satisfies the requirement ...` | PyPI 不可达 | 设置 `PIP_INDEX_URL` 为国内镜像 |
| `未获得任何代理内核` | 内核下载失败且 `bin/` 为空 | 本地下载 Linux 内核并上传到 `bin/` |

> 若服务器已有本地代理（如 `127.0.0.1:7890`），可让脚本继承代理变量：
> `sudo env https_proxy=http://127.0.0.1:7890 http_proxy=http://127.0.0.1:7890 bash install_debian.sh`

诊断网络连通性：

```bash
getent hosts github.com raw.githubusercontent.com api.github.com
curl -I -m 10 https://github.com
curl -I -m 10 https://raw.githubusercontent.com
env | grep -i proxy
```

安装完成后：

```bash
sudo nano /opt/vpn_check/.env          # 填入订阅与 Gemini Cookie
sudo systemctl start vpn-check.service # 立即执行一次
systemctl status vpn-check.timer       # 查看每 2 小时定时器
journalctl -u vpn-check.service -f     # 查看 systemd 执行日志
tail -f /opt/vpn_check/run_log.log     # 查看运行日志
```

> 自定义目录 / 关闭定时器：`sudo bash install_debian.sh --project-dir /srv/vpn_check --no-timer`
>
> 内核默认从官方 GitHub Releases 下载；如需固定版本可设置 `SINGBOX_VERSION=v1.13.16`。

常用参数：

| 参数 | 说明 |
| --- | --- |
| `--project-dir PATH` | 指定项目目录（默认脚本所在目录或 `/opt/vpn_check`） |
| `--repo URL` / `REPO_URL=...` | 目录不存在时克隆仓库 |
| `--no-timer` | 只安装依赖与内核，不创建 systemd 定时器 |

### Cron 备选方案

```cron
0 */2 * * * /opt/vpn_check/run_check.sh -q >> /opt/vpn_check/cron_exec.log 2>&1
```

### Windows 计划任务

```powershell
# 每天 08:00 执行一次（路径按实际位置修改）
schtasks /Create /TN "vpn_check" /SC DAILY /ST 08:00 /F `
  /TR "powershell -NoProfile -ExecutionPolicy Bypass -Command \"cd 'C:\path\to\vpn_check'; .\.venv\Scripts\python.exe main.py --quiet\""
```

> 程序为 One-Shot CLI，无守护进程，适合 Cron / systemd timer / Windows 计划任务等任意调度方式。

---

<a id="config"></a>

## ⚙️ 配置参考（.env）

所有可调参数集中在 [`core/config.py`](./core/config.py)，敏感项通过 `.env` 注入。读取优先级：**系统环境变量 > `.env` > 代码默认值**。

### 订阅与拉取

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `SUBSCRIBE_name_N` | `订阅源_N` | 第 N 个订阅的显示名称（N 取 1~10） |
| `SUBSCRIBE_URL_N` | 空 | 第 N 个订阅地址；至少配置 1 组，否则启动时报配置致命错误 |
| `SUBSCRIPTION_PROXY` | `http://127.0.0.1:7890,socks5h://127.0.0.1:10808,socks5h://127.0.0.1:20000` | 订阅直连失败时依次尝试的本地代理，逗号分隔；显式留空则只走直连 |
| `SUBSCRIBE_TIMEOUT` | `15` | 单个订阅拉取超时（秒） |
| `SUBSCRIBE_RETRY` | `1` | 单订阅重试次数 |
| `SUBSCRIBE_WORKERS` | `5` | 订阅并发拉取数 |

### 探针与超时

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PROBE_TIMEOUT` | `6` | 国际 / 国内连通性探针超时（秒） |
| `PROBE_METHOD` | `HEAD` | 探针 HTTP 方法，可选 `HEAD` / `GET` |
| `SITE_TIMEOUT` | `12` | Google / Gemini / Grok 网页探测超时（秒） |
| `EGRESS_TIMEOUT` | `6` | 落地 IP 探测超时（秒） |

### Gemini 深度检测

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `GEMINI_1PSID` | 空 | Gemini Cookie `__Secure-1PSID`，留空则跳过提问测试 |
| `GEMINI_1PSIDTS` | 空 | 配套 Cookie `__Secure-1PSIDTS` |
| `GEMINI_CHAT_QUESTION` | `请回答：1+1等于几？只回答一个阿拉伯数字。` | 提问内容 |
| `GEMINI_CHAT_EXPECT` | `2` | 期望答案关键字，命中即视为提问成功 |
| `GEMINI_CHAT_TIMEOUT` | `25` | 提问接口超时（秒） |

> Cookie 获取方式：浏览器登录 `gemini.google.com` → DevTools → Application → Cookies → 复制 `__Secure-1PSID` 与 `__Secure-1PSIDTS`。

### 内核与并发

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `XRAY_BIN` | 自动查找 `bin/xray[.exe]` | Xray-core 路径 |
| `SINGBOX_BIN` | 自动查找 `bin/sing-box[.exe]` | Sing-box 路径 |
| `KERNEL_START_TIMEOUT` | `8` | 内核启动等待（秒） |
| `KERNEL_STOP_TIMEOUT` | `3` | 内核退出等待（秒） |
| `ENABLE_CORE_FALLBACK` | `1` | 首选内核失败时自动切换备用内核 |
| `DEFAULT_WORKERS` | `10` | 默认并发线程数 |
| `MAX_WORKERS` | `32` | 并发上限（`--workers` 超出时自动收敛） |
| `VPN_CHECK_TEMP_DIR` | `.temp` | 运行期临时目录（仅读取系统环境变量；文件以 `temp_` 开头） |

### IP 归属地（可选）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `IP_LOCATION_TIMEOUT` | `6` | 归属地查询超时（秒） |
| `IPINFO_TOKEN` | 空 | ipinfo.io Token（可选，提高配额） |
| `IPINFO_URL` | `https://ipinfo.io/{ip}/json` | 查询地址模板 |

### 安装脚本专用

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `SINGBOX_VERSION` | 最新版本，失败回退 `v1.13.16` | `install_debian.sh` 下载的 Sing-box 版本 |
| `REPO_URL` | `https://github.com/Wangjinyao1/vpn_check.git` | 一键安装时用于克隆仓库的地址 |
| `GH_PROXY` | 空 | 首选 GitHub 加速前缀；失败时自动尝试 `gh-proxy.com` / `ghfast.top` / `ghproxy.net` |

> `.env` 已被 `.gitignore` 忽略，仓库只保留脱敏模板 [`.env.example`](./.env.example)。

---

<a id="export"></a>

## 📦 Passwall 导出产物

每次运行后写入 `export/`：

| 文件 | 用途 |
| --- | --- |
| `passwall_nodes_ok.txt` | 代理通节点分享链接（Passwall → 节点列表 → 导入粘贴） |
| `passwall_nodes_gemini_ok.txt` | 代理通且 Gemini 可访问的节点链接 |
| `passwall_nodes_gemini_chat_ok.txt` | 代理通、Gemini 可访问且**真实提问成功**的节点链接 |
| `passwall_nodes_ok_b64.txt` | 代理通节点 Base64 聚合（可作自定义订阅源） |
| `passwall_nodes_all.txt` | 本次全部抓取节点链接 |
| `passwall_uci_ok.txt` | UCI 批量导入脚本，上传路由器后 `sh passwall_uci_ok.txt` |

UCI 字段已逐项对照上游 [`subscribe.lua`](https://github.com/Openwrt-Passwall/openwrt-passwall/blob/main/luci-app-passwall/root/usr/share/passwall/subscribe.lua)：`type`、`protocol`、`transport`、`password`、`ws_host/ws_path`、`grpc_serviceName`、`httpupgrade_*`、`xhttp_*`、`tls_serverName`、`utls/fingerprint`、`reality_*`、`hysteria2_*` 等。

### 导入 Passwall

1. **节点列表导入**：Passwall → 节点列表 → 导入，粘贴 `passwall_nodes_ok.txt` 内容（每行一条分享链接）。
2. **自定义订阅**：把 `passwall_nodes_ok_b64.txt` 放到任意静态文件服务，将 URL 填入 Passwall → 订阅。
3. **UCI 批量导入**：脚本仅新增节点、不删除已有配置，末尾自动 `uci commit passwall` 并重启服务。

```bash
scp export/passwall_uci_ok.txt root@192.168.1.1:/tmp/
ssh root@192.168.1.1 "sh /tmp/passwall_uci_ok.txt"
```

> `export/` 内含节点凭据，已加入 `.gitignore`，**禁止提交**。

---

<a id="testing"></a>

## 🧪 单元测试与验证

### 运行单元测试

```bash
python -m unittest discover -s tests -v
```

[`tests/test_core.py`](./tests/test_core.py) 的覆盖范围：

| 覆盖点 | 说明 |
| --- | --- |
| 链接解析 | VLESS Reality / VLESS WS / VMess JSON / Hysteria2 / AnyTLS / Shadowsocks（含 SIP003 插件） |
| 跨订阅去重 | 连接指纹 SHA256 去重 |
| 内核配置 | Xray / Sing-box JSON 结构与字段映射 |
| Passwall 导出 | UCI 字段映射、单引号转义、Gemini 可访问 / 提问成功清单筛选 |
| Gemini 判据 | 特性开关、地区码、封锁文案、回复解析 |
| 订阅配额 | `Subscription-Userinfo` 解析 |
| 内核自检 | `xray run -test` / `sing-box check`（二进制存在时执行） |

### 冒烟运行

```bash
# 仅测 2 个节点，跳过 Gemini 提问与导出
python main.py --limit 2 --skip-gemini-chat --no-export
```

### 提交前检查

```bash
python -m unittest discover -s tests -v
python main.py --limit 2 --skip-gemini-chat --no-export
git status --short        # 确认无敏感文件进入暂存区
```

---

<a id="security"></a>

## 🔐 上传 GitHub 前的保密性审查

本项目可在本地/私有服务器运行，但**禁止把运行期敏感数据提交到 GitHub**。

### 已隔离的敏感文件（`.gitignore`）

- `.env`（订阅链接、Gemini Cookie）
- `Project_Require.md`（手写需求，含真实订阅令牌）
- `export/`（节点分享链接与密码）
- `.temp/`、`*.log`、`run_log.log`、`test_results.txt`
- `bin/`（大体积内核二进制）
- `.venv/`、`__pycache__/`、`.vscode/`

### 代码层约束

- 代码中不含任何真实订阅 token、Cookie 或个人信息路径。
- 所有敏感项必须通过 `.env` 注入，`.env.example` 只保留占位值。
- Passwall 导出脚本对值做单引号转义，避免命令注入。

### 提交前自查

```bash
# 1. 确认敏感文件未被跟踪
git ls-files | grep -E '(^\.env$|Project_Require|^export/|^bin/|run_log|test_results)' && echo '发现敏感文件！' || echo 'OK'

# 2. 扫描潜在密钥
git grep -nEI '(token|secret|password|passwd|api[_-]?key|BEGIN [A-Z ]*PRIVATE KEY)' -- . ':!*.md' || true

# 3. 确认忽略规则生效
git check-ignore -v .env Project_Require.md export/passwall_uci_ok.txt run_log.log
```

如曾误提交 `.env`，请立刻轮换订阅令牌与 Cookie，并使用 `git filter-repo` 清理历史后再推送。

---

<a id="changelog"></a>

## 📈 版本迭代

> 版本规则：小改 +0.01，中改 +0.1，大改 +1。项目早期版本标记为 `7.00`，模块化重构后升至 `8.00`，当前版本 `9.02`。

| 版本 | 日期 | 类型 | 变更摘要 |
| --- | --- | --- | --- |
| 9.02 | 2026-10-29 | 小改 (+0.01) | 内核下载改为多镜像自动回退（`GH_PROXY` → gh-proxy.com → ghfast.top → ghproxy.net → 直连），强制 HTTP/1.1 并加入重试 / 低速中断，修复镜像 502 与 HTTP/2 断流导致「未获得任何代理内核」 |
| 9.01 | 2026-10-29 | 小改 (+0.01) | 修复镜像不支持 git 协议时的安装失败：`git clone` 失败自动回退源码压缩包（curl + tar），并自动清理不完整克隆目录；README 补充对应排错说明 |
| 9.00 | 2026-10-29 | 大版本 (+1) | 精简定位：移除 MySQL 持久化层、`--no-db`、PyMySQL 依赖与全部数据表；IP 归属地简化为进程缓存 + ipinfo；新增「Gemini 提问成功」节点导出；专注 Google / Gemini / Grok 三站点与 Passwall 导出 |
| 8.03 | 2026-10-29 | 小改 (+0.01) | 修复一键安装：`install_debian.sh` 默认 `REPO_URL`、新增 `GH_PROXY` 加速 clone 与内核下载、补充连接超时与失败提示；新增 `.gitattributes` 强制 shell 脚本 LF；README 增加「两条命令一键安装」 |
| 8.02 | 2026-10-29 | 小改 (+0.01) | 修正部署文档：方式 B 必须先有脚本文件；新增「离线部署」（`git archive` + 上传 Linux 内核）、GitHub 不可达排错表、PyPI 镜像与代理用法 |
| 8.01 | 2026-10-29 | 小改 (+0.01) | 完善 README：新增徽章与目录、完整 `.env` 配置参考、探针清单、Gemini 三态结果、失败码说明、Passwall 导入步骤、单元测试与贡献指南，并将安装命令替换为仓库真实地址 |
| 8.00 | 2026-10-28 | 大版本 (+1) | 全量模块化重构：拆分 models/parsers/subscription/netprobe/report/logging；修复 VMess `net` 传输映射、WS Host 字段、Xray 26 `allowInsecure` 移除、Sing-box AnyTLS/Hysteria2 配置、记录表去重与字段溢出；新增浏览器指纹网页探测、内核降级、Passwall Gemini 清单、Debian 13 一键安装、保密性审查清单、单元测试 |
| 7.00 | 2026-10-16 | 基线 | 重构前的单文件核心版本 |

---

<a id="faq"></a>

## ❓ 常见问题

**Q：Gemini 显示“可用”，但浏览器打开仍提示地区不支持？**
A：免登录判定基于页面特性开关与 Google GeoIP 地区码，可能受登录态、账号地区或 A/B 实验影响。配置 `GEMINI_1PSID` 后可启用真实提问验证，以提问结果为准。

**Q：Grok 显示 ✅，但实际打不开？**
A：Google / Grok 列表示“链路可达”。Grok 前置 Cloudflare 风控，对非浏览器请求常返回 403/429；能收到 HTTP 响应即证明代理链路正常。

**Q：为什么某些 Hysteria2 节点显示 🔴？**
A：Hysteria2 基于 QUIC/UDP。若本地网络封锁 UDP 或节点服务端离线，内核能启动但无法连通目标，会归类为 `PROXY_CONNECT_FAIL` 或 `TIMEOUT`。

**Q：订阅提示“返回 HTML 页面”？**
A：通常是订阅令牌失效、被运营商劫持，或该订阅需要先通过代理拉取。可在 `.env` 配置 `SUBSCRIPTION_PROXY` 指向本地代理。

**Q：启动提示“未找到 xray 或 sing-box 内核二进制”？**
A：确认 `bin/` 下的文件名与权限：Linux 需 `chmod +x bin/xray bin/sing-box`；也可用 `XRAY_BIN` / `SINGBOX_BIN` 指定绝对路径。至少提供一个内核才能运行。

**Q：Windows 下控制台中文乱码？**
A：程序启动时已将 stdout/stderr 切换为 UTF-8；若仍异常，请先执行 `chcp 65001` 或改用 Windows Terminal。

**Q：巡检太慢 / 大量超时？**
A：先用 `--limit` / `--filter` 缩小范围，适当降低 `--workers`；网络质量差时可增大 `PROBE_TIMEOUT`、`SITE_TIMEOUT`。

**Q：只想看 Gemini 可用的节点？**
A：运行 `--ok-only` 可精简终端输出；`export/passwall_nodes_gemini_ok.txt` 是「可访问」节点，`export/passwall_nodes_gemini_chat_ok.txt` 是「真实提问成功」节点（需配置 `GEMINI_1PSID`）。

---

<a id="contributing"></a>

## 🤝 贡献指南

1. Fork 仓库并从 `main` 新建分支：`git switch -c feat/your-change`
2. 遵循项目约定：
   - 解析逻辑 → [`core/parsers.py`](./core/parsers.py)；订阅拉取 → [`core/subscription.py`](./core/subscription.py)；网络探测 → [`core/netprobe.py`](./core/netprobe.py)
   - 内核配置与生命周期只在 [`core/engine.py`](./core/engine.py)，不要在 checker 中直接拼 JSON
   - 模块间只传 [`core/models.py`](./core/models.py) 中的模型对象，避免裸 `dict`
   - 所有可调参数集中到 [`core/config.py`](./core/config.py)，禁止散落魔法值
   - 纯函数（解析 / 判定 / 配置生成）必须可单元测试，测试放 `tests/`
3. 提交前运行单元测试与冒烟命令，并同步更新 `README.md` 与版本号（小改 +0.01 / 中改 +0.1 / 大改 +1）
4. 发起 Pull Request，说明变更动机、影响范围与验证结果

---

<a id="disclaimer"></a>

## ⚠️ 免责声明

- 本项目仅用于个人学习、网络质量评估与自用节点筛选，请遵守所在地区法律法规及服务提供商条款。
- 禁止用于商业转售、恶意扫描、攻击或任何侵害他人权益的用途。
- 作者不对因使用本工具产生的任何直接或间接损失负责。
- 订阅令牌、Gemini Cookie 等敏感信息请自行妥善保管，切勿提交到公开仓库。

---

<a id="thanks"></a>

## 🌟 开源参考与致谢

- [**OpenWrt-Passwall**](https://github.com/Openwrt-Passwall/openwrt-passwall)：探针规则、三级分级、UCI 字段与协议解析规范
- [**Gemini-Config-Checker**](https://github.com/MatinSenPai/Gemini-Config-Checker)：Gemini / AI Studio 地区判定与提问验证思路
- [**Clash-SpeedTest**](https://github.com/zhsama/clash-speedtest)：并发测速与报表看板设计
- [**RegionRestrictionCheck**](https://github.com/xykt/RegionRestrictionCheck)：Google 特性开关与地区码解析算法
- [**Sing-box**](https://github.com/SagerNet/sing-box) / [**Xray-core**](https://github.com/XTLS/Xray-core)：底层代理内核

<a id="license"></a>

## 📄 License

[MIT](./LICENSE)
