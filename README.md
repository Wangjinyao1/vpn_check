# VPN Check & Passwall Optimizer

> 面向中国大陆网络环境的机场节点质量评估工具：用真实代理内核逐节点建隧道，按 OpenWrt-Passwall 规则分级，验证 Google / Gemini / Grok 可达性与 Gemini 真实提问能力，并导出可直接落地的 Passwall 配置。

---

## 🎯 项目目的

从多个机场订阅中筛出**自己真正可用**的节点：

1. 节点能否稳定出海（不是只“握手成功”）
2. Google / Gemini / Grok 三个关键站点是否可访问
3. Gemini 是否被地区封锁（“**Gemini 目前不支持你所在的地区。敬请期待！**”）
4. 配置登录凭据时，Gemini 能否**真实提问并收到回答**
5. 最终生成可粘贴到 OpenWrt Passwall 的节点列表、Base64 订阅与 UCI 一键导入脚本

---

## ✨ 核心特性

- **真实内核隧道**：Xray-core / Sing-box 在本地随机高位端口建立 SOCKS5 隧道，逐节点实测。
- **Passwall 三级连通分级**：🟢 代理通 / 🟡 仅直连 / 🔴 无网络，判定顺序与 Passwall 探针一致。
- **三网页可用性**：Google（`www.google.com/?hl=zh_CN`）、Gemini（`gemini.google.com/app`）、Grok（`grok.com`）。
  - Google / Grok 使用浏览器指纹访问，HTTP 层有响应即判定“链路可达”（403/429 为站点风控页，不代表代理不可用）。
  - Gemini 由深度检测独立判定“可用 / 地区封锁 / 不可达”。
- **Gemini 双引擎判据**：
  - 免登录：解析 Google 前端特性开关 `45631641` 与 GeoIP 三位地区码（对齐 `xykt/RegionRestrictionCheck`）。
  - 登录提问：配置 `GEMINI_1PSID` 后调用 `StreamGenerate` 发起真实问答，验证模型是否可用（对齐 `MatinSenPai/Gemini-Config-Checker`）。
- **出海落地识别**：Cloudflare trace 获取落地 IP，归属地优先读通用缓存表，缺失时回源并写回。
- **全协议解析**：VLESS（Reality/Vision）、VMess、Trojan、Shadowsocks（SIP002/2022/插件）、Hysteria2（端口跳跃/混淆）、AnyTLS。
- **订阅配额识别**：解析 `Subscription-Userinfo`，展示节余流量与到期时间；远端缺失时继承数据库历史值。
- **Passwall 原生导出**：节点链接、Base64 订阅、Gemini 可用节点清单、UCI 导入脚本。
- **可选持久化**：MySQL 记录节点、逐次测试结果与批次汇总，支持查重去重。
- **纯 CLI / One-Shot**：适配 Cron / systemd timer，日志单文件 3MB 封顶。

---

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
        终端看板 + 报告归档 + Passwall 导出 + MySQL 持久化
```

### 连通分级（对齐 Passwall）

| 级别 | 含义 | 判定条件 |
| --- | --- | --- |
| 🟢 Level 0 | 代理通 | 国际探针（Google/Gstatic/Cloudflare）任一返回 200/204 |
| 🟡 Level 1 | 仅直连 | 国际探针全失败，但国内探针任一可达 |
| 🔴 Level 2 | 无网络 | 国内外探针全部失败，或内核启动失败 |

### Gemini 判定顺序

1. `generativelanguage.googleapis.com/v1beta/models` 连通性探针（200/400/403 均视为到达 Google 网关）
2. AI Studio 重定向 / `available-regions` 封锁页判定
3. Gemini Web App：地区码属于 `CHN/RUS/IRN/PRK/...` → 直接封锁；命中中英文封锁文案 → 封锁；特性开关为 `false` → 封锁
4. 以上通过且配置了 Cookie → 提交提问并解析流式回复，输出 `回答成功 / 提问受阻 / 未测`

---

## 🏗️ 项目架构与目录结构

```text
vpn_check/
├── main.py                    # CLI 入口：编排拉取 → 探测 → 报告 → 导出 → 入库
├── net_check.py               # 兼容旧入口，转发 main.main()
├── install_debian.sh          # Debian 13 一键安装（依赖/内核/venv/systemd timer）
├── run_check.sh               # Linux 手动/定时执行包装脚本
├── requirements.txt           # PySocks / PyMySQL / curl_cffi
├── core/
│   ├── config.py              # 统一配置中心（.env 解析、探针规则、路径、超时）
│   ├── models.py              # 领域模型（ProxyNode / SiteProbe / GeminiVerdict / NodeResult）
│   ├── parsers.py             # 分享链接解析与连接指纹去重
│   ├── subscription.py        # 订阅拉取、配额解析、跨订阅汇总
│   ├── engine.py              # Xray / Sing-box 配置生成与隧道生命周期
│   ├── netprobe.py            # SOCKS5 HTTP 探针、落地 IP 探测
│   ├── checker.py             # 探测管道、三级分级、并发调度
│   ├── gemini.py              # Gemini 地区封锁与提问验证
│   ├── ip_location.py         # IP 归属地缓存 / 助手脚本 / ipinfo 回源
│   ├── database.py            # MySQL DDL、去重写入、缓存查询
│   ├── exporter.py            # Passwall 链接 / Base64 / UCI 导出
│   ├── report.py              # 终端决策看板
│   └── logging_setup.py       # run_log.log（单文件 3MB）
├── tests/test_core.py         # 解析 / 配置 / 导出 / Gemini 判据单元测试
├── bin/                       # 内核二进制（不入库，安装脚本自动下载）
├── export/                    # Passwall 导出产物（含节点凭据，禁止提交）
├── .github/
│   └── copilot-instructions.md # 项目记忆：开发规范、结构约定与验证要求
├── .temp/                     # temp_* 运行时配置与内核日志（禁止提交）
├── .env                       # 敏感配置（禁止提交）
├── .env.example               # 脱敏配置模板
└── run_log.log                # 运行日志（禁止提交）
```

### 内核选择策略

| 协议 / 场景 | 首选内核 | 说明 |
| --- | --- | --- |
| VLESS / VMess / Trojan | Xray | 支持 Reality、Vision、WS、gRPC、XHTTP、HTTPUpgrade、mKCP |
| Shadowsocks | Xray | 标准加密；带 SIP003 插件时切 Sing-box |
| Hysteria2 | Sing-box | QUIC、端口跳跃、salamander 混淆 |
| AnyTLS | Sing-box | ≥1.13.16 自动启用 `client_metadata` |

内核启动失败时按配置自动切换备用内核（`ENABLE_CORE_FALLBACK=1`），并在结果中标记降级。

---

## 🚀 快速开始

### 1. 环境要求

- Python 3.10+
- `bin/xray` 与 `bin/sing-box`（Windows 为 `.exe`）
- 依赖：`pip install -r requirements.txt`

### 2. 配置敏感参数

```powershell
Copy-Item .env.example .env
notepad .env
```

最小配置只需订阅源：

```ini
SUBSCRIBE_name_1=机场名称
SUBSCRIBE_URL_1=https://example.com/api/v1/client/subscribe?token=your_token
```

可选：`GEMINI_1PSID` / `GEMINI_1PSIDTS`（启用真实提问）、`DB_*`（启用持久化）。

### 3. 本地运行

```powershell
# 完整巡检
python main.py

# 调试：仅测 3 个节点，跳过提问与数据库
python main.py --limit 3 --skip-gemini-chat --no-db

# 静默模式（Cron 友好）
python main.py --quiet
```

---

## 🖥️ Debian 13 一键安装

仓库根目录提供 [`install_debian.sh`](./install_debian.sh)，自动完成系统依赖、Python 虚拟环境、Xray/Sing-box 内核下载、`.env` 初始化与 systemd 定时器安装。

### 方式 A：已克隆仓库

```bash
cd /opt/vpn_check
sudo bash install_debian.sh
```

> 脚本会自动识别所在目录；若项目不在脚本同级目录，可用 `--project-dir` 指定。

### 方式 B：从 GitHub 一键安装

```bash
sudo REPO_URL=https://github.com/<你的账号>/<你的仓库>.git bash install_debian.sh
```

### 方式 C：远程脚本直装

```bash
curl -fsSL https://raw.githubusercontent.com/<你的账号>/<你的仓库>/main/install_debian.sh -o /tmp/install_debian.sh
sudo REPO_URL=https://github.com/<你的账号>/<你的仓库>.git bash /tmp/install_debian.sh
```

安装完成后：

```bash
sudo nano /opt/vpn_check/.env          # 填入订阅与数据库配置
sudo systemctl start vpn-check.service # 立即执行一次
systemctl status vpn-check.timer       # 查看每 2 小时定时器
tail -f /opt/vpn_check/run_log.log     # 查看运行日志
```

> 自定义目录 / 关闭定时器：`sudo bash install_debian.sh --project-dir /srv/vpn_check --no-timer`
>
> 内核默认从官方 GitHub Releases 下载；如需固定版本可设置 `SINGBOX_VERSION=v1.13.16`。

### Cron 备选方案

```cron
0 */2 * * * /opt/vpn_check/run_check.sh -q >> /opt/vpn_check/cron_exec.log 2>&1
```

---

## 🧭 CLI 参数

| 参数 | 说明 |
| --- | --- |
| `--limit N` | 仅测试前 N 个节点 |
| `--filter KW` | 按节点名称关键字过滤 |
| `--protocol vless,anytls` | 仅测试指定协议 |
| `--workers N` | 并发线程数（默认 10，上限 32） |
| `--skip-gemini` | 跳过 Gemini 深度检测（仍做网页可达性） |
| `--skip-gemini-chat` | Gemini 仅测地区，不发起提问 |
| `--no-db` | 不写 MySQL |
| `--no-export` | 不导出 Passwall 配置 |
| `--ok-only` | 控制台仅显示总览与排行榜 |
| `--quiet`, `-q` | 静默模式，仅输出最终摘要 |
| `--report-file PATH` | 指定报告归档路径 |
| `--export-dir PATH` | 指定导出目录 |
| `--version` | 显示版本 |

---

## 🗄️ 数据表说明与聚合关系（MySQL）

所有业务表使用项目前缀 `vpn_check_`，主键自增，均含 `created_at` / `updated_at`。

### `vpn_check_node`：节点元数据

| 字段 | 说明 |
| --- | --- |
| `fingerprint` | 连接指纹 SHA256（协议+地址+端口+UUID+SNI+传输参数），**唯一索引去重** |
| `name` / `protocol` / `address` / `port` / `uuid` / `sni` / `security` | 节点基本信息 |
| `params_json` | 归一化后的传输与协议参数 |
| `sub_name` / `sub_url` | 归属订阅 |
| `raw_link` | 原始分享链接 |
| `remaining_traffic` / `expire_time` | 机场配额快照 |

### `vpn_check_test_record`：单节点测试记录

每次巡检每个节点写入一条；`UNIQUE(node_id, tested_at)` 保证同批次重复执行不会重复写入。

关键字段：`level`、`latency_ms`、`kernel`、`core_fallback`、`google_ok`、`gemini_ok`、`grok_ok`、`gemini_blocked`、`gemini_status`、`gemini_studio_status`、`gemini_api_ok`、`gemini_chat_ok`、`gemini_reply`、`gemini_region`、`outbound_ip`、`outbound_location`、`fail_code`、`fail_reason`。

### `vpn_check_run_batch`：批次汇总

`batch_time` 唯一；记录总节点数、三级数量、Gemini 可用与提问成功数量、批次耗时。与 `test_record` 通过 `batch_time ≈ tested_at` 逻辑关联（不建外键，便于按时间清理历史数据）。

### `ip_address_location`：通用 IP 归属地字典（跨项目共享）

`ip` 唯一索引；字段 `country` / `region` / `city` / `location` / `org` / `loc`。
由 `outbound_ip = ip` 与测试记录关联，避免重复调用第三方 API。

### 聚合关系

```text
vpn_check_node (1) ──< (N) vpn_check_test_record (N) >── (1) vpn_check_run_batch
                                     │
                                     └── outbound_ip ──► ip_address_location.ip
```

### 查询示例：每个节点的最新测试结果

```sql
SELECT
    n.sub_name AS `订阅`,
    n.name AS `节点`,
    n.protocol AS `协议`,
    CONCAT(n.address, ':', n.port) AS `入口`,
    CASE r.level WHEN 0 THEN '🟢 代理通' WHEN 1 THEN '🟡 仅直连' ELSE '🔴 无网络' END AS `分级`,
    r.latency_ms AS `延迟(ms)`,
    r.outbound_ip AS `落地IP`,
    r.outbound_location AS `落地归属地`,
    IF(r.google_ok, '✅', '❌') AS `Google`,
    CASE
        WHEN r.gemini_blocked THEN '⛔ 地区封锁'
        WHEN r.gemini_ok THEN CONCAT('✅ 可用 ', r.gemini_region)
        ELSE '❌ 不通'
    END AS `Gemini`,
    IF(r.grok_ok, '✅', '❌') AS `Grok`,
    CASE r.gemini_chat_ok WHEN 1 THEN '✅ 回答成功' WHEN 0 THEN '⚠️ 提问受阻' ELSE '➖ 未测' END AS `提问`,
    r.tested_at AS `测试时间`
FROM vpn_check_node n
JOIN vpn_check_test_record r ON r.node_id = n.id
JOIN (
    SELECT MAX(id) AS max_id FROM vpn_check_test_record GROUP BY node_id
) latest ON latest.max_id = r.id
WHERE r.level = 0
ORDER BY r.latency_ms ASC;
```

---

## 📦 Passwall 导出产物

每次运行后写入 `export/`：

| 文件 | 用途 |
| --- | --- |
| `passwall_nodes_ok.txt` | 代理通节点分享链接（Passwall → 节点列表 → 导入粘贴） |
| `passwall_nodes_gemini_ok.txt` | 代理通且 Gemini 可用的节点链接 |
| `passwall_nodes_ok_b64.txt` | 代理通节点 Base64 聚合（可作自定义订阅源） |
| `passwall_nodes_all.txt` | 本次全部抓取节点链接 |
| `passwall_uci_ok.txt` | UCI 批量导入脚本，上传路由器后 `sh passwall_uci_ok.txt` |

UCI 字段严格对齐 Passwall `subscribe.lua`：`type`、`protocol`、`transport`、`ws_host/ws_path`、`grpc_serviceName`、`tls_serverName`、`utls/fingerprint`、`reality_*`、`hysteria2_*` 等。

> `export/` 内含节点凭据，已加入 `.gitignore`，**禁止提交**。

---

## 🔐 上传 GitHub 前的保密性审查

本项目可在本地/私有服务器运行，但**禁止把运行期敏感数据提交到 GitHub**。

### 已隔离的敏感文件（`.gitignore`）

- `.env`（订阅链接、Gemini Cookie、数据库账号）
- `Project_Require.md`（手写需求，含真实订阅令牌）
- `export/`（节点分享链接与密码）
- `.temp/`、`*.log`、`run_log.log`、`test_results.txt`
- `bin/`（大体积内核二进制）
- `.venv/`、`__pycache__/`、`.vscode/`

### 代码层约束

- 代码中不含任何真实订阅 token、Cookie、数据库密码或个人信息路径。
- 数据库默认值改为本机占位，账号/密码必须通过 `.env` 注入。
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

## 📈 版本迭代

> 说明：项目早期版本已在代码中标记为 `7.00`，为保持版本连续性，本次按规范“大版本 +1”直接升级到 `8.00`；此后按规范继续递增（小改 +0.01，中改 +0.1，大改 +1）。

| 版本 | 日期 | 类型 | 变更摘要 |
| --- | --- | --- | --- |
| 8.00 | 2026-10-28 | 大版本 (+1) | 全量模块化重构：拆分 models/parsers/subscription/netprobe/report/logging；修复 VMess `net` 传输映射、WS Host 字段、Xray 26 `allowInsecure` 移除、Sing-box AnyTLS/Hysteria2 配置、记录表去重与字段溢出；新增浏览器指纹网页探测、内核降级、Passwall Gemini 清单、Debian 13 一键安装、保密性审查清单、单元测试 |
| 7.00 | 2026-10-16 | 基线 | 重构前的单文件核心版本 |

---

## ❓ 常见问题

**Q：Gemini 显示“可用”，但浏览器打开仍提示地区不支持？**
A：免登录判定基于页面特性开关与 Google GeoIP 地区码，可能受登录态、账号地区或 A/B 实验影响。配置 `GEMINI_1PSID` 后可启用真实提问验证，以提问结果为准。

**Q：Grok 显示 ✅，但实际打不开？**
A：Google / Grok 列表示“链路可达”。Grok 前置 Cloudflare 风控，对非浏览器请求常返回 403/429；能收到 HTTP 响应即证明代理链路正常。

**Q：为什么某些 Hysteria2 节点显示 🔴？**
A：Hysteria2 基于 QUIC/UDP。若本地网络封锁 UDP 或节点服务端离线，内核能启动但无法连通目标，会归类为 `PROXY_CONNECT_FAIL` 或 `TIMEOUT`。

**Q：没有 MySQL 能否使用？**
A：可以。`--no-db` 或留空 `DB_*` 即跳过持久化，其余功能不受影响。IP 归属地会自动降级到 ipinfo 回源。

**Q：订阅提示“返回 HTML 页面”？**
A：通常是订阅令牌失效、被运营商劫持，或该订阅需要先通过代理拉取。可在 `.env` 配置 `SUBSCRIPTION_PROXY` 指向本地代理。

---

## 🌟 开源参考与致谢

- [**OpenWrt-Passwall**](https://github.com/Openwrt-Passwall/openwrt-passwall)：探针规则、三级分级、UCI 字段与协议解析规范
- [**Gemini-Config-Checker**](https://github.com/MatinSenPai/Gemini-Config-Checker)：Gemini / AI Studio 地区判定与提问验证思路
- [**Clash-SpeedTest**](https://github.com/zhsama/clash-speedtest)：并发测速与报表看板设计
- [**RegionRestrictionCheck**](https://github.com/xykt/RegionRestrictionCheck)：Google 特性开关与地区码解析算法
- [**Sing-box**](https://github.com/SagerNet/sing-box) / [**Xray-core**](https://github.com/XTLS/Xray-core)：底层代理内核

## 📄 License

[MIT](./LICENSE)
