# vpn_check 重新规划（v9.03 → v10.x）

> 依据：`README.md`（v9.03 功能与原理）、`Project_Require.md`（六条需求）、《AI 编程规范》、`.github/copilot-instructions.md`、`run_log.log` 与 `test_results.txt` 的实际运行记录。
>
> 本文件是**规划文档**，不改变当前代码行为；确认后再按阶段落地，并按规范同步 README 与版本号。

---

## 一、现状诊断（v9.03 实测基线）

### 1.1 已达标的部分

| 需求 | 状态 | 证据 |
| --- | --- | --- |
| ① 三站点（Google / Gemini / Grok）访问测试 + Gemini 能否提问 | ✅ 已实现 | `core/checker.py` 三站点探测；`core/gemini.py` 三态判定 + `StreamGenerate` 提问 |
| ② 严格对齐 OpenWrt-Passwall | ✅ 已实现 | 8 个国际/国内探针、三级分级、`subscribe.lua` 字段映射、内核选择策略 |
| ③ 多机场订阅（5 组） | ⚠️ 部分 | 支持 1~10 组并发拉取，但**部分订阅源的格式无法解析**（见 1.3-1） |
| ④ 上传 GitHub + 保密性审查 | ⚠️ 半自动 | `.gitignore` 已隔离 `.env`/`export/`/`bin/`，审查仍靠人工清单，无 CI 兜底 |
| ⑤ Debian 13 一键安装 | ✅ 已实现 | `install_debian.sh`（依赖 + 内核 + venv + systemd timer + 多镜像回退） |
| ⑥ 每节点测速 | ✅ 已实现 | `core/speedtest.py`：Ookla CLI（`HTTPS_PROXY` 走隧道）/ 内置 SOCKS5 采样双引擎 |

代码规模：4,883 行（含脚本），14 个 `core/` 模块，39 个单测全部通过（1.4s）。

### 1.2 真实运行表现

| 运行时间 | 节点数 | 耗时 | 🟢 代理通 | Gemini 可用 | 提问成功 |
| --- | --- | --- | --- | --- | --- |
| 2026-10-28 22:00 | 51 | 195.8s | 32 | 22 | 0 |
| 2026-10-30 21:21 | 2 | 7.6s | 0 | 0 | 0 |

结论：**链路评估能力已经成立**（51 节点里挑出 32 个可用），但「提问成功」始终为 0，且单次快照无法回答「哪个节点长期稳定」——而这正是需求「评估出合适的节点自己用」的核心。

### 1.3 关键缺口（按严重度排序）

| # | 问题 | 证据 | 影响 |
| --- | --- | --- | --- |
| 1 | **Clash YAML 订阅整源丢弃** | 日志 `[某机场] 订阅返回 Clash YAML，非 Passwall 可用的 URI 列表`（同一时段连续两次） | 一个机场**全部节点归零**，需求③形同失效 |
| 2 | **测速在并发线程内执行** | `checker._evaluate` 内直接调 `measure_speed`，与 `--workers 10` 同池 | 多节点抢同一出口带宽，Mbps 相互压低，**排行榜不可比** |
| 3 | **无历史沉淀** | v9.00 移除 MySQL，只留 `test_results.txt` | 单次抖动即误杀好节点，无法算成功率/稳定性 |
| 4 | **规范冲突未裁决** | 规范第 6/7/12 条要求 MySQL 持久化 + `Google_Antigravity.ip_address_location` 通用表；`.github` 记忆写「无数据库」 | 项目与规范不一致，后续开发无准绳 |
| 5 | **Gemini Cookie 失效无区分** | 缺 `__Secure-1PSID` 时 `chat_ok=None`；Cookie 过期后一律 `chat_ok=False` | 无法区分「节点不行」与「Cookie 过期」，误杀节点 |
| 6 | **订阅代理空转** | 默认 `127.0.0.1:7890/10808/20000` 均无监听，每次拉取多耗 ~6s 并刷 ERROR 日志 | 日志噪音、启动变慢 |
| 7 | **hysteria2 全灭** | 10-30 运行 2/2 节点 `PROXY_CONNECT_FAIL`（均为 hysteria2） | 疑似本地 UDP 被封 / 内核版本不匹配，需专项排查 |
| 8 | **无结构化输出** | 只有终端文本 + `test_results.txt` | 无法二次分析、无法给看板/路由器消费 |
| 9 | **无 CI** | `.github/` 仅有 `copilot-instructions.md`，无 workflows | 单测与密钥扫描全靠手动，需求④缺自动化 |
| 10 | **无升级路径** | `install_debian.sh` 只能首装 | 服务器上迭代需手工覆盖 |

---

## 二、目标重定义

| 维度 | v9.03 现状 | v10.0 目标 |
| --- | --- | --- |
| 定位 | 单次节点体检工具 | **长期选点系统**：一次体检 + 历史趋势 + 稳定排名 |
| 订阅兼容 | URI 列表 + Base64 | 追加 Clash / Mihomo YAML（覆盖全部在用的机场） |
| 测速可信度 | 并发抢带宽 | 独立测速阶段 + 可配并发，默认全量内置采样 |
| 结果形态 | 文本报告 | 文本 + `report.json` + `report.html`（本地）+ `docs/index.html`（脱敏发布） |
| 数据 | 无 | 本地 SQLite（5 张 `vpn_check_*` 表） |
| 工程保障 | 手动单测 | GitHub Actions：单测 + shellcheck + 密钥扫描 |
| 运维 | 首装脚本 | 首装 + 升级脚本 + 定时巡检 + 失败告警 |

---

## 三、路线图（四个阶段）

### 阶段 A：止血与兼容 —— v9.10 ✅ 已完成（2026-10-30）

| 编号 | 任务 | 落点 | 状态 |
| --- | --- | --- | --- |
| A1 | **Clash/Mihomo YAML 解析**：`proxies:` 段 → `ProxyNode`（type/ws-opts/reality-opts/plugin 映射到现有 `params`） | 新增 `core/clash.py`，`subscription.py` 分流 | ✅ 完成；先试 `flag=passwall`（省一次解析），失败回退 YAML；新增 `build_share_link` 反向生成链接，保证 YAML 来源节点能导出 |
| A2 | **订阅代理短路**：拉取前先 TCP 探活，不通直接跳过并降为 DEBUG | `core/subscription.py` | ✅ 完成；探活结果进程内缓存 |
| A3 | **Gemini Cookie 预检**：登录态失效时新增 `cookie_invalid` 标记，报告中单列 | `core/gemini.py`、`models.py` | ✅ 完成；Cookie 失效时降级为免登录判定，**不再把节点误判为不可用** |
| A4 | **测速阶段解耦**：测速移出探测线程池，独立阶段重建隧道执行；默认 `builtin` 全量 10 MB 采样，`--speed-workers` 默认 2，失败重试 1 次 | `core/checker.py`、`core/speedtest.py` | ✅ 完成；新增 `run_speed_phase()` / `measure_node_speed()` |
| A5 | **`--json` 输出**：完整结果落 `report.json`（含每探针、每站点、Gemini、测速、失败码） | `core/report.py` | ✅ 完成；`build_json()`，且不输出 `uuid` / `raw` 凭据 |
| A6 | **hysteria2 专项排查** | `core/engine.py` | ✅ 已定位（见下），非内核问题 |
| A7 | **Passwall 导出字段对齐**：克隆上游仓库逐字段核对，重写 `core/exporter.py` | `core/exporter.py` | ✅ 完成（2026-10-30 补充，见 A7 记录） |

#### A7 对齐记录（源码依据）

| 修正项 | 原实现 | 上游实际规则 |
| --- | --- | --- |
| SS 加密方式 | 只写 `method` | Xray/sing-box 的 CBI 用 `rewrite_option` 改写为 `method`，**SS-Rust 直接读 `ss_method`** → 两者都写 |
| `tcp_guise_http_host/path` | `uci set` 写字符串 | 是 **DynamicList**，必须 `uci add_list` |
| 节点来源 | 未写 | `add_mode='1'`（导入）+ `group`（订阅名） |
| `transport` | 对 SS 不写 | Xray 下 SS 强制 `transport='raw'` |
| `xhttp_mode` | 一律 `params.mode or auto` | `http(h2)` → 固定 `stream-one`；显式 `xhttp` 才取 `mode` |
| `grpc_mode` | 未写 | `params.mode or 'gun'` |
| `tls_allowInsecure` | 仅在 `insecure` 时写 | 始终显式写 `0/1`，避免继承全局默认 |
| `reality_spiderX` | 对所有类型都写 | sing-box CBI 无该选项，仅 Xray 写 |
| `tcp_fast_open` | 所有类型都写 | sing-box CBI 无该选项，仅 Xray 写 |
| 段落创建 | `uci -q add` | `uci add`（部分固件 `-q` 不回显 section 名） |
| 字段体检 | 无 | 新增 `validate_node_fields()`，导出前静态校验必填项 |

> 附带结论：Passwall 的 sing-box 节点有 `tls_pinSHA256` 选项，机场下发的 `pcs` **在路由器侧是有效的**，本项目导出时会完整保留——本地测速降级只影响本地评估，不影响最终上机配置。

#### A6 排查结论（实测记录）

1. `sing-box check` 校验配置通过 → **不是配置非法**。
2. 内核 debug 日志：`x509: certificate signed by unknown authority` → 机场用自签证书 + `pcs` 证书指纹。
3. `pin_sha256` 此前**解析出来了但从未写进配置**（真实缺陷，已修）。
4. 尝试下发 `certificate_public_key_sha256` 后报 `unrecognized remote public key`，并实测
   `sha256(远端公钥) ≠ pcs` → 证明机场给的是**证书哈希**，sing-box 只认**公钥哈希**，无法换算。
5. 结论：改为「检测到 `pcs` 即降级 `insecure`」（`HYSTERIA2_PIN_INSECURE` 可关），并补充 UDP 失败提示。
6. 残留事实：机场 A 的 10 个带 `pcs` 的 Hy2 节点在降级后仍全部超时，判定为**节点侧不可达**；同一时刻
   机场 B 的 10 个 Hy2 节点（无 `pcs`、URI 自带 `insecure=1`）实测返回 204，说明本机 UDP 正常。

### 阶段 B：历史与稳定性 —— v9.2（核心价值，2~3 天）

存储已定为本地 SQLite（见 4.1 / 4.2），直接按表结构实施：

| 编号 | 任务 | 说明 |
| --- | --- | --- |
| B1 | **SQLite 持久化层** | 新增 `core/store.py`，按 4.2 建 5 张 `vpn_check_*` 表（中文注释），`.data/vpn_check.db`，30 天保留策略；`--no-db` 可跳过写入 |
| B2 | **稳定性指标** | 近 7 天：出现次数、代理通率、Gemini 可用率、延迟中位数/P90、抖动、带宽中位数 |
| B3 | **复合评分** | `score = w₁·成功率 + w₂·(1/延迟) + w₃·log(带宽) + w₄·Gemini + w₅·提问 + w₆·成本(倍率)`，权重进 `core/config.py` |
| B4 | **新 CLI** | `--compare`（对比上次）、`--history <fingerprint>`（单节点趋势）、`--top N`（复合分 Top N） |
| B5 | **IP 归属地** | 改写 `core/ip_location.py`：先查 `vpn_check_ip_location` 表，未命中走 ipinfo 再落库（字段与规范第 12 条通用表对齐，便于日后回灌） |

### 阶段 C：交付与自动化 —— v10.0（大版本，3~5 天）

| 编号 | 任务 | 说明 |
| --- | --- | --- |
| C1 | **双形态 HTML 看板** | `report.html`（完整，仅本地）+ `docs/index.html`（脱敏，供 Pages）；含总览卡片、可用榜、测速榜、Gemini 三态、订阅质量、趋势折线 |
| C1b | **Pages 发布闸门** | `scripts/privacy_scan.py`：按 4.3 五条规则扫描 `docs/`，命中即中止发布并打印命中行 |
| C2 | **CI** | `.github/workflows/ci.yml`：单测 + `shellcheck` + `gitleaks` + 「工作区无 `.env`/`export/`」断言 |
| C3 | **Passwall 导出校验** | UCI 生成后做必填字段白名单校验（`type`/`server`/`port`/`tls_serverName`…），缺失即告警 |
| C4 | **升级脚本** | `update.sh`：备份 `.env` → `git pull`（含镜像回退）→ 更新依赖与内核 → 重启 timer |
| C5 | **失败告警** | systemd `OnFailure` + 可选 webhook/邮件（配置为空则不触发） |
| C6 | **文档同步** | README 增补阶段 A~C 全部变更，`CHANGELOG` 与 README 版本表分离，版本号升至 `10.00` |

### 阶段 D：扩展（v10.1+，按需）

- 协议补齐：TUIG/Tuic、SS2022、Hysteria v1（**以 Passwall 实际支持表为准，不盲目加**）
- 订阅流量/到期阈值告警（`Subscription-Userinfo` 已有数据）
- 路由器侧回连验证：SSH 到 OpenWrt 实导 UCI 并回报节点状态

---

## 四、已裁决事项（2026-10-30 确认）

### 4.1 存储：本地 SQLite（已定）

**决定**：只用本地 SQLite，不接 MySQL。

**随之产生的规范偏差，必须在 README 中显式声明豁免理由**：

| 规范条款 | 要求 | 本项目处理 |
| --- | --- | --- |
| 第 6 条 | 业务数据持久化到数据库，项目名前缀，自增/UUID 主键，`created_at`/`updated_at`，去重 | ✅ 遵守（表名全部 `vpn_check_` 前缀，符合要求） |
| 第 7 条 | MySQL 连接与中文注释建表 | ⚠️ 豁免：改用 SQLite，建表语句保留中文注释 |
| 第 12 条 | IP 归属地从 `Google_Antigravity.ip_address_location` 读取并回写 | ⚠️ 豁免：改为本地表 `vpn_check_ip_location`，首次查 ipinfo 后落库去重；字段与原通用表对齐（`ip`/`country`/`region`/`city`/`isp`），便于日后需要时导出并回灌通用表 |

**豁免理由（写入 README）**：工具需在无外网数据库的机器（Windows 工作站、旁路 VPS、路由器旁主机）上独立运行；SQLite 单文件零运维，且数据不出本机，符合本项目「节点凭据不外泄」的保密要求。

### 4.2 表设计（阶段 B 落地）

| 表名 | 作用 | 关键字段 | 去重键 |
| --- | --- | --- | --- |
| `vpn_check_run` | 每次巡检批次 | `run_id`(UUID)、起止时间、节点总数/代理通/Gemini/提问、`workers`、`speed_provider`、`version` | `run_id` 唯一 |
| `vpn_check_node` | 节点档案（跨批次稳定身份） | `fingerprint`、`name_display`、`protocol`、`server`、`port`、`sub_name`、`first_seen`、`last_seen` | `fingerprint` 唯一 |
| `vpn_check_result` | 单批次单节点结果 | `run_id`、`fingerprint`、`level`、`latency_ms`、`jitter_ms`、`download_mbps`、`upload_mbps`、`egress_ip`、`egress_country`、`gemini_status`、`gemini_region`、`chat_ok`、`fail_code` | `(run_id, fingerprint)` |
| `vpn_check_subscription` | 订阅源健康度 | `name`、`url_hash`（**不存明文令牌**）、`node_count`、`remaining_traffic`、`expire_time`、`error` | `(name, url_hash, run_id)` |
| `vpn_check_ip_location` | IP 归属地缓存（豁免第 12 条后的本地替代） | `ip`、`country`、`region`、`city`、`isp` | `ip` 唯一 |

- 所有表均含 `id INTEGER PRIMARY KEY AUTOINCREMENT`、`created_at`、`updated_at`（规范第 6 条）。
- 库文件：`.data/vpn_check.db`，加入 `.gitignore`；保留策略默认 30 天（`DB_RETENTION_DAYS`）。

### 4.3 交付：HTML 看板 + GitHub Pages（已定，附强制脱敏）

**决定**：生成单文件 HTML 看板，并发布到 GitHub Pages。

**风险**：Pages 是公开仓库页面，任何访问者都能看到你的节点数量、存活率与地区分布；若泄露 server/port/UUID，等于把订阅凭据公开。**因此设双产物 + 硬闸门**：

| 产物 | 路径 | 内容 | 用途 |
| --- | --- | --- | --- |
| 完整版 | `report.html` | 含节点名、`server:port`、落地 IP、订阅名 | 仅本地查看，**禁止提交**（已列入 `.gitignore`） |
| 公开版 | `docs/index.html` | **无** server/port/UUID/密码/订阅令牌/完整 IP；节点以 `fp:8位` 标识，落地只显示国家+城市 | 供 GitHub Pages 发布 |

**脱敏规则（CI 强制校验，不通过即失败）**：

1. 所有 IPv4 / IPv6 一律不出现（代之以国家·城市）
2. 所有 UUID 形态字符串（`8-4-4-4-12`）不得出现
3. 所有 `token=` / `/api/v1/client/` 片段不得出现
4. 节点 `server` 与 `port` 字段不得出现（只保留协议与协议族统计）
5. 订阅源只显示自定义别名（如「机场A」「机场B」），URL 一律 `hash8`

### 4.4 测速：全量内置引擎（已定）

**决定**：默认 `SPEEDTEST_PROVIDER=builtin`，对所有代理通节点全量采样 10 MB；Ookla 仅保留为手动选项（`--speed-provider ookla`）。

**必须配套的公平性约束**（否则全量数字不可比）：

- 测速独立成阶段，与探测线程池解耦，`--speed-workers` 默认 **2**
- 报告中标注当次并发度；`--speed-workers 1` 时数字最可比，用于最终定榜
- 单节点失败重试 1 次，避免抖动被记成 0 Mbps
- 全量耗时估算：32 个代理通节点 × (10 MB 下载 + 3 次 ping) ÷ 2 并发 ≈ 8~12 分钟，需在 README 写明

### 4.5 其余约定

1. **Clash 订阅**：先尝试带 `flag=passwall` / 订阅 UA 请求 URI 列表，失败则回退 YAML 解析——两条路都做。
2. **Gemini Cookie**：维持手工填 `.env`，但增加启动时预检与「Cookie 失效」独立状态，避免误杀节点。

---

## 五、验收标准（v10.0 收官）

```bash
# 1. 单测全绿且覆盖新增模块
python -m unittest discover -s tests -v

# 2. 5 个订阅源全部解析出节点（含 Clash YAML 源）
python main.py --limit 0 --skip-speed --json

# 3. 测速可复现（单并发最可比）
python main.py --speed-workers 1 --json
# 同一节点两次测速偏差 < 15%

# 4. 报告形态齐备
ls test_results.txt report.json report.html docs/index.html

# 5. 公开版通过脱敏闸门
python scripts/privacy_scan.py docs/index.html && echo PASS

# 6. 交付无敏感信息（report.html / .data / *.db 均不得入库）
git ls-files | grep -E '(^\.env$|Project_Require|^export/|^bin/|run_log|test_results|^\.data/|\.db$|report\.(json|html))' && echo FAIL || echo OK

# 7. Debian 升级可用
sudo bash update.sh && systemctl status vpn-check.timer
```

---

## 六、版本规划一览

| 版本 | 主题 | 类型 |
| --- | --- | --- |
| 9.10 | 阶段 A：Clash 兼容、测速分层、JSON 输出、Cookie 预检 | 中改 (+0.1) |
| 9.20 | 阶段 B：历史沉淀、稳定性评分、`--compare/--history/--top` | 中改 (+0.1) |
| 10.00 | 阶段 C：HTML 看板、CI、导出校验、升级与告警 | 大改 (+1) |
| 10.1x | 阶段 D：协议补齐、配额告警、路由器回连 | 小改 (+0.01) |
