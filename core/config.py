# -*- coding: utf-8 -*-
"""core/config.py — 项目统一配置中心
====================================
遵循《AI 编程规范》第 9 条：所有可调参数集中在本文件。

- 敏感信息统一从 `.env` 读取（不落盘、不硬编码）
- 探针与连通性规则对齐 OpenWrt-Passwall
- 临时文件统一存放 `.temp/`，文件名以 `temp_` 开头
"""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

# ---------------------------------------------------------------------------
# 路径与平台
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = BASE_DIR / ".env"
IS_WINDOWS = sys.platform.startswith("win")

TEMP_DIR = Path(os.environ.get("VPN_CHECK_TEMP_DIR", BASE_DIR / ".temp"))
LOG_FILE = BASE_DIR / "run_log.log"
REPORT_FILE = BASE_DIR / "test_results.txt"
JSON_FILE = BASE_DIR / "report.json"
EXPORT_DIR = BASE_DIR / "export"


def load_env(env_path: Path) -> Dict[str, str]:
    """解析 .env 文件（零第三方依赖，支持 export 前缀、行内注释与引号）"""
    env_vars: Dict[str, str] = {}
    if not env_path.exists():
        return env_vars
    with open(env_path, "r", encoding="utf-8-sig", errors="replace") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.lower().startswith("export "):
                line = line[7:].lstrip()
            key, _, value = line.partition("=")
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            elif " #" in value:
                value = value.split(" #", 1)[0].rstrip()
            env_vars[key.strip()] = value
    return env_vars


_ENV = load_env(ENV_FILE)


def env_get(key: str, default: str = "") -> str:
    """读取配置：操作系统环境变量 > .env > 默认值"""
    value = os.environ.get(key)
    if value is None or value == "":
        value = _ENV.get(key, default)
    return value.strip()


def env_int(key: str, default: int) -> int:
    try:
        return int(env_get(key, str(default)))
    except (TypeError, ValueError):
        return default


def env_float(key: str, default: float) -> float:
    try:
        return float(env_get(key, str(default)))
    except (TypeError, ValueError):
        return default


def env_bool(key: str, default: bool = False) -> bool:
    raw = env_get(key, "1" if default else "0").lower()
    return raw in ("1", "true", "yes", "on", "y")


# ---------------------------------------------------------------------------
# 需求三：机场订阅源（支持 1..MAX_SUBSCRIPTIONS 组）
# ---------------------------------------------------------------------------
MAX_SUBSCRIPTIONS = 10

SUBSCRIBE_ITEMS: List[Dict[str, str]] = []
for _idx in range(1, MAX_SUBSCRIPTIONS + 1):
    _url = env_get(f"SUBSCRIBE_URL_{_idx}")
    if _url:
        SUBSCRIBE_ITEMS.append(
            {"name": env_get(f"SUBSCRIBE_name_{_idx}") or f"订阅源_{_idx}", "url": _url}
        )

# 订阅拉取依次尝试的 UA，尽量拿到 URI 列表而非混淆格式
SUBSCRIBE_USER_AGENTS: Tuple[str, ...] = (
    "v2rayN/6.23",
    "ClashMeta/v1.18.0",
    "Shadowrocket/1.0",
)
SUBSCRIBE_TIMEOUT = env_float("SUBSCRIBE_TIMEOUT", 15.0)
SUBSCRIBE_RETRY = env_int("SUBSCRIBE_RETRY", 1)
SUBSCRIBE_WORKERS = env_int("SUBSCRIBE_WORKERS", 5)

# 直连失败时依次尝试的本地代理（Passwall 代理拉取模式）
SUBSCRIPTION_PROXIES: Tuple[str, ...] = tuple(
    p.strip()
    for p in env_get(
        "SUBSCRIPTION_PROXY",
        "http://127.0.0.1:7890,socks5h://127.0.0.1:10808,socks5h://127.0.0.1:20000",
    ).split(",")
    if p.strip()
)

# 占位 / 广告 / 公告节点过滤词（订阅常见伪节点）
FILTER_KEYWORDS: Tuple[str, ...] = (
    "剩余流量", "套餐到期", "距离下次重置", "过期时间", "过期流量",
    "重置日期", "重置剩余", "流量重置", "官网", "屏蔽广告", "通知",
    "公告", "群", "客服", "续费", "订阅", "购买", "地址发布", "网址发布",
)

# ---------------------------------------------------------------------------
# 需求一：三网页可用性探测
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class SiteTarget:
    """网页探测目标定义

    reachable_any_status: HTTP 层有响应即视为链路可达。
    grok.com / google.com 会对非浏览器指纹返回 403/429 风控页，
    但能收到响应已证明代理链路可用；Gemini 的可用性由深度检测单独判定。
    """
    name: str
    url: str
    ok_codes: Tuple[int, ...] = (200, 204, 301, 302, 304)
    reachable_any_status: bool = False


TARGET_SITES: Tuple[SiteTarget, ...] = (
    SiteTarget("Google", "https://www.google.com/?hl=zh_CN", reachable_any_status=True),
    SiteTarget("Gemini", "https://gemini.google.com/app"),
    SiteTarget("Grok", "https://grok.com/", reachable_any_status=True),
)
SITE_TIMEOUT = env_float("SITE_TIMEOUT", 12.0)

# ---------------------------------------------------------------------------
# Gemini 深度检测（对齐 xykt/RegionRestrictionCheck 与 MatinSenPai/Gemini-Config-Checker）
# ---------------------------------------------------------------------------
GEMINI_APP_URL = "https://gemini.google.com/app"
GEMINI_STUDIO_URL = "https://aistudio.google.com/prompts/new_chat"
GEMINI_API_REACH_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models?pageSize=1&key=x"
)
GEMINI_STREAM_URL = (
    "https://gemini.google.com/_/BardChatUi/data/"
    "assistant.lamda.BardFrontendService/StreamGenerate"
)

GEMINI_1PSID = env_get("GEMINI_1PSID")
GEMINI_1PSIDTS = env_get("GEMINI_1PSIDTS")
GEMINI_CHAT_QUESTION = env_get("GEMINI_CHAT_QUESTION", "请回答：1+1等于几？只回答一个阿拉伯数字。")
GEMINI_CHAT_TIMEOUT = env_float("GEMINI_CHAT_TIMEOUT", 25.0)
GEMINI_CHAT_EXPECT = env_get("GEMINI_CHAT_EXPECT", "2")

# 免登录判定：Google 前端下发的 Gemini 可用性特性开关 ID 与地理代码正则
GEMINI_FEATURE_FLAG_ID = "45631641"
GEMINI_REGION_CODE_PATTERN = r',2,1,200,"([A-Z]{3})"'
GEMINI_FEATURE_FLAG_PATTERN = (
    r'["\']?' + GEMINI_FEATURE_FLAG_ID + r'["\']?\s*[:,\s]\s*(?:null\s*,\s*)?(true|false)'
)

# Google 官方明确不开放 Gemini 的国家/地区（一票否决）
GEMINI_BLOCKED_REGIONS = frozenset({"CHN", "RUS", "IRN", "PRK", "SYR", "CUB", "BLR"})

# 地区封锁文本特征（中英文），命中即判定“不支持你所在的地区”
GEMINI_REGION_BLOCK_KEYWORDS: Tuple[str, ...] = (
    "isn't available in your country",
    "not yet available in your country",
    "not available in your country",
    "not currently supported in your country",
    "currently supported in your country",
    "country not supported",
    "unsupported region",
    "unsupported_country",
    "目前不支持你所在的地区",
    "目前不支持你所在的国家",
    "不支持你所在的国家/地区",
    "不支持你所在的国家或地区",
    "无法在你的国家/地区使用",
    "你所在的地区暂不支持",
    "敬请期待",
)

# 提问接口错误码特征
GEMINI_CHAT_BLOCK_MARKERS: Tuple[str, ...] = (
    "1060", "1018", "user location is not supported",
)

# ---------------------------------------------------------------------------
# 需求二：OpenWrt-Passwall 探针规则
# ---------------------------------------------------------------------------
PROBES_INTERNATIONAL: Tuple[Tuple[str, str], ...] = (
    ("Google204", "https://www.google.com/generate_204"),
    ("Gstatic204", "https://www.gstatic.com/generate_204"),
    ("Cloudflare", "https://cp.cloudflare.com/"),
    ("YouTube204", "https://www.youtube.com/generate_204"),
)
PROBES_DOMESTIC: Tuple[Tuple[str, str], ...] = (
    ("MIUI_CN", "https://connect.rom.miui.com/generate_204"),
    ("HiCloud_CN", "https://connectivitycheck.platform.hicloud.com/generate_204"),
    ("VIVO_CN", "https://wifi.vivo.com.cn/generate_204"),
    ("Baidu", "https://www.baidu.com"),
)
PROBE_TIMEOUT = env_float("PROBE_TIMEOUT", 6.0)
PROBE_METHOD = env_get("PROBE_METHOD", "HEAD").upper()
PROBE_VALID_CODES: Tuple[int, ...] = (200, 204)

# 出海落地 IP 探测
EGRESS_TRACE_URL = "https://cloudflare.com/cdn-cgi/trace"
EGRESS_FALLBACK_URL = "http://ip-api.com/json/?fields=query,countryCode"
EGRESS_TIMEOUT = env_float("EGRESS_TIMEOUT", 6.0)

# ---------------------------------------------------------------------------
# 需求六：节点测速（指标对齐 Speedtest CLI）
# ---------------------------------------------------------------------------
# 测速引擎：builtin（内置采样，默认，全量节点都测）/ ookla（官方 CLI，耗流量大）/ auto
SPEEDTEST_PROVIDER = env_get("SPEEDTEST_PROVIDER", "builtin").lower()
# 官方 CLI 路径，留空则自动查找 bin/speedtest[.exe] 与 PATH
SPEEDTEST_BIN = env_get("SPEEDTEST_BIN", "")
# Speedtest CLI 单节点整轮超时（秒）：官方测试含选服 + 下载 + 上传
SPEEDTEST_OOKLA_TIMEOUT = env_float("SPEEDTEST_OOKLA_TIMEOUT", 60.0)
# 内置实现的 ping 采样次数（用于计算抖动的样本量）
SPEEDTEST_PINGS = env_int("SPEEDTEST_PINGS", 3)
# 下载地址模板，需含 {bytes} 占位符；多个地址逗号分隔，按顺序回退
SPEEDTEST_URLS: Tuple[str, ...] = tuple(
    item.strip()
    for item in env_get(
        "SPEEDTEST_URL",
        "https://speed.cloudflare.com/__down?bytes={bytes},https://proof.ovh.net/files/10Mb.dat",
    ).split(",")
    if item.strip()
)
SPEEDTEST_ENABLED = env_bool("SPEEDTEST_ENABLED", True)
# 测速并发度：全量测速在本机同一出口上进行，并发越高越容易互相抢带宽
# 1 = 数据最可比（用于最终定榜），2 = 速度与可信度的折中
SPEEDTEST_WORKERS = env_int("SPEEDTEST_WORKERS", 2)
# 只测延迟/可用性、不测带宽的节点数上限（0 = 全部代理通节点都测）
SPEEDTEST_TOP = env_int("SPEEDTEST_TOP", 0)
# 低于该速率视为采样异常（节点抖动或镜像被限速），自动重测一次并取较好值
SPEEDTEST_RETRY_FLOOR = env_float("SPEEDTEST_RETRY_FLOOR", 0.1)
SPEEDTEST_DOWNLOAD_BYTES = env_int("SPEEDTEST_DOWNLOAD_BYTES", 10 * 1024 * 1024)
SPEEDTEST_DOWNLOAD_TIMEOUT = env_float("SPEEDTEST_DOWNLOAD_TIMEOUT", 10.0)
SPEEDTEST_UPLOAD_ENABLED = env_bool("SPEEDTEST_UPLOAD_ENABLED", False)
SPEEDTEST_UPLOAD_URL = env_get("SPEEDTEST_UPLOAD_URL", "https://speed.cloudflare.com/__up")
SPEEDTEST_UPLOAD_BYTES = env_int("SPEEDTEST_UPLOAD_BYTES", 2 * 1024 * 1024)
SPEEDTEST_UPLOAD_TIMEOUT = env_float("SPEEDTEST_UPLOAD_TIMEOUT", 10.0)
# 传输窗口下限（秒）：避免小样本把瞬时速率放大成异常高值
SPEEDTEST_WINDOW_FLOOR = env_float("SPEEDTEST_WINDOW_FLOOR", 0.05)

# Hysteria2 证书指纹：机场下发的 pcs/pin_sha256 是「证书哈希」，sing-box 只支持
# 「公钥哈希」。无法换算时退化为跳过证书校验（仅用于连通性评估），置 0 可关闭该退化。
HYSTERIA2_PIN_INSECURE = env_bool("HYSTERIA2_PIN_INSECURE", True)

# ---------------------------------------------------------------------------
# 内核路径与生命周期
# ---------------------------------------------------------------------------
def _find_bin(name: str) -> str:
    """在 bin/ 目录查找内核可执行文件，Linux 下自动补执行权限"""
    candidates = [BASE_DIR / "bin" / f"{name}.exe", BASE_DIR / "bin" / name]
    for cand in candidates:
        if cand.exists():
            if not IS_WINDOWS:
                try:
                    os.chmod(cand, 0o755)
                except OSError:
                    pass
            return str(cand)
    return f"{name}.exe" if IS_WINDOWS else name


XRAY_PATH = env_get("XRAY_BIN") or _find_bin("xray")
SINGBOX_PATH = env_get("SINGBOX_BIN") or _find_bin("sing-box")
KERNEL_START_TIMEOUT = env_float("KERNEL_START_TIMEOUT", 8.0)
KERNEL_STOP_TIMEOUT = env_float("KERNEL_STOP_TIMEOUT", 3.0)
ENABLE_CORE_FALLBACK = env_bool("ENABLE_CORE_FALLBACK", True)

# ---------------------------------------------------------------------------
# 并发与输出
# ---------------------------------------------------------------------------
DEFAULT_WORKERS = env_int("DEFAULT_WORKERS", 10)
MAX_WORKERS = env_int("MAX_WORKERS", 32)

# ---------------------------------------------------------------------------
# IP 归属地（可选，用于展示节点落地信息）
# ---------------------------------------------------------------------------
IP_LOCATION_TIMEOUT = env_float("IP_LOCATION_TIMEOUT", 6.0)
IPINFO_TOKEN = env_get("IPINFO_TOKEN", "")
IPINFO_URL = env_get("IPINFO_URL", "https://ipinfo.io/{ip}/json")

# ---------------------------------------------------------------------------
# 导出
# ---------------------------------------------------------------------------
EXPORT_OK_FILE = "passwall_nodes_ok.txt"
EXPORT_ALL_FILE = "passwall_nodes_all.txt"
EXPORT_B64_FILE = "passwall_nodes_ok_b64.txt"
EXPORT_GEMINI_FILE = "passwall_nodes_gemini_ok.txt"
EXPORT_GEMINI_CHAT_FILE = "passwall_nodes_gemini_chat_ok.txt"
EXPORT_UCI_FILE = "passwall_uci_ok.txt"


@dataclass
class ConfigIssue:
    """配置校验问题描述"""
    key: str
    message: str
    fatal: bool = False


def validate() -> List[ConfigIssue]:
    """启动前配置体检，返回问题列表（fatal=True 表示无法继续）"""
    issues: List[ConfigIssue] = []
    if not SUBSCRIBE_ITEMS:
        issues.append(ConfigIssue("SUBSCRIBE_URL_*", "未配置任何订阅源，请在 .env 中设置 SUBSCRIBE_URL_1", True))
    if DEFAULT_WORKERS < 1:
        issues.append(ConfigIssue("DEFAULT_WORKERS", "并发数必须大于 0，将回退为 10", False))
    if PROBE_METHOD not in ("HEAD", "GET"):
        issues.append(ConfigIssue("PROBE_METHOD", "仅支持 HEAD 或 GET，将回退为 HEAD", False))
    if not Path(XRAY_PATH).exists() and not Path(SINGBOX_PATH).exists():
        issues.append(ConfigIssue("XRAY_BIN/SINGBOX_BIN", "未找到 xray 或 sing-box 内核二进制", True))
    if SPEEDTEST_ENABLED and not any("{bytes}" in url for url in SPEEDTEST_URLS):
        issues.append(
            ConfigIssue("SPEEDTEST_URL", "测速地址缺少 {bytes} 占位符，将按服务端默认大小采样", False)
        )
    if SPEEDTEST_PROVIDER == "ookla" and not speedtest_binary_available():
        issues.append(
            ConfigIssue("SPEEDTEST_PROVIDER", "指定 ookla 但未找到 speedtest CLI，将回退内置测速", False)
        )
    return issues


def speedtest_binary_available() -> bool:
    """检测官方 Speedtest CLI 是否可用（显式路径 > bin/ > PATH）"""
    if SPEEDTEST_BIN:
        return Path(SPEEDTEST_BIN).exists()
    for name in ("speedtest.exe", "speedtest"):
        if (BASE_DIR / "bin" / name).exists():
            return True
    return shutil.which("speedtest") is not None


def ensure_directories() -> None:
    """创建运行期必需目录"""
    for directory in (TEMP_DIR, EXPORT_DIR):
        directory.mkdir(parents=True, exist_ok=True)
