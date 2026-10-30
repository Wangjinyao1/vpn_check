# -*- coding: utf-8 -*-
"""core/models.py — 领域模型
============================
集中定义节点、探针与测试结果的不可变数据结构，供解析、探测与导出复用。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# 连通性分级（对齐 OpenWrt-Passwall）
LEVEL_PROXY = 0     # 🟢 代理通
LEVEL_DOMESTIC = 1  # 🟡 仅直连（国内可达、国际不可达）
LEVEL_DEAD = 2      # 🔴 无网络

LEVEL_TAGS = {
    LEVEL_PROXY: "🟢 代理通",
    LEVEL_DOMESTIC: "🟡 仅直连",
    LEVEL_DEAD: "🔴 无网络",
}

SITE_GOOGLE = "Google"
SITE_GEMINI = "Gemini"
SITE_GROK = "Grok"

# 内核名称
CORE_XRAY = "xray"
CORE_SINGBOX = "sing-box"


@dataclass
class ProxyNode:
    """代理节点领域模型（解析结果统一归一化到 params）"""

    name: str
    protocol: str                 # vless / vmess / trojan / shadowsocks / hysteria2 / anytls
    address: str
    port: int
    uuid: str = ""                # UUID 或密码
    sni: str = ""
    security: str = ""            # tls / reality / ""
    params: Dict[str, str] = field(default_factory=dict)
    raw: str = ""
    sub_name: str = ""
    sub_url: str = ""
    remaining_traffic: str = ""
    expire_time: str = ""

    # ---- 归一化后的常用属性 ----
    @property
    def network(self) -> str:
        """传输方式：tcp / ws / grpc / http / httpupgrade / xhttp / mkcp / quic"""
        return (self.params.get("network") or "tcp").lower()

    @property
    def host(self) -> str:
        return self.params.get("host", "")

    @property
    def path(self) -> str:
        return self.params.get("path", "")

    @property
    def service_name(self) -> str:
        return self.params.get("service_name", "")

    @property
    def reality(self) -> bool:
        return self.security == "reality" or bool(self.params.get("pbk"))

    @property
    def tls(self) -> bool:
        return self.security in ("tls", "reality") or self.params.get("tls") == "1"

    @property
    def allow_insecure(self) -> bool:
        return self.params.get("allow_insecure", "0") in ("1", "true", "True")

    @property
    def preferred_core(self) -> str:
        """与 Passwall 一致的内核选择策略"""
        if self.protocol in ("anytls", "hysteria2"):
            return CORE_SINGBOX
        if self.protocol == "shadowsocks" and self.params.get("plugin"):
            return CORE_SINGBOX
        if self.network in ("xhttp", "mkcp", "quic"):
            return CORE_XRAY
        return CORE_XRAY

    @property
    def fingerprint(self) -> str:
        """连接级唯一指纹：仅取连接身份，忽略易变的节点名称，用于跨订阅去重"""
        parts = [
            self.protocol,
            self.address.lower(),
            str(self.port),
            self.uuid,
            self.sni.lower(),
            self.security,
            self.network,
            self.host.lower(),
            self.path,
            self.service_name,
            self.params.get("method", ""),
            self.params.get("pbk", ""),
            self.params.get("plugin", ""),
        ]
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()

    @property
    def endpoint(self) -> str:
        return f"{self.address}:{self.port}"

    def display(self, width: int = 32) -> str:
        name = self.name if len(self.name) <= width else self.name[: width - 1] + "…"
        return f"[{self.protocol.upper()}] {name} ({self.endpoint})"

    def __str__(self) -> str:  # pragma: no cover - 调试辅助
        return self.display()


@dataclass
class SiteProbe:
    """单站点 HTTP 探测结果"""
    name: str
    url: str
    ok: bool = False
    code: int = 0
    latency_ms: float = 0.0
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "url": self.url,
            "ok": self.ok,
            "code": self.code,
            "latency_ms": self.latency_ms,
            "error": self.error,
        }


@dataclass
class GeminiVerdict:
    """Gemini / Google AI Studio 综合判定"""

    access_ok: bool = False             # 是否可正常访问（且未被地区封锁）
    http_code: int = 0                  # Gemini Web App 响应码
    access_ms: float = 0.0              # 首次字节耗时
    region_blocked: bool = False        # 是否命中地区封锁
    region_code: str = ""               # Google GeoIP 三位地区码（USA/JPN/CHN…）
    region_reason: str = ""             # 判定依据描述
    gemini_status: str = "error"        # ok / blocked / error / http_xxx
    studio_status: str = "error"        # ok / blocked / signin / error
    api_reach_ok: bool = False          # Generative Language API 连通性
    feature_flag: Optional[bool] = None  # 45631641 特性开关原始值
    chat_ok: Optional[bool] = None      # 提问：True/False/None(未测)
    cookie_invalid: bool = False        # Cookie 已失效（与节点质量无关，避免误杀节点）
    chat_code: int = 0
    chat_ms: float = 0.0
    reply_snippet: str = ""
    error: str = ""

    @property
    def available(self) -> bool:
        """可在 Gemini 正常使用（含提问题）"""
        return self.access_ok and not self.region_blocked

    @property
    def chat_tag(self) -> str:
        if self.cookie_invalid:
            return "🍪 Cookie失效"
        if self.chat_ok is True:
            return "✅ 回答成功"
        if self.chat_ok is False:
            return "⚠️ 提问受阻"
        return "➖ 未测"


@dataclass
class SpeedResult:
    """单节点测速结果（吞吐单位 Mbps，时延单位 ms）

    指标对齐 Speedtest CLI：ping / jitter / download / upload，
    provider 记录实际生效的测速引擎（ookla / builtin）。
    """

    download_mbps: float = 0.0
    upload_mbps: float = 0.0
    downloaded_bytes: int = 0
    uploaded_bytes: int = 0
    download_ms: float = 0.0
    upload_ms: float = 0.0
    ping_ms: float = 0.0
    jitter_ms: float = 0.0
    provider: str = ""
    server: str = ""
    url: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.download_mbps > 0 and not self.error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "download_mbps": self.download_mbps,
            "upload_mbps": self.upload_mbps,
            "downloaded_bytes": self.downloaded_bytes,
            "uploaded_bytes": self.uploaded_bytes,
            "download_ms": self.download_ms,
            "upload_ms": self.upload_ms,
            "ping_ms": self.ping_ms,
            "jitter_ms": self.jitter_ms,
            "provider": self.provider,
            "server": self.server,
            "url": self.url,
            "error": self.error,
        }


@dataclass
class NodeResult:
    """单节点完整测试结果"""

    node: ProxyNode
    level: int = LEVEL_DEAD
    latency_ms: float = 0.0
    core: str = ""
    fallback_used: bool = False
    egress_ip: str = ""
    egress_location: str = ""
    sites: Dict[str, SiteProbe] = field(default_factory=dict)
    probes: Dict[str, SiteProbe] = field(default_factory=dict)
    gemini: Optional[GeminiVerdict] = None
    speed: Optional[SpeedResult] = None
    fail_code: str = ""
    fail_reason: str = ""
    kernel_error: str = ""

    @property
    def level_tag(self) -> str:
        return LEVEL_TAGS.get(self.level, "❓ 未知")

    @property
    def is_proxy_ok(self) -> bool:
        return self.level == LEVEL_PROXY

    @property
    def gemini_available(self) -> bool:
        return bool(self.gemini and self.gemini.available)

    @property
    def gemini_chat_ok(self) -> bool:
        return bool(self.gemini and self.gemini.chat_ok is True)

    @property
    def speed_mbps(self) -> float:
        return self.speed.download_mbps if self.speed else 0.0

    def site_ok(self, name: str) -> bool:
        probe = self.sites.get(name)
        return bool(probe and probe.ok)


@dataclass
class SubscriptionResult:
    """单个订阅源的拉取与解析结果"""

    name: str
    url: str
    nodes: List[ProxyNode] = field(default_factory=list)
    remaining_traffic: str = ""
    expire_time: str = ""
    error: str = ""
    elapsed_s: float = 0.0

    @property
    def ok(self) -> bool:
        return bool(self.nodes)
