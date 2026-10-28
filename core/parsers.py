# -*- coding: utf-8 -*-
"""core/parsers.py — 分享链接解析器
==================================
严格对齐 OpenWrt-Passwall `subscribe.lua` 的链路解析规范，支持：

- VLESS（Reality / Vision / WS / gRPC / XHTTP / HTTPUpgrade）
- VMess（v2rayN Base64 JSON 与简洁 URI）
- Trojan（TLS / Reality / WS / gRPC）
- Shadowsocks（SIP002、2022-blake3、obfs / v2ray-plugin / shadow-tls）
- Hysteria2（含端口跳跃与 salamander 混淆）
- AnyTLS（Passwall 官方字段映射）

解析结果统一归一化为 `ProxyNode.params`，供内核配置、Passwall 导出与去重共用。
"""

from __future__ import annotations

import base64
import json
import logging
import urllib.parse
from typing import Dict, List, Optional, Tuple

from core import config
from core.models import ProxyNode

logger = logging.getLogger("vpn_check.parsers")

# 归一化后的传输方式集合
NETWORK_ALIASES = {
    "tcp": "tcp",
    "raw": "tcp",
    "ws": "ws",
    "websocket": "ws",
    "grpc": "grpc",
    "gun": "grpc",
    "h2": "http",
    "http": "http",
    "httpupgrade": "httpupgrade",
    "xhttp": "xhttp",
    "splithttp": "xhttp",
    "kcp": "mkcp",
    "mkcp": "mkcp",
    "quic": "quic",
}


def b64_decode(text: str) -> str:
    """宽松 Base64 解码：兼容标准/URL-Safe、缺失填充与空白字符"""
    clean = "".join(text.split())
    if not clean:
        return ""
    if "-" in clean or "_" in clean:
        clean = clean.replace("-", "+").replace("_", "/")
    clean = clean.rstrip("=")
    clean += "=" * (-len(clean) % 4)
    try:
        return base64.b64decode(clean).decode("utf-8", errors="replace")
    except (ValueError, TypeError):
        return ""


def _parse_query(query: str) -> Dict[str, str]:
    if not query:
        return {}
    parsed = urllib.parse.parse_qs(query, keep_blank_values=True)
    return {k.lower(): v[0] for k, v in parsed.items()}


def _split_uri(raw: str, scheme: str) -> Tuple[str, str, str]:
    """拆分 URI 为 (主体, 查询串, 片段名)"""
    body = raw[len(scheme):].strip()
    fragment = ""
    if "#" in body:
        body, fragment = body.split("#", 1)
        fragment = urllib.parse.unquote(fragment).strip()
    query = ""
    if "?" in body:
        body, query = body.split("?", 1)
    body = body.strip()
    return body, query, fragment


def split_host_port(host_port: str, default_port: int = 443) -> Tuple[str, int]:
    """解析 host:port，兼容 [IPv6]:port 形式"""
    host_port = host_port.strip().strip("/")
    if host_port.startswith("["):
        end = host_port.find("]")
        if end == -1:
            raise ValueError(f"非法 IPv6 地址: {host_port}")
        address = host_port[1:end]
        rest = host_port[end + 1:]
        port = int(rest.lstrip(":")) if rest.startswith(":") and rest[1:] else default_port
        return address, port
    if host_port.count(":") == 1:
        address, port_str = host_port.rsplit(":", 1)
        return address, int(port_str or default_port)
    if host_port.count(":") > 1:  # 未加方括号的 IPv6，无端口
        return host_port, default_port
    return host_port, default_port


def _normalize_network(raw: str) -> str:
    return NETWORK_ALIASES.get((raw or "tcp").lower(), "tcp")


def _truthy(value: str) -> bool:
    return str(value).lower() in ("1", "true", "yes")


def _base_params(query: Dict[str, str]) -> Dict[str, str]:
    """抽取三协议通用的传输 / TLS / Reality 参数"""
    network = _normalize_network(query.get("type") or query.get("net") or "tcp")
    params: Dict[str, str] = {
        "network": network,
        "header_type": (query.get("headertype") or query.get("type_header") or "none").lower(),
        "host": query.get("host", ""),
        "path": urllib.parse.unquote(query.get("path", "")),
        "service_name": query.get("servicename", "") or query.get("path", ""),
        "mode": query.get("mode", ""),
        "flow": query.get("flow", ""),
        "encryption": query.get("encryption", "none") or "none",
        "fp": query.get("fp", ""),
        "alpn": query.get("alpn", ""),
        "pbk": query.get("pbk", ""),
        "sid": query.get("sid", ""),
        "spx": query.get("spx", "/"),
        "allow_insecure": "1" if _truthy(query.get("allowinsecure") or query.get("insecure") or "") else "0",
        "seed": query.get("seed", ""),
        "quic_security": query.get("quicsecurity", "none"),
        "quic_key": query.get("key", ""),
    }
    if network == "grpc":
        params["service_name"] = query.get("servicename") or query.get("path", "")
    if network == "tcp":
        header = (query.get("headertype") or query.get("headertype") or "none").lower()
        params["header_type"] = header if header in ("http", "none") else "none"
    return params


# ---------------------------------------------------------------------------
# VLESS
# ---------------------------------------------------------------------------
def parse_vless(raw: str, sub_name: str, sub_url: str) -> Optional[ProxyNode]:
    try:
        body, query_str, fragment = _split_uri(raw, "vless://")
        if "@" not in body:
            return None
        user_info, host_port = body.rsplit("@", 1)
        uuid = urllib.parse.unquote(user_info)
        address, port = split_host_port(host_port, 443)
        if not uuid or not address:
            return None

        query = _parse_query(query_str)
        params = _base_params(query)
        security = query.get("security", "").lower()
        if not security and params.get("flow"):
            security = "tls"

        return ProxyNode(
            name=fragment or f"VLESS_{address}_{port}",
            protocol="vless",
            address=address,
            port=port,
            uuid=uuid,
            sni=query.get("sni", "") or query.get("peer", "") or params.get("host", "") or address,
            security=security,
            params=params,
            raw=raw,
            sub_name=sub_name,
            sub_url=sub_url,
        )
    except (ValueError, IndexError, AttributeError) as exc:
        logger.debug("VLESS 解析失败: %s (%s)", raw[:80], exc)
        return None


# ---------------------------------------------------------------------------
# VMess
# ---------------------------------------------------------------------------
def _vmess_from_json(data: Dict[str, object], raw: str, sub_name: str, sub_url: str) -> Optional[ProxyNode]:
    address = str(data.get("add", "")).strip()
    try:
        port = int(data.get("port", 0) or 0)
    except (TypeError, ValueError):
        return None
    if not address or not port:
        return None

    network = _normalize_network(str(data.get("net", "tcp")))
    tls_enabled = str(data.get("tls", "")).lower() in ("tls", "1", "true")
    host = str(data.get("host", "") or "")
    path = urllib.parse.unquote(str(data.get("path", "") or ""))
    params: Dict[str, str] = {
        "network": network,
        "host": host,
        "path": path,
        "service_name": path,
        "header_type": str(data.get("type", "none") or "none").lower(),
        "alter_id": str(data.get("aid", 0) or 0),
        "scy": str(data.get("scy", "auto") or "auto"),
        "fp": str(data.get("fp", "") or ""),
        "alpn": str(data.get("alpn", "") or ""),
        "allow_insecure": "1" if _truthy(str(data.get("allowinsecure") or data.get("allowInsecure") or data.get("insecure") or "")) else "0",
    }
    if network == "tcp":
        params["header_type"] = "http" if params["header_type"] == "http" else "none"
    if network == "grpc":
        params["service_name"] = str(data.get("path", "") or "")

    return ProxyNode(
        name=str(data.get("ps", "") or f"VMess_{address}_{port}"),
        protocol="vmess",
        address=address,
        port=port,
        uuid=str(data.get("id", "") or ""),
        sni=str(data.get("sni", "") or host or address),
        security="tls" if tls_enabled else "",
        params=params,
        raw=raw,
        sub_name=sub_name,
        sub_url=sub_url,
    )


def parse_vmess(raw: str, sub_name: str, sub_url: str) -> Optional[ProxyNode]:
    try:
        body, query_str, fragment = _split_uri(raw, "vmess://")
        decoded = b64_decode(body)
        if decoded.lstrip().startswith("{"):
            data = json.loads(decoded)
            node = _vmess_from_json(data, raw, sub_name, sub_url)
            if node:
                if fragment and not node.name:
                    node.name = fragment
                return node

        # 兜底：uuid@host:port?type=ws&security=tls 形式
        if "@" in body:
            user_info, host_port = body.rsplit("@", 1)
            address, port = split_host_port(host_port, 443)
            query = _parse_query(query_str)
            params = _base_params(query)
            params["alter_id"] = query.get("aid", "0")
            params["scy"] = query.get("scy", "auto")
            return ProxyNode(
                name=fragment or f"VMess_{address}_{port}",
                protocol="vmess",
                address=address,
                port=port,
                uuid=urllib.parse.unquote(user_info),
                sni=query.get("sni", "") or params.get("host", "") or address,
                security=query.get("security", "").lower(),
                params=params,
                raw=raw,
                sub_name=sub_name,
                sub_url=sub_url,
            )
        return None
    except (ValueError, IndexError, AttributeError, json.JSONDecodeError) as exc:
        logger.debug("VMess 解析失败: %s (%s)", raw[:80], exc)
        return None


# ---------------------------------------------------------------------------
# Trojan
# ---------------------------------------------------------------------------
def parse_trojan(raw: str, sub_name: str, sub_url: str) -> Optional[ProxyNode]:
    try:
        body, query_str, fragment = _split_uri(raw, "trojan://")
        if "@" not in body:
            return None
        password, host_port = body.rsplit("@", 1)
        address, port = split_host_port(host_port, 443)
        query = _parse_query(query_str)
        params = _base_params(query)
        security = query.get("security", "tls").lower() or "tls"
        return ProxyNode(
            name=fragment or f"Trojan_{address}_{port}",
            protocol="trojan",
            address=address,
            port=port,
            uuid=urllib.parse.unquote(password),
            sni=query.get("sni", "") or query.get("peer", "") or params.get("host", "") or address,
            security=security,
            params=params,
            raw=raw,
            sub_name=sub_name,
            sub_url=sub_url,
        )
    except (ValueError, IndexError, AttributeError) as exc:
        logger.debug("Trojan 解析失败: %s (%s)", raw[:80], exc)
        return None


# ---------------------------------------------------------------------------
# Shadowsocks
# ---------------------------------------------------------------------------
def _split_ss_plugin(plugin: str) -> Tuple[str, str]:
    """拆分 SIP003 插件串：obfs-local;obfs=http;obfs-host=a.com"""
    if not plugin:
        return "", ""
    parts = [p for p in plugin.split(";") if p]
    return parts[0], ";".join(parts[1:])


def parse_shadowsocks(raw: str, sub_name: str, sub_url: str) -> Optional[ProxyNode]:
    try:
        body, query_str, fragment = _split_uri(raw, "ss://")
        method = password = ""
        address = ""
        port = 0

        if "@" in body:
            user_info, host_port = body.rsplit("@", 1)
            user_info = urllib.parse.unquote(user_info)
            if ":" not in user_info:
                user_info = b64_decode(user_info)
            if ":" not in user_info:
                return None
            method, password = user_info.split(":", 1)
            address, port = split_host_port(host_port, 8388)
        else:
            decoded = b64_decode(body)
            if "@" not in decoded:
                return None
            user_info, host_port = decoded.rsplit("@", 1)
            if ":" not in user_info:
                return None
            method, password = user_info.split(":", 1)
            address, port = split_host_port(host_port, 8388)

        query = _parse_query(query_str)
        plugin, plugin_opts = _split_ss_plugin(query.get("plugin", ""))
        params = {
            "method": method,
            "plugin": plugin,
            "plugin_opts": plugin_opts,
            "allow_insecure": "1" if _truthy(query.get("allowinsecure", "")) else "0",
        }
        return ProxyNode(
            name=fragment or f"SS_{address}_{port}",
            protocol="shadowsocks",
            address=address,
            port=port,
            uuid=password,
            security="tls" if plugin == "shadow-tls" else "",
            params=params,
            raw=raw,
            sub_name=sub_name,
            sub_url=sub_url,
        )
    except (ValueError, IndexError, AttributeError) as exc:
        logger.debug("Shadowsocks 解析失败: %s (%s)", raw[:80], exc)
        return None


# ---------------------------------------------------------------------------
# Hysteria2
# ---------------------------------------------------------------------------
def parse_hysteria2(raw: str, sub_name: str, sub_url: str) -> Optional[ProxyNode]:
    scheme = "hysteria2://" if raw.startswith("hysteria2://") else "hy2://"
    try:
        body, query_str, fragment = _split_uri(raw, scheme)
        password = ""
        if "@" in body:
            auth, host_port = body.rsplit("@", 1)
            password = urllib.parse.unquote(auth)
        else:
            host_port = body
        address, port = split_host_port(host_port, 443)
        query = _parse_query(query_str)
        params = {
            "sni": query.get("sni", ""),
            "obfs": query.get("obfs", ""),
            "obfs_password": query.get("obfs-password", "") or query.get("obfs_password", ""),
            "up_mbps": query.get("upmbps", ""),
            "down_mbps": query.get("downmbps", ""),
            "ports": query.get("mport", "") or query.get("ports", ""),
            "hop_interval": query.get("hopinterval", "") or query.get("hop-interval", ""),
            "pin_sha256": query.get("pcs", "") or query.get("pinsha256", ""),
            "allow_insecure": "1" if _truthy(query.get("allowinsecure") or query.get("insecure") or "") else "0",
        }
        return ProxyNode(
            name=fragment or f"Hy2_{address}_{port}",
            protocol="hysteria2",
            address=address,
            port=port,
            uuid=password,
            sni=params["sni"] or address,
            security="tls",
            params=params,
            raw=raw,
            sub_name=sub_name,
            sub_url=sub_url,
        )
    except (ValueError, IndexError, AttributeError) as exc:
        logger.debug("Hysteria2 解析失败: %s (%s)", raw[:80], exc)
        return None


# ---------------------------------------------------------------------------
# AnyTLS
# ---------------------------------------------------------------------------
def parse_anytls(raw: str, sub_name: str, sub_url: str) -> Optional[ProxyNode]:
    try:
        body, query_str, fragment = _split_uri(raw, "anytls://")
        if "@" not in body:
            return None
        auth, host_port = body.rsplit("@", 1)
        address, port = split_host_port(host_port, 443)
        query = _parse_query(query_str)
        security = query.get("security", "tls").lower() or "tls"
        params = {
            "sni": query.get("sni", "") or query.get("peer", ""),
            "fp": query.get("fp", ""),
            "alpn": query.get("alpn", ""),
            "allow_insecure": "1" if _truthy(query.get("insecure") or query.get("allowinsecure") or "") else "0",
            "pbk": query.get("pbk", ""),
            "sid": query.get("sid", ""),
        }
        return ProxyNode(
            name=fragment or f"AnyTLS_{address}_{port}",
            protocol="anytls",
            address=address,
            port=port,
            uuid=urllib.parse.unquote(auth),
            sni=params["sni"] or address,
            security=security,
            params=params,
            raw=raw,
            sub_name=sub_name,
            sub_url=sub_url,
        )
    except (ValueError, IndexError, AttributeError) as exc:
        logger.debug("AnyTLS 解析失败: %s (%s)", raw[:80], exc)
        return None


# ---------------------------------------------------------------------------
# 分发与去重
# ---------------------------------------------------------------------------
PARSERS = {
    "vless://": parse_vless,
    "vmess://": parse_vmess,
    "trojan://": parse_trojan,
    "ss://": parse_shadowsocks,
    "hysteria2://": parse_hysteria2,
    "hy2://": parse_hysteria2,
    "anytls://": parse_anytls,
}


def is_placeholder(name: str) -> bool:
    """识别订阅中的流量/公告占位伪节点"""
    return any(keyword in name for keyword in config.FILTER_KEYWORDS)


def parse_node_link(raw: str, sub_name: str = "", sub_url: str = "") -> Optional[ProxyNode]:
    """按 URI Scheme 分发解析，未知协议与占位节点返回 None"""
    line = (raw or "").strip()
    if not line or line.startswith("#"):
        return None
    for scheme, parser in PARSERS.items():
        if line.lower().startswith(scheme):
            node = parser(line, sub_name, sub_url)
            if node and is_placeholder(node.name):
                return None
            return node
    return None


def parse_subscription_text(content: str, sub_name: str, sub_url: str) -> List[ProxyNode]:
    """解析订阅正文：支持整段 Base64、明文 URI 列表与换行混排"""
    if not content:
        return []
    text = content.strip()
    if "://" not in text:
        decoded = b64_decode(text)
        if "://" in decoded:
            text = decoded
    nodes: List[ProxyNode] = []
    for line in text.splitlines():
        node = parse_node_link(line, sub_name, sub_url)
        if node:
            nodes.append(node)
    return nodes


def dedupe_nodes(nodes: List[ProxyNode]) -> List[ProxyNode]:
    """按连接指纹去重，保留首次出现的节点（保持订阅顺序）"""
    seen = set()
    unique: List[ProxyNode] = []
    for node in nodes:
        fp = node.fingerprint
        if fp in seen:
            continue
        seen.add(fp)
        unique.append(node)
    return unique
