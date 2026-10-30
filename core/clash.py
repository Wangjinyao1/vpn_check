# -*- coding: utf-8 -*-
"""core/clash.py — Clash / Mihomo YAML 订阅解析
==============================================
部分机场（例如 qiuyin）只返回 Clash YAML，不返回 Passwall 可用的 URI 列表。
本模块把 YAML 中的 `proxies:` 段转换为统一的 `ProxyNode`，使其同样能进入
隧道探测、测速与 Passwall 导出流程。

字段映射对齐 Clash Meta / Mihomo 的 proxy 定义：
`type` / `server` / `port` / `uuid` / `password` / `cipher` / `network`
`tls` / `sni` / `servername` / `alpn` / `client-fingerprint` / `skip-cert-verify`
`ws-opts` / `grpc-opts` / `reality-opts` / `plugin` / `plugin-opts`
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.models import ProxyNode
from core.parsers import build_share_link

logger = logging.getLogger("vpn_check.clash")

try:  # PyYAML 为可选依赖：缺失时仅跳过 Clash 订阅，不影响其他格式
    import yaml

    HAS_YAML = True
except Exception:  # noqa: BLE001 - 缺少依赖时降级
    yaml = None
    HAS_YAML = False

# Clash 类型 → 本项目协议名
TYPE_MAP: Dict[str, str] = {
    "ss": "shadowsocks",
    "vmess": "vmess",
    "vless": "vless",
    "trojan": "trojan",
    "hysteria2": "hysteria2",
    "hy2": "hysteria2",
    "anytls": "anytls",
}

# Clash 插件名 → SIP003 插件名（Passwall 侧使用）
PLUGIN_MAP: Dict[str, str] = {
    "obfs": "obfs-local",
    "v2ray-plugin": "v2ray-plugin",
    "shadow-tls": "shadow-tls",
    "restls": "restls",
}


def looks_like_clash_yaml(text: str) -> bool:
    """判断订阅正文是否为 Clash / Mihomo YAML"""
    head = (text or "").lstrip()[:400].lower()
    return head.startswith("port:") or "\nproxies:" in head or head.startswith("proxies:")


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _alpn_text(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return ",".join(str(item) for item in value if str(item).strip())
    return _as_text(value)


def _ws_opts(proxy: Dict[str, Any]) -> tuple:
    """(headers.Host, path) — 兼容 ws-opts 与旧版 ws-headers/ws-path"""
    opts = proxy.get("ws-opts") or proxy.get("ws-options") or {}
    host = ""
    path = "/"
    if isinstance(opts, dict):
        headers = opts.get("headers") or {}
        if isinstance(headers, dict):
            for key, item in headers.items():
                if str(key).lower() == "host":
                    host = _as_text(item)
        path = _as_text(opts.get("path")) or "/"
    if not host:
        headers = proxy.get("ws-headers") or {}
        if isinstance(headers, dict):
            host = _as_text(headers.get("Host") or headers.get("host") or "")
    if path == "/" and proxy.get("ws-path"):
        path = _as_text(proxy.get("ws-path")) or "/"
    return host, path


def _grpc_service(proxy: Dict[str, Any]) -> str:
    opts = proxy.get("grpc-opts") or {}
    if isinstance(opts, dict):
        return _as_text(opts.get("grpc-service-name") or opts.get("serviceName") or "")
    return ""


def _reality_opts(proxy: Dict[str, Any]) -> Dict[str, str]:
    opts = proxy.get("reality-opts") or {}
    if not isinstance(opts, dict):
        return {}
    return {
        "pbk": _as_text(opts.get("public-key") or opts.get("public_key") or ""),
        "sid": _as_text(opts.get("short-id") or opts.get("short_id") or ""),
        "spx": _as_text(opts.get("spider-x") or "/"),
    }


def _ss_plugin(proxy: Dict[str, Any]) -> tuple:
    """返回 (SIP003 插件名, 插件参数串)"""
    raw_name = _as_text(proxy.get("plugin")).lower()
    if not raw_name:
        return "", ""
    plugin = PLUGIN_MAP.get(raw_name, raw_name)
    opts = proxy.get("plugin-opts") or {}
    if not isinstance(opts, dict):
        return plugin, _as_text(opts)

    if raw_name in ("obfs", "simple-obfs"):
        parts = []
        if opts.get("mode"):
            parts.append(f"obfs={_as_text(opts.get('mode'))}")
        if opts.get("host"):
            parts.append(f"obfs-host={_as_text(opts.get('host'))}")
        return plugin, ";".join(parts)

    parts = [f"{key}={_as_text(value)}" for key, value in opts.items() if _as_text(value)]
    return plugin, ";".join(parts)


def _common_params(proxy: Dict[str, Any]) -> Dict[str, str]:
    network_raw = _as_text(proxy.get("network") or "tcp").lower()
    network = {
        "tcp": "tcp",
        "raw": "tcp",
        "ws": "ws",
        "websocket": "ws",
        "grpc": "grpc",
        "h2": "http",
        "http": "http",
        "httpupgrade": "httpupgrade",
        "xhttp": "xhttp",
        "splithttp": "xhttp",
        "kcp": "mkcp",
        "mkcp": "mkcp",
        "quic": "quic",
    }.get(network_raw, "tcp")

    host = ""
    path = ""
    service_name = ""
    if network == "ws":
        host, path = _ws_opts(proxy)
    elif network == "grpc":
        service_name = _grpc_service(proxy)
    elif network in ("http", "httpupgrade", "xhttp"):
        opts = proxy.get("http-opts") or {}
        if isinstance(opts, dict):
            hosts = opts.get("host") or []
            host = _as_text(hosts[0]) if isinstance(hosts, list) and hosts else _as_text(hosts)
            paths = opts.get("path") or []
            path = _as_text(paths[0]) if isinstance(paths, list) and paths else _as_text(paths)
        path = path or "/"

    params: Dict[str, str] = {
        "network": network,
        "host": host,
        "path": path,
        "service_name": service_name,
        "header_type": "none",
        "flow": _as_text(proxy.get("flow")),
        "encryption": _as_text(proxy.get("encryption")) or "none",
        "fp": _as_text(proxy.get("client-fingerprint")),
        "alpn": _alpn_text(proxy.get("alpn")),
        "allow_insecure": "1" if _as_bool(proxy.get("skip-cert-verify")) else "0",
    }
    params.update({key: value for key, value in _reality_opts(proxy).items() if value})
    return params


def _node_from_proxy(proxy: Dict[str, Any], sub_name: str, sub_url: str) -> Optional[ProxyNode]:
    if not isinstance(proxy, dict):
        return None
    protocol = TYPE_MAP.get(_as_text(proxy.get("type")).lower())
    if not protocol:
        return None
    address = _as_text(proxy.get("server"))
    port = _as_int(proxy.get("port"))
    if not address or port <= 0:
        return None

    params = _common_params(proxy)
    name = _as_text(proxy.get("name")) or f"{protocol}_{address}_{port}"
    sni = _as_text(proxy.get("servername") or proxy.get("sni") or params.get("host") or "")
    reality = bool(params.get("pbk"))
    tls = _as_bool(proxy.get("tls")) or _as_text(proxy.get("tls")).lower() == "tls" or reality

    if protocol == "vless":
        uuid = _as_text(proxy.get("uuid"))
        if not uuid:
            return None
        security = "reality" if reality else ("tls" if tls else "")
    elif protocol == "vmess":
        uuid = _as_text(proxy.get("uuid"))
        if not uuid:
            return None
        params["alter_id"] = str(_as_int(proxy.get("alterId")))
        params["scy"] = _as_text(proxy.get("cipher")) or "auto"
        security = "tls" if tls else ""
    elif protocol == "trojan":
        uuid = _as_text(proxy.get("password"))
        if not uuid:
            return None
        security = "reality" if reality else ("tls" if tls else "tls")
    elif protocol == "shadowsocks":
        uuid = _as_text(proxy.get("password"))
        if not uuid:
            return None
        params["method"] = _as_text(proxy.get("cipher")) or "aes-256-gcm"
        plugin, plugin_opts = _ss_plugin(proxy)
        params["plugin"] = plugin
        params["plugin_opts"] = plugin_opts
        security = "tls" if plugin == "shadow-tls" else ""
    elif protocol == "hysteria2":
        uuid = _as_text(proxy.get("password") or proxy.get("auth"))
        if not uuid:
            return None
        params["sni"] = sni
        params["obfs"] = _as_text(proxy.get("obfs"))
        params["obfs_password"] = _as_text(proxy.get("obfs-password"))
        params["up_mbps"] = _as_text(proxy.get("up"))
        params["down_mbps"] = _as_text(proxy.get("down"))
        ports = proxy.get("ports")
        params["ports"] = ",".join(str(item) for item in ports) if isinstance(ports, list) else _as_text(ports)
        params["hop_interval"] = _as_text(proxy.get("hop-interval"))
        security = "tls"
    else:  # anytls
        uuid = _as_text(proxy.get("password"))
        if not uuid:
            return None
        params["sni"] = sni
        security = "tls"

    node = ProxyNode(
        name=name,
        protocol=protocol,
        address=address,
        port=port,
        uuid=uuid,
        sni=sni or address,
        security=security,
        params=params,
        raw="",
        sub_name=sub_name,
        sub_url=sub_url,
    )
    node.raw = build_share_link(node)
    return node


def parse_clash_yaml(text: str, sub_name: str = "", sub_url: str = "") -> List[ProxyNode]:
    """解析 Clash / Mihomo YAML 的 proxies 列表"""
    if not text or not HAS_YAML:
        if text and not HAS_YAML:
            logger.warning("缺少 PyYAML，无法解析 Clash YAML 订阅（pip install PyYAML）")
        return []
    try:
        document = yaml.safe_load(text)
    except Exception as exc:  # noqa: BLE001 - YAML 结构异常统一降级
        logger.warning("Clash YAML 解析失败: %s", exc)
        return []
    if not isinstance(document, dict):
        return []

    proxies = document.get("proxies")
    if not isinstance(proxies, list):
        return []

    nodes: List[ProxyNode] = []
    for item in proxies:
        node = _node_from_proxy(item, sub_name, sub_url)
        if node:
            nodes.append(node)
    logger.info("%s: Clash YAML 解析出 %d 个节点（共 %d 条）", sub_name or "订阅", len(nodes), len(proxies))
    return nodes
