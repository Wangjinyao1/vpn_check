# -*- coding: utf-8 -*-
"""core/exporter.py — OpenWrt-Passwall 配置导出
==============================================
严格对齐 Passwall `subscribe.lua` 的字段命名，生成可直接落地的三类产物：

- 节点分享链接列表（手工粘贴导入）
- Base64 聚合订阅（自定义远程订阅源）
- UCI Shell 脚本（路由器一键批量导入）

字段映射参考：
https://github.com/Openwrt-Passwall/openwrt-passwall/blob/main/luci-app-passwall/root/usr/share/passwall/subscribe.lua
"""

from __future__ import annotations

import base64
import logging
import time
from pathlib import Path
from typing import Dict, List, Tuple

from core import config
from core.models import CORE_SINGBOX, NodeResult, ProxyNode

logger = logging.getLogger("vpn_check.exporter")


def _quote(value: object) -> str:
    """UCI 值使用单引号包裹，内部单引号按 shell 规则转义"""
    text = str(value if value is not None else "").replace("\r", " ").replace("\n", " ")
    return "'" + text.replace("'", "'\\''") + "'"


def _passwall_profile(node: ProxyNode) -> Tuple[str, str]:
    """返回 Passwall 的 (内核类型, 传输方式)"""
    if node.protocol in ("anytls", "hysteria2") or (node.protocol == "shadowsocks" and node.params.get("plugin")):
        core = "sing-box"
        mapping = {"tcp": "tcp", "ws": "ws", "grpc": "grpc", "http": "http", "httpupgrade": "httpupgrade"}
        return core, mapping.get(node.network, "tcp")
    core = "Xray"
    mapping = {
        "tcp": "raw",
        "ws": "ws",
        "grpc": "grpc",
        "http": "xhttp",
        "xhttp": "xhttp",
        "httpupgrade": "httpupgrade",
        "mkcp": "mkcp",
        "quic": "quic",
    }
    return core, mapping.get(node.network, "raw")


def _uci_node_block(node: ProxyNode, index: int) -> List[str]:
    core, transport = _passwall_profile(node)
    params = node.params
    remarks = node.name.replace("\r", " ").replace("\n", " ")[:100] or f"node_{index}"

    lines = [
        f"# ---- #{index} [{node.protocol.upper()}] {remarks} ----",
        "sec=$(uci -q add passwall nodes)",
        f"uci set passwall.$sec.type={_quote(core)}",
        f"uci set passwall.$sec.protocol={_quote(node.protocol)}",
        f"uci set passwall.$sec.remarks={_quote(remarks)}",
        f"uci set passwall.$sec.address={_quote(node.address)}",
        f"uci set passwall.$sec.port={_quote(node.port)}",
        "uci set passwall.$sec.timeout='60'",
        "uci set passwall.$sec.tcp_fast_open='1'",
    ]

    if node.protocol in ("vless", "vmess"):
        lines.append(f"uci set passwall.$sec.uuid={_quote(node.uuid)}")
    if node.protocol == "vless":
        lines.append(f"uci set passwall.$sec.encryption={_quote(params.get('encryption') or 'none')}")
        if params.get("flow"):
            lines.append(f"uci set passwall.$sec.flow={_quote(params['flow'])}")
    if node.protocol == "vmess":
        lines.append(f"uci set passwall.$sec.alter_id={_quote(params.get('alter_id') or '0')}")
        lines.append(f"uci set passwall.$sec.security={_quote(params.get('scy') or 'auto')}")
    if node.protocol in ("trojan", "anytls"):
        lines.append(f"uci set passwall.$sec.password={_quote(node.uuid)}")
    if node.protocol == "shadowsocks":
        lines.append(f"uci set passwall.$sec.password={_quote(node.uuid)}")
        lines.append(f"uci set passwall.$sec.method={_quote(params.get('method') or 'aes-256-gcm')}")
        if params.get("plugin"):
            lines.append(f"uci set passwall.$sec.plugin={_quote(params['plugin'])}")
            lines.append(f"uci set passwall.$sec.plugin_opts={_quote(params.get('plugin_opts', ''))}")
    if node.protocol == "hysteria2":
        lines.append(f"uci set passwall.$sec.hysteria2_auth_password={_quote(node.uuid)}")
        for key in ("up_mbps", "down_mbps"):
            if params.get(key):
                lines.append(f"uci set passwall.$sec.hysteria2_{key}={_quote(params[key])}")
        if params.get("ports"):
            lines.append(f"uci set passwall.$sec.hysteria2_hop={_quote(params['ports'])}")
        if params.get("hop_interval"):
            lines.append(f"uci set passwall.$sec.hysteria2_hop_interval={_quote(params['hop_interval'])}")
        if params.get("obfs") and params.get("obfs_password"):
            lines.append(f"uci set passwall.$sec.hysteria2_obfs_type={_quote(params['obfs'])}")
            lines.append(f"uci set passwall.$sec.hysteria2_obfs_password={_quote(params['obfs_password'])}")

    if node.protocol in ("vless", "vmess", "trojan"):
        lines.append(f"uci set passwall.$sec.transport={_quote(transport)}")
    if node.network == "ws":
        lines.append(f"uci set passwall.$sec.ws_host={_quote(node.host)}")
        lines.append(f"uci set passwall.$sec.ws_path={_quote(node.path or '/')}")
    elif node.network == "tcp" and node.params.get("header_type") == "http":
        lines.append("uci set passwall.$sec.tcp_guise='http'")
        lines.append(f"uci set passwall.$sec.tcp_guise_http_host={_quote(node.host)}")
        lines.append(f"uci set passwall.$sec.tcp_guise_http_path={_quote(node.path or '/')}")
    if node.network == "grpc":
        lines.append(f"uci set passwall.$sec.grpc_serviceName={_quote(node.service_name)}")
    if node.network == "httpupgrade":
        lines.append(f"uci set passwall.$sec.httpupgrade_host={_quote(node.host)}")
        lines.append(f"uci set passwall.$sec.httpupgrade_path={_quote(node.path or '/')}")
    if node.network in ("xhttp", "http"):
        lines.append(f"uci set passwall.$sec.xhttp_host={_quote(node.host)}")
        lines.append(f"uci set passwall.$sec.xhttp_path={_quote(node.path or '/')}")
        lines.append(f"uci set passwall.$sec.xhttp_mode={_quote(node.params.get('mode') or 'auto')}")

    if node.tls or node.protocol in ("hysteria2", "anytls"):
        lines.append("uci set passwall.$sec.tls='1'")
        server_name = node.sni or node.host
        if server_name:
            lines.append(f"uci set passwall.$sec.tls_serverName={_quote(server_name)}")
        if node.allow_insecure:
            lines.append("uci set passwall.$sec.tls_allowInsecure='1'")
        if params.get("fp"):
            lines.append("uci set passwall.$sec.utls='1'")
            lines.append(f"uci set passwall.$sec.fingerprint={_quote(params['fp'])}")
        if params.get("alpn"):
            lines.append(f"uci set passwall.$sec.alpn={_quote(params['alpn'])}")
        if params.get("pin_sha256"):
            lines.append(f"uci set passwall.$sec.tls_pinSHA256={_quote(params['pin_sha256'])}")
    else:
        lines.append("uci set passwall.$sec.tls='0'")

    if node.reality:
        lines.append("uci set passwall.$sec.reality='1'")
        lines.append(f"uci set passwall.$sec.reality_publicKey={_quote(params.get('pbk', ''))}")
        lines.append(f"uci set passwall.$sec.reality_shortId={_quote(params.get('sid', ''))}")
        lines.append(f"uci set passwall.$sec.reality_spiderX={_quote(params.get('spx') or '/')}")

    lines.append("")
    return lines


def _write_links(path: Path, nodes: List[ProxyNode]) -> int:
    links = [node.raw for node in nodes if node.raw]
    path.write_text("\n".join(links) + ("\n" if links else ""), encoding="utf-8")
    return len(links)


def _write_b64(path: Path, nodes: List[ProxyNode]) -> int:
    links = [node.raw for node in nodes if node.raw]
    encoded = base64.b64encode("\n".join(links).encode("utf-8")).decode("ascii")
    path.write_text(encoded + "\n", encoding="utf-8")
    return len(links)


def export_artifacts(
    nodes: List[ProxyNode],
    results: List[NodeResult],
    export_dir: Path = config.EXPORT_DIR,
) -> Dict[str, object]:
    """导出全部 Passwall 产物，返回统计信息"""
    export_dir.mkdir(parents=True, exist_ok=True)
    now_text = time.strftime("%Y-%m-%d %H:%M:%S")

    ranked = sorted(
        [result for result in results if result.is_proxy_ok],
        key=lambda item: item.latency_ms,
    )
    ok_nodes = [result.node for result in ranked]
    gemini_nodes = [result.node for result in ranked if result.gemini_available]
    chat_nodes = [result.node for result in ranked if result.gemini_chat_ok]

    all_path = export_dir / config.EXPORT_ALL_FILE
    ok_path = export_dir / config.EXPORT_OK_FILE
    b64_path = export_dir / config.EXPORT_B64_FILE
    gemini_path = export_dir / config.EXPORT_GEMINI_FILE
    chat_path = export_dir / config.EXPORT_GEMINI_CHAT_FILE
    uci_path = export_dir / config.EXPORT_UCI_FILE

    total_links = _write_links(all_path, nodes)
    ok_links = _write_links(ok_path, ok_nodes)
    gemini_links = _write_links(gemini_path, gemini_nodes)
    chat_links = _write_links(chat_path, chat_nodes)
    _write_b64(b64_path, ok_nodes)

    uci_lines = [
        "#!/bin/sh",
        f"# OpenWrt Passwall 节点批量导入脚本（代理通 {len(ok_nodes)} 个，其中 Gemini 可用 {gemini_links} 个、提问成功 {chat_links} 个）",
        f"# 生成时间: {now_text}",
        "# 用法: 上传至路由器后执行 sh " + config.EXPORT_UCI_FILE,
        "# 说明: 脚本仅新增节点, 不会删除已有配置",
        "",
    ]
    for index, node in enumerate(ok_nodes, 1):
        uci_lines.extend(_uci_node_block(node, index))
    uci_lines.extend(
        [
            "uci commit passwall",
            "/etc/init.d/passwall restart",
            "echo 'Passwall 节点导入完成并已重启服务'",
            "",
        ]
    )
    uci_path.write_text("\n".join(uci_lines), encoding="utf-8")

    logger.info(
        "导出完成：全部 %d / 代理通 %d / Gemini 可用 %d / 提问成功 %d",
        total_links,
        ok_links,
        gemini_links,
        chat_links,
    )
    return {
        "total": total_links,
        "available": ok_links,
        "gemini_available": gemini_links,
        "gemini_chat": chat_links,
        "nodes": ok_nodes,
        "gemini_nodes": gemini_nodes,
        "chat_nodes": chat_nodes,
        "paths": {
            "all": str(all_path),
            "ok": str(ok_path),
            "b64": str(b64_path),
            "gemini": str(gemini_path),
            "gemini_chat": str(chat_path),
            "uci": str(uci_path),
        },
    }
