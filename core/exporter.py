# -*- coding: utf-8 -*-
"""core/exporter.py — OpenWrt-Passwall 配置导出
==============================================
严格对齐 Passwall 源码（`luci-app-passwall/root/usr/share/passwall/subscribe.lua`
与 `luci-app-passwall/luasrc/model/cbi/passwall/client/type/*.lua`）：

- 节点段：`/etc/config/passwall` 中 `type=nodes` 的 section
- 内核类型 `type`：`Xray` / `sing-box` / `Hysteria2` / `SS-Rust`
- 字段名区分核心：SS 加密方式在 Xray/sing-box 下写 `method`（CBI 用
  `rewrite_option` 改写），SS-Rust 下写 `ss_method`，因此两者都写；
  `tcp_guise_http_host` / `tcp_guise_http_path` 是 DynamicList，必须 `uci add_list`
- Hysteria2 与上游一致走 sing-box：`type=sing-box` + `protocol=hysteria2`
  （专用 Hysteria2 核心分支不写 protocol 字段，且依赖额外二进制）

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
from core.models import NodeResult, ProxyNode

logger = logging.getLogger("vpn_check.exporter")

# Passwall 支持的内核类型
TYPE_XRAY = "Xray"
TYPE_SINGBOX = "sing-box"

# 传输层取值（Xray 用 raw，sing-box 用 tcp）
XRAY_TRANSPORT = {
    "tcp": "raw",
    "ws": "ws",
    "grpc": "grpc",
    "http": "xhttp",
    "xhttp": "xhttp",
    "httpupgrade": "httpupgrade",
    "mkcp": "mkcp",
    "quic": "quic",
}


def _quote(value: object) -> str:
    """UCI 值使用单引号包裹，内部单引号按 shell 规则转义"""
    text = str(value if value is not None else "").replace("\r", " ").replace("\n", " ")
    return "'" + text.replace("'", "'\\''") + "'"


def _add_list(option: str, value: object) -> str:
    """DynamicList 型字段必须用 add_list 写入（uci set 会写成字符串导致解析失败）"""
    return f"uci add_list passwall.$sec.{option}={_quote(value)}"


def _passwall_profile(node: ProxyNode) -> Tuple[str, str, str]:
    """返回 Passwall 的 (type, protocol, transport)

    与 subscribe.lua 的分配规则一致：
    - Hysteria2 / AnyTLS → sing-box（上游优先 sing-box，缺核心才用专用 Hysteria2 核心）
    - Shadowsocks：带 SIP003 插件时用 sing-box，否则用 Xray（transport 强制 raw）
    - VLESS / VMess / Trojan → Xray
    """
    if node.protocol == "hysteria2":
        return TYPE_SINGBOX, "hysteria2", ""
    if node.protocol == "anytls":
        return TYPE_SINGBOX, "anytls", ""
    if node.protocol == "shadowsocks":
        if node.params.get("plugin"):
            return TYPE_SINGBOX, "shadowsocks", ""
        return TYPE_XRAY, "shadowsocks", "raw"
    return TYPE_XRAY, node.protocol, XRAY_TRANSPORT.get(node.network, "raw")


def _credential_lines(node: ProxyNode, protocol: str) -> List[str]:
    params = node.params
    lines: List[str] = []

    if protocol in ("vless", "vmess"):
        lines.append(f"uci set passwall.$sec.uuid={_quote(node.uuid)}")
    elif protocol == "shadowsocks":
        lines.append(f"uci set passwall.$sec.password={_quote(node.uuid)}")
        method = params.get("method") or "aes-256-gcm"
        # Xray / sing-box 的 CBI 把 ss_method 改写为 method；SS-Rust 直接用 ss_method
        lines.append(f"uci set passwall.$sec.method={_quote(method)}")
        lines.append(f"uci set passwall.$sec.ss_method={_quote(method)}")
        if params.get("plugin"):
            lines.append("uci set passwall.$sec.plugin_enabled='1'")
            lines.append(f"uci set passwall.$sec.plugin={_quote(params['plugin'])}")
            lines.append(f"uci set passwall.$sec.plugin_opts={_quote(params.get('plugin_opts', ''))}")
    elif protocol == "hysteria2":
        lines.append(f"uci set passwall.$sec.hysteria2_auth_password={_quote(node.uuid)}")
        for key in ("up_mbps", "down_mbps"):
            if params.get(key):
                lines.append(f"uci set passwall.$sec.hysteria2_{key}={_quote(params[key])}")
        if params.get("ports"):
            lines.append(f"uci set passwall.$sec.hysteria2_hop={_quote(params['ports'])}")
        if params.get("hop_interval"):
            lines.append(f"uci set passwall.$sec.hysteria2_hop_interval={_quote(params['hop_interval'])}")
        if params.get("obfs"):
            lines.append(f"uci set passwall.$sec.hysteria2_obfs_type={_quote(params['obfs'])}")
            if params.get("obfs_password"):
                lines.append(
                    f"uci set passwall.$sec.hysteria2_obfs_password={_quote(params['obfs_password'])}"
                )
    else:  # trojan / anytls 使用 password
        lines.append(f"uci set passwall.$sec.password={_quote(node.uuid)}")

    if protocol == "vless":
        lines.append(f"uci set passwall.$sec.encryption={_quote(params.get('encryption') or 'none')}")
        if params.get("flow"):
            lines.append(f"uci set passwall.$sec.flow={_quote(params['flow'])}")
    if protocol == "vmess":
        lines.append(f"uci set passwall.$sec.alter_id={_quote(params.get('alter_id') or '0')}")
        lines.append(f"uci set passwall.$sec.security={_quote(params.get('scy') or 'auto')}")
    return lines


def _transport_lines(node: ProxyNode, transport: str) -> List[str]:
    """传输层字段（仅 Xray 生效；sing-box 分支的 SS/AnyTLS/Hysteria2 无 transport）"""
    params = node.params
    network = node.network
    lines = [f"uci set passwall.$sec.transport={_quote(transport)}"]

    if network == "ws":
        lines.append(f"uci set passwall.$sec.ws_host={_quote(node.host)}")
        lines.append(f"uci set passwall.$sec.ws_path={_quote(node.path or '/')}")
    elif network == "grpc":
        lines.append(f"uci set passwall.$sec.grpc_serviceName={_quote(node.service_name)}")
        lines.append(f"uci set passwall.$sec.grpc_mode={_quote(params.get('mode') or 'gun')}")
    elif network == "httpupgrade":
        lines.append(f"uci set passwall.$sec.httpupgrade_host={_quote(node.host)}")
        lines.append(f"uci set passwall.$sec.httpupgrade_path={_quote(node.path or '/')}")
    elif network in ("xhttp", "http"):
        # 上游规则：h2(http) 映射到 xhttp 时 mode 固定 stream-one，显式 xhttp 才取 mode/auto
        mode = "stream-one" if network == "http" else (params.get("mode") or "auto")
        lines.append(f"uci set passwall.$sec.xhttp_host={_quote(node.host)}")
        lines.append(f"uci set passwall.$sec.xhttp_path={_quote(node.path or '/')}")
        lines.append(f"uci set passwall.$sec.xhttp_mode={_quote(mode)}")
    elif network == "tcp" and params.get("header_type") == "http":
        lines.append("uci set passwall.$sec.tcp_guise='http'")
        lines.append(_add_list("tcp_guise_http_host", node.host))
        lines.append(_add_list("tcp_guise_http_path", node.path or "/"))
    elif network == "mkcp":
        lines.append(f"uci set passwall.$sec.mkcp_guise={_quote(params.get('header_type') or 'none')}")
        if params.get("seed"):
            lines.append(f"uci set passwall.$sec.mkcp_seed={_quote(params['seed'])}")
    elif network == "quic":
        lines.append(f"uci set passwall.$sec.quic_guise={_quote(params.get('header_type') or 'none')}")
        lines.append(f"uci set passwall.$sec.quic_security={_quote(params.get('quic_security') or 'none')}")
        if params.get("quic_key"):
            lines.append(f"uci set passwall.$sec.quic_key={_quote(params['quic_key'])}")
    return lines


def _tls_lines(node: ProxyNode, core: str) -> List[str]:
    params = node.params
    tls_required = node.tls or node.protocol in ("hysteria2", "anytls")
    if not tls_required:
        return ["uci set passwall.$sec.tls='0'"]

    lines = ["uci set passwall.$sec.tls='1'"]
    server_name = node.sni or node.host
    if server_name:
        lines.append(f"uci set passwall.$sec.tls_serverName={_quote(server_name)}")
    # 上游始终显式写入 0/1，避免继承全局默认值
    lines.append(f"uci set passwall.$sec.tls_allowInsecure={_quote('1' if node.allow_insecure else '0')}")
    if params.get("alpn"):
        lines.append(f"uci set passwall.$sec.alpn={_quote(params['alpn'])}")
    if params.get("fp"):
        lines.append("uci set passwall.$sec.utls='1'")
        lines.append(f"uci set passwall.$sec.fingerprint={_quote(params['fp'])}")
    if params.get("pin_sha256"):
        lines.append(f"uci set passwall.$sec.tls_pinSHA256={_quote(params['pin_sha256'])}")
    return lines


def _reality_lines(node: ProxyNode, core: str) -> List[str]:
    if not node.reality:
        return []
    params = node.params
    lines = [
        "uci set passwall.$sec.reality='1'",
        f"uci set passwall.$sec.reality_publicKey={_quote(params.get('pbk', ''))}",
        f"uci set passwall.$sec.reality_shortId={_quote(params.get('sid', ''))}",
    ]
    # sing-box 的 CBI 没有 spiderX 选项
    if core == TYPE_XRAY:
        lines.append(f"uci set passwall.$sec.reality_spiderX={_quote(params.get('spx') or '/')}")
    return lines


def _uci_node_block(node: ProxyNode, index: int) -> List[str]:
    core, protocol, transport = _passwall_profile(node)
    remarks = node.name.replace("\r", " ").replace("\n", " ")[:100] or f"node_{index}"

    lines = [
        f"# ---- #{index} [{node.protocol.upper()}] {remarks} ----",
        "sec=$(uci add passwall nodes)",
        f"uci set passwall.$sec.type={_quote(core)}",
        f"uci set passwall.$sec.protocol={_quote(protocol)}",
        f"uci set passwall.$sec.remarks={_quote(remarks)}",
        f"uci set passwall.$sec.address={_quote(node.address)}",
        f"uci set passwall.$sec.port={_quote(node.port)}",
        "uci set passwall.$sec.add_mode='1'",
        "uci set passwall.$sec.timeout='60'",
    ]
    if node.sub_name:
        lines.append(f"uci set passwall.$sec.group={_quote(node.sub_name)}")
    if core == TYPE_XRAY:
        # sing-box 的 CBI 无 tcp_fast_open 选项
        lines.append("uci set passwall.$sec.tcp_fast_open='1'")

    lines.extend(_credential_lines(node, protocol))
    if core == TYPE_XRAY:
        lines.extend(_transport_lines(node, transport or "raw"))
    lines.extend(_tls_lines(node, core))
    lines.extend(_reality_lines(node, core))

    lines.append("")
    return lines


def validate_node_fields(node: ProxyNode) -> List[str]:
    """导出前的字段体检，返回问题描述（空列表表示通过）

    目的：把“路由器上不生效”的风险提前暴露，而不是导入后才发现某个字段为空。
    """
    core, protocol, _ = _passwall_profile(node)
    params = node.params
    issues: List[str] = []

    if not node.address:
        issues.append("缺少 address")
    if not node.port:
        issues.append("缺少 port")
    if protocol in ("vless", "vmess") and not node.uuid:
        issues.append("缺少 uuid")
    if protocol in ("trojan", "shadowsocks") and not node.uuid:
        issues.append("缺少 password")
    if protocol == "hysteria2" and not node.uuid:
        issues.append("缺少 hysteria2_auth_password")
    if protocol == "anytls" and not node.uuid:
        issues.append("缺少 password")
    if protocol == "shadowsocks" and not params.get("method"):
        issues.append("缺少 method")
    if node.network == "ws" and not node.path:
        issues.append("WS 缺少 path（Passwall 侧会默认 /）")
    if node.network == "grpc" and not node.service_name:
        issues.append("gRPC 缺少 serviceName")
    if node.reality and not params.get("pbk"):
        issues.append("Reality 缺少 publicKey")
    if (node.tls or protocol in ("hysteria2", "anytls")) and not (node.sni or node.host):
        issues.append("TLS 缺少 serverName")
    if node.network in ("xhttp", "http") and not node.path:
        issues.append("XHTTP 缺少 path")
    return issues


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

    warnings: Dict[str, List[str]] = {}
    for node in ok_nodes:
        issues = validate_node_fields(node)
        if issues:
            warnings[node.name] = issues
            logger.warning("[%s] 导出字段不完整: %s", node.name, "; ".join(issues))

    uci_lines = [
        "#!/bin/sh",
        f"# OpenWrt Passwall 节点批量导入脚本（代理通 {len(ok_nodes)} 个，其中 Gemini 可用 {gemini_links} 个、提问成功 {chat_links} 个）",
        f"# 生成时间: {now_text}",
        "# 用法: 上传至路由器后执行 sh " + config.EXPORT_UCI_FILE,
        "# 说明: 脚本仅新增节点, 不会删除已有配置；字段命名对齐 passwall 上游 subscribe.lua",
        "#       add_mode=1 表示“导入”节点，便于在节点列表里与订阅节点区分",
        "",
    ]
    if warnings:
        uci_lines.append(f"# 注意: {len(warnings)} 个节点存在字段缺失，详见运行日志与 README 的字段体检说明")
        uci_lines.append("")

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
        "导出完成：全部 %d / 代理通 %d / Gemini 可用 %d / 提问成功 %d / 字段告警 %d",
        total_links,
        ok_links,
        gemini_links,
        chat_links,
        len(warnings),
    )
    return {
        "total": total_links,
        "available": ok_links,
        "gemini_available": gemini_links,
        "gemini_chat": chat_links,
        "nodes": ok_nodes,
        "gemini_nodes": gemini_nodes,
        "chat_nodes": chat_nodes,
        "warnings": warnings,
        "paths": {
            "all": str(all_path),
            "ok": str(ok_path),
            "b64": str(b64_path),
            "gemini": str(gemini_path),
            "gemini_chat": str(chat_path),
            "uci": str(uci_path),
        },
    }
