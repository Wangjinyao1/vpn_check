# -*- coding: utf-8 -*-
"""core/engine.py — 真实内核隧道引擎
====================================
对齐 OpenWrt-Passwall 的节点运行方式：

- VLESS / VMess / Trojan / Shadowsocks → Xray-core
- AnyTLS / Hysteria2 / 带插件的 Shadowsocks → Sing-box
- 按协议与传输方式生成内核原生配置，本地随机高位端口暴露 SOCKS5
- 配置与日志写入 `.temp/temp_<core>_<port>.*`，退出即销毁
- 内核启动失败时捕获 stderr 日志，并支持切换备用内核重试
"""

from __future__ import annotations

import json
import logging
import re
import socket
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core import config
from core.models import CORE_SINGBOX, CORE_XRAY, ProxyNode
from core.netprobe import HttpResult, socks5_http

logger = logging.getLogger("vpn_check.engine")


class KernelError(RuntimeError):
    """内核启动或配置错误"""


def get_free_port() -> int:
    """获取本地空闲 TCP 端口"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def is_port_listening(port: int, timeout: float = 0.2) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# 内核版本探测（部分字段随版本变化）
# ---------------------------------------------------------------------------
_VERSION_CACHE: Dict[str, Tuple[int, int, int]] = {}


def core_version(core: str) -> Tuple[int, int, int]:
    if core in _VERSION_CACHE:
        return _VERSION_CACHE[core]
    binary = config.XRAY_PATH if core == CORE_XRAY else config.SINGBOX_PATH
    version: Tuple[int, int, int] = (0, 0, 0)
    try:
        completed = subprocess.run(
            [binary, "version"],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        match = re.search(r"(\d+)\.(\d+)\.(\d+)", completed.stdout + completed.stderr)
        if match:
            version = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    except Exception as exc:  # noqa: BLE001
        logger.debug("获取 %s 版本失败: %s", core, exc)
    _VERSION_CACHE[core] = version
    return version


def _binary_available(core: str) -> bool:
    path = config.XRAY_PATH if core == CORE_XRAY else config.SINGBOX_PATH
    return Path(path).exists()


def select_cores(node: ProxyNode) -> List[str]:
    """返回候选内核顺序（首选 + 备用），并过滤掉不存在的内核"""
    preferred = node.preferred_core
    candidates = [preferred]
    if config.ENABLE_CORE_FALLBACK:
        fallback = CORE_SINGBOX if preferred == CORE_XRAY else CORE_XRAY
        unsupported = (
            fallback == CORE_SINGBOX and node.network in ("xhttp", "mkcp", "quic")
        ) or (fallback == CORE_XRAY and node.protocol in ("anytls", "hysteria2"))
        if not unsupported:
            candidates.append(fallback)
    return [core for core in candidates if _binary_available(core)]


# ---------------------------------------------------------------------------
# Xray 配置
# ---------------------------------------------------------------------------
def _xray_stream_settings(node: ProxyNode) -> dict:
    network = node.network
    stream: dict = {"network": network, "security": "none"}
    major = core_version(CORE_XRAY)[0]

    if node.reality:
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName": node.sni or node.host or node.address,
            "fingerprint": node.params.get("fp") or "chrome",
            "publicKey": node.params.get("pbk", ""),
            "shortId": node.params.get("sid", ""),
            "spiderX": node.params.get("spx", "/"),
        }
    elif node.tls:
        stream["security"] = "tls"
        tls_settings: dict = {"serverName": node.sni or node.host or node.address}
        if node.params.get("fp"):
            tls_settings["fingerprint"] = node.params["fp"]
        if node.params.get("alpn"):
            tls_settings["alpn"] = [item for item in node.params["alpn"].split(",") if item]
        # Xray 26 起移除 allowInsecure，仅旧版本下发
        if node.allow_insecure and major < 26:
            tls_settings["allowInsecure"] = True
        stream["tlsSettings"] = tls_settings

    if network == "ws":
        stream["wsSettings"] = {"path": node.path or "/", "host": node.host or node.sni}
    elif network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": node.service_name,
            "multiMode": node.params.get("mode") == "multi",
        }
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": node.path or "/", "host": node.host}
    elif network == "http":
        stream["network"] = "xhttp"
        stream["xhttpSettings"] = {
            "mode": node.params.get("mode") or "auto",
            "path": node.path or "/",
            "host": node.host,
        }
    elif network == "xhttp":
        stream["xhttpSettings"] = {
            "mode": node.params.get("mode") or "auto",
            "path": node.path or "/",
            "host": node.host,
        }
    elif network == "mkcp":
        stream["kcpSettings"] = {
            "mtu": 1350,
            "tti": 50,
            "uplinkCapacity": 12,
            "downlinkCapacity": 100,
            "congestion": False,
            "readBufferSize": 2,
            "writeBufferSize": 2,
            "header": {"type": node.params.get("header_type") or "none"},
            "seed": node.params.get("seed", ""),
        }
    elif network == "quic":
        stream["quicSettings"] = {
            "security": node.params.get("quic_security") or "none",
            "key": node.params.get("quic_key", ""),
            "header": {"type": node.params.get("header_type") or "none"},
        }
    elif network == "tcp" and node.params.get("header_type") == "http":
        header = {
            "type": "http",
            "request": {
                "path": [node.path or "/"],
                "headers": {"Host": [node.host]} if node.host else {},
            },
        }
        if major >= 25:
            stream["rawSettings"] = {"header": header}
        else:
            stream["tcpSettings"] = {"header": header}

    return stream


def build_xray_config(node: ProxyNode, socks_port: int) -> dict:
    """生成 Xray-core 出站配置"""
    outbound: dict = {
        "tag": "proxy",
        "protocol": node.protocol,
        "streamSettings": _xray_stream_settings(node),
    }

    if node.protocol == "vless":
        user: dict = {"id": node.uuid, "encryption": node.params.get("encryption") or "none"}
        if node.params.get("flow"):
            user["flow"] = node.params["flow"]
        outbound["settings"] = {
            "vnext": [{"address": node.address, "port": node.port, "users": [user]}]
        }
    elif node.protocol == "vmess":
        outbound["settings"] = {
            "vnext": [
                {
                    "address": node.address,
                    "port": node.port,
                    "users": [
                        {
                            "id": node.uuid,
                            "alterId": int(node.params.get("alter_id") or 0),
                            "security": node.params.get("scy") or "auto",
                        }
                    ],
                }
            ]
        }
    elif node.protocol == "trojan":
        outbound["settings"] = {
            "servers": [{"address": node.address, "port": node.port, "password": node.uuid}]
        }
    elif node.protocol == "shadowsocks":
        outbound["settings"] = {
            "servers": [
                {
                    "address": node.address,
                    "port": node.port,
                    "method": node.params.get("method") or "aes-256-gcm",
                    "password": node.uuid,
                }
            ]
        }
    else:
        raise KernelError(f"Xray 不支持协议: {node.protocol}")

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
            }
        ],
        "outbounds": [outbound],
    }


# ---------------------------------------------------------------------------
# Sing-box 配置
# ---------------------------------------------------------------------------
def _singbox_tls(node: ProxyNode) -> Optional[dict]:
    if not (node.tls or node.protocol in ("anytls", "hysteria2")):
        return None
    tls: dict = {
        "enabled": True,
        "server_name": node.sni or node.host or node.address,
        "insecure": node.allow_insecure,
    }
    # Hysteria2 证书指纹：机场下发的 pcs/pin_sha256 是「证书哈希」，而 sing-box 只支持
    # 「公钥哈希」(certificate_public_key_sha256)，两者无法互算。直接下发会导致
    # "unrecognized remote public key" 而必然失败，因此改为跳过证书校验的降级策略。
    if node.protocol == "hysteria2" and node.params.get("pin_sha256") and config.HYSTERIA2_PIN_INSECURE:
        tls["insecure"] = True
        logger.debug("[%s] 检测到证书指纹，sing-box 无法校验证书哈希，降级为 insecure", node.name)
    if node.params.get("alpn"):
        tls["alpn"] = [item for item in node.params["alpn"].split(",") if item]
    if node.params.get("fp"):
        tls["utls"] = {"enabled": True, "fingerprint": node.params["fp"]}
    if node.reality:
        tls["reality"] = {
            "enabled": True,
            "public_key": node.params.get("pbk", ""),
            "short_id": node.params.get("sid", ""),
        }
    return tls


def _singbox_transport(node: ProxyNode) -> Optional[dict]:
    network = node.network
    if network == "ws":
        transport: dict = {"type": "ws", "path": node.path or "/"}
        if node.host:
            transport["headers"] = {"Host": node.host}
        return transport
    if network == "grpc":
        return {"type": "grpc", "service_name": node.service_name}
    if network == "http":
        transport = {"type": "http", "path": node.path or "/"}
        if node.host:
            transport["host"] = [node.host]
        return transport
    if network == "httpupgrade":
        return {"type": "httpupgrade", "path": node.path or "/", "host": node.host}
    return None


def _parse_port_ranges(raw: str) -> List[str]:
    """将 2000-3000,4000 解析为 sing-box server_ports 格式 2000:3000,4000"""
    ranges: List[str] = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        if "-" in item:
            start, _, end = item.partition("-")
            if start.isdigit() and end.isdigit():
                ranges.append(f"{start}:{end}")
        elif item.isdigit():
            ranges.append(item)
    return ranges


def build_singbox_config(node: ProxyNode, socks_port: int) -> dict:
    """生成 Sing-box 出站配置"""
    outbound: dict = {
        "type": node.protocol,
        "tag": "proxy",
        "server": node.address,
        "server_port": node.port,
    }
    tls = _singbox_tls(node)

    if node.protocol == "vless":
        outbound["uuid"] = node.uuid
        if node.params.get("flow"):
            outbound["flow"] = node.params["flow"]
        if tls:
            outbound["tls"] = tls
        transport = _singbox_transport(node)
        if transport:
            outbound["transport"] = transport
    elif node.protocol == "vmess":
        outbound.update(
            {
                "uuid": node.uuid,
                "security": node.params.get("scy") or "auto",
                "alter_id": int(node.params.get("alter_id") or 0),
            }
        )
        if tls:
            outbound["tls"] = tls
        transport = _singbox_transport(node)
        if transport:
            outbound["transport"] = transport
    elif node.protocol == "trojan":
        outbound["password"] = node.uuid
        if tls:
            outbound["tls"] = tls
        transport = _singbox_transport(node)
        if transport:
            outbound["transport"] = transport
    elif node.protocol == "shadowsocks":
        outbound.update(
            {
                "method": node.params.get("method") or "aes-256-gcm",
                "password": node.uuid,
            }
        )
        if node.params.get("plugin"):
            outbound["plugin"] = node.params["plugin"]
            if node.params.get("plugin_opts"):
                outbound["plugin_opts"] = node.params["plugin_opts"]
    elif node.protocol == "anytls":
        outbound.update(
            {
                "password": node.uuid,
                "idle_session_check_interval": "30s",
                "idle_session_timeout": "30s",
                "min_idle_session": 5,
            }
        )
        if core_version(CORE_SINGBOX) >= (1, 13, 16):
            outbound["client_metadata"] = "anytls/0.0.13"
        if tls:
            outbound["tls"] = tls
    elif node.protocol == "hysteria2":
        outbound["password"] = node.uuid
        for key in ("up_mbps", "down_mbps"):
            try:
                if node.params.get(key):
                    outbound[key] = int(float(node.params[key]))
            except ValueError:
                pass
        if node.params.get("obfs") and node.params.get("obfs_password"):
            outbound["obfs"] = {
                "type": node.params["obfs"],
                "password": node.params["obfs_password"],
            }
        ranges = _parse_port_ranges(node.params.get("ports", ""))
        if ranges:
            outbound.pop("server_port", None)
            outbound["server_ports"] = ranges
            match = re.match(r"(\d+)", node.params.get("hop_interval") or "30")
            outbound["hop_interval"] = f"{max(5, int(match.group(1)) if match else 30)}s"
        if tls:
            outbound["tls"] = tls
    else:
        raise KernelError(f"Sing-box 不支持协议: {node.protocol}")

    return {
        "log": {"level": "warn"},
        "inbounds": [
            {"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": socks_port}
        ],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        "route": {"rules": [{"inbound": ["socks-in"], "outbound": "proxy"}]},
    }


def build_config(node: ProxyNode, socks_port: int, core: str) -> dict:
    if core == CORE_SINGBOX:
        return build_singbox_config(node, socks_port)
    return build_xray_config(node, socks_port)


# ---------------------------------------------------------------------------
# 隧道生命周期
# ---------------------------------------------------------------------------
class KernelTunnel:
    """单节点真实内核隧道上下文管理器"""

    def __init__(self, node: ProxyNode, core: str):
        self.node = node
        self.core = core
        self.port = get_free_port()
        self.binary = config.XRAY_PATH if core == CORE_XRAY else config.SINGBOX_PATH
        config.TEMP_DIR.mkdir(parents=True, exist_ok=True)
        self.config_path = config.TEMP_DIR / f"temp_{core}_{self.port}.json"
        self.log_path = config.TEMP_DIR / f"temp_{core}_{self.port}.log"
        self.proc: Optional[subprocess.Popen] = None
        self.last_error = ""
        self._log_handle = None

    def __enter__(self) -> "KernelTunnel":
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()

    def start(self) -> bool:
        if not Path(self.binary).exists():
            self.last_error = f"内核二进制不存在: {self.binary}"
            return False
        try:
            payload = build_config(self.node, self.port, self.core)
        except (KernelError, ValueError) as exc:
            self.last_error = str(exc)
            return False

        with open(self.config_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)

        command = (
            [self.binary, "run", "-c", str(self.config_path)]
            if self.core == CORE_SINGBOX
            else [self.binary, "run", "-config", str(self.config_path)]
        )
        try:
            self._log_handle = open(self.log_path, "w", encoding="utf-8")
            self.proc = subprocess.Popen(
                command,
                stdout=self._log_handle,
                stderr=subprocess.STDOUT,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception as exc:  # noqa: BLE001
            self.last_error = f"内核启动异常: {exc}"
            self._cleanup()
            return False

        deadline = time.time() + config.KERNEL_START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                self.last_error = self._read_log_tail() or f"{self.core} 进程提前退出"
                self._cleanup()
                return False
            if is_port_listening(self.port):
                return True
            time.sleep(0.08)

        self.last_error = f"{self.core} SOCKS5 端口就绪超时"
        self.stop()
        return False

    def stop(self) -> None:
        if self.proc is not None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=config.KERNEL_STOP_TIMEOUT)
            except Exception:  # noqa: BLE001
                try:
                    self.proc.kill()
                except Exception:  # noqa: BLE001
                    pass
            self.proc = None
        self._cleanup()

    def _read_log_tail(self, lines: int = 8) -> str:
        try:
            if self.log_path.exists():
                content = self.log_path.read_text(encoding="utf-8", errors="replace").strip()
                if content:
                    return " | ".join(content.splitlines()[-lines:])[:400]
        except OSError:
            pass
        return ""

    def _cleanup(self) -> None:
        if self._log_handle is not None:
            try:
                self._log_handle.close()
            except OSError:
                pass
            self._log_handle = None
        for path in (self.config_path, self.log_path):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass

    def request(self, url: str, method: str = "HEAD", timeout: float = 6.0) -> HttpResult:
        return socks5_http(self.port, url, method=method, timeout=timeout)
