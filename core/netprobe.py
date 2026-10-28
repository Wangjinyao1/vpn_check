# -*- coding: utf-8 -*-
"""core/netprobe.py — 轻量 SOCKS5 HTTP 探针
==========================================
不依赖 requests，直接通过本地内核 SOCKS5 端口完成 HTTP/HTTPS 探测，
返回状态码、首字节延迟与响应正文，供连通性分级与网页可用性判定使用。
"""

from __future__ import annotations

import json
import logging
import re
import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from core import config

logger = logging.getLogger("vpn_check.netprobe")

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
)

MAX_HEADER_BYTES = 16 * 1024
MAX_BODY_BYTES = 512 * 1024


@dataclass
class HttpResult:
    """一次 HTTP 探测结果"""

    status: int = 0
    latency_ms: float = 0.0
    headers: str = ""
    body: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status > 0 and not self.error


def _build_request(url: str, method: str, extra_headers: Optional[Dict[str, str]]) -> Tuple[str, str, int]:
    parsed = urllib.parse.urlsplit(url)
    if not parsed.hostname:
        raise ValueError(f"非法 URL: {url}")
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    default_port = 443 if parsed.scheme == "https" else 80
    host_header = host if port == default_port else f"{host}:{port}"
    if ":" in host and not host.startswith("["):
        host_header = f"[{host}]" if port == default_port else f"[{host}]:{port}"

    lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host_header}",
        f"User-Agent: {DEFAULT_UA}",
        "Accept: */*",
        "Accept-Language: zh-CN,zh;q=0.9,en;q=0.8",
        "Accept-Encoding: identity",
        "Connection: close",
    ]
    for key, value in (extra_headers or {}).items():
        if key.lower() in ("host", "connection", "content-length"):
            continue
        lines.append(f"{key}: {value}")
    return "\r\n".join(lines) + "\r\n\r\n", parsed.scheme, port


def _read_response(sock: socket.socket, read_body: bool) -> Tuple[str, bytes]:
    """读取响应头；read_body=True 时继续读取正文（有上限）"""
    buffer = bytearray()
    header_end = -1
    while header_end == -1:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buffer.extend(chunk)
        header_end = buffer.find(b"\r\n\r\n")
        if len(buffer) > MAX_HEADER_BYTES and header_end == -1:
            break

    if header_end == -1:
        return buffer.decode("latin-1", errors="replace"), b""

    raw_headers = bytes(buffer[:header_end]).decode("latin-1", errors="replace")
    body = bytearray(buffer[header_end + 4:])
    if read_body:
        while len(body) < MAX_BODY_BYTES:
            try:
                chunk = sock.recv(8192)
            except (socket.timeout, OSError):
                break
            if not chunk:
                break
            body.extend(chunk)
    return raw_headers, bytes(body)


def _decode_body(raw_headers: str, body: bytes) -> str:
    charset = "utf-8"
    match = re.search(r"charset=([\w\-]+)", raw_headers, re.I)
    if match:
        charset = match.group(1)
    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def socks5_http(
    socks_port: int,
    url: str,
    method: str = "HEAD",
    timeout: float = 6.0,
    read_body: bool = False,
    extra_headers: Optional[Dict[str, str]] = None,
) -> HttpResult:
    """经本地 SOCKS5 隧道发起 HTTP(S) 请求"""
    import socks  # PySocks

    started = time.time()
    conn: Optional[socket.socket] = None
    try:
        request_text, scheme, port = _build_request(url, method, extra_headers)
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname or ""

        raw_sock = socks.socksocket()
        raw_sock.set_proxy(socks.SOCKS5, "127.0.0.1", socks_port, rdns=True)
        raw_sock.settimeout(timeout)
        raw_sock.connect((host, port))

        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            conn = raw_sock

        conn.sendall(request_text.encode("latin-1", errors="replace"))
        raw_headers, body = _read_response(conn, read_body)
        latency_ms = round((time.time() - started) * 1000, 1)

        if not raw_headers.startswith("HTTP/"):
            return HttpResult(latency_ms=latency_ms, error="非法 HTTP 响应")

        status_line = raw_headers.split("\r\n", 1)[0]
        parts = status_line.split(" ", 2)
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        return HttpResult(
            status=status,
            latency_ms=latency_ms,
            headers=raw_headers,
            body=_decode_body(raw_headers, body) if body else "",
        )
    except Exception as exc:  # noqa: BLE001 - 网络异常类型繁多
        return HttpResult(
            latency_ms=round((time.time() - started) * 1000, 1),
            error=f"{type(exc).__name__}: {exc}",
        )
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass


def _parse_trace(text: str) -> Tuple[str, str]:
    ip_match = re.search(r"^ip=([0-9a-fA-F:.]+)$", text, re.M)
    loc_match = re.search(r"^loc=([A-Z]+)$", text, re.M)
    return (ip_match.group(1) if ip_match else "", loc_match.group(1) if loc_match else "")


def _trace_via_socket(socks_port: int, timeout: float) -> Tuple[str, str]:
    """纯 socket 实现 SOCKS5 + Cloudflare trace，无第三方依赖兜底"""
    try:
        sock = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
    except OSError as exc:
        logger.debug("连接本地 SOCKS5 失败: %s", exc)
        return "", ""
    try:
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        if sock.recv(2) != b"\x05\x00":
            return "", ""
        host = b"cloudflare.com"
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + (80).to_bytes(2, "big"))
        reply = sock.recv(10)
        if len(reply) < 4 or reply[1] != 0:
            return "", ""
        sock.sendall(
            b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: cloudflare.com\r\n"
            b"User-Agent: curl/8.5.0\r\nConnection: close\r\n\r\n"
        )
        chunks = []
        while True:
            data = sock.recv(2048)
            if not data:
                break
            chunks.append(data)
        return _parse_trace(b"".join(chunks).decode("utf-8", errors="ignore"))
    except OSError as exc:
        logger.debug("原生 SOCKS5 trace 探测失败: %s", exc)
        return "", ""
    finally:
        try:
            sock.close()
        except OSError:
            pass


def fetch_egress_ip(socks_port: int, timeout: float = config.EGRESS_TIMEOUT) -> Tuple[str, str]:
    """探测节点出海真实落地 IP 与 Cloudflare 地理码，返回 (ip, loc)"""
    try:
        from curl_cffi import requests as cffi_requests

        proxies = {
            "http": f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}",
        }
        response = cffi_requests.get(
            config.EGRESS_TRACE_URL, proxies=proxies, timeout=timeout, verify=False
        )
        if response.status_code == 200:
            ip, loc = _parse_trace(response.text)
            if ip:
                return ip, loc

        response = cffi_requests.get(
            config.EGRESS_FALLBACK_URL, proxies=proxies, timeout=timeout, verify=False
        )
        if response.status_code == 200:
            data = json.loads(response.text)
            if data.get("query"):
                return str(data["query"]), str(data.get("countryCode", ""))
    except Exception as exc:  # noqa: BLE001
        logger.debug("curl_cffi 探测落地 IP 失败: %s", exc)

    return _trace_via_socket(socks_port, timeout)


def fetch_html(
    socks_port: int,
    url: str,
    timeout: float,
    extra_headers: Optional[Dict[str, str]] = None,
) -> HttpResult:
    """GET 并读取正文（供 Gemini 无 curl_cffi 环境兜底使用）"""
    return socks5_http(
        socks_port, url, method="GET", timeout=timeout, read_body=True, extra_headers=extra_headers
    )


def fetch_via_socks(
    socks_port: int,
    url: str,
    timeout: float,
    read_body: bool = False,
    impersonate: str = "chrome120",
) -> HttpResult:
    """优先使用 curl_cffi 浏览器指纹经 SOCKS5 访问，失败时回退原生 socket

    Cloudflare 保护的站点（如 grok.com）会对原生 TLS 指纹直接断链，
    因此网页可用性探测必须使用真实浏览器指纹。
    """
    try:
        from curl_cffi import requests as cffi_requests

        proxy = f"socks5h://127.0.0.1:{socks_port}"
        session = cffi_requests.Session()
        session.proxies = {"http": proxy, "https": proxy}
        response = session.get(
            url,
            timeout=timeout,
            impersonate=impersonate,
            verify=False,
            allow_redirects=True,
        )
        return HttpResult(
            status=response.status_code,
            latency_ms=round(response.elapsed.total_seconds() * 1000, 1),
            headers=str(response.headers),
            body=(response.text or "") if read_body else "",
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("curl_cffi 站点探测失败(%s)，回退原生 socket: %s", url, exc)
        return socks5_http(socks_port, url, method="GET", timeout=timeout, read_body=read_body)
