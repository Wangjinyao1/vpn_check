# -*- coding: utf-8 -*-
"""core/speedtest.py — 节点测速
================================
经节点自己的本地 SOCKS5 隧道测量吞吐与时延，指标对齐 Speedtest CLI（Ookla）：
ping / jitter / download / upload。

两种测速引擎（`SPEEDTEST_PROVIDER`）：

- `ookla`：调用官方 Speedtest CLI，通过 `HTTPS_PROXY=socks5://127.0.0.1:<端口>`
  让 CLI 走当前节点隧道，直接解析 `speedtest -f json` 结果
- `builtin`：纯 Python 经 SOCKS5 采样（ping 抖动 + 定量下载 + 可选上传），
  下载采样到 `SPEEDTEST_DOWNLOAD_BYTES` / `SPEEDTEST_DOWNLOAD_TIMEOUT` 即停止，
  统计窗口取「首字节到达 → 采样结束」，剔除握手与 TLS 建链耗时
- `auto`（默认）：检测到官方 CLI 用 Ookla，否则回退内置实现
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import ssl
import subprocess
import time
import urllib.parse
from pathlib import Path
from typing import List, Tuple

from core import config
from core.models import SpeedResult

logger = logging.getLogger("vpn_check.speedtest")

MB_BITS = 1_000_000.0
CHUNK_SIZE = 64 * 1024
USER_AGENT = "curl/8.5.0"


def mbps(byte_count: int, seconds: float) -> float:
    """字节数 / 时长 → Mbps（1 Mbps = 1e6 bit/s，保留两位小数）"""
    if byte_count <= 0 or seconds <= 0:
        return 0.0
    return round(byte_count * 8 / seconds / MB_BITS, 2)


def format_speed(value: float) -> str:
    """测速展示：0 表示未测/失败"""
    if value <= 0:
        return "-"
    if value >= 100:
        return f"{value:.0f} Mbps"
    if value >= 10:
        return f"{value:.1f} Mbps"
    return f"{value:.2f} Mbps"


def _format_url(template: str, size: int) -> str:
    """替换模板中的 {bytes} 占位符"""
    if "{bytes}" in template:
        return template.replace("{bytes}", str(size))
    return template


def _ookla_binary() -> str:
    """定位官方 Speedtest CLI：显式路径 > bin/ > PATH"""
    if config.SPEEDTEST_BIN:
        return config.SPEEDTEST_BIN if Path(config.SPEEDTEST_BIN).exists() else ""
    for name in ("speedtest.exe", "speedtest"):
        candidate = config.BASE_DIR / "bin" / name
        if candidate.exists():
            if not config.IS_WINDOWS:
                try:
                    os.chmod(candidate, 0o755)
                except OSError:
                    pass
            return str(candidate)
    return shutil.which("speedtest") or ""


def resolved_provider() -> str:
    """实际生效的测速引擎：ookla / builtin"""
    if config.SPEEDTEST_PROVIDER in ("ookla", "auto") and _ookla_binary():
        return "ookla"
    return "builtin"


def parse_ookla_output(text: str) -> SpeedResult:
    """解析 `speedtest -f json` 的输出（bandwidth 单位为 bytes/s）"""
    payload = json.loads(text)
    if not isinstance(payload, dict) or payload.get("type") != "result":
        raise ValueError("不是 Speedtest CLI 结果 JSON")

    ping = payload.get("ping") or {}
    download = payload.get("download") or {}
    upload = payload.get("upload") or {}
    server = payload.get("server") or {}
    result_url = payload.get("result") or {}

    server_name = str(server.get("name") or "")
    server_location = str(server.get("location") or "")
    result = SpeedResult(
        provider="ookla",
        download_mbps=round(float(download.get("bandwidth") or 0) * 8 / MB_BITS, 2),
        upload_mbps=round(float(upload.get("bandwidth") or 0) * 8 / MB_BITS, 2),
        downloaded_bytes=int(download.get("bytes") or 0),
        uploaded_bytes=int(upload.get("bytes") or 0),
        download_ms=round(float(download.get("elapsed") or 0), 1),
        upload_ms=round(float(upload.get("elapsed") or 0), 1),
        ping_ms=round(float(ping.get("latency") or 0), 2),
        jitter_ms=round(float(ping.get("jitter") or 0), 2),
        server=f"{server_name} ({server_location})" if server_name and server_location else (server_name or server_location),
        url=str(result_url.get("url") or ""),
    )
    if result.download_mbps <= 0:
        result.error = "Speedtest 返回的下载速率为空"
    return result


def _ookla_speed(socks_port: int, timeout: float) -> SpeedResult:
    """调用官方 Speedtest CLI，经 HTTPS_PROXY 环境变量走节点隧道"""
    binary = _ookla_binary()
    if not binary:
        return SpeedResult(provider="ookla", error="未找到 speedtest CLI 二进制")

    proxy = f"socks5://127.0.0.1:{socks_port}"
    env = dict(os.environ)
    env.update(
        {
            "HTTP_PROXY": proxy,
            "HTTPS_PROXY": proxy,
            "ALL_PROXY": proxy,
            "http_proxy": proxy,
            "https_proxy": proxy,
            "all_proxy": proxy,
            "NO_PROXY": "",
            "no_proxy": "",
        }
    )
    command = [binary, "--accept-license", "--accept-gdpr", "-f", "json", "-p", "no"]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired:
        return SpeedResult(provider="ookla", error=f"Speedtest CLI 超时（{timeout:.0f}s）")
    except Exception as exc:  # noqa: BLE001
        return SpeedResult(provider="ookla", error=f"{type(exc).__name__}: {exc}")

    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip().splitlines()
        return SpeedResult(
            provider="ookla",
            error=f"Speedtest CLI 退出码 {completed.returncode}: {detail[-1] if detail else '无输出'}",
        )
    try:
        return parse_ookla_output(completed.stdout)
    except Exception as exc:  # noqa: BLE001
        return SpeedResult(provider="ookla", error=f"Speedtest 结果解析失败: {exc}")


def _tcp_ping(socks_port: int, host: str, port: int, rounds: int, timeout: float) -> Tuple[float, float]:
    """经 SOCKS5 多次 TCP 握手，返回 (平均延迟 ms, 抖动 ms)"""
    import socks  # PySocks

    samples: List[float] = []
    for _ in range(max(rounds, 1)):
        started = time.monotonic()
        raw_sock = None
        try:
            raw_sock = socks.socksocket()
            raw_sock.set_proxy(socks.SOCKS5, "127.0.0.1", socks_port, rdns=True)
            raw_sock.settimeout(timeout)
            raw_sock.connect((host, port))
            samples.append((time.monotonic() - started) * 1000)
        except Exception as exc:  # noqa: BLE001 - 单次失败不影响其余样本
            logger.debug("ping 采样失败(%s:%s): %s", host, port, exc)
        finally:
            if raw_sock is not None:
                try:
                    raw_sock.close()
                except OSError:
                    pass

    if not samples:
        return 0.0, 0.0
    average = sum(samples) / len(samples)
    if len(samples) > 1:
        jitter = sum(abs(b - a) for a, b in zip(samples, samples[1:])) / (len(samples) - 1)
    else:
        jitter = 0.0
    return round(average, 2), round(jitter, 2)


def _download_via_curl(socks_port: int, url: str, timeout: float, max_bytes: int) -> Tuple[int, float, str]:
    """curl_cffi 流式下载，返回 (采样字节数, 传输窗口秒数, 错误)"""
    from curl_cffi import requests as cffi_requests

    proxy = f"socks5h://127.0.0.1:{socks_port}"
    session = cffi_requests.Session()
    session.proxies = {"http": proxy, "https": proxy}
    response = None
    received = 0
    first_byte_at = 0.0
    started = time.monotonic()
    deadline = started + timeout
    try:
        response = session.get(
            url,
            stream=True,
            timeout=timeout,
            impersonate="chrome120",
            verify=False,
            allow_redirects=True,
        )
        if response.status_code >= 400:
            return 0, 0.0, f"HTTP {response.status_code}"
        for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
            if not chunk:
                continue
            now = time.monotonic()
            if first_byte_at == 0.0:
                first_byte_at = now
            received += len(chunk)
            if received >= max_bytes or now >= deadline:
                break
    except Exception as exc:  # noqa: BLE001 - 网络异常类型繁多
        return received, 0.0, f"{type(exc).__name__}: {exc}"
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:  # noqa: BLE001
                pass
        try:
            session.close()
        except Exception:  # noqa: BLE001
            pass

    if received <= 0:
        return 0, 0.0, "未收到测速数据"
    window = max(time.monotonic() - (first_byte_at or started), config.SPEEDTEST_WINDOW_FLOOR)
    return received, window, ""


def _download_via_socket(socks_port: int, url: str, timeout: float, max_bytes: int) -> Tuple[int, float, str]:
    """原生 SOCKS5 + socket 下载兜底，返回 (采样字节数, 传输窗口秒数, 错误)"""
    import socks  # PySocks

    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or ""
    if not host:
        return 0, 0.0, f"非法测速地址: {url}"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    raw_sock = None
    conn = None
    try:
        raw_sock = socks.socksocket()
        raw_sock.set_proxy(socks.SOCKS5, "127.0.0.1", socks_port, rdns=True)
        raw_sock.settimeout(timeout)
        raw_sock.connect((host, port))
        if parsed.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            conn = raw_sock

        request_text = (
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n"
            "Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
        )
        conn.sendall(request_text.encode("latin-1", errors="replace"))

        buffer = bytearray()
        while b"\r\n\r\n" not in buffer:
            chunk = conn.recv(4096)
            if not chunk:
                return 0, 0.0, "响应头不完整"
            buffer.extend(chunk)

        header_end = buffer.find(b"\r\n\r\n")
        raw_headers = bytes(buffer[:header_end]).decode("latin-1", errors="replace")
        status_line = raw_headers.split("\r\n", 1)[0]
        parts = status_line.split(" ", 2)
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        if status >= 400 or status == 0:
            return 0, 0.0, f"HTTP {status or '非法响应'}"

        body = buffer[header_end + 4:]
        received = len(body)
        first_byte_at = time.monotonic()
        deadline = first_byte_at + timeout
        while received < max_bytes and time.monotonic() < deadline:
            chunk = conn.recv(CHUNK_SIZE)
            if not chunk:
                break
            received += len(chunk)

        if received <= 0:
            return 0, 0.0, "未收到测速数据"
        window = max(time.monotonic() - first_byte_at, config.SPEEDTEST_WINDOW_FLOOR)
        return received, window, ""
    except Exception as exc:  # noqa: BLE001 - 网络异常类型繁多
        return 0, 0.0, f"{type(exc).__name__}: {exc}"
    finally:
        for sock in (conn, raw_sock):
            if sock is None:
                continue
            try:
                sock.close()
            except OSError:
                pass


def download_speed(
    socks_port: int,
    timeout: float = config.SPEEDTEST_DOWNLOAD_TIMEOUT,
    max_bytes: int = config.SPEEDTEST_DOWNLOAD_BYTES,
) -> Tuple[float, int, float, str, str]:
    """逐地址尝试下载测速，返回 (Mbps, 采样字节, 窗口毫秒, 命中地址, 错误)"""
    last_error = ""
    for template in config.SPEEDTEST_URLS:
        url = _format_url(template, max_bytes)
        received, window, error = _download_via_curl(socks_port, url, timeout, max_bytes)
        if error:
            logger.debug("curl_cffi 测速失败(%s)，回退原生 socket: %s", url, error)
            received, window, error = _download_via_socket(socks_port, url, timeout, max_bytes)
        if not error and received > 0:
            return mbps(received, window), received, round(window * 1000, 1), url, ""
        last_error = error or "测速失败"
    return 0.0, 0, 0.0, "", last_error


def upload_speed(
    socks_port: int,
    timeout: float = config.SPEEDTEST_UPLOAD_TIMEOUT,
    size: int = config.SPEEDTEST_UPLOAD_BYTES,
) -> Tuple[float, int, float, str]:
    """上传测速（默认关闭），返回 (Mbps, 上传字节, 耗时毫秒, 错误)"""
    from curl_cffi import requests as cffi_requests

    proxy = f"socks5h://127.0.0.1:{socks_port}"
    session = cffi_requests.Session()
    session.proxies = {"http": proxy, "https": proxy}
    payload = b"\x00" * max(size, 1)
    started = time.monotonic()
    try:
        response = session.post(
            config.SPEEDTEST_UPLOAD_URL,
            data=payload,
            headers={"Content-Type": "application/octet-stream"},
            timeout=timeout,
            impersonate="chrome120",
            verify=False,
        )
        if response.status_code >= 400:
            return 0.0, 0, 0.0, f"HTTP {response.status_code}"
    except Exception as exc:  # noqa: BLE001 - 网络异常类型繁多
        return 0.0, 0, 0.0, f"{type(exc).__name__}: {exc}"
    finally:
        try:
            session.close()
        except Exception:  # noqa: BLE001
            pass

    elapsed = max(time.monotonic() - started, config.SPEEDTEST_WINDOW_FLOOR)
    return mbps(size, elapsed), size, round(elapsed * 1000, 1), ""


def _builtin_speed(socks_port: int, upload: bool = False) -> SpeedResult:
    """内置实现：ping / jitter + 定量下载 + 可选上传"""
    result = SpeedResult(provider="builtin")
    try:
        value, received, window_ms, url, error = download_speed(socks_port)
        result.download_mbps = value
        result.downloaded_bytes = received
        result.download_ms = window_ms
        result.url = url
        result.error = error
        if value > 0:
            parsed = urllib.parse.urlsplit(url)
            host = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if host:
                result.ping_ms, result.jitter_ms = _tcp_ping(
                    socks_port,
                    host,
                    port,
                    config.SPEEDTEST_PINGS,
                    min(config.SPEEDTEST_DOWNLOAD_TIMEOUT, 5.0),
                )
        if value > 0 and upload:
            up_mbps, up_bytes, up_ms, up_error = upload_speed(socks_port)
            result.upload_mbps = up_mbps
            result.uploaded_bytes = up_bytes
            result.upload_ms = up_ms
            if up_error:
                result.error = f"上传测速失败: {up_error}"
    except Exception as exc:  # noqa: BLE001 - 测速失败不影响节点主判定
        logger.debug("节点测速异常: %s", exc)
        result.error = f"{type(exc).__name__}: {exc}"
    return result


def measure_speed(socks_port: int, upload: bool = False) -> SpeedResult:
    """对已建立的 SOCKS5 隧道执行测速，异常一律收敛为 SpeedResult

    引擎选择：`ookla` 优先调用官方 CLI；失败或不可用时回退内置实现。
    """
    provider = config.SPEEDTEST_PROVIDER
    if provider in ("ookla", "auto") and _ookla_binary():
        result = _ookla_speed(socks_port, config.SPEEDTEST_OOKLA_TIMEOUT)
        if result.download_mbps > 0:
            return result
        logger.warning("Speedtest CLI 测速失败，回退内置实现: %s", result.error)
    elif provider == "ookla":
        logger.warning("未找到 Speedtest CLI 二进制，回退内置实现")
    return _builtin_speed(socks_port, upload=upload)
