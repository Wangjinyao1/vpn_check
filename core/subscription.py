# -*- coding: utf-8 -*-
"""core/subscription.py — 机场订阅拉取与流量识别
==============================================
- 多 UA / 多后端（urllib、curl_cffi 浏览器指纹、本地代理）容错拉取
- 解析 `Subscription-Userinfo` 标头，换算节余流量与到期时间
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Iterable, List, Optional, Tuple

from core import config
from core.clash import looks_like_clash_yaml, parse_clash_yaml
from core.models import ProxyNode, SubscriptionResult
from core.parsers import is_placeholder, parse_subscription_text

logger = logging.getLogger("vpn_check.subscription")

# 本地代理可用性缓存：同一进程内只探活一次，避免每次拉取都白等 2 秒
_PROXY_ALIVE: Dict[str, bool] = {}


def _format_bytes(size: float) -> str:
    units = (("TB", 1024 ** 4), ("GB", 1024 ** 3), ("MB", 1024 ** 2), ("KB", 1024))
    for unit, base in units:
        if size >= base:
            return f"{size / base:.2f} {unit}"
    return f"{size:.0f} B"


def parse_userinfo(header_value: str) -> Tuple[str, str]:
    """解析 Subscription-Userinfo，返回 (节余流量文本, 到期时间文本)"""
    if not header_value:
        return "", ""
    items: Dict[str, float] = {}
    for part in header_value.split(";"):
        key, sep, value = part.strip().partition("=")
        if not sep:
            continue
        try:
            items[key.strip().lower()] = float(value.strip())
        except ValueError:
            continue

    remaining_text = ""
    total = items.get("total", 0.0)
    if total > 0:
        used = items.get("upload", 0.0) + items.get("download", 0.0)
        remaining = max(0.0, total - used)
        remaining_text = f"{_format_bytes(remaining)} / {_format_bytes(total)}"

    expire_text = ""
    expire = items.get("expire", 0.0)
    if expire > 0:
        try:
            expire_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(expire))
        except (OverflowError, OSError, ValueError):
            expire_text = ""
    return remaining_text, expire_text


def _insecure_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch_urllib(url: str, user_agent: str, timeout: float) -> Tuple[bytes, str]:
    request = urllib.request.Request(url, headers={"User-Agent": user_agent})
    with urllib.request.urlopen(request, timeout=timeout, context=_insecure_context()) as response:
        return response.read(), response.headers.get("Subscription-Userinfo", "") or ""


def _fetch_curl(url: str, timeout: float, proxy: Optional[str] = None) -> Tuple[bytes, str]:
    from curl_cffi import requests as cffi_requests  # 延迟导入，缺少库时走 urllib 分支

    proxies = {"http": proxy, "https": proxy} if proxy else None
    response = cffi_requests.get(
        url,
        impersonate="chrome120",
        timeout=timeout,
        verify=False,
        proxies=proxies,
    )
    if response.status_code != 200 or not response.content:
        raise RuntimeError(f"HTTP {response.status_code}")
    return response.content, response.headers.get("Subscription-Userinfo", "") or ""


def _proxy_endpoint(proxy: str) -> Optional[Tuple[str, int]]:
    """从代理 URL 拆出 (host, port)，用于拉取前的 TCP 探活"""
    try:
        parsed = urllib.parse.urlsplit(proxy if "://" in proxy else f"http://{proxy}")
    except ValueError:
        return None
    host = parsed.hostname
    if not host:
        return None
    default_port = 1080 if (parsed.scheme or "").startswith("socks") else 8080
    return host, parsed.port or default_port


def _proxy_alive(proxy: str, timeout: float = 0.8) -> bool:
    """本地代理是否真的在监听——不通的直接跳过，避免每次空等超时"""
    cached = _PROXY_ALIVE.get(proxy)
    if cached is not None:
        return cached
    endpoint = _proxy_endpoint(proxy)
    alive = False
    if endpoint:
        try:
            with socket.create_connection(endpoint, timeout=timeout):
                alive = True
        except OSError:
            alive = False
    _PROXY_ALIVE[proxy] = alive
    if not alive:
        logger.debug("本地代理不可用，跳过: %s", proxy)
    return alive


def _download(url: str) -> Tuple[str, str]:
    """多策略拉取订阅正文，返回 (文本内容, Userinfo 标头)"""
    errors: List[str] = []

    for attempt in range(max(1, config.SUBSCRIBE_RETRY)):
        for user_agent in config.SUBSCRIBE_USER_AGENTS[:2]:
            try:
                payload, userinfo = _fetch_urllib(url, user_agent, config.SUBSCRIBE_TIMEOUT)
                text = payload.decode("utf-8", errors="replace")
                if text.strip():
                    return text, userinfo
            except Exception as exc:  # noqa: BLE001 - 网络异常类型繁多，统一降级
                errors.append(f"urllib: {exc}")
        if attempt + 1 < config.SUBSCRIBE_RETRY:
            time.sleep(1.0)

    try:
        payload, userinfo = _fetch_curl(url, config.SUBSCRIBE_TIMEOUT)
        return payload.decode("utf-8", errors="replace"), userinfo
    except Exception as exc:  # noqa: BLE001
        errors.append(f"curl_cffi: {exc}")

    for proxy in config.SUBSCRIPTION_PROXIES:
        if not _proxy_alive(proxy):
            continue
        try:
            payload, userinfo = _fetch_curl(url, min(config.SUBSCRIBE_TIMEOUT, 8.0), proxy)
            return payload.decode("utf-8", errors="replace"), userinfo
        except Exception as exc:  # noqa: BLE001
            errors.append(f"proxy {proxy}: {exc}")

    raise RuntimeError("; ".join(errors[-3:]) or "订阅响应为空")


def _uri_list_variant(url: str) -> str:
    """追加 flag=passwall 参数，请求机场返回 Passwall 可用的 URI 列表"""
    if "flag=passwall" in url:
        return ""
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}flag=passwall"


def _try_uri_list(url: str) -> Optional[Tuple[str, str]]:
    """Clash YAML 订阅的第二方案：带 flag=passwall 重新拉取 URI 列表"""
    variant = _uri_list_variant(url)
    if not variant:
        return None
    try:
        content, userinfo = _download(variant)
    except Exception as exc:  # noqa: BLE001 - 机场不支持该参数时静默回退
        logger.debug("flag=passwall 拉取失败: %s", _sanitize_error(exc, url))
        return None
    if not content.strip() or looks_like_clash_yaml(content) or content.lstrip().startswith("<"):
        return None
    return content, userinfo


def _looks_like_clash_yaml(text: str) -> bool:
    """兼容旧调用点"""
    return looks_like_clash_yaml(text)


def _sanitize_error(message: str, url: str) -> str:
    """从错误信息中抹除订阅地址与 token，避免日志/控制台泄露凭据"""
    text = str(message or "")
    if url:
        text = text.replace(url, "<订阅地址>")
    text = re.sub(r"(?i)(token=)[^&\s;'\"]+", r"\1***", text)
    text = re.sub(r"(?i)(/api/v1/client/)[A-Za-z0-9]+", r"\1***", text)
    return text[:500]


def fetch_subscription(name: str, url: str) -> SubscriptionResult:
    """拉取并解析单个订阅源（异常不外抛，结果中携带错误信息）"""
    started = time.time()
    result = SubscriptionResult(name=name, url=url)
    try:
        content, userinfo_raw = _download(url)
    except Exception as exc:  # noqa: BLE001
        result.error = _sanitize_error(exc, url)
        result.elapsed_s = round(time.time() - started, 2)
        logger.warning("[%s] 订阅拉取失败: %s", name, result.error)
        return result

    if _looks_like_clash_yaml(content):
        retry = _try_uri_list(url)
        if retry:
            content, userinfo_raw = retry
            logger.info("[%s] 订阅为 Clash YAML，已改用 flag=passwall 获取 URI 列表", name)
        else:
            nodes = [node for node in parse_clash_yaml(content, name, url) if not is_placeholder(node.name)]
            remaining, expire = parse_userinfo(userinfo_raw)
            for node in nodes:
                node.remaining_traffic = remaining
                node.expire_time = expire
            result.nodes = nodes
            result.remaining_traffic = remaining
            result.expire_time = expire
            result.elapsed_s = round(time.time() - started, 2)
            if not nodes:
                result.error = "订阅返回 Clash YAML，但未解析出受支持的节点"
                logger.warning("[%s] %s", name, result.error)
            else:
                logger.info("[%s] Clash YAML 解析成功：%d 个节点", name, len(nodes))
            return result

    if content.lstrip().startswith("<"):
        result.error = "订阅返回 HTML 页面（订阅可能已失效，或需要通过代理拉取）"
        result.elapsed_s = round(time.time() - started, 2)
        logger.warning("[%s] %s", name, result.error)
        return result

    remaining, expire = parse_userinfo(userinfo_raw)
    nodes = parse_subscription_text(content, name, url)

    for node in nodes:
        node.remaining_traffic = remaining
        node.expire_time = expire

    result.nodes = nodes
    result.remaining_traffic = remaining
    result.expire_time = expire
    result.elapsed_s = round(time.time() - started, 2)
    if not nodes:
        result.error = "订阅内容中未解析到受支持的节点"
        logger.warning("[%s] %s", name, result.error)
    return result


def fetch_all(items: Iterable[Dict[str, str]], workers: int = config.SUBSCRIBE_WORKERS) -> List[SubscriptionResult]:
    """并发拉取全部订阅源，保持配置顺序返回"""
    item_list = list(items)
    if not item_list:
        return []
    results: Dict[str, SubscriptionResult] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(item_list)))) as pool:
        futures = {
            pool.submit(fetch_subscription, item["name"], item["url"]): item for item in item_list
        }
        for future in as_completed(futures):
            item = futures[future]
            try:
                results[item["url"]] = future.result()
            except Exception as exc:  # noqa: BLE001
                results[item["url"]] = SubscriptionResult(
                    name=item["name"],
                    url=item["url"],
                    error=_sanitize_error(exc, item["url"]),
                )
    return [results[item["url"]] for item in item_list]


def collect_nodes(results: Iterable[SubscriptionResult]) -> List[ProxyNode]:
    """跨订阅汇总节点（同一节点仅保留首次出现的订阅归属）"""
    merged: List[ProxyNode] = []
    seen = set()
    for result in results:
        for node in result.nodes:
            fingerprint = node.fingerprint
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            merged.append(node)
    return merged
