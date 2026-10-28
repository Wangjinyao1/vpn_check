# -*- coding: utf-8 -*-
"""core/ip_location.py — IP 归属地查询（规范第 12 条）
=====================================================
统一归属地数据源优先级：

1. 通用缓存表 `ip_address_location`（跨项目共享、自动去重）
2. `check_ip_add_only.py` 官方实现（存在时直接复用其查询与入库逻辑）
3. ipinfo.io API 兜底，并将结果写回缓存表
"""

from __future__ import annotations

import importlib.util
import json
import logging
import threading
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, Optional

from core import config

logger = logging.getLogger("vpn_check.ip_location")

_CACHE: Dict[str, Dict[str, str]] = {}
_CACHE_LOCK = threading.Lock()
_HELPER_MODULE = None
_HELPER_LOADED = False


def _load_helper():
    """按需加载规范指定的 check_ip_add_only.py"""
    global _HELPER_MODULE, _HELPER_LOADED
    if _HELPER_LOADED:
        return _HELPER_MODULE
    _HELPER_LOADED = True
    if not config.IP_LOCATION_HELPER:
        logger.debug("未配置 IP_LOCATION_HELPER，使用内置归属地实现")
        return None
    path = Path(config.IP_LOCATION_HELPER).expanduser()
    if not path.exists():
        logger.debug("IP 归属地助手不存在，使用内置实现: %s", path)
        return None
    try:
        spec = importlib.util.spec_from_file_location("check_ip_add_only", str(path))
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            _HELPER_MODULE = module
            # 助手自带 stdout 日志会污染报表，统一改由 root 文件日志接管
            helper_logger = logging.getLogger("check_ip_add")
            helper_logger.handlers.clear()
            helper_logger.propagate = True
    except Exception as exc:  # noqa: BLE001
        logger.warning("加载 IP 归属地助手失败: %s", exc)
    return _HELPER_MODULE


def _query_ipinfo(ip: str) -> Dict[str, str]:
    """调用 ipinfo.io 获取归属地"""
    url = config.IPINFO_URL.format(ip=urllib.parse.quote(ip))
    if config.IPINFO_TOKEN:
        separator = "&" if "?" in url else "?"
        url = f"{url}{separator}token={urllib.parse.quote(config.IPINFO_TOKEN)}"
    request = urllib.request.Request(url, headers={"User-Agent": "vpn_check/8.0"})
    with urllib.request.urlopen(request, timeout=config.IP_LOCATION_TIMEOUT) as response:
        data = json.loads(response.read().decode("utf-8", errors="replace"))
    country = str(data.get("country", ""))
    region = str(data.get("region", ""))
    city = str(data.get("city", ""))
    parts = [part for part in (country, region, city) if part]
    return {
        "ip": ip,
        "country": country,
        "region": region,
        "city": city,
        "location": " ".join(parts),
        "org": str(data.get("org", "")),
        "loc": str(data.get("loc", "")),
        "source": "ipinfo",
    }


def _lookup_database(ip: str) -> Dict[str, str]:
    if not config.DB_ENABLED:
        return {}
    try:
        from core import database

        return database.lookup_ip_location(ip)
    except Exception as exc:  # noqa: BLE001
        logger.debug("查询归属地缓存失败 (%s): %s", ip, exc)
        return {}


def _store_database(info: Dict[str, str]) -> None:
    if not config.DB_ENABLED or not info.get("location"):
        return
    try:
        from core import database

        database.upsert_ip_location(info)
    except Exception as exc:  # noqa: BLE001
        logger.debug("写入归属地缓存失败 (%s): %s", info.get("ip"), exc)


def get_location(ip: str) -> Dict[str, str]:
    """获取 IP 归属地信息，未命中缓存时自动回源并写回"""
    if not ip:
        return {}
    with _CACHE_LOCK:
        cached = _CACHE.get(ip)
    if cached:
        return cached

    info: Dict[str, str] = {}

    helper = _load_helper()
    if helper is not None and hasattr(helper, "get_ip_location"):
        try:
            result = helper.get_ip_location(ip) or {}
            if result.get("location"):
                info = dict(result)
        except Exception as exc:  # noqa: BLE001
            logger.debug("助手查询归属地失败 (%s): %s", ip, exc)

    if not info:
        info = _lookup_database(ip)

    if not info:
        try:
            info = _query_ipinfo(ip)
            _store_database(info)
        except Exception as exc:  # noqa: BLE001
            logger.debug("ipinfo 查询失败 (%s): %s", ip, exc)

    if info:
        with _CACHE_LOCK:
            _CACHE[ip] = info
    return info


def format_location(info: Optional[Dict[str, str]]) -> str:
    """格式化为报表展示用的归属地文本"""
    if not info:
        return ""
    location = info.get("location", "").strip()
    if location:
        return location
    parts = [info.get(key, "") for key in ("country", "region", "city")]
    return " ".join(part for part in parts if part)
