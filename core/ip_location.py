# -*- coding: utf-8 -*-
"""core/ip_location.py — IP 归属地查询
=====================================
数据来源：

1. 进程内缓存（同一 IP 只查询一次）
2. ipinfo.io API（可选 `IPINFO_TOKEN` 提升配额）
"""

from __future__ import annotations

import json
import logging
import threading
import urllib.parse
import urllib.request
from typing import Dict, Optional

from core import __version__, config

logger = logging.getLogger("vpn_check.ip_location")

_CACHE: Dict[str, Dict[str, str]] = {}
_CACHE_LOCK = threading.Lock()


def _query_ipinfo(ip: str) -> Dict[str, str]:
    """调用 ipinfo.io 获取归属地"""
    url = config.IPINFO_URL.format(ip=urllib.parse.quote(ip))
    if config.IPINFO_TOKEN:
        separator = "&" if "?" in url else "?"
        url = f"{url}{separator}token={urllib.parse.quote(config.IPINFO_TOKEN)}"
    request = urllib.request.Request(url, headers={"User-Agent": f"vpn_check/{__version__}"})
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


def get_location(ip: str) -> Dict[str, str]:
    """获取 IP 归属地信息（进程内缓存 + ipinfo 回源）"""
    if not ip:
        return {}
    with _CACHE_LOCK:
        cached = _CACHE.get(ip)
    if cached:
        return cached

    info: Dict[str, str] = {}
    try:
        info = _query_ipinfo(ip)
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
