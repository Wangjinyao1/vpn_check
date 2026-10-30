# -*- coding: utf-8 -*-
"""core/gemini.py — Gemini 深度检测引擎
======================================
融合两条开源实现的关键判据：

1. `xykt/RegionRestrictionCheck` 免登录判定
   - 解析 Google 前端下发的特性开关 `45631641`（true/false）
   - 正则提取 Google GeoIP 判定的三位国家/地区码

2. `MatinSenPai/Gemini-Config-Checker` 三阶评估
   - Generative Language API 连通性探针
   - Google AI Studio 重定向封锁判定
   - Gemini Web App 地区封锁文本判定
   - 配置 Cookie 后执行真实 StreamGenerate 提问，验证能否正常对话
"""

from __future__ import annotations

import json
import logging
import re
import time
import urllib.parse
from typing import List, Optional, Tuple

from core import config
from core.models import GeminiVerdict
from core.netprobe import fetch_html, socks5_http

logger = logging.getLogger("vpn_check.gemini")

try:
    from curl_cffi import requests as cffi_requests

    HAS_CURL_CFFI = True
except Exception:  # noqa: BLE001 - 缺少库时降级为原生 socket 探针
    cffi_requests = None
    HAS_CURL_CFFI = False

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

STUDIO_BLOCK_MARKERS = ("available-region", "available_regions", "unsupported_country")
STUDIO_SIGNIN_MARKERS = ("accounts.google.com", "/welcome")


def extract_region_code(html: str) -> str:
    """提取 Google GeoIP 识别的三位地区码（如 USA / JPN / HKG）"""
    if not html:
        return ""
    match = re.search(config.GEMINI_REGION_CODE_PATTERN, html)
    return match.group(1) if match else ""


def extract_feature_flag(html: str) -> Optional[bool]:
    """解析 Gemini 可用性特性开关 45631641 的布尔值"""
    if not html:
        return None
    match = re.search(config.GEMINI_FEATURE_FLAG_PATTERN, html, re.I)
    if not match:
        return None
    return match.group(1).lower() == "true"


def detect_region_block(html: str) -> str:
    """扫描页面文本中的地区封锁特征，返回命中的关键词"""
    if not html:
        return ""
    lowered = html.lower()
    for keyword in config.GEMINI_REGION_BLOCK_KEYWORDS:
        if keyword.lower() in lowered:
            return keyword
    return ""


def evaluate_region(html: str) -> Tuple[bool, str, Optional[bool]]:
    """免登录可用性综合判定，返回 (是否可用, 地区码, 特性开关)"""
    region_code = extract_region_code(html)
    feature_flag = extract_feature_flag(html)
    available = feature_flag is True and region_code not in config.GEMINI_BLOCKED_REGIONS
    return available, region_code, feature_flag


# ---------------------------------------------------------------------------
# 流式回复解析
# ---------------------------------------------------------------------------
def _walk_strings(data: object, sink: List[str], depth: int = 0) -> None:
    if depth > 8:
        return
    if isinstance(data, str):
        stripped = data.strip()
        # Gemini 会把内层帧再序列化成字符串，优先递归解析出真实文本
        if stripped[:1] in ("[", "{") and len(stripped) < 200_000:
            try:
                _walk_strings(json.loads(stripped), sink, depth + 1)
                return
            except json.JSONDecodeError:
                pass
        if data:
            sink.append(data)
    elif isinstance(data, list):
        for item in data:
            _walk_strings(item, sink, depth + 1)
    elif isinstance(data, dict):
        for item in data.values():
            _walk_strings(item, sink, depth + 1)


def extract_reply_text(raw: str) -> str:
    """从 StreamGenerate 的流式帧中抽取模型回复文本"""
    if not raw:
        return ""
    candidates: List[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("["):
            try:
                _walk_strings(json.loads(line), candidates)
            except json.JSONDecodeError:
                continue
        elif len(line) < 4000 and not line.startswith(")]}'"):
            candidates.append(line)

    usable = [
        item
        for item in candidates
        if item
        and not item.startswith("http")
        and item.lower() not in ("generic", "en", "zh-cn", "null")
        and len(item) <= 600
    ]
    if not usable:
        return ""
    expected = config.GEMINI_CHAT_EXPECT
    for item in usable:
        if expected and expected in item:
            return item
    return max(usable, key=len)


def _build_chat_payload(question: str) -> str:
    """构造 Gemini Web 前端要求的 81 位 f.req 结构"""
    inner = json.dumps(
        [[question, 0, None, [], None, None, 0], ["zh-CN"]], ensure_ascii=False
    )
    struct: List[object] = [None, inner]
    struct.extend([None] * (81 - len(struct)))
    return json.dumps(struct, ensure_ascii=False)


def _extract_session_tokens(html: str) -> Tuple[str, str]:
    at_match = re.search(r'["\']SNlM0e["\']\s*:\s*["\']([^"\']+)["\']', html)
    bl_match = re.search(r'["\']cfb2h["\']\s*:\s*["\']([^"\']+)["\']', html)
    at_token = at_match.group(1) if at_match else ""
    bl_version = bl_match.group(1) if bl_match else "boq_assistant-bard-web-server_20240826.08_p0"
    return at_token, bl_version


# ---------------------------------------------------------------------------
# 主检测流程
# ---------------------------------------------------------------------------
def check_gemini(socks_port: int, do_chat: bool = True) -> GeminiVerdict:
    """对指定 SOCKS5 隧道执行 Gemini 三阶检测"""
    verdict = GeminiVerdict()
    proxy_url = f"socks5h://127.0.0.1:{socks_port}"
    cookies = {}
    if config.GEMINI_1PSID:
        cookies["__Secure-1PSID"] = config.GEMINI_1PSID
    if config.GEMINI_1PSIDTS:
        cookies["__Secure-1PSIDTS"] = config.GEMINI_1PSIDTS

    session = None
    if HAS_CURL_CFFI:
        session = cffi_requests.Session()
        session.proxies = {"http": proxy_url, "https": proxy_url}

    # ---- 阶段一：Generative Language API 连通性 ----
    try:
        if session is not None:
            response = session.get(config.GEMINI_API_REACH_URL, timeout=8.0, impersonate="chrome120")
            status = response.status_code
        else:
            status = socks5_http(socks_port, config.GEMINI_API_REACH_URL, "GET", 8.0).status
        # 400/403 表示已到达 Google API 网关（仅密钥无效），说明链路未被拦截
        verdict.api_reach_ok = status in (200, 400, 403)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Google API 探针异常: %s", exc)

    # ---- 阶段二：Google AI Studio 地区限制 ----
    try:
        if session is not None:
            studio = session.get(
                config.GEMINI_STUDIO_URL,
                headers=BROWSER_HEADERS,
                cookies=cookies,
                timeout=config.SITE_TIMEOUT,
                impersonate="chrome120",
            )
            final_url = str(studio.url).lower()
            studio_text = studio.text.lower()
            studio_status = studio.status_code
        else:
            result = socks5_http(
                socks_port, config.GEMINI_STUDIO_URL, "GET", config.SITE_TIMEOUT,
                read_body=True, extra_headers=BROWSER_HEADERS,
            )
            final_url = config.GEMINI_STUDIO_URL
            studio_text = result.body.lower()
            studio_status = result.status

        if any(marker in final_url or marker in studio_text for marker in STUDIO_BLOCK_MARKERS):
            verdict.studio_status = "blocked"
        elif any(marker in final_url for marker in STUDIO_SIGNIN_MARKERS):
            verdict.studio_status = "signin"
        elif studio_status in (200, 302, 304):
            verdict.studio_status = "ok"
        else:
            verdict.studio_status = f"http_{studio_status}"
    except Exception as exc:  # noqa: BLE001
        logger.debug("AI Studio 探测异常: %s", exc)
        verdict.studio_status = "error"

    # ---- 阶段三：Gemini Web App 地区封锁 ----
    html = ""
    try:
        if session is not None:
            page = session.get(
                config.GEMINI_APP_URL,
                headers=BROWSER_HEADERS,
                cookies=cookies,
                timeout=config.SITE_TIMEOUT,
                impersonate="chrome120",
            )
            html = page.text or ""
            verdict.http_code = page.status_code
            verdict.access_ms = round(page.elapsed.total_seconds() * 1000, 1)
            final_url = str(page.url).lower()
        else:
            result = fetch_html(
                socks_port, config.GEMINI_APP_URL, config.SITE_TIMEOUT, BROWSER_HEADERS
            )
            html = result.body
            verdict.http_code = result.status
            verdict.access_ms = result.latency_ms
            final_url = config.GEMINI_APP_URL
            if result.error:
                verdict.error = result.error
    except Exception as exc:  # noqa: BLE001
        verdict.gemini_status = "error"
        verdict.error = f"访问异常: {exc}"
        return verdict

    verdict.region_code = extract_region_code(html)
    verdict.feature_flag = extract_feature_flag(html)

    # Cookie 失效不等于节点不可用：降级为免登录判定，仅标记提问不可用
    if cookies and "accounts.google.com" in final_url:
        verdict.cookie_invalid = True
        logger.warning("Gemini Cookie 已失效，降级为免登录地区判定")
        try:
            if session is not None:
                page = session.get(
                    config.GEMINI_APP_URL,
                    headers=BROWSER_HEADERS,
                    timeout=config.SITE_TIMEOUT,
                    impersonate="chrome120",
                )
                html = page.text or ""
                verdict.http_code = page.status_code
                verdict.access_ms = round(page.elapsed.total_seconds() * 1000, 1)
                final_url = str(page.url).lower()
                verdict.region_code = extract_region_code(html)
                verdict.feature_flag = extract_feature_flag(html)
        except Exception as exc:  # noqa: BLE001
            logger.debug("免登录重试失败: %s", exc)

    if verdict.region_code in config.GEMINI_BLOCKED_REGIONS:
        verdict.gemini_status = "blocked"
        verdict.region_blocked = True
        verdict.region_reason = f"Google 识别地区不受支持 ({verdict.region_code})"
        verdict.error = verdict.region_reason
        return verdict

    if any(marker in final_url for marker in ("available-region", "unsupported", "unavailable")):
        verdict.gemini_status = "blocked"
        verdict.region_blocked = True
        verdict.region_reason = "重定向至地区受限页面"
        verdict.error = verdict.region_reason
        return verdict

    block_keyword = detect_region_block(html)
    if block_keyword:
        verdict.gemini_status = "blocked"
        verdict.region_blocked = True
        verdict.region_reason = f"命中地区封锁提示: {block_keyword}"
        verdict.error = verdict.region_reason
        return verdict

    if verdict.feature_flag is False:
        verdict.gemini_status = "blocked"
        verdict.region_blocked = True
        verdict.region_reason = f"区域特性开关关闭 ({verdict.region_code or '未知'})"
        verdict.error = verdict.region_reason
        return verdict

    if verdict.feature_flag is True or (
        verdict.http_code in (200, 302, 304)
        and verdict.region_code
        and verdict.region_code not in config.GEMINI_BLOCKED_REGIONS
    ):
        verdict.gemini_status = "ok"
        verdict.access_ok = True
        verdict.region_reason = (
            f"免登录特性已激活 (Google识别: {verdict.region_code})"
            if verdict.region_code
            else "免登录特性已激活"
        )
    else:
        verdict.gemini_status = f"http_{verdict.http_code}"
        verdict.error = f"未获取有效 Gemini 页面特征 (HTTP {verdict.http_code})"
        return verdict

    if verdict.studio_status == "blocked":
        verdict.region_blocked = True
        verdict.access_ok = False
        verdict.region_reason = "Google AI Studio 地区受限"
        return verdict

    # ---- 阶段四：真实提问验证 ----
    if not do_chat:
        return verdict
    if not config.GEMINI_1PSID:
        verdict.chat_ok = None
        verdict.error = "未配置 GEMINI_1PSID，跳过提问测试"
        return verdict
    if verdict.cookie_invalid:
        verdict.chat_ok = None
        verdict.error = "Cookie 已失效，跳过提问测试（请更新 GEMINI_1PSID / GEMINI_1PSIDTS）"
        return verdict
    if session is None:
        verdict.chat_ok = None
        verdict.error = "缺少 curl_cffi，无法执行登录提问"
        return verdict

    return _chat_test(session, html, cookies, verdict)


def _chat_test(session, html: str, cookies: dict, verdict: GeminiVerdict) -> GeminiVerdict:
    """提交真实问题并解析回复，验证节点是否具备对话能力"""
    at_token, bl_version = _extract_session_tokens(html)
    if not at_token:
        verdict.chat_ok = False
        verdict.cookie_invalid = True
        verdict.error = "未提取到 SNlM0e 会话令牌，Cookie 可能已失效，请重新获取"
        return verdict

    form_data = {"at": at_token, "f.req": _build_chat_payload(config.GEMINI_CHAT_QUESTION)}
    url = (
        f"{config.GEMINI_STREAM_URL}?bl={urllib.parse.quote(bl_version)}"
        f"&hl=zh-CN&_reqid={int(time.time() * 1000) % 100000}&rt=c"
    )
    started = time.time()
    try:
        response = session.post(
            url,
            data=form_data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
                "x-goog-ext-525005358-jspb": '["en"]',
                "Origin": "https://gemini.google.com",
                "Referer": "https://gemini.google.com/",
            },
            cookies=cookies,
            timeout=config.GEMINI_CHAT_TIMEOUT,
            impersonate="chrome120",
        )
        verdict.chat_code = response.status_code
        verdict.chat_ms = round((time.time() - started) * 1000, 1)
        raw = response.text or ""

        if response.status_code != 200:
            verdict.chat_ok = False
            verdict.error = f"提问接口响应 HTTP {response.status_code}"
            return verdict

        for marker in config.GEMINI_CHAT_BLOCK_MARKERS:
            if marker in raw:
                verdict.chat_ok = False
                verdict.region_blocked = True
                verdict.region_reason = f"提问被限制 ({marker})"
                verdict.error = f"提问接口返回受限标记: {marker}"
                return verdict

        reply = extract_reply_text(raw)
        verdict.reply_snippet = reply[:200]
        if reply and config.GEMINI_CHAT_EXPECT in reply:
            verdict.chat_ok = True
            verdict.error = ""
        elif reply:
            verdict.chat_ok = True
            verdict.error = "已获取模型回复（未命中预期答案）"
        else:
            verdict.chat_ok = False
            verdict.error = "提问接口未返回可解析的回复内容"
    except Exception as exc:  # noqa: BLE001
        verdict.chat_ok = False
        verdict.chat_ms = round((time.time() - started) * 1000, 1)
        verdict.error = f"提问通信失败: {exc}"
    return verdict
