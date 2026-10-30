# -*- coding: utf-8 -*-
"""core/report.py — 终端决策看板
================================
统一生成总览、可用节点排行榜、测速排行榜、订阅质量对比、失败归类与明细清单。
中英文混排按终端显示宽度对齐，避免表格错位。
"""

from __future__ import annotations

import time
import unicodedata
from collections import Counter
from typing import Any, Dict, List, Optional

from core.models import NodeResult, ProxyNode, SITE_GEMINI, SITE_GOOGLE, SITE_GROK
from core.speedtest import format_speed

BAR = "═" * 66


def _char_width(char: str) -> int:
    return 2 if unicodedata.east_asian_width(char) in ("F", "W") or ord(char) >= 0x1F000 else 1


def text_width(text: str) -> int:
    return sum(_char_width(char) for char in str(text))


def pad(text: object, width: int, align: str = "left") -> str:
    """按显示宽度填充或截断（超宽时追加省略号）"""
    value = str(text)
    if text_width(value) > width:
        result = ""
        used = 0
        for char in value:
            char_width = _char_width(char)
            if used + char_width > width - 1:
                break
            result += char
            used += char_width
        value = result + "…"
    gap = width - text_width(value)
    if align == "right":
        return " " * gap + value
    if align == "center":
        left = gap // 2
        return " " * left + value + " " * (gap - left)
    return value + " " * gap


def format_progress(done: int, total: int, result: NodeResult) -> str:
    """单节点进度行"""
    if result.is_proxy_ok:
        details = [f"{result.latency_ms:.0f}ms"]
        if result.speed:
            details.append(f"↓{format_speed(result.speed.download_mbps)}")
        if result.egress_ip:
            details.append(result.egress_ip)
        if result.gemini and result.gemini.region_code:
            details.append(f"Gemini:{result.gemini.region_code}")
        info = " | ".join(details)
    else:
        info = result.fail_reason[:40] or "不可达"
    return f" [{done:>3}/{total:>3}] {result.level_tag} | {pad(result.node.name, 26)} | {info}"


def _speed_samples(results: List[NodeResult]) -> List[float]:
    return [
        result.speed.download_mbps
        for result in results
        if result.speed and result.speed.download_mbps > 0
    ]


def format_summary(results: List[NodeResult]) -> str:
    """静默模式的一行摘要"""
    total = len(results)
    proxy_ok = sum(1 for result in results if result.is_proxy_ok)
    gemini_ok = sum(1 for result in results if result.gemini_available)
    chat_ok = sum(1 for result in results if result.gemini and result.gemini.chat_ok is True)
    summary = (
        f"总计 {total} | 🟢 代理通 {proxy_ok} | 🤖 Gemini 可用 {gemini_ok} | 💬 提问成功 {chat_ok}"
    )
    samples = _speed_samples(results)
    if samples:
        summary += f" | 🚀 平均下载 {format_speed(sum(samples) / len(samples))}"
    return summary


def _site_stats(results: List[NodeResult]) -> Dict[str, int]:
    return {
        "Google": sum(1 for result in results if result.site_ok(SITE_GOOGLE)),
        "Gemini": sum(1 for result in results if result.site_ok(SITE_GEMINI)),
        "Grok": sum(1 for result in results if result.site_ok(SITE_GROK)),
    }


def _overview(results: List[NodeResult]) -> List[str]:
    total = len(results)
    counts = Counter(result.level for result in results)
    rate = counts[0] / total * 100 if total else 0.0
    sites = _site_stats(results)
    gemini_available = sum(1 for result in results if result.gemini_available)
    gemini_blocked = sum(1 for result in results if result.gemini and result.gemini.region_blocked)
    chat_ok = sum(1 for result in results if result.gemini and result.gemini.chat_ok is True)
    chat_fail = sum(1 for result in results if result.gemini and result.gemini.chat_ok is False)
    fallback = sum(1 for result in results if result.fallback_used)

    lines = [
        BAR,
        " 📊 测 试 总 览 (Overview)",
        BAR,
        f" 节点总数   : {total} 个（备用内核降级 {fallback} 个）",
        f" 连通分级   : 🟢 代理通 {counts[0]} ({rate:.1f}%) · 🟡 仅直连 {counts[1]} · 🔴 无网络 {counts[2]}",
        f" 三网页可达 : Google ✅{sites['Google']} · Gemini ✅{sites['Gemini']} · Grok ✅{sites['Grok']}  (/ {total})",
        f" Gemini评估 : 可用 ✅{gemini_available} · 地区封锁 ⛔{gemini_blocked} ｜ 提问成功 💬{chat_ok} · 提问受阻 ⚠️{chat_fail}",
    ]

    samples = _speed_samples(results)
    if samples:
        fastest = max(
            (result for result in results if result.speed_mbps > 0),
            key=lambda result: result.speed_mbps,
        )
        lines.append(
            f" 节点测速   : 已测 {len(samples)} 个 · 平均 {format_speed(sum(samples) / len(samples))} · "
            f"最高 {format_speed(max(samples))}（{fastest.node.name}）"
        )

    invalid_cookie = sum(1 for result in results if result.gemini and result.gemini.cookie_invalid)
    if invalid_cookie:
        lines.append(
            f" Cookie 状态 : 🍪 失效 {invalid_cookie} 个 —— 提问结果不可信，请更新 GEMINI_1PSID / GEMINI_1PSIDTS"
        )
    return lines


def _ranking(results: List[NodeResult]) -> List[str]:
    ranked = sorted([result for result in results if result.is_proxy_ok], key=lambda item: item.latency_ms)
    lines = [
        "",
        BAR,
        f" 🏆 可 用 节 点 排 行 榜（代理通 {len(ranked)} 个，按延迟升序）",
        BAR,
    ]
    if not ranked:
        lines.append(" （本次未发现代理通节点）")
        return lines

    header = (
        f"{pad('排名', 6)} {pad('节点名称', 28)} {pad('协议', 10)} {pad('延迟', 10)} {pad('下载', 14)} "
        f"{pad('落地 IP / 归属地', 32)} {pad('Google可达', 10)} {pad('Gemini', 12)} {pad('Grok可达', 8)} {pad('提问', 12)}"
    )
    lines.append(header)
    lines.append("-" * 151)
    for index, result in enumerate(ranked, 1):
        gemini_text = "✅" if result.site_ok(SITE_GEMINI) else "❌"
        if result.gemini:
            if result.gemini.region_blocked:
                gemini_text = f"⛔{result.gemini.region_code}" if result.gemini.region_code else "⛔封锁"
            elif result.gemini.available:
                gemini_text = f"✅{result.gemini.region_code}" if result.gemini.region_code else "✅可用"
            else:
                gemini_text = "❌"
        chat_text = result.gemini.chat_tag if result.gemini else "➖"
        egress = result.egress_ip or "-"
        if result.egress_location:
            egress += f" ({result.egress_location})"
        lines.append(
            f"{pad(f'#{index}', 6)} {pad(result.node.name, 28)} {pad(result.node.protocol, 10)} "
            f"{pad(f'{result.latency_ms:.0f}ms', 10)} {pad(format_speed(result.speed_mbps), 14)} {pad(egress, 32)} "
            f"{pad('✅' if result.site_ok(SITE_GOOGLE) else '❌', 7)} "
            f"{pad(gemini_text, 12)} {pad('✅' if result.site_ok(SITE_GROK) else '❌', 6)} {pad(chat_text, 12)}"
        )
    return lines


def _speed_ranking(results: List[NodeResult]) -> List[str]:
    measured = sorted(
        [result for result in results if result.is_proxy_ok and result.speed_mbps > 0],
        key=lambda result: result.speed_mbps,
        reverse=True,
    )
    lines = [
        "",
        BAR,
        f" 🚀 节 点 测 速 排 行 榜（已测 {len(measured)} 个，按下载速率降序）",
        BAR,
    ]
    if not measured:
        lines.append(" （本次未采集到测速数据）")
        return lines

    lines.append(
        f"{pad('排名', 6)} {pad('节点名称', 28)} {pad('协议', 10)} {pad('下载', 14)} "
        f"{pad('上传', 14)} {pad('Ping', 10)} {pad('抖动', 10)} {pad('落地 IP / 归属地', 32)}"
    )
    lines.append("-" * 131)
    for index, result in enumerate(measured, 1):
        upload = format_speed(result.speed.upload_mbps) if result.speed else "-"
        ping = f"{result.speed.ping_ms:.0f}ms" if result.speed and result.speed.ping_ms > 0 else "-"
        jitter = f"{result.speed.jitter_ms:.1f}ms" if result.speed and result.speed.jitter_ms > 0 else "-"
        egress = result.egress_ip or "-"
        if result.egress_location:
            egress += f" ({result.egress_location})"
        lines.append(
            f"{pad(f'#{index}', 6)} {pad(result.node.name, 28)} {pad(result.node.protocol, 10)} "
            f"{pad(format_speed(result.speed_mbps), 14)} {pad(upload, 14)} "
            f"{pad(ping, 10)} {pad(jitter, 10)} {pad(egress, 32)}"
        )
    return lines


def _subscription_quality(results: List[NodeResult]) -> List[str]:
    stats: Dict[str, Dict[str, int]] = {}
    for result in results:
        name = result.node.sub_name or "未归类"
        bucket = stats.setdefault(name, {"total": 0, "proxy": 0, "gemini": 0, "chat": 0})
        bucket["total"] += 1
        bucket["proxy"] += int(result.is_proxy_ok)
        bucket["gemini"] += int(result.gemini_available)
        bucket["chat"] += int(bool(result.gemini and result.gemini.chat_ok is True))

    lines = ["", BAR, " 📡 各 订 阅 源 质 量 对 比 (Subscription Quality)", BAR]
    lines.append(
        f"{pad('订阅名称', 22)} {pad('总节点', 8)} {pad('代理通', 8)} "
        f"{pad('可用率', 10)} {pad('Gemini可用', 12)} {pad('提问成功', 10)}"
    )
    lines.append("-" * 76)
    for name, bucket in stats.items():
        total = bucket["total"] or 1
        rate_text = f"{bucket['proxy'] / total * 100:.1f}%"
        lines.append(
            f"{pad(name, 22)} {pad(bucket['total'], 8)} {pad(bucket['proxy'], 8)} "
            f"{pad(rate_text, 10)} {pad(bucket['gemini'], 12)} {pad(bucket['chat'], 10)}"
        )
    return lines


def _failures(results: List[NodeResult]) -> List[str]:
    failed = [result for result in results if not result.is_proxy_ok]
    if not failed:
        return []
    counter = Counter(
        (result.fail_code or "UNKNOWN") for result in failed
    )
    lines = ["", BAR, f" 🔍 故 障 与 失 败 归 类（共 {len(failed)} 个不可用节点）", BAR]
    for code, count in counter.most_common():
        lines.append(f" · {pad(code, 22)} : {count} 个节点")
    return lines


def _details(results: List[NodeResult]) -> List[str]:
    lines = ["", BAR, " 📋 全 部 节 点 明 细 清 单", BAR]
    for result in results:
        if result.is_proxy_ok:
            info = (
                f"{result.latency_ms:.0f}ms | {result.egress_ip or '-'} | "
                f"下载 {format_speed(result.speed_mbps)}"
            )
        else:
            info = result.fail_reason[:48] or result.fail_code
        lines.append(
            f" [{result.level_tag}] {pad(result.node.name, 30)} ({pad(result.node.protocol, 10)}) -> {info}"
        )
    return lines


def render_report(nodes: List[ProxyNode], results: List[NodeResult], ok_only: bool = False) -> str:
    """生成完整决策报告"""
    lines: List[str] = [""]
    lines.extend(_overview(results))
    lines.extend(_ranking(results))
    lines.extend(_speed_ranking(results))
    lines.extend(_subscription_quality(results))
    lines.extend(_failures(results))
    if not ok_only:
        lines.extend(_details(results))
    lines.extend(
        [
            "",
            BAR,
            f" 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')} | 探测规则: OpenWrt-Passwall | 节点来源: {len(nodes)} 个",
            BAR,
        ]
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 结构化输出（供本地二次分析 / HTML 看板消费）
# ---------------------------------------------------------------------------
def _gemini_dict(result: NodeResult) -> Optional[Dict[str, Any]]:
    verdict = result.gemini
    if verdict is None:
        return None
    return {
        "status": verdict.gemini_status,
        "studio_status": verdict.studio_status,
        "available": verdict.available,
        "access_ok": verdict.access_ok,
        "http_code": verdict.http_code,
        "access_ms": verdict.access_ms,
        "region_blocked": verdict.region_blocked,
        "region_code": verdict.region_code,
        "region_reason": verdict.region_reason,
        "api_reach_ok": verdict.api_reach_ok,
        "feature_flag": verdict.feature_flag,
        "chat_ok": verdict.chat_ok,
        "cookie_invalid": verdict.cookie_invalid,
        "chat_code": verdict.chat_code,
        "chat_ms": verdict.chat_ms,
        "reply_snippet": verdict.reply_snippet,
        "error": verdict.error,
    }


def _node_dict(result: NodeResult) -> Dict[str, Any]:
    node = result.node
    return {
        "name": node.name,
        "protocol": node.protocol,
        "address": node.address,
        "port": node.port,
        "sub_name": node.sub_name,
        "fingerprint": node.fingerprint,
        "level": result.level,
        "level_tag": result.level_tag,
        "proxy_ok": result.is_proxy_ok,
        "latency_ms": result.latency_ms,
        "core": result.core,
        "fallback_used": result.fallback_used,
        "egress_ip": result.egress_ip,
        "egress_location": result.egress_location,
        "probes": {name: probe.to_dict() for name, probe in result.probes.items()},
        "sites": {name: probe.to_dict() for name, probe in result.sites.items()},
        "gemini": _gemini_dict(result),
        "speed": result.speed.to_dict() if result.speed else None,
        "fail_code": result.fail_code,
        "fail_reason": result.fail_reason,
    }


def build_json(
    nodes: List[ProxyNode],
    results: List[NodeResult],
    meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """结构化结果：字段与 core/models.py 一一对应，便于 jq 与看板消费"""
    total = len(results)
    proxy_ok = sum(1 for result in results if result.is_proxy_ok)
    gemini_ok = sum(1 for result in results if result.gemini_available)
    chat_ok = sum(1 for result in results if result.gemini and result.gemini.chat_ok is True)
    cookie_invalid = sum(1 for result in results if result.gemini and result.gemini.cookie_invalid)
    samples = _speed_samples(results)

    return {
        "meta": {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "node_total": len(nodes),
            "tested": total,
            "rules": "OpenWrt-Passwall",
            **(meta or {}),
        },
        "summary": {
            "total": total,
            "proxy_ok": proxy_ok,
            "domestic_only": sum(1 for result in results if result.level == 1),
            "dead": sum(1 for result in results if result.level == 2),
            "gemini_available": gemini_ok,
            "gemini_chat_ok": chat_ok,
            "cookie_invalid": cookie_invalid,
            "speed_measured": len(samples),
            "speed_avg_mbps": round(sum(samples) / len(samples), 2) if samples else 0.0,
            "speed_max_mbps": round(max(samples), 2) if samples else 0.0,
        },
        "nodes": [_node_dict(result) for result in results],
    }
