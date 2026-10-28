# -*- coding: utf-8 -*-
"""core/report.py — 终端决策看板
================================
统一生成总览、可用节点排行榜、订阅质量对比、失败归类与明细清单。
中英文混排按终端显示宽度对齐，避免表格错位。
"""

from __future__ import annotations

import time
import unicodedata
from collections import Counter
from typing import Dict, List

from core.models import NodeResult, ProxyNode, SITE_GEMINI, SITE_GOOGLE, SITE_GROK

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
        if result.egress_ip:
            details.append(result.egress_ip)
        if result.gemini and result.gemini.region_code:
            details.append(f"Gemini:{result.gemini.region_code}")
        info = " | ".join(details)
    else:
        info = result.fail_reason[:40] or "不可达"
    return f" [{done:>3}/{total:>3}] {result.level_tag} | {pad(result.node.name, 26)} | {info}"


def format_summary(results: List[NodeResult]) -> str:
    """静默模式的一行摘要"""
    total = len(results)
    proxy_ok = sum(1 for result in results if result.is_proxy_ok)
    gemini_ok = sum(1 for result in results if result.gemini_available)
    chat_ok = sum(1 for result in results if result.gemini and result.gemini.chat_ok is True)
    return (
        f"总计 {total} | 🟢 代理通 {proxy_ok} | 🤖 Gemini 可用 {gemini_ok} | 💬 提问成功 {chat_ok}"
    )


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

    return [
        BAR,
        " 📊 测 试 总 览 (Overview)",
        BAR,
        f" 节点总数   : {total} 个（备用内核降级 {fallback} 个）",
        f" 连通分级   : 🟢 代理通 {counts[0]} ({rate:.1f}%) · 🟡 仅直连 {counts[1]} · 🔴 无网络 {counts[2]}",
        f" 三网页可达 : Google ✅{sites['Google']} · Gemini ✅{sites['Gemini']} · Grok ✅{sites['Grok']}  (/ {total})",
        f" Gemini评估 : 可用 ✅{gemini_available} · 地区封锁 ⛔{gemini_blocked} ｜ 提问成功 💬{chat_ok} · 提问受阻 ⚠️{chat_fail}",
    ]


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
        f"{pad('排名', 6)} {pad('节点名称', 28)} {pad('协议', 10)} {pad('延迟', 10)} "
        f"{pad('落地 IP / 归属地', 32)} {pad('Google可达', 10)} {pad('Gemini', 12)} {pad('Grok可达', 8)} {pad('提问', 12)}"
    )
    lines.append(header)
    lines.append("-" * 136)
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
            f"{pad(f'{result.latency_ms:.0f}ms', 10)} {pad(egress, 32)} "
            f"{pad('✅' if result.site_ok(SITE_GOOGLE) else '❌', 7)} "
            f"{pad(gemini_text, 12)} {pad('✅' if result.site_ok(SITE_GROK) else '❌', 6)} {pad(chat_text, 12)}"
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
            info = f"{result.latency_ms:.0f}ms | {result.egress_ip or '-'}"
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
