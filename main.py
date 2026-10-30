# -*- coding: utf-8 -*-
"""main.py — VPN Check 统一运行主程序
====================================
一次执行完成：

1. 并发拉取 `.env` 中配置的全部机场订阅，解析并跨订阅去重
2. 启动真实内核（Xray / Sing-box）逐节点建立 SOCKS5 隧道
3. 按 Passwall 规则执行国际 / 国内探针分级，测试 Google / Gemini / Grok
4. 对代理通节点做定量下载测速（可选上传），生成测速排行榜
5. Gemini 免登录地区判定 + 可选的登录提问验证
6. 输出终端决策看板、归档报告并导出 Passwall 配置
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import List, Optional, Sequence

from core import __version__, config
from core.checker import run_pipeline, run_speed_phase
from core.logging_setup import setup_logging
from core.models import SubscriptionResult
from core.report import build_json, format_progress, format_summary, render_report
from core.speedtest import format_speed, resolved_provider
from core.subscription import collect_nodes, fetch_all

# Windows 控制台编码保护
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001 - 非标准流时忽略
        pass

logger = logging.getLogger("vpn_check.main")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vpn_check",
        description="VPN Check — 基于 OpenWrt-Passwall 与 Gemini-Config-Checker 体系的节点评估工具",
    )
    parser.add_argument("--limit", type=int, default=0, help="仅测试前 N 个节点（调试用）")
    parser.add_argument("--filter", type=str, default="", help="按节点名称关键字过滤")
    parser.add_argument("--protocol", type=str, default="", help="仅测试指定协议，逗号分隔（如 vless,anytls）")
    parser.add_argument("--workers", type=int, default=config.DEFAULT_WORKERS, help="并发测试线程数")
    parser.add_argument("--skip-gemini", action="store_true", help="跳过 Gemini 深度检测")
    parser.add_argument("--skip-gemini-chat", action="store_true", help="Gemini 仅测访问，跳过登录提问")
    parser.add_argument("--skip-speed", action="store_true", help="跳过节点下载测速")
    parser.add_argument(
        "--speed-workers",
        type=int,
        default=config.SPEEDTEST_WORKERS,
        help="测速并发度（1 = 数据最可比，默认 %(default)s）",
    )
    parser.add_argument(
        "--speed-top",
        type=int,
        default=config.SPEEDTEST_TOP,
        help="仅对延迟最低的前 N 个代理通节点测速（0 = 全部）",
    )
    parser.add_argument(
        "--speed-provider",
        choices=("auto", "ookla", "builtin"),
        default=None,
        help="测速引擎，默认取 .env 的 SPEEDTEST_PROVIDER（内置采样）",
    )
    parser.add_argument("--json", action="store_true", help="额外输出结构化 JSON 报告")
    parser.add_argument(
        "--json-file", type=str, default=str(config.JSON_FILE), help="JSON 报告路径"
    )
    parser.add_argument("--no-export", action="store_true", help="不导出 Passwall 配置")
    parser.add_argument("--ok-only", action="store_true", help="控制台仅展示总览与可用节点榜")
    parser.add_argument("--quiet", "-q", action="store_true", help="静默模式（适配 Cron 定时任务）")
    parser.add_argument("--report-file", type=str, default=str(config.REPORT_FILE), help="报告归档路径")
    parser.add_argument("--export-dir", type=str, default=str(config.EXPORT_DIR), help="Passwall 导出目录")
    parser.add_argument("--version", action="version", version=f"vpn_check {__version__}")
    return parser


def print_banner() -> None:
    print("=" * 66)
    print(f"  🌐 VPN Node Evaluator & Passwall Optimizer v{__version__}")
    print("  严格遵循 OpenWrt-Passwall、Gemini-Config-Checker 与项目开发规范")
    print("=" * 66)


def _print_subscription_results(subscriptions: List[SubscriptionResult], quiet: bool) -> None:
    if quiet:
        return
    for item in subscriptions:
        if item.ok:
            print(
                f"  ✅ {item.name:<18} 获取 {len(item.nodes):>3} 节点"
                f"（{item.elapsed_s:>5.1f}s，节余流量: {item.remaining_traffic or '未提供'}）"
            )
        else:
            print(f"  ⚠️  {item.name:<18} 获取失败: {item.error}")


def _apply_filters(nodes, filter_text: str, protocols: str, limit: int, quiet: bool):
    filtered = nodes
    if filter_text:
        filtered = [node for node in filtered if filter_text in node.name]
        if not quiet:
            print(f"  ⚙️  --filter '{filter_text}' 生效：匹配 {len(filtered)} 个节点")
    if protocols:
        allowed = {item.strip().lower() for item in protocols.split(",") if item.strip()}
        filtered = [node for node in filtered if node.protocol.lower() in allowed]
        if not quiet:
            print(f"  ⚙️  --protocol 生效：匹配 {len(filtered)} 个节点")
    if limit > 0:
        filtered = filtered[:limit]
        if not quiet:
            print(f"  ⚙️  --limit 生效：仅测试前 {len(filtered)} 个节点")
    return filtered


def _run(args: argparse.Namespace) -> int:
    setup_logging()
    config.ensure_directories()

    if args.speed_provider:
        config.SPEEDTEST_PROVIDER = args.speed_provider
    if args.speed_workers < 1:
        args.speed_workers = 1

    issues = config.validate()
    fatal = [issue for issue in issues if issue.fatal]
    if not args.quiet:
        print_banner()
        for issue in issues:
            prefix = "❌" if issue.fatal else "⚠️ "
            print(f" {prefix} 配置体检 [{issue.key}]: {issue.message}")
    if fatal:
        print("❌ 配置不完整，程序终止。请参考 .env.example 完善配置。")
        return 2

    if not args.quiet:
        print(f"\n📡 [1/3] 拉取订阅（共 {len(config.SUBSCRIBE_ITEMS)} 个订阅源）...")
    subscriptions = fetch_all(config.SUBSCRIBE_ITEMS)
    _print_subscription_results(subscriptions, args.quiet)

    nodes = collect_nodes(subscriptions)
    if not nodes:
        print("❌ 所有订阅均未解析到可用节点，程序退出。")
        return 1
    if not args.quiet:
        print(f"  🔗 跨订阅去重后共 {len(nodes)} 个节点")

    test_nodes = _apply_filters(nodes, args.filter, args.protocol, args.limit, args.quiet)
    if not test_nodes:
        print("❌ 过滤后无待测节点，程序退出。")
        return 1

    if not args.quiet:
        print(f"\n🚀 [2/4] 启动内核隧道探测（{len(test_nodes)} 节点，{args.workers} 并发）...")
        if not args.skip_gemini and not config.GEMINI_1PSID:
            print("  ℹ️  未配置 GEMINI_1PSID：执行免登录访问与地区封锁检测，跳过提问测试")
        if not args.skip_speed and config.SPEEDTEST_ENABLED:
            engine = "Ookla Speedtest CLI" if resolved_provider() == "ookla" else "内置 SOCKS5 采样"
            print(f"  ⚡ 测速引擎: {engine}（下载 {config.SPEEDTEST_DOWNLOAD_BYTES // 1024 // 1024} MB 采样）")

    def on_progress(done: int, total: int, result) -> None:
        if not args.quiet:
            print(format_progress(done, total, result), flush=True)

    started = time.time()
    results = run_pipeline(
        test_nodes,
        workers=max(1, args.workers),
        check_gemini_flag=not args.skip_gemini,
        do_chat=not args.skip_gemini and not args.skip_gemini_chat,
        callback=on_progress,
    )
    elapsed = round(time.time() - started, 1)
    if not args.quiet:
        print(f"  ⏱️  探测完成，总耗时 {elapsed} 秒")

    # 独立测速阶段：与探测线程池解耦，避免多节点同时抢同一条出口带宽
    if not args.skip_speed and config.SPEEDTEST_ENABLED:
        if not args.quiet:
            print(f"\n⚡ [3/4] 节点测速（并发 {args.speed_workers}，数字横向比较请用 --speed-workers 1）...")

        def on_speed(done: int, total: int, result) -> None:
            if args.quiet:
                return
            speed = result.speed
            text = format_speed(speed.download_mbps) if speed else "-"
            print(f"  ⚡ [{done:>3}/{total:>3}] {result.node.name[:30]:<32} ↓{text}", flush=True)

        measured = run_speed_phase(
            results,
            workers=args.speed_workers,
            top=args.speed_top,
            upload=config.SPEEDTEST_UPLOAD_ENABLED,
            callback=on_speed,
        )
        if not args.quiet:
            print(f"  ⏱️  测速完成 {measured} 个节点，累计耗时 {round(time.time() - started, 1)} 秒")
    elif not args.quiet:
        print("\n➖ 已跳过节点测速")

    if not args.quiet:
        print("\n📋 [4/4] 汇总测试报告 ...")
    report_text = render_report(test_nodes, results, ok_only=args.ok_only)
    if not args.quiet:
        print(report_text)

    report_path = Path(args.report_file)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report_text, encoding="utf-8")
    if not args.quiet:
        print(f"\n📄 完整报告已归档: {report_path}")

    if args.json:
        json_path = Path(args.json_file)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        payload = build_json(
            test_nodes,
            results,
            meta={
                "version": __version__,
                "workers": args.workers,
                "speed_workers": args.speed_workers,
                "speed_provider": resolved_provider(),
                "speed_enabled": not args.skip_speed and config.SPEEDTEST_ENABLED,
                "gemini_chat": not args.skip_gemini and not args.skip_gemini_chat,
            },
        )
        json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        if not args.quiet:
            print(f"  🧾 JSON 报告: {json_path}")

    if not args.no_export:
        from core import exporter

        export_result = exporter.export_artifacts(test_nodes, results, Path(args.export_dir))
        if not args.quiet:
            print(
                f"  ✅ Passwall 导出完成：代理通 {export_result['available']} / "
                f"Gemini 可用 {export_result['gemini_available']} / "
                f"提问成功 {export_result['gemini_chat']} / 总计 {export_result['total']}"
            )
            for key, path in export_result["paths"].items():
                print(f"     -> {key}: {path}")
            warnings = export_result.get("warnings") or {}
            if warnings:
                print(f"  ⚠️  字段体检: {len(warnings)} 个节点存在缺失字段，导入路由器后可能不生效")
                for name, issues in list(warnings.items())[:5]:
                    print(f"     ! {name}: {'；'.join(issues)}")
    elif not args.quiet:
        print("  ➖ 已跳过 Passwall 配置导出（--no-export）")

    print(f"\n✨ {format_summary(results)}")
    logger.info("巡检完成: %s", format_summary(results))
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return _run(args)
    except KeyboardInterrupt:
        print("\n⛔ 已手动中断。")
        return 130
    except Exception as exc:  # noqa: BLE001
        logger.exception("主程序异常终止")
        print(f"❌ 程序异常终止: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
