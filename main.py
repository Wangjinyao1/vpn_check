# -*- coding: utf-8 -*-
"""main.py — VPN Check 统一运行主程序
====================================
一次执行完成：

1. 并发拉取 `.env` 中配置的全部机场订阅，解析并跨订阅去重
2. 启动真实内核（Xray / Sing-box）逐节点建立 SOCKS5 隧道
3. 按 Passwall 规则执行国际 / 国内探针分级，测试 Google / Gemini / Grok
4. Gemini 免登录地区判定 + 可选的登录提问验证
5. 输出终端决策看板、归档报告、导出 Passwall 配置并持久化 MySQL
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path
from typing import List, Optional, Sequence

from core import __version__, config
from core.checker import run_pipeline
from core.logging_setup import setup_logging
from core.models import SubscriptionResult
from core.report import format_progress, format_summary, render_report
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
    parser.add_argument("--no-db", action="store_true", help="不写入 MySQL")
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

    db_ready = False
    if not args.no_db and config.DB_ENABLED:
        from core import database

        db_ready = database.init_database()
        if not db_ready and not args.quiet:
            print("  ⚠️  数据库不可用，本次将跳过持久化（不影响其余功能）")

    if not args.quiet:
        print(f"\n📡 [1/4] 拉取订阅（共 {len(config.SUBSCRIBE_ITEMS)} 个订阅源）...")
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

    if not args.quiet:
        print("\n📋 [3/4] 汇总测试报告 ...")
    report_text = render_report(test_nodes, results, ok_only=args.ok_only)
    if not args.quiet:
        print(report_text)

    report_path = Path(args.report_file)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report_text, encoding="utf-8")
    if not args.quiet:
        print(f"\n📄 完整报告已归档: {report_path}")

    if not args.no_export:
        from core import exporter

        export_result = exporter.export_artifacts(test_nodes, results, Path(args.export_dir))
        if not args.quiet:
            print(
                f"  ✅ Passwall 导出完成：代理通 {export_result['available']} / "
                f"Gemini 可用 {export_result['gemini_available']} / 总计 {export_result['total']}"
            )
            for key, path in export_result["paths"].items():
                print(f"     -> {key}: {path}")
    elif not args.quiet:
        print("  ➖ 已跳过 Passwall 配置导出（--no-export）")

    if db_ready:
        from core import database

        ok = database.persist_test_batch(test_nodes, results, elapsed_seconds=elapsed)
        if not args.quiet:
            marker = "🗄️ " if ok else "⚠️ "
            print(f"  {marker}测试数据持久化: {'成功' if ok else '失败'}")
    elif not args.no_db and config.DB_ENABLED and not args.quiet:
        print("  ⚠️  数据库不可用，已跳过数据入库")
    elif not args.quiet:
        print("  ➖ 已跳过数据库持久化（--no-db）")

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
