# -*- coding: utf-8 -*-
"""core/checker.py — 探测管道与并发调度
======================================
严格对齐 OpenWrt-Passwall 的探针判定顺序：

1. 国际主探针（Google generate_204）→ 判定 🟢 代理通
2. 国际失败后回退国内探针 → 判定 🟡 仅直连
3. 全部失败 → 🔴 无网络

代理通节点继续执行：
- 三网页探测（Google / Gemini / Grok）
- 出海落地 IP 与归属地识别
- Gemini 免登录地区封锁 + 登录提问验证
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional, Tuple

from core import config
from core.engine import KernelTunnel, select_cores
from core.gemini import check_gemini
from core.ip_location import format_location, get_location
from core.models import (
    LEVEL_DEAD,
    LEVEL_DOMESTIC,
    LEVEL_PROXY,
    SITE_GEMINI,
    GeminiVerdict,
    NodeResult,
    ProxyNode,
    SiteProbe,
)
from core.netprobe import fetch_egress_ip, fetch_via_socks

logger = logging.getLogger("vpn_check.checker")

ProgressCallback = Callable[[int, int, NodeResult], None]


def _make_probe(name: str, url: str, status: int, latency_ms: float, error: str, ok_codes: Tuple[int, ...]) -> SiteProbe:
    return SiteProbe(
        name=name,
        url=url,
        ok=status in ok_codes,
        code=status,
        latency_ms=latency_ms,
        error=error,
    )


def _probe_international(tunnel: KernelTunnel, result: NodeResult) -> Tuple[bool, float]:
    """国际主探针：主探针失败时用备用探针复核，避免单点抖动误判"""

    def _request(name: str, url: str) -> tuple:
        response = tunnel.request(url, method=config.PROBE_METHOD, timeout=config.PROBE_TIMEOUT)
        # 仅当服务端明确拒绝该 HTTP 方法时才改用 GET，避免死节点重复等待超时
        if response.status in (403, 405, 501) and config.PROBE_METHOD == "HEAD":
            response = tunnel.request(url, method="GET", timeout=config.PROBE_TIMEOUT)
        result.probes[name] = _make_probe(
            name, url, response.status, response.latency_ms, response.error, config.PROBE_VALID_CODES
        )
        return response.status, response.latency_ms

    name, url = config.PROBES_INTERNATIONAL[0]
    status, latency_ms = _request(name, url)
    if status in config.PROBE_VALID_CODES:
        return True, latency_ms

    for backup_name, backup_url in config.PROBES_INTERNATIONAL[1:3]:
        status, latency_ms = _request(backup_name, backup_url)
        if status in config.PROBE_VALID_CODES:
            return True, latency_ms
    return False, latency_ms


def _probe_domestic(tunnel: KernelTunnel, result: NodeResult) -> bool:
    """国内探针：任意一个通过即视为具备直连能力"""
    for name, url in config.PROBES_DOMESTIC:
        response = tunnel.request(url, method=config.PROBE_METHOD, timeout=config.PROBE_TIMEOUT)
        result.probes[name] = _make_probe(
            name, url, response.status, response.latency_ms, response.error, config.PROBE_VALID_CODES
        )
        if result.probes[name].ok:
            return True
    return False


def _probe_sites(tunnel: KernelTunnel, result: NodeResult) -> None:
    """三网页可达性探测（使用浏览器指纹，兼容 Cloudflare 保护的站点）"""
    for target in config.TARGET_SITES:
        if target.name == SITE_GEMINI and result.gemini is not None:
            continue
        response = fetch_via_socks(tunnel.port, target.url, config.SITE_TIMEOUT)
        ok = response.status in target.ok_codes or (
            target.reachable_any_status and response.status > 0
        )
        result.sites[target.name] = SiteProbe(
            name=target.name,
            url=target.url,
            ok=ok,
            code=response.status,
            latency_ms=response.latency_ms,
            error=response.error,
        )


def _classify_failure(error: str) -> str:
    """将底层异常归类为可聚合的失败代码"""
    lowered = (error or "").lower()
    if "generalproxyerror" in lowered or "socks server failure" in lowered:
        return "PROXY_CONNECT_FAIL"
    if "timed out" in lowered or "timeout" in lowered:
        return "TIMEOUT"
    if "refused" in lowered:
        return "CONN_REFUSED"
    if "ssl" in lowered or "tls" in lowered or "certificate" in lowered:
        return "TLS_ERROR"
    if "reset" in lowered or "broken pipe" in lowered or "eof" in lowered:
        return "CONN_RESET"
    if "name or service" in lowered or "nodename" in lowered or "dns" in lowered:
        return "DNS_ERROR"
    return "UNREACHABLE"


def _evaluate(node: ProxyNode, tunnel: KernelTunnel, check_gemini_flag: bool, do_chat: bool) -> NodeResult:
    """在已就绪的隧道上执行完整评估"""
    result = NodeResult(node=node, core=tunnel.core)

    proxy_ok, latency_ms = _probe_international(tunnel, result)
    if proxy_ok:
        result.level = LEVEL_PROXY
        result.latency_ms = latency_ms

        _probe_sites(tunnel, result)

        egress_ip, loc_code = fetch_egress_ip(tunnel.port)
        result.egress_ip = egress_ip
        if egress_ip:
            location = get_location(egress_ip)
            result.egress_location = format_location(location) or loc_code
        else:
            result.egress_location = loc_code

        if check_gemini_flag:
            verdict: GeminiVerdict = check_gemini(tunnel.port, do_chat=do_chat)
            result.gemini = verdict
            result.sites[SITE_GEMINI] = SiteProbe(
                name=SITE_GEMINI,
                url=config.GEMINI_APP_URL,
                ok=verdict.available,
                code=verdict.http_code,
                latency_ms=verdict.access_ms,
                error="" if verdict.available else verdict.error or verdict.region_reason,
            )
        return result

    if _probe_domestic(tunnel, result):
        result.level = LEVEL_DOMESTIC
        result.fail_code = "DOMESTIC_ONLY"
        result.fail_reason = "节点仅直连（国内可达、国际不可达）"
        return result

    result.level = LEVEL_DEAD
    errors = [probe.error for probe in result.probes.values() if probe.error]
    primary_error = errors[0] if errors else "全部探针不可达"
    result.fail_code = _classify_failure(primary_error)
    result.fail_reason = primary_error[:200]
    return result


def test_single_node(node: ProxyNode, check_gemini_flag: bool = True, do_chat_flag: bool = True) -> NodeResult:
    """测试单个节点（全生命周期异常保护，永不中断全量巡检）"""
    cores = select_cores(node)
    if not cores:
        return NodeResult(
            node=node,
            level=LEVEL_DEAD,
            fail_code="NO_KERNEL",
            fail_reason="未找到可用内核二进制",
        )

    start_errors: List[str] = []
    for index, core in enumerate(cores):
        tunnel = KernelTunnel(node, core)
        if not tunnel.start():
            start_errors.append(f"{core}: {tunnel.last_error}")
            logger.warning("[%s] 内核 %s 启动失败: %s", node.name, core, tunnel.last_error)
            continue
        try:
            result = _evaluate(node, tunnel, check_gemini_flag, do_chat_flag)
            result.fallback_used = index > 0
            return result
        except Exception as exc:  # noqa: BLE001
            logger.warning("[%s] 测试管道异常: %s", node.name, exc)
            return NodeResult(
                node=node,
                level=LEVEL_DEAD,
                core=core,
                fail_code="PIPELINE_ERROR",
                fail_reason=f"测试异常: {exc}",
            )
        finally:
            tunnel.stop()

    return NodeResult(
        node=node,
        level=LEVEL_DEAD,
        core=cores[0],
        fail_code="KERNEL_START",
        fail_reason="; ".join(start_errors)[:250],
    )


def run_pipeline(
    nodes: List[ProxyNode],
    workers: int = config.DEFAULT_WORKERS,
    check_gemini_flag: bool = True,
    do_chat: bool = True,
    callback: Optional[ProgressCallback] = None,
) -> List[NodeResult]:
    """并发调度全量节点测试，按输入顺序返回结果"""
    if not nodes:
        return []
    worker_count = max(1, min(workers, config.MAX_WORKERS, len(nodes)))
    results: Dict[str, NodeResult] = {}
    lock = threading.Lock()
    completed = 0
    started = time.time()

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(test_single_node, node, check_gemini_flag, do_chat): node
            for node in nodes
        }
        for future in as_completed(futures):
            node = futures[future]
            try:
                verdict = future.result()
            except Exception as exc:  # noqa: BLE001
                verdict = NodeResult(
                    node=node,
                    level=LEVEL_DEAD,
                    fail_code="PIPELINE_ERROR",
                    fail_reason=f"并发调度异常: {exc}",
                )
            results[node.fingerprint] = verdict
            with lock:
                completed += 1
                if callback:
                    callback(completed, len(nodes), verdict)

    logger.info("探测完成：%d 个节点，耗时 %.1f 秒", len(nodes), time.time() - started)
    return [results[node.fingerprint] for node in nodes if node.fingerprint in results]
