# -*- coding: utf-8 -*-
"""核心单元测试
=============
覆盖解析、配置生成、Passwall 导出映射与 Gemini 判据等纯逻辑，
并在内核二进制存在时调用官方 `run -test` / `check` 做配置合法性验证。
"""

from __future__ import annotations

import base64
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from core import config
from core.engine import build_singbox_config, build_xray_config
from core.exporter import _uci_node_block, export_artifacts
from core.gemini import evaluate_region, extract_feature_flag, extract_region_code, extract_reply_text
from core.models import LEVEL_PROXY, GeminiVerdict, NodeResult, ProxyNode, SpeedResult
from core.parsers import dedupe_nodes, parse_node_link
from core.report import format_summary, render_report
from core.speedtest import _format_url, format_speed, mbps, parse_ookla_output
from core.subscription import parse_userinfo


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode().rstrip("=")


VLESS_REALITY = (
    "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443"
    "?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome"
    "&pbk=7xKSmY9K1qxi4-oo8x2sPHDwdJxRh0hZOf34d5BRRUw&sid=0123&spx=%2F"
    "&type=tcp&flow=xtls-rprx-vision#Tokyo-Reality"
)

VLESS_WS = (
    "vless://11111111-1111-1111-1111-111111111111@5.6.7.8:443"
    "?encryption=none&security=tls&sni=edge.example.com&host=edge.example.com"
    "&path=%2Fws&type=ws#Edge-WS"
)

VMESS_JSON = {
    "v": "2",
    "ps": "VMess-WS",
    "add": "9.9.9.9",
    "port": 443,
    "id": "11111111-1111-1111-1111-111111111111",
    "aid": 0,
    "scy": "auto",
    "net": "ws",
    "type": "none",
    "host": "vm.example.com",
    "path": "/vm",
    "tls": "tls",
    "sni": "vm.example.com",
}

HY2_LINK = (
    "hysteria2://password123@6.6.6.6:443?sni=hy.example.com&insecure=1"
    "&obfs=salamander&obfs-password=obfs-pass&mport=20000-30000&upmbps=50&downmbps=200#Hy2"
)

ANYTLS_LINK = "anytls://secret@7.7.7.7:8443?security=tls&sni=any.example.com&insecure=1#AnyTLS"

SS_LINK = (
    f"ss://{_b64('aes-256-gcm:pass')}@8.8.4.4:8388"
    "?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com#SS-Plugin"
)


class ParserTests(unittest.TestCase):
    def test_vless_reality(self) -> None:
        node = parse_node_link(VLESS_REALITY, "测试订阅", "https://example.com/sub")
        self.assertIsNotNone(node)
        assert node is not None
        self.assertEqual(node.protocol, "vless")
        self.assertEqual(node.address, "1.2.3.4")
        self.assertEqual(node.port, 443)
        self.assertEqual(node.security, "reality")
        self.assertTrue(node.reality)
        self.assertEqual(node.params["flow"], "xtls-rprx-vision")
        self.assertEqual(node.params["pbk"], "7xKSmY9K1qxi4-oo8x2sPHDwdJxRh0hZOf34d5BRRUw")
        self.assertEqual(node.sni, "www.microsoft.com")
        self.assertEqual(node.preferred_core, "xray")

    def test_vless_ws(self) -> None:
        node = parse_node_link(VLESS_WS)
        assert node is not None
        self.assertEqual(node.network, "ws")
        self.assertEqual(node.host, "edge.example.com")
        self.assertEqual(node.path, "/ws")
        self.assertTrue(node.tls)

    def test_vmess_json(self) -> None:
        link = "vmess://" + _b64(json.dumps(VMESS_JSON))
        node = parse_node_link(link)
        assert node is not None
        self.assertEqual(node.protocol, "vmess")
        self.assertEqual(node.address, "9.9.9.9")
        self.assertEqual(node.network, "ws")
        self.assertEqual(node.host, "vm.example.com")
        self.assertEqual(node.path, "/vm")
        self.assertTrue(node.tls)

    def test_hysteria2(self) -> None:
        node = parse_node_link(HY2_LINK)
        assert node is not None
        self.assertEqual(node.protocol, "hysteria2")
        self.assertEqual(node.uuid, "password123")
        self.assertEqual(node.params["ports"], "20000-30000")
        self.assertEqual(node.params["obfs"], "salamander")
        self.assertEqual(node.preferred_core, "sing-box")

    def test_anytls(self) -> None:
        node = parse_node_link(ANYTLS_LINK)
        assert node is not None
        self.assertEqual(node.protocol, "anytls")
        self.assertEqual(node.uuid, "secret")
        self.assertTrue(node.tls)
        self.assertTrue(node.allow_insecure)

    def test_shadowsocks_plugin(self) -> None:
        node = parse_node_link(SS_LINK)
        assert node is not None
        self.assertEqual(node.protocol, "shadowsocks")
        self.assertEqual(node.params["method"], "aes-256-gcm")
        self.assertEqual(node.uuid, "pass")
        self.assertEqual(node.params["plugin"], "obfs-local")
        self.assertIn("obfs=http", node.params["plugin_opts"])
        self.assertEqual(node.preferred_core, "sing-box")

    def test_placeholder_filtered(self) -> None:
        self.assertIsNone(parse_node_link(VLESS_REALITY.replace("#Tokyo-Reality", "#剩余流量：100G")))

    def test_fingerprint_ignores_name(self) -> None:
        first = parse_node_link(VLESS_WS)
        second = parse_node_link(VLESS_WS.replace("#Edge-WS", "#另一台同名节点"))
        assert first is not None and second is not None
        self.assertEqual(first.fingerprint, second.fingerprint)

    def test_cross_subscription_dedupe(self) -> None:
        first = parse_node_link(VLESS_WS, "订阅A", "https://a")
        second = parse_node_link(VLESS_WS, "订阅B", "https://b")
        assert first is not None and second is not None
        self.assertEqual(len(dedupe_nodes([first, second])), 1)

    def test_base64_body_keeps_trailing_slash(self) -> None:
        from core.parsers import _split_uri

        body, _, _ = _split_uri("vmess://AbC/", "vmess://")
        self.assertEqual(body, "AbC/")

    def test_shadowsocks_with_trailing_slash(self) -> None:
        link = f"ss://{_b64('aes-256-gcm:pass')}@8.8.4.4:8388/?plugin=v2ray-plugin%3Btls#SS"
        node = parse_node_link(link)
        assert node is not None
        self.assertEqual(node.address, "8.8.4.4")
        self.assertEqual(node.port, 8388)
        self.assertEqual(node.params["plugin"], "v2ray-plugin")


class UserinfoTests(unittest.TestCase):
    def test_userinfo(self) -> None:
        remaining, expire = parse_userinfo(
            "upload=1073741824; download=2147483648; total=53687091200; expire=1893456000"
        )
        self.assertIn("/", remaining)
        self.assertTrue(expire)

    def test_userinfo_empty(self) -> None:
        self.assertEqual(parse_userinfo(""), ("", ""))

    def test_error_sanitizer_redacts_token(self) -> None:
        from core.subscription import _sanitize_error

        url = "https://example.com/api/v1/client/subscribe?token=abcdef123456"
        message = f"Failed to fetch {url}: token=abcdef123456 rejected"
        sanitized = _sanitize_error(message, url)
        self.assertNotIn("abcdef123456", sanitized)
        self.assertIn("<订阅地址>", sanitized)


class GeminiTests(unittest.TestCase):
    def test_region_and_flag(self) -> None:
        html = 'x ,2,1,200,"USA" y {"45631641":true} z'
        self.assertEqual(extract_region_code(html), "USA")
        self.assertIs(extract_feature_flag(html), True)
        available, code, flag = evaluate_region(html)
        self.assertTrue(available)
        self.assertEqual(code, "USA")
        self.assertIs(flag, True)

    def test_flag_false_blocks(self) -> None:
        html = '["45631641",null,false] ,2,1,200,"JPN"'
        self.assertIs(extract_feature_flag(html), False)
        available, _, _ = evaluate_region(html)
        self.assertFalse(available)

    def test_blocked_region(self) -> None:
        html = '{"45631641":true} ,2,1,200,"CHN"'
        available, code, _ = evaluate_region(html)
        self.assertFalse(available)
        self.assertEqual(code, "CHN")

    def test_extract_reply(self) -> None:
        frame = [["wrb.fr", None, json.dumps([["1+1 等于 2"]])]]
        text = extract_reply_text(")]}'\n\n" + json.dumps(frame))
        self.assertIn("2", text)

    def test_extract_numeric_reply(self) -> None:
        frame = [["wrb.fr", None, json.dumps([["2"]])]]
        self.assertEqual(extract_reply_text(json.dumps(frame)), "2")


class ConfigBuilderTests(unittest.TestCase):
    def test_xray_vless_reality(self) -> None:
        node = parse_node_link(VLESS_REALITY)
        assert node is not None
        payload = build_xray_config(node, 18080)
        outbound = payload["outbounds"][0]
        self.assertEqual(outbound["protocol"], "vless")
        self.assertEqual(outbound["streamSettings"]["security"], "reality")
        self.assertEqual(outbound["streamSettings"]["realitySettings"]["shortId"], "0123")
        self.assertEqual(outbound["settings"]["vnext"][0]["users"][0]["flow"], "xtls-rprx-vision")

    def test_xray_vmess_ws(self) -> None:
        node = parse_node_link("vmess://" + _b64(json.dumps(VMESS_JSON)))
        assert node is not None
        payload = build_xray_config(node, 18081)
        stream = payload["outbounds"][0]["streamSettings"]
        self.assertEqual(stream["network"], "ws")
        self.assertEqual(stream["wsSettings"]["host"], "vm.example.com")
        self.assertEqual(payload["outbounds"][0]["settings"]["vnext"][0]["users"][0]["security"], "auto")

    def test_singbox_anytls(self) -> None:
        node = parse_node_link(ANYTLS_LINK)
        assert node is not None
        payload = build_singbox_config(node, 18082)
        outbound = payload["outbounds"][0]
        self.assertEqual(outbound["type"], "anytls")
        self.assertTrue(outbound["tls"]["enabled"])
        self.assertTrue(outbound["tls"]["insecure"])

    def test_singbox_hysteria2_hop(self) -> None:
        node = parse_node_link(HY2_LINK)
        assert node is not None
        payload = build_singbox_config(node, 18083)
        outbound = payload["outbounds"][0]
        self.assertEqual(outbound["server_ports"], ["20000:30000"])
        self.assertNotIn("server_port", outbound)
        self.assertEqual(outbound["obfs"]["type"], "salamander")


class ExporterTests(unittest.TestCase):
    def test_uci_mapping(self) -> None:
        node = parse_node_link(VLESS_REALITY)
        assert node is not None
        block = "\n".join(_uci_node_block(node, 1))
        self.assertIn("uci set passwall.$sec.type='Xray'", block)
        self.assertIn("uci set passwall.$sec.transport='raw'", block)
        self.assertIn("uci set passwall.$sec.reality='1'", block)
        self.assertIn("uci set passwall.$sec.reality_publicKey=", block)

    def test_gemini_chat_export(self) -> None:
        node = parse_node_link(VLESS_REALITY)
        assert node is not None
        result = NodeResult(node=node, level=LEVEL_PROXY)
        result.gemini = GeminiVerdict(access_ok=True, chat_ok=True, region_code="JPN")

        with tempfile.TemporaryDirectory() as tmp:
            stats = export_artifacts([node], [result], Path(tmp))
            chat_file = Path(tmp) / config.EXPORT_GEMINI_CHAT_FILE
            gemini_file = Path(tmp) / config.EXPORT_GEMINI_FILE
            self.assertEqual(stats["gemini_chat"], 1)
            self.assertIn(node.raw, chat_file.read_text(encoding="utf-8"))
            self.assertIn(node.raw, gemini_file.read_text(encoding="utf-8"))

    def test_uci_quote_escapes_single_quote(self) -> None:
        node = ProxyNode(
            name="it's a node",
            protocol="trojan",
            address="1.2.3.4",
            port=443,
            uuid="p'w",
            security="tls",
            params={"network": "tcp"},
            raw="trojan://p'w@1.2.3.4:443#x",
        )
        block = "\n".join(_uci_node_block(node, 1))
        self.assertIn("'\\''", block)


class SpeedTestTests(unittest.TestCase):
    def test_mbps_conversion(self) -> None:
        self.assertEqual(mbps(1_000_000, 1.0), 8.0)
        self.assertEqual(mbps(2_500_000, 2.0), 10.0)
        self.assertEqual(mbps(0, 1.0), 0.0)
        self.assertEqual(mbps(1024, 0), 0.0)

    def test_format_speed(self) -> None:
        self.assertEqual(format_speed(0), "-")
        self.assertEqual(format_speed(8.234), "8.23 Mbps")
        self.assertEqual(format_speed(45.6), "45.6 Mbps")
        self.assertEqual(format_speed(123.4), "123 Mbps")

    def test_url_template(self) -> None:
        self.assertEqual(_format_url("https://speed.test/down?bytes={bytes}", 42), "https://speed.test/down?bytes=42")
        self.assertEqual(_format_url("https://speed.test/down", 42), "https://speed.test/down")

    def test_default_speed_url_uses_bytes_placeholder(self) -> None:
        self.assertTrue(any("{bytes}" in url for url in config.SPEEDTEST_URLS))

    def test_speed_result(self) -> None:
        self.assertFalse(SpeedResult().ok)
        node = parse_node_link(VLESS_REALITY)
        assert node is not None
        result = NodeResult(node=node, level=LEVEL_PROXY)
        self.assertEqual(result.speed_mbps, 0.0)
        result.speed = SpeedResult(download_mbps=42.5, downloaded_bytes=10_000_000)
        self.assertEqual(result.speed_mbps, 42.5)
        self.assertTrue(result.speed.ok)

    def test_parse_ookla_output(self) -> None:
        payload = {
            "type": "result",
            "ping": {"jitter": 0.42, "latency": 18.5, "low": 17, "high": 22},
            "download": {"bandwidth": 12_500_000, "bytes": 125_000_000, "elapsed": 10_000},
            "upload": {"bandwidth": 3_750_000, "bytes": 37_500_000, "elapsed": 10_000},
            "server": {"name": "Test Server", "location": "Tokyo", "country": "Japan"},
            "result": {"url": "https://www.speedtest.net/result/c/abc"},
        }
        result = parse_ookla_output(json.dumps(payload))
        self.assertEqual(result.provider, "ookla")
        self.assertEqual(result.download_mbps, 100.0)
        self.assertEqual(result.upload_mbps, 30.0)
        self.assertEqual(result.ping_ms, 18.5)
        self.assertEqual(result.jitter_ms, 0.42)
        self.assertEqual(result.server, "Test Server (Tokyo)")
        self.assertTrue(result.ok)

    def test_parse_ookla_output_invalid(self) -> None:
        with self.assertRaises(ValueError):
            parse_ookla_output('{"type": "log"}')
        with self.assertRaises(ValueError):
            parse_ookla_output("not-json")

    def test_report_renders_speed(self) -> None:
        node = parse_node_link(VLESS_REALITY)
        assert node is not None
        result = NodeResult(node=node, level=LEVEL_PROXY, latency_ms=88.0)
        result.speed = SpeedResult(download_mbps=42.5, downloaded_bytes=10_000_000)
        text = render_report([node], [result])
        self.assertIn("测 速 排 行 榜", text)
        self.assertIn("42.5 Mbps", text)
        self.assertIn("平均下载 42.5 Mbps", format_summary([result]))


@unittest.skipUnless(Path(config.XRAY_PATH).exists(), "xray 二进制不存在")
class XrayKernelValidationTests(unittest.TestCase):
    def _validate(self, node: ProxyNode) -> None:
        config.ensure_directories()
        path = config.TEMP_DIR / "temp_xray_unittest.json"
        path.write_text(json.dumps(build_xray_config(node, 18084)), encoding="utf-8")
        try:
            completed = subprocess.run(
                [config.XRAY_PATH, "run", "-test", "-config", str(path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        finally:
            path.unlink(missing_ok=True)

    def test_reality(self) -> None:
        node = parse_node_link(VLESS_REALITY)
        assert node is not None
        self._validate(node)

    def test_vmess_ws(self) -> None:
        node = parse_node_link("vmess://" + _b64(json.dumps(VMESS_JSON)))
        assert node is not None
        self._validate(node)


@unittest.skipUnless(Path(config.SINGBOX_PATH).exists(), "sing-box 二进制不存在")
class SingboxKernelValidationTests(unittest.TestCase):
    def _validate(self, node: ProxyNode) -> None:
        config.ensure_directories()
        path = config.TEMP_DIR / "temp_singbox_unittest.json"
        path.write_text(json.dumps(build_singbox_config(node, 18085)), encoding="utf-8")
        try:
            completed = subprocess.run(
                [config.SINGBOX_PATH, "check", "-c", str(path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        finally:
            path.unlink(missing_ok=True)

    def test_anytls(self) -> None:
        node = parse_node_link(ANYTLS_LINK)
        assert node is not None
        self._validate(node)

    def test_hysteria2(self) -> None:
        node = parse_node_link(HY2_LINK)
        assert node is not None
        self._validate(node)

    def test_shadowsocks_plugin(self) -> None:
        node = parse_node_link(SS_LINK)
        assert node is not None
        self._validate(node)


if __name__ == "__main__":
    unittest.main()
