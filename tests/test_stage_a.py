# -*- coding: utf-8 -*-
"""tests/test_stage_a.py — 阶段 A 新增能力测试

覆盖：
- Clash / Mihomo YAML 订阅解析（VLESS Reality / SS 插件 / Hysteria2 / Trojan WS）
- 分享链接反向生成与解析闭环（Clash 来源节点必须能导出 Passwall）
- 结构化 JSON 报告结构
- Gemini Cookie 失效状态
- Hysteria2 证书指纹降级策略
- 订阅拉取前的本地代理探活
"""

from __future__ import annotations

import json
import unittest

from core import config
from core.clash import looks_like_clash_yaml, parse_clash_yaml
from core.engine import build_singbox_config
from core.models import GeminiVerdict, LEVEL_PROXY, NodeResult, ProxyNode, SpeedResult
from core.parsers import build_share_link, parse_node_link
from core.report import build_json
from core.subscription import _proxy_alive, _proxy_endpoint

CLASH_SAMPLE = """
port: 7890
proxies:
  - name: "香港-Reality"
    type: vless
    server: hk1.example.com
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    network: tcp
    tls: true
    servername: www.microsoft.com
    flow: xtls-rprx-vision
    client-fingerprint: chrome
    reality-opts:
      public-key: PUBKEY123
      short-id: abcd
  - name: "日本-WS"
    type: vmess
    server: jp1.example.com
    port: 8443
    uuid: 66666666-7777-8888-9999-000000000000
    alterId: 0
    cipher: auto
    network: ws
    tls: true
    servername: jp1.example.com
    ws-opts:
      path: /ray
      headers:
        Host: cdn.example.com
  - name: "新加坡-SS"
    type: ss
    server: sg1.example.com
    port: 8388
    cipher: aes-256-gcm
    password: ss-pass
    plugin: obfs
    plugin-opts:
      mode: http
      host: bing.com
  - name: "美国-Hy2"
    type: hysteria2
    server: us1.example.com
    port: 443
    password: hy2-pass
    sni: www.bing.com
    skip-cert-verify: true
  - name: "剩余流量：128GB"
    type: ss
    server: 127.0.0.1
    port: 1
    cipher: aes-128-gcm
    password: x
"""


class ClashParserTests(unittest.TestCase):
    def test_detect_clash_yaml(self):
        self.assertTrue(looks_like_clash_yaml(CLASH_SAMPLE))
        self.assertFalse(looks_like_clash_yaml("vless://uuid@host:443#name"))
        self.assertFalse(looks_like_clash_yaml("<html>blocked</html>"))

    def test_parse_all_supported_types(self):
        nodes = parse_clash_yaml(CLASH_SAMPLE, "测试机场", "https://example.com/sub")
        by_name = {node.name: node for node in nodes}
        self.assertEqual(len(nodes), 5)
        self.assertEqual(by_name["香港-Reality"].protocol, "vless")
        self.assertEqual(by_name["香港-Reality"].security, "reality")
        self.assertEqual(by_name["香港-Reality"].params["pbk"], "PUBKEY123")
        self.assertEqual(by_name["香港-Reality"].params["flow"], "xtls-rprx-vision")

    def test_vmess_ws_mapping(self):
        nodes = parse_clash_yaml(CLASH_SAMPLE)
        vmess = next(node for node in nodes if node.protocol == "vmess")
        self.assertEqual(vmess.network, "ws")
        self.assertEqual(vmess.path, "/ray")
        self.assertEqual(vmess.host, "cdn.example.com")
        self.assertTrue(vmess.tls)
        self.assertEqual(vmess.params["alter_id"], "0")

    def test_ss_plugin_mapping(self):
        nodes = parse_clash_yaml(CLASH_SAMPLE)
        ss = next(node for node in nodes if node.protocol == "shadowsocks")
        self.assertEqual(ss.params["method"], "aes-256-gcm")
        self.assertEqual(ss.params["plugin"], "obfs-local")
        self.assertIn("obfs=http", ss.params["plugin_opts"])
        self.assertIn("obfs-host=bing.com", ss.params["plugin_opts"])

    def test_hysteria2_mapping(self):
        nodes = parse_clash_yaml(CLASH_SAMPLE)
        hy2 = next(node for node in nodes if node.protocol == "hysteria2")
        self.assertEqual(hy2.uuid, "hy2-pass")
        self.assertEqual(hy2.sni, "www.bing.com")
        self.assertTrue(hy2.tls)
        self.assertEqual(hy2.allow_insecure, True)

    def test_invalid_yaml_returns_empty(self):
        self.assertEqual(parse_clash_yaml("- just\n- a\n- list"), [])
        self.assertEqual(parse_clash_yaml(""), [])

    def test_unsupported_type_skipped(self):
        text = "proxies:\n  - name: x\n    type: ssr\n    server: a.com\n    port: 1\n"
        self.assertEqual(parse_clash_yaml(text), [])


class ShareLinkRoundTripTests(unittest.TestCase):
    def test_clash_node_generates_link(self):
        nodes = parse_clash_yaml(CLASH_SAMPLE)
        for node in nodes:
            self.assertTrue(node.raw, f"{node.name} 未生成分享链接")

    def test_vless_link_round_trip(self):
        original = parse_node_link(
            "vless://11111111-2222-3333-4444-555555555555@hk.example.com:443"
            "?type=tcp&security=reality&sni=www.microsoft.com&flow=xtls-rprx-vision"
            "&pbk=PUBKEY&sid=abcd&fp=chrome#香港"
        )
        self.assertIsNotNone(original)
        rebuilt = parse_node_link(build_share_link(original))
        self.assertIsNotNone(rebuilt)
        self.assertEqual(rebuilt.fingerprint, original.fingerprint)

    def test_trojan_link_round_trip(self):
        original = parse_node_link("trojan://pass@t.example.com:443?sni=t.example.com#T")
        rebuilt = parse_node_link(build_share_link(original))
        self.assertEqual(rebuilt.fingerprint, original.fingerprint)

    def test_hysteria2_link_round_trip(self):
        original = parse_node_link("hysteria2://pw@h.example.com:443?sni=a.com&insecure=1#H")
        rebuilt = parse_node_link(build_share_link(original))
        self.assertEqual(rebuilt.fingerprint, original.fingerprint)

    def test_shadowsocks_link_round_trip(self):
        original = parse_node_link(
            "ss://YWVzLTI1Ni1nY206cGFzcw==@s.example.com:8388#S"
        )
        rebuilt = parse_node_link(build_share_link(original))
        self.assertEqual(rebuilt.fingerprint, original.fingerprint)


class JsonReportTests(unittest.TestCase):
    def _result(self) -> NodeResult:
        node = ProxyNode(
            name="节点A", protocol="vless", address="1.2.3.4", port=443, uuid="u1",
            sni="a.com", security="tls", params={"network": "tcp"},
        )
        result = NodeResult(node=node, level=LEVEL_PROXY, latency_ms=88.0, core="xray")
        result.egress_ip = "5.6.7.8"
        result.egress_location = "日本 东京"
        result.speed = SpeedResult(download_mbps=42.5, ping_ms=88.0, provider="builtin")
        result.gemini = GeminiVerdict(access_ok=True, gemini_status="ok", region_code="JPN")
        return result

    def test_json_structure(self):
        results = [self._result()]
        payload = build_json([results[0].node], results, meta={"version": "9.10"})
        self.assertEqual(payload["meta"]["version"], "9.10")
        self.assertEqual(payload["summary"]["proxy_ok"], 1)
        self.assertEqual(payload["summary"]["speed_measured"], 1)
        node_payload = payload["nodes"][0]
        for key in ("name", "protocol", "level", "speed", "gemini", "fail_code", "fingerprint"):
            self.assertIn(key, node_payload)
        self.assertEqual(node_payload["gemini"]["region_code"], "JPN")
        # 必须可被 jq 类工具直接解析
        json.loads(json.dumps(payload, ensure_ascii=False))

    def test_json_excludes_credentials(self):
        payload = build_json([], [self._result()])
        text = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn('"uuid"', text)
        self.assertNotIn('"raw"', text)


class GeminiCookieStateTests(unittest.TestCase):
    def test_cookie_invalid_tag(self):
        verdict = GeminiVerdict(chat_ok=False, cookie_invalid=True)
        self.assertIn("Cookie", verdict.chat_tag)

    def test_chat_tag_states(self):
        self.assertIn("回答成功", GeminiVerdict(chat_ok=True).chat_tag)
        self.assertIn("提问受阻", GeminiVerdict(chat_ok=False).chat_tag)
        self.assertIn("未测", GeminiVerdict(chat_ok=None).chat_tag)


class Hysteria2PinTests(unittest.TestCase):
    def _node(self, pin: str) -> ProxyNode:
        params = {"sni": "www.bing.com"}
        if pin:
            params["pin_sha256"] = pin
        return ProxyNode(
            name="hy2", protocol="hysteria2", address="1.2.3.4", port=443,
            uuid="pw", sni="www.bing.com", security="tls", params=params,
        )

    def test_pin_downgrades_to_insecure(self):
        """sing-box 只认公钥哈希，机场的证书哈希无法直接下发，应降级而非报错"""
        config_sb = build_singbox_config(self._node("a" * 64), 18081)
        tls = config_sb["outbounds"][0]["tls"]
        self.assertTrue(tls["insecure"])
        self.assertNotIn("certificate_public_key_sha256", tls)

    def test_without_pin_keeps_verify(self):
        tls = build_singbox_config(self._node(""), 18082)["outbounds"][0]["tls"]
        self.assertFalse(tls["insecure"])


class SubscriptionProxyTests(unittest.TestCase):
    def test_endpoint_parsing(self):
        self.assertEqual(_proxy_endpoint("http://127.0.0.1:7890"), ("127.0.0.1", 7890))
        self.assertEqual(_proxy_endpoint("socks5h://127.0.0.1:10808"), ("127.0.0.1", 10808))
        self.assertEqual(_proxy_endpoint("127.0.0.1:7890"), ("127.0.0.1", 7890))
        self.assertEqual(_proxy_endpoint("socks5://127.0.0.1"), ("127.0.0.1", 1080))
        self.assertIsNone(_proxy_endpoint("http://"))

    def test_dead_proxy_detected_fast(self):
        """未监听的端口必须快速判死，不能拖慢订阅拉取"""
        self.assertFalse(_proxy_alive("http://127.0.0.1:9"))
        # 第二次命中缓存
        self.assertFalse(_proxy_alive("http://127.0.0.1:9"))


class SpeedPhaseRetryTests(unittest.TestCase):
    def test_retry_when_below_floor(self):
        """极低速属于采样异常，应重测一次并取较好值，而不是把好节点记成 0.02 Mbps"""
        from core import checker

        calls = []

        def fake_measure(port, upload=False):
            calls.append(port)
            if len(calls) == 1:
                return SpeedResult(download_mbps=0.02, provider="builtin")
            return SpeedResult(download_mbps=12.5, provider="builtin")

        class FakeTunnel:
            def __init__(self, node, core):
                self.port = 12345

            def start(self):
                return True

            def stop(self):
                pass

        originals = (checker.measure_speed, checker.KernelTunnel, checker.select_cores)
        checker.measure_speed = fake_measure
        checker.KernelTunnel = FakeTunnel
        checker.select_cores = lambda node: ["xray"]
        try:
            node = ProxyNode(name="n", protocol="vless", address="1.1.1.1", port=443, uuid="u")
            result = checker.measure_node_speed(node)
            self.assertEqual(len(calls), 2)
            self.assertEqual(result.download_mbps, 12.5)
            self.assertEqual(result.error, "")
        finally:
            checker.measure_speed, checker.KernelTunnel, checker.select_cores = originals


if __name__ == "__main__":
    unittest.main()
