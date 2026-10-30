# -*- coding: utf-8 -*-
"""tests/test_passwall_alignment.py — Passwall 导出字段对齐测试

断言全部来自上游源码（2026-10-30 克隆版本）：
- `subscribe.lua`：type / protocol / transport 的分配规则
- `client/type/1_sing-box.lua`：`s.option_prefix="singbox_"`，SS 加密方式用
  `ss_method` 且 `rewrite_option="method"`（即写 `method`）
- `client/type/3_ss-rust.lua`：`ss_method` 无改写（即写 `ss_method`）
- `client/type/5_hysteria2.lua`：hop/auth_password 等 `rewrite_option=o.option`
  （即写 `hysteria2_*` 前缀）；tls_serverName / tls_allowInsecure / tls_pinSHA256 不前缀
- `client/type/2_xray.lua`：`tcp_guise_http_host` 为 DynamicList（必须 add_list）
"""

from __future__ import annotations

import unittest

from core.exporter import _passwall_profile, _uci_node_block, validate_node_fields
from core.models import ProxyNode


def _node(protocol: str, **kwargs) -> ProxyNode:
    params = kwargs.pop("params", {})
    return ProxyNode(
        name=kwargs.pop("name", f"{protocol}-node"),
        protocol=protocol,
        address=kwargs.pop("address", "1.2.3.4"),
        port=kwargs.pop("port", 443),
        uuid=kwargs.pop("uuid", "credential"),
        sni=kwargs.pop("sni", "a.example.com"),
        security=kwargs.pop("security", "tls"),
        params=params,
        raw=kwargs.pop("raw", f"{protocol}://c@1.2.3.4:443#n"),
    )


class TypeProtocolMappingTests(unittest.TestCase):
    def test_hysteria2_uses_singbox(self):
        """上游优先 sing-box + protocol=hysteria2，缺核心才用专用 Hysteria2 核心"""
        core, protocol, transport = _passwall_profile(_node("hysteria2"))
        self.assertEqual(core, "sing-box")
        self.assertEqual(protocol, "hysteria2")
        self.assertEqual(transport, "")

    def test_anytls_uses_singbox(self):
        core, protocol, _ = _passwall_profile(_node("anytls"))
        self.assertEqual((core, protocol), ("sing-box", "anytls"))

    def test_plain_ss_uses_xray_raw(self):
        core, protocol, transport = _passwall_profile(_node("shadowsocks", params={"method": "aes-256-gcm"}))
        self.assertEqual((core, protocol, transport), ("Xray", "shadowsocks", "raw"))

    def test_ss_with_plugin_uses_singbox(self):
        core, protocol, _ = _passwall_profile(
            _node("shadowsocks", params={"method": "aes-256-gcm", "plugin": "obfs-local"})
        )
        self.assertEqual((core, protocol), ("sing-box", "shadowsocks"))

    def test_vless_http_maps_to_xhttp(self):
        _, _, transport = _passwall_profile(_node("vless", params={"network": "http"}))
        self.assertEqual(transport, "xhttp")

    def test_vless_tcp_maps_to_raw(self):
        _, _, transport = _passwall_profile(_node("vless", params={"network": "tcp"}))
        self.assertEqual(transport, "raw")


class UciFieldTests(unittest.TestCase):
    def test_ss_writes_both_method_keys(self):
        """Xray/sing-box 读 method，SS-Rust 读 ss_method，必须都写"""
        block = "\n".join(
            _uci_node_block(_node("shadowsocks", params={"method": "2022-blake3-aes-128-gcm"}), 1)
        )
        self.assertIn("uci set passwall.$sec.method='2022-blake3-aes-128-gcm'", block)
        self.assertIn("uci set passwall.$sec.ss_method='2022-blake3-aes-128-gcm'", block)

    def test_ss_plugin_enabled_flag(self):
        block = "\n".join(
            _uci_node_block(
                _node("shadowsocks", params={"method": "aes-256-gcm", "plugin": "obfs-local",
                                             "plugin_opts": "obfs=http"}),
                1,
            )
        )
        self.assertIn("uci set passwall.$sec.plugin_enabled='1'", block)
        self.assertIn("uci set passwall.$sec.plugin='obfs-local'", block)

    def test_hysteria2_fields(self):
        block = "\n".join(
            _uci_node_block(
                _node("hysteria2", params={"ports": "20000-30000", "obfs": "salamander",
                                           "obfs_password": "pw", "up_mbps": "50"}),
                1,
            )
        )
        self.assertIn("uci set passwall.$sec.protocol='hysteria2'", block)
        self.assertIn("uci set passwall.$sec.hysteria2_auth_password='credential'", block)
        self.assertIn("uci set passwall.$sec.hysteria2_hop='20000-30000'", block)
        self.assertIn("uci set passwall.$sec.hysteria2_obfs_type='salamander'", block)
        self.assertIn("uci set passwall.$sec.hysteria2_up_mbps='50'", block)

    def test_hysteria2_no_tcp_fast_open(self):
        """sing-box 的 CBI 没有 tcp_fast_open 选项"""
        block = "\n".join(_uci_node_block(_node("hysteria2"), 1))
        self.assertNotIn("tcp_fast_open", block)

    def test_tcp_guise_host_is_dynamic_list(self):
        node = _node(
            "vless",
            params={"network": "tcp", "header_type": "http", "host": "cdn.example.com", "path": "/x"},
        )
        block = "\n".join(_uci_node_block(node, 1))
        self.assertIn("uci set passwall.$sec.tcp_guise='http'", block)
        self.assertIn("uci add_list passwall.$sec.tcp_guise_http_host='cdn.example.com'", block)
        self.assertIn("uci add_list passwall.$sec.tcp_guise_http_path='/x'", block)

    def test_http_transport_mode_stream_one(self):
        node = _node("vless", params={"network": "http", "path": "/x", "mode": "auto"})
        block = "\n".join(_uci_node_block(node, 1))
        self.assertIn("uci set passwall.$sec.transport='xhttp'", block)
        self.assertIn("uci set passwall.$sec.xhttp_mode='stream-one'", block)

    def test_grpc_mode_default_gun(self):
        node = _node("vless", params={"network": "grpc", "service_name": "svc"})
        block = "\n".join(_uci_node_block(node, 1))
        self.assertIn("uci set passwall.$sec.grpc_serviceName='svc'", block)
        self.assertIn("uci set passwall.$sec.grpc_mode='gun'", block)

    def test_reality_spider_x_only_for_xray(self):
        reality = {"network": "tcp", "pbk": "PUB", "sid": "ab", "spx": "/"}
        xray_block = "\n".join(_uci_node_block(_node("vless", security="reality", params=dict(reality)), 1))
        self.assertIn("uci set passwall.$sec.reality_publicKey='PUB'", xray_block)
        self.assertIn("uci set passwall.$sec.reality_spiderX='/'", xray_block)

        # sing-box（anytls）没有 reality_spiderX 选项
        singbox_block = "\n".join(_uci_node_block(_node("anytls", security="reality", params=dict(reality)), 1))
        self.assertIn("uci set passwall.$sec.reality='1'", singbox_block)
        self.assertNotIn("reality_spiderX", singbox_block)

    def test_tls_allow_insecure_explicit(self):
        block = "\n".join(_uci_node_block(_node("vless", params={"network": "tcp"}), 1))
        self.assertIn("uci set passwall.$sec.tls='1'", block)
        self.assertIn("uci set passwall.$sec.tls_allowInsecure='0'", block)

    def test_pin_sha256_exported(self):
        node = _node("hysteria2", params={"pin_sha256": "a" * 64})
        block = "\n".join(_uci_node_block(node, 1))
        self.assertIn(f"uci set passwall.$sec.tls_pinSHA256='{'a' * 64}'", block)

    def test_add_mode_and_group(self):
        node = _node("vless", params={"network": "tcp"})
        node.sub_name = "一分机场"
        block = "\n".join(_uci_node_block(node, 1))
        self.assertIn("uci set passwall.$sec.add_mode='1'", block)
        self.assertIn("uci set passwall.$sec.group='一分机场'", block)

    def test_section_created_without_quiet_flag(self):
        """uci -q add 在部分固件上不回显 section 名，必须用普通 uci add"""
        block = "\n".join(_uci_node_block(_node("vless", params={"network": "tcp"}), 1))
        self.assertIn("sec=$(uci add passwall nodes)", block)
        self.assertNotIn("uci -q add", block)


class FieldValidationTests(unittest.TestCase):
    def test_missing_uuid_reported(self):
        node = _node("vless", uuid="", params={"network": "tcp"})
        self.assertIn("缺少 uuid", validate_node_fields(node))

    def test_missing_ss_method_reported(self):
        node = _node("shadowsocks", params={})
        self.assertIn("缺少 method", validate_node_fields(node))

    def test_reality_without_pbk_reported(self):
        node = _node("vless", security="reality", params={"network": "tcp"})
        self.assertIn("Reality 缺少 publicKey", validate_node_fields(node))

    def test_valid_node_passes(self):
        node = _node("vless", params={"network": "ws", "path": "/ray", "host": "cdn.example.com"})
        self.assertEqual(validate_node_fields(node), [])


if __name__ == "__main__":
    unittest.main()
