#!/usr/bin/env python3
"""Clash YAML import must preserve connection settings through URI export."""

import unittest

import yaml

from node_lookup import parse_node_uri
from platform_refresh import uri_to_clash_proxy

try:
    from clash_import import parse_clash_subscription
except ModuleNotFoundError as error:
    if error.name != "clash_import":
        raise
    parse_clash_subscription = None


UUID = "12345678-1234-1234-1234-123456789abc"


class ClashImportTest(unittest.TestCase):
    def import_text(self, text):
        self.assertIsNotNone(parse_clash_subscription, "Clash YAML importer is missing")
        return parse_clash_subscription(text)

    def import_proxies(self, proxies):
        return self.import_text(yaml.safe_dump({"proxies": proxies}, allow_unicode=True))

    def test_raw_trojan_and_ss_keep_names_endpoints_and_credentials(self):
        nodes = self.import_text("""proxies:
  - name: 'Hong Kong #1'
    type: trojan
    server: edge.example
    port: 443
    password: 'p@ss:word?# with space'
  - name: '\u4e1c\u4eac SS'
    type: ss
    server: '2001:db8::1'
    port: 8388
    cipher: aes-256-gcm
    password: '\u5bc6\u7801:@?#'
""")
        self.assertEqual(len(nodes), 2)
        self.assertEqual(uri_to_clash_proxy(nodes[0]), {
            "name": "Hong Kong #1", "type": "trojan", "server": "edge.example", "port": 443,
            "password": "p@ss:word?# with space", "tls": True,
        })
        self.assertEqual(uri_to_clash_proxy(nodes[1]), {
            "name": "\u4e1c\u4eac SS", "type": "ss", "server": "2001:db8::1", "port": 8388,
            "cipher": "aes-256-gcm", "password": "\u5bc6\u7801:@?#",
        })
        self.assertEqual(parse_node_uri(nodes[1])["name"], "\u4e1c\u4eac SS")

    def test_trojan_tls_and_websocket_settings_survive_uri_conversion(self):
        nodes = self.import_proxies([{
            "name": "WS", "type": "trojan", "server": "edge.example", "port": 443,
            "password": "secret", "sni": "tls.example", "skip-cert-verify": False,
            "client-fingerprint": "chrome", "alpn": ["h2", "http/1.1"], "network": "ws",
            "ws-opts": {"path": "/connect?a=1&b=2", "headers": {"Host": "cdn.example"}},
        }])
        self.assertEqual(len(nodes), 1)
        self.assertEqual(uri_to_clash_proxy(nodes[0]), {
            "name": "WS", "type": "trojan", "server": "edge.example", "port": 443,
            "password": "secret", "tls": True, "sni": "tls.example", "skip-cert-verify": False,
            "client-fingerprint": "chrome", "alpn": ["h2", "http/1.1"], "network": "ws",
            "ws-opts": {"path": "/connect?a=1&b=2", "headers": {"Host": "cdn.example"}},
        })

    def test_vless_reality_and_grpc_survive_uri_conversion(self):
        nodes = self.import_proxies([{
            "name": "Reality", "type": "vless", "server": "2001:db8::2", "port": 443,
            "uuid": UUID, "tls": True, "flow": "xtls-rprx-vision", "servername": "tls.example",
            "client-fingerprint": "chrome", "network": "grpc",
            "grpc-opts": {"grpc-service-name": "proxy/service"},
            "reality-opts": {"public-key": "public_key", "short-id": "01"},
        }])
        self.assertEqual(len(nodes), 1)
        self.assertEqual(uri_to_clash_proxy(nodes[0]), {
            "name": "Reality", "type": "vless", "server": "2001:db8::2", "port": 443,
            "uuid": UUID, "tls": True, "flow": "xtls-rprx-vision", "servername": "tls.example",
            "client-fingerprint": "chrome", "network": "grpc",
            "grpc-opts": {"grpc-service-name": "proxy/service"},
            "reality-opts": {"public-key": "public_key", "short-id": "01"},
        })

    def test_vmess_websocket_tls_survive_uri_conversion(self):
        nodes = self.import_proxies([{
            "name": "VMess", "type": "vmess", "server": "vmess.example", "port": 8443,
            "uuid": UUID, "alterId": 0, "cipher": "auto", "tls": True,
            "servername": "tls.example", "skip-cert-verify": True,
            "client-fingerprint": "firefox", "alpn": ["h2"], "network": "ws",
            "ws-opts": {"path": "/ws", "headers": {"Host": "cdn.example"}},
        }])
        self.assertEqual(len(nodes), 1)
        self.assertEqual(uri_to_clash_proxy(nodes[0]), {
            "name": "VMess", "type": "vmess", "server": "vmess.example", "port": 8443,
            "uuid": UUID, "alterId": 0, "cipher": "auto", "tls": True,
            "servername": "tls.example", "skip-cert-verify": True,
            "client-fingerprint": "firefox", "alpn": ["h2"], "network": "ws",
            "ws-opts": {"path": "/ws", "headers": {"Host": "cdn.example"}},
        })

    def test_hysteria2_obfuscation_and_port_ranges_survive_uri_conversion(self):
        nodes = self.import_proxies([{
            "name": "HY2", "type": "hysteria2", "server": "hy2.example", "port": 443,
            "password": "auth:@?#", "sni": "tls.example", "skip-cert-verify": False,
            "alpn": ["h3"], "obfs": "salamander", "obfs-password": "obfs:@?#",
            "ports": "443,5000-5100",
        }])
        self.assertEqual(len(nodes), 1)
        self.assertEqual(uri_to_clash_proxy(nodes[0]), {
            "name": "HY2", "type": "hysteria2", "server": "hy2.example", "port": 443,
            "password": "auth:@?#", "sni": "tls.example", "skip-cert-verify": False,
            "alpn": ["h3"], "obfs": "salamander", "obfs-password": "obfs:@?#",
            "ports": "443,5000-5100",
        })

    def test_connection_options_that_cannot_be_exported_skip_the_entire_node(self):
        base = {"name": "SS", "type": "ss", "server": "ss.example", "port": 8388,
                "cipher": "aes-128-gcm", "password": "secret"}
        for option in [
            {"plugin": "v2ray-plugin", "plugin-opts": {"mode": "websocket"}},
            {"dialer-proxy": "other"}, {"interface-name": "eth0"}, {"ip-version": "ipv4"},
        ]:
            with self.subTest(option=option):
                self.assertEqual(self.import_proxies([{**base, **option}]), [])
        self.assertEqual(len(self.import_proxies([base])), 1)

    def test_udp_and_fast_open_flags_survive_conversion_including_false_values(self):
        for protocol, credentials in [
            ("ss", {"cipher": "aes-128-gcm", "password": "secret"}),
            ("trojan", {"password": "secret"}),
            ("vmess", {"uuid": UUID, "cipher": "auto", "alterId": 0}),
            ("vless", {"uuid": UUID}),
            ("hysteria2", {"password": "secret"}),
        ]:
            with self.subTest(protocol=protocol):
                nodes = self.import_proxies([{
                    "name": "Flags", "type": protocol, "server": "edge.example", "port": 443,
                    **credentials, "udp": False, "tcp-fast-open": True,
                }])
                self.assertEqual(len(nodes), 1)
                proxy = uri_to_clash_proxy(nodes[0])
                self.assertIsNotNone(proxy)
                self.assertIs(proxy["udp"], False)
                self.assertIs(proxy["tfo"], True)
        base = {"name": "Flags", "type": "trojan", "server": "edge.example", "port": 443,
                "password": "secret"}
        self.assertEqual(self.import_proxies([{**base, "tfo": True, "tcp-fast-open": False}]), [])
        self.assertEqual(self.import_proxies([{**base, "udp": "true"}]), [])

    def test_legacy_websocket_aliases_are_preserved_and_conflicts_rejected(self):
        base = {"name": "Legacy", "type": "vmess", "server": "vmess.example", "port": 443,
                "uuid": UUID, "cipher": "auto", "alterId": 0, "network": "ws", "udp": True,
                "ws-path": "/ws", "ws-headers": {"Host": "cdn.example"},
                "ws-opts": {"path": "/ws", "headers": {"Host": "cdn.example"}}}
        nodes = self.import_proxies([base])
        self.assertEqual(len(nodes), 1)
        proxy = uri_to_clash_proxy(nodes[0])
        self.assertIsNotNone(proxy)
        self.assertEqual(proxy["ws-opts"], {"path": "/ws", "headers": {"Host": "cdn.example"}})
        self.assertIs(proxy["udp"], True)
        for option in [{"ws-path": "/other"}, {"ws-headers": {"Host": "other.example"}}]:
            with self.subTest(option=option):
                self.assertEqual(self.import_proxies([{**base, **option}]), [])
        del base["ws-opts"]
        self.assertEqual(len(self.import_proxies([base])), 1)

    def test_unsupported_transports_headers_and_nested_options_are_not_lost(self):
        base = {"name": "VLESS", "type": "vless", "server": "vless.example", "port": 443,
                "uuid": UUID, "tls": True}
        options = [
            {"network": "ws", "ws-opts": {"path": "/", "headers": {"X-Token": "secret"}}},
            {"network": "ws", "ws-opts": {"path": "/", "max-early-data": 2048}},
            {"network": "grpc", "grpc-opts": {"grpc-service-name": "s", "grpc-mode": "gun"}},
            {"network": "tcp", "ws-opts": {"path": "/"}},
            {"network": "http", "http-opts": {"path": ["/"]}},
            {"reality-opts": {"public-key": "key", "short-id": "01", "spider-x": "/"}},
        ]
        for option in options:
            with self.subTest(option=option):
                self.assertEqual(self.import_proxies([{**base, **option}]), [])
        self.assertEqual(self.import_proxies([{
            **base, "type": "vmess", "cipher": "auto", "alterId": 0, "network": "grpc",
            "grpc-opts": {"grpc-service-name": "cannot-represent"},
        }]), [])

    def test_malformed_documents_unknown_nodes_and_providers_yield_no_nodes(self):
        documents = [
            "proxies: [", "hello", "- trojan://secret@edge.example:443", "proxies: null",
            "proxies: {}", "proxies: [null, 1, false]", "proxies: [{type: wireguard}]",
            "proxy-providers: {remote: {type: http, url: 'https://example.test/provider'}}",
            "!!python/object/apply:os.system ['echo unsafe']",
        ]
        for text in documents:
            with self.subTest(text=text):
                self.assertEqual(self.import_text(text), [])

    def test_bad_field_types_do_not_abort_valid_neighbors(self):
        base = {"name": "Good", "type": "trojan", "server": "edge.example", "port": 443,
                "password": "secret"}
        for field, values in {
            "port": [True, "443", 0, 65536, 443.0],
            "server": [True, "", "edge example", "http://edge.example", "edge.example@other.example",
                       "edge.example?path", "edge.example#fragment", "edge.example%40other.example"],
            "password": [True, None, "", ["secret"]],
            "skip-cert-verify": ["false", 0, None],
            "alpn": ["h2", ["h2,h3"], [False], []],
            "name": [False, {}, ""],
        }.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    nodes = self.import_proxies([{**base, field: value}, base])
                    self.assertEqual(len(nodes), 1)
                    self.assertEqual(parse_node_uri(nodes[0])["name"], "Good")

    def test_rules_and_provider_configuration_cannot_create_imported_nodes(self):
        nodes = self.import_text("""proxies:
  - {name: Real, type: trojan, server: edge.example, port: 443, password: secret}
rules: ["MATCH,DIRECT"]
script: {code: "trojan://wrong@other.example:443"}
proxy-providers:
  remote: {type: http, url: 'https://example.test/provider'}
""")
        self.assertEqual(len(nodes), 1)
        self.assertEqual(parse_node_uri(nodes[0])["server"], "edge.example")

    def test_aliases_duplicate_fields_and_deep_documents_are_rejected(self):
        self.assertEqual(self.import_text("proxies: &p [*p]"), [])
        self.assertEqual(self.import_text("""proxies:
  - {name: Node, type: trojan, server: edge.example, port: 443, password: first, password: second}
"""), [])
        self.assertEqual(self.import_text("proxies: " + "[" * 1000 + "]" * 1000), [])

    def test_node_count_limit_rejects_oversized_lists(self):
        text = "proxies:\n" + "  - null\n" * 20001
        self.assertEqual(self.import_text(text), [])

    def test_fast_open_aliases_validate_both_types_even_when_python_values_compare_equal(self):
        base = {"name": "Flags", "type": "trojan", "server": "edge.example", "port": 443,
                "password": "secret"}
        for options in [{"tfo": True, "tcp-fast-open": 1}, {"tfo": False, "tcp-fast-open": 0}]:
            with self.subTest(options=options):
                self.assertEqual(self.import_proxies([{**base, **options}]), [])


if __name__ == "__main__":
    unittest.main()
