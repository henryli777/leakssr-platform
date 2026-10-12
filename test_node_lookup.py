#!/usr/bin/env python3
"""Offline coverage for node provenance and connection matching."""

import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import node_lookup


def encode(value, urlsafe=True):
    encoder = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    return encoder(value.encode("utf-8")).decode("ascii").rstrip("=")


SOURCE_A = "https://one.example/api/v1/client/subscribe?token=first"
SOURCE_B = "https://two.example/api/v1/client/subscribe?token=second"
UUID = "12345678-1234-1234-1234-123456789abc"
VLESS = "vless://" + UUID + "@HK.Example:443?security=tls&type=ws#Hong%20Kong"


class NodeLookupTest(unittest.TestCase):
    def test_merges_renamed_nodes_and_preserves_every_source(self):
        renamed = (
            "vless://" + UUID + "@hk.example:443?type=ws&security=tls#Primary"
        )
        index = node_lookup.build_node_index(
            {SOURCE_A: [VLESS], SOURCE_B: [renamed, renamed]},
            [{"url": SOURCE_A, "provider": "Airport A", "available": True}],
            [renamed],
        )

        self.assertEqual(index["version"], 1)
        self.assertEqual(len(index["nodes"]), 1)
        node = index["nodes"][0]
        self.assertEqual(set(node["names"]), {"Hong Kong", "Primary"})
        self.assertEqual(set(node["uris"]), {VLESS, renamed})
        self.assertEqual(node["server"], "hk.example")
        self.assertEqual(node["port"], 443)
        self.assertTrue(node["published"])
        self.assertEqual(len(node["source_ids"]), 2)
        sid = hashlib.sha1(SOURCE_A.encode()).hexdigest()[:12]
        self.assertEqual(index["sources"][sid]["url"], SOURCE_A)
        self.assertEqual(index["sources"][sid]["provider"], "Airport A")
        self.assertEqual(index["sources"][sid]["detail_page"], "source.html?id=" + sid)

    def test_keeps_different_credentials_or_transport_options_separate(self):
        alternate_user = VLESS.replace(UUID, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        alternate_transport = VLESS.replace("type=ws", "type=grpc")
        index = node_lookup.build_node_index(
            {SOURCE_A: [VLESS, alternate_user, alternate_transport]}
        )
        self.assertEqual(len(index["nodes"]), 3)

    def test_publication_is_matched_by_connection_instead_of_label(self):
        renamed = VLESS.replace("Hong%20Kong", "Renamed")
        index = node_lookup.build_node_index(
            {SOURCE_A: [VLESS, "trojan://secret@other.example:443#Other"]},
            published_nodes=[renamed],
        )
        self.assertEqual(sum(node["published"] for node in index["nodes"]), 1)
        unpublished = node_lookup.build_node_index({SOURCE_A: [VLESS]}, published_nodes=[])
        self.assertFalse(unpublished["nodes"][0]["published"])

    def test_exported_name_aliases_update_search_without_replacing_original_name(self):
        index = node_lookup.build_node_index({SOURCE_A: [VLESS]})
        original_name = index["nodes"][0]["name"]
        renamed_uri = VLESS.replace("Hong%20Kong", "Different")
        node_lookup.add_node_name_aliases(index, {renamed_uri: ["Client Node", "Client Node_1", "Client Node"]})
        node = index["nodes"][0]
        self.assertEqual(node["name"], original_name)
        self.assertEqual(node["names"], ["Hong Kong", "Client Node", "Client Node_1"])
        self.assertEqual(len(node_lookup.search_node_index(index, "CLIENT NODE_1")), 1)
        self.assertEqual(len(node_lookup.search_node_index(index, "hong kong")), 1)

    def test_exported_name_aliases_ignore_unknown_connections_without_credential_leaks(self):
        alternate_user = VLESS.replace(UUID, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        index = node_lookup.build_node_index({SOURCE_A: [VLESS, alternate_user]})
        unknown = VLESS.replace(UUID, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
        node_lookup.add_node_name_aliases(index, {
            VLESS: ["Known Export"], unknown: ["Unknown Export"], "vless://broken": ["Broken Export"],
        })
        matches = node_lookup.search_node_index(index, "Known Export")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["uri"], VLESS)
        self.assertEqual(node_lookup.search_node_index(index, "Unknown Export"), [])
        self.assertEqual(node_lookup.search_node_index(index, "Broken Export"), [])

    def test_exported_name_aliases_ignore_non_utf8_labels(self):
        index = node_lookup.build_node_index({SOURCE_A: [VLESS]})
        node_lookup.add_node_name_aliases(index, {VLESS: ["\ud800", "Valid Export"]})
        self.assertEqual(index["nodes"][0]["names"], ["Hong Kong", "Valid Export"])
        json.dumps(index, ensure_ascii=False).encode("utf-8")

    def test_query_matches_decoded_names_uuid_fragments_and_all_terms(self):
        index = node_lookup.build_node_index({SOURCE_A: [VLESS]})
        for query in ["HONG KONG", "hong 789abc", "HK.EXAMPLE:443", "123456789abc"]:
            with self.subTest(query=query):
                matches = node_lookup.search_node_index(index, query)
                self.assertEqual(len(matches), 1)
                self.assertEqual(matches[0]["sources"][0]["url"], SOURCE_A)
        self.assertEqual(node_lookup.search_node_index(index, "hong missing"), [])
        self.assertEqual(node_lookup.search_node_index(index, ""), [])
        self.assertEqual(node_lookup.search_node_index(index, "   "), [])

    def test_full_uri_query_matches_renamed_equivalent_connection(self):
        index = node_lookup.build_node_index({SOURCE_A: [VLESS]})
        query = (
            "vless://" + UUID + "@hk.example:443?type=ws&security=tls#Different"
        )
        self.assertEqual(len(node_lookup.search_node_index(index, query)), 1)
        self.assertEqual(node_lookup.search_node_index(index, "vless://hk.example"), [])
        self.assertEqual(node_lookup.search_node_index(index, "https://hk.example"), [])

    def test_malformed_protocol_prefix_never_matches_a_display_name(self):
        index = node_lookup.build_node_index({SOURCE_A: [VLESS.replace("Hong%20Kong", "vless%3A%2Fbroken")]})
        self.assertEqual(node_lookup.search_node_index(index, "vless:/broken"), [])

    def test_vmess_decodes_embedded_name_and_normalizes_json_order(self):
        config = {
            "v": "2", "ps": "Tokyo Main", "add": "TOKYO.EXAMPLE", "port": "443",
            "id": UUID, "aid": "0", "net": "ws", "path": "/connect", "tls": "tls",
        }
        first = "vmess://" + encode(json.dumps(config))
        renamed_config = dict(reversed(list(config.items())))
        renamed_config.update(ps="Backup", port=443, aid=0)
        second = "vmess://" + encode(json.dumps(renamed_config))
        parsed = node_lookup.parse_node_uri(first)
        self.assertEqual(parsed["name"], "Tokyo Main")
        self.assertEqual(parsed["server"], "tokyo.example")
        self.assertEqual(node_lookup.canonical_node_key(first), node_lookup.canonical_node_key(second))
        renamed_config["path"] = "/different"
        different = "vmess://" + encode(json.dumps(renamed_config))
        self.assertNotEqual(node_lookup.canonical_node_key(first), node_lookup.canonical_node_key(different))

    def test_ss_sip002_and_full_base64_match_including_ipv6(self):
        auth = encode("aes-256-gcm:secret", urlsafe=False)
        first = "ss://" + auth + "@[2001:db8::1]:8388#First"
        second = "ss://" + encode("aes-256-gcm:secret@[2001:0db8::1]:8388") + "#Second"
        literal = "ss://aes-256-gcm:secret@[2001:db8::1]:8388#Literal"
        self.assertEqual(node_lookup.canonical_node_key(first), node_lookup.canonical_node_key(second))
        self.assertEqual(node_lookup.canonical_node_key(first), node_lookup.canonical_node_key(literal))
        parsed = node_lookup.parse_node_uri(first)
        self.assertEqual(parsed["server"], "2001:db8::1")
        index = node_lookup.build_node_index({SOURCE_A: [first]})
        self.assertEqual(len(node_lookup.search_node_index(index, "[2001:0db8::1]:8388")), 1)
        self.assertEqual(len(node_lookup.search_node_index(index, "2001:0db8::1")), 1)
        self.assertEqual(len(node_lookup.search_node_index(index, "[2001:db8::1]")), 1)

    def test_ss_plugin_configuration_is_not_discarded(self):
        base = "ss://" + encode("aes-128-gcm:password") + "@ss.example:8388"
        first = base + "?plugin=v2ray-plugin%3Btls#First"
        second = base + "?plugin=obfs-local%3Bobfs%3Dhttp#Second"
        self.assertNotEqual(node_lookup.canonical_node_key(first), node_lookup.canonical_node_key(second))

    def test_ss_password_percent_encoding_has_equivalent_identity(self):
        first = "ss://aes-256-gcm:p%40ss%3Aword@ss.example:8388"
        second = "ss://" + encode("aes-256-gcm:p@ss:word") + "@ss.example:8388"
        self.assertEqual(node_lookup.canonical_node_key(first), node_lookup.canonical_node_key(second))

    def test_ssr_decodes_remarks_and_preserves_obfuscation_configuration(self):
        content = "ssr.example:443:auth_sha1_v4:aes-256-cfb:tls1.2_ticket_auth:" + encode("secret")
        first = "ssr://" + encode(content + "/?remarks=" + encode("Tokyo SSR") + "&obfsparam=" + encode("a.example"))
        renamed = "ssr://" + encode(content + "/?obfsparam=" + encode("a.example") + "&remarks=" + encode("Backup"))
        different = "ssr://" + encode(content + "/?obfsparam=" + encode("b.example"))
        self.assertEqual(node_lookup.parse_node_uri(first)["name"], "Tokyo SSR")
        self.assertEqual(node_lookup.canonical_node_key(first), node_lookup.canonical_node_key(renamed))
        self.assertNotEqual(node_lookup.canonical_node_key(first), node_lookup.canonical_node_key(different))

    def test_ssr_without_query_accepts_the_standard_trailing_slash(self):
        content = "ssr.example:443:auth_sha1_v4:aes-256-cfb:plain:" + encode("secret")
        first = "ssr://" + encode(content + "/")
        second = "ssr://" + encode(content + "/?remarks=" + encode("Backup"))
        self.assertIsNotNone(node_lookup.parse_node_uri(first))
        self.assertEqual(node_lookup.canonical_node_key(first), node_lookup.canonical_node_key(second))

    def test_vmess_rejects_nonstring_or_missing_server_fields(self):
        for server in [None, [], {}, 123, ""]:
            with self.subTest(server=server):
                uri = "vmess://" + encode(json.dumps({"add": server, "port": "443", "id": UUID}))
                self.assertIsNone(node_lookup.parse_node_uri(uri))

    def test_non_utf8_vmess_data_is_skipped_without_aborting_valid_nodes(self):
        for field in ["path", "ps"]:
            with self.subTest(field=field):
                config = {"add": "example.test", "port": 443, "id": "user", field: "\ud800"}
                malformed = "vmess://" + encode(json.dumps(config))
                try:
                    index = node_lookup.build_node_index({SOURCE_A: [VLESS, malformed]})
                    json.dumps(index, ensure_ascii=False).encode("utf-8")
                except UnicodeError as error:
                    self.fail("Malformed node aborted index construction: " + str(error))
                self.assertEqual(len(index["nodes"]), 1)
                self.assertEqual(index["nodes"][0]["uri"], VLESS)
                self.assertIsNone(node_lookup.parse_node_uri(malformed))

    def test_hysteria_alias_query_order_and_percent_encoded_password(self):
        first = "hy2://p%40ss@[2001:db8::2]:443/?sni=edge.example&insecure=1#First"
        second = "hysteria2://p%40ss@[2001:0db8::2]:443?insecure=1&sni=edge.example#Second"
        parsed = node_lookup.parse_node_uri(first)
        self.assertEqual(parsed["protocol"], "hysteria2")
        self.assertEqual(node_lookup.canonical_node_key(first), node_lookup.canonical_node_key(second))

    def test_trojan_credentials_with_encoded_at_sign_are_preserved(self):
        first = "trojan://p%40ss@trojan.example:443?sni=edge.example#First"
        second = first.replace("p%40ss", "another")
        self.assertIsNotNone(node_lookup.parse_node_uri(first))
        self.assertNotEqual(node_lookup.canonical_node_key(first), node_lookup.canonical_node_key(second))

    def test_invalid_nodes_are_skipped_without_fabricating_matches(self):
        malformed = [
            "", "ss://broken", "vmess://not-json", "ssr://garbage",
            "vless://missing-server", "vless://user@bad.example:70000", "https://example.org",
            "trojan://password@bad host:443", "trojan://password@host:zero",
        ]
        for uri in malformed:
            with self.subTest(uri=uri):
                self.assertIsNone(node_lookup.parse_node_uri(uri))
                self.assertIsNone(node_lookup.canonical_node_key(uri))
        index = node_lookup.build_node_index({SOURCE_A: malformed})
        self.assertEqual(index["nodes"], [])

    def test_offline_rebuild_uses_provider_pairs_and_skips_missing_corrupt_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / "good.json").write_text(json.dumps({"url": SOURCE_A, "provider": "Airport A"}))
            (directory / "good.txt").write_text(VLESS + "\ninvalid\n")
            (directory / "missing.json").write_text(json.dumps({"url": SOURCE_B}))
            (directory / "broken.json").write_text("{")
            (directory / "orphan.txt").write_text(VLESS)
            index = node_lookup.rebuild_node_index(directory)
            missing = node_lookup.rebuild_node_index(directory / "absent")
        self.assertEqual(len(index["nodes"]), 1)
        self.assertEqual(len(index["sources"]), 2)
        self.assertEqual(index["nodes"][0]["names"], ["Hong Kong"])
        self.assertEqual(missing["nodes"], [])

    def test_offline_rebuild_preserves_stale_origins_with_current_availability_and_exports(self):
        omitted = "trojan://secret@other.example:443#Omitted"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / "providers"
            directory.mkdir()
            (directory / "current.json").write_text(json.dumps({"url": SOURCE_A}))
            (directory / "current.txt").write_text(VLESS + "\n" + omitted)
            (directory / "stale.json").write_text(json.dumps({"url": SOURCE_B, "available": True}))
            (directory / "stale.txt").write_text(VLESS)
            (root / "url_meta.json").write_text(json.dumps([{"url": SOURCE_A, "available": True}]))
            (root / "all.txt").write_text(encode(VLESS))
            index = node_lookup.rebuild_node_index(directory)
        sources = {source["url"]: source for source in index["sources"].values()}
        self.assertTrue(sources[SOURCE_A]["available"])
        self.assertFalse(sources[SOURCE_B]["available"])
        matches = node_lookup.search_node_index(index, "hong kong")
        self.assertEqual(len(matches[0]["sources"]), 2)
        self.assertTrue(matches[0]["published"])
        self.assertFalse(node_lookup.search_node_index(index, "omitted")[0]["published"])

    def test_offline_rebuild_empty_current_manifests_are_authoritative(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / "providers"
            directory.mkdir()
            (directory / "one.json").write_text(json.dumps({"url": SOURCE_A, "available": True}))
            (directory / "one.txt").write_text(VLESS)
            (root / "url_meta.json").write_text("[]")
            (root / "all.txt").write_text("")
            index = node_lookup.rebuild_node_index(directory)
        self.assertEqual(len(index["nodes"]), 1)
        self.assertFalse(next(iter(index["sources"].values()))["available"])
        self.assertFalse(index["nodes"][0]["published"])

    def test_offline_rebuild_without_current_manifests_reports_unknown_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "providers"
            directory.mkdir()
            (directory / "unknown.json").write_text(json.dumps({"url": SOURCE_A}))
            (directory / "unknown.txt").write_text(VLESS)
            (directory / "explicit.json").write_text(json.dumps({"url": SOURCE_B, "available": False}))
            (directory / "explicit.txt").write_text(VLESS)
            index = node_lookup.rebuild_node_index(directory)
        sources = {source["url"]: source for source in index["sources"].values()}
        self.assertIsNone(sources[SOURCE_A]["available"])
        self.assertFalse(sources[SOURCE_B]["available"])
        self.assertIsNone(index["nodes"][0]["published"])

    def test_cli_outputs_original_sources_as_json_from_another_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            index_path = Path(tmp) / "node_index.json"
            index_path.write_text(json.dumps(node_lookup.build_node_index({SOURCE_A: [VLESS]})))
            result = subprocess.run(
                [sys.executable, str(Path(__file__).with_name("node_lookup.py")), "hong", "kong", "--index", str(index_path), "--json"],
                cwd=tmp, capture_output=True, text=True, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        matches = json.loads(result.stdout)
        self.assertEqual(matches[0]["sources"][0]["url"], SOURCE_A)

    def test_cli_rebuild_writes_index_without_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "providers"
            directory.mkdir()
            (directory / "one.json").write_text(json.dumps({"url": SOURCE_A}))
            (directory / "one.txt").write_text(VLESS)
            output = Path(tmp) / "result.json"
            result = subprocess.run(
                [sys.executable, str(Path(__file__).with_name("node_lookup.py")), "--rebuild", "--providers-dir", str(directory), "--output", str(output)],
                cwd=tmp, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            index = json.loads(output.read_text())
        self.assertEqual(len(index["nodes"]), 1)


if __name__ == "__main__":
    unittest.main()
