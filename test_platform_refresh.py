import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import stat
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

import requests
import yaml


MODULE_PATH = Path(__file__).with_name("platform_refresh.py")
if MODULE_PATH.exists():
    import platform_refresh as refresh
else:
    refresh = None


class PlatformRefreshTest(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(refresh, "The server refresh module must exist")
        # Refresh tests isolate fetching/publication; engine behavior has its own tests.
        self.validation = patch.object(refresh, "validate_nodes", side_effect=self.passing_validation, create=True)
        self.validation.start()
        self.addCleanup(self.validation.stop)

    @staticmethod
    def passing_validation(nodes, converted, **kwargs):
        checked = datetime.now(timezone.utc).isoformat(timespec="seconds")
        results = {node["id"]: {"status": "passed" if node["uri"] in converted else "unsupported",
                                 "checked_at": checked, "latency_ms": 100 if node["uri"] in converted else None,
                                 "reason": "https_probes_passed" if node["uri"] in converted else "unsupported_conversion"}
                   for node in nodes}
        return results, {"status": "completed", "engine": "mihomo", "checked_at": checked,
                         "probe_urls": ["https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204"],
                         "timeout_ms": 8000, "vantage_point": "43.108.37.222"}

    def test_only_connectivity_passed_nodes_enter_every_export(self):
        urls = ["https://one.example/sub", "https://two.example/sub"]
        good = "trojan://pass@good.example:443#HK"
        failed = "trojan://pass@bad.example:443#JP"
        unsupported = "ss://aes-128-gcm:pass@ss.example:443?plugin=unknown#US"
        alias = good.replace("#HK", "#Hong%20Kong")
        fetch = lambda url, timeout: refresh.FetchResult(
            (good + "\n" + failed + "\n" + unsupported if url == urls[0] else alias).encode(), 200, {}, 1)

        def validate(nodes, converted, **kwargs):
            results, summary = self.passing_validation(nodes, converted, **kwargs)
            for node in nodes:
                if node["server"] == "bad.example":
                    results[node["id"]].update(status="failed", latency_ms=None, reason="probe_failed")
            return results, summary

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            health = refresh.refresh(root, urls, fetch=fetch, validator=validate)
            self.assertEqual(health["nodes_total"], 3)
            self.assertEqual(health["nodes_verified"], 1)
            self.assertEqual(health["published_nodes_total"], 1)
            self.assertEqual(health["nodes_failed"], 1)
            self.assertEqual(health["nodes_unverified"], 1)
            self.assertEqual(health["verified_protocol_counts"], {"trojan": 1})
            self.assertEqual(health["yaml_nodes_total"], 1)
            self.assertEqual(health["validation"]["counts"], {"passed": 1, "failed": 1, "unsupported": 1, "unverified": 0})
            index = json.loads((root / "sub/node_index.json").read_text())
            self.assertEqual(len(index["nodes"]), 3)
            self.assertEqual(sum(node["published"] for node in index["nodes"]), 1)
            self.assertEqual(len(next(node for node in index["nodes"] if node["server"] == "good.example")["source_ids"]), 2)
            self.assertEqual((root / "sub/all.txt").read_text().strip(), good)
            self.assertEqual((root / "sub/proto/trojan.txt").read_text().strip(), good)
            self.assertEqual((root / "sub/proto/ss.txt").read_text(), "")
            self.assertEqual((root / "sub/regions/jp/passwall2.txt").read_text(), "")
            for path in root.joinpath("sub").rglob("*.txt"):
                self.assertNotIn(failed, path.read_text())
                self.assertNotIn(unsupported, path.read_text())
            metadata = json.loads((root / "sub/url_meta.json").read_text())
            self.assertEqual([item["nodes_total"] for item in metadata], [3, 1])
            self.assertEqual([item["nodes_verified"] for item in metadata], [1, 1])
            self.assertEqual([item["nodes_published"] for item in metadata], [1, 1])

    def test_unavailable_checker_fails_closed_without_discarding_provenance(self):
        uri = "trojan://pass@one.example:443#US"
        fetch = lambda url, timeout: refresh.FetchResult(uri.encode(), 200, {}, 1)

        def unavailable(nodes, converted, **kwargs):
            return {}, {"status": "unavailable", "engine": "mihomo", "checked_at": None,
                        "reason": "core_unavailable", "probe_urls": [], "vantage_point": "43.108.37.222"}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            health = refresh.refresh(root, ["https://one.example/sub"], fetch=fetch, validator=unavailable)
            self.assertEqual(health["nodes_total"], 1)
            self.assertEqual(health["nodes_verified"], 0)
            self.assertEqual(health["nodes_unverified"], 1)
            self.assertEqual((root / "sub/all.txt").read_text(), "")
            self.assertEqual(yaml.safe_load((root / "sub/all.yaml").read_text()), {"proxies": []})
            node = json.loads((root / "sub/node_index.json").read_text())["nodes"][0]
            self.assertFalse(node["published"])
            self.assertEqual(node["validation"]["status"], "unverified")

    def test_invalid_validation_options_fail_before_fetch(self):
        for options in ({"check_timeout_ms": 0}, {"check_timeout_ms": 40000}, {"check_workers": 0},
                        {"check_workers": 65}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):
                    refresh.refresh(directory, [], **options)

    def test_checker_exception_never_leaks_secret_or_publishes_nodes(self):
        fetch = lambda url, timeout: refresh.FetchResult(b"trojan://pass@one.example:443", 200, {}, 1)
        def broken(nodes, converted, **kwargs):
            raise RuntimeError("sensitive-controller-secret")
        with tempfile.TemporaryDirectory() as directory:
            health = refresh.refresh(directory, ["https://one.example/sub"], fetch=fetch, validator=broken)
            self.assertEqual(health["nodes_verified"], 0)
            self.assertEqual(health["validation"]["reason"], "checker_error")
            self.assertNotIn("sensitive-controller-secret", json.dumps(health))
            self.assertEqual(Path(directory, "sub/all.txt").read_text(), "")

    def test_health_write_failure_cannot_switch_exports_without_health(self):
        uri = "trojan://pass@one.example:443"
        good = lambda url, timeout: refresh.FetchResult(uri.encode(), 200, {}, 1)
        bad = lambda url, timeout: refresh.FetchResult(b"Denied", 403, {}, 1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = refresh.refresh(root, ["https://one.example/sub"], fetch=good)
            with patch.object(refresh, "_atomic_json", side_effect=OSError("disk full")), self.assertRaises(OSError):
                refresh.refresh(root, ["https://one.example/sub"], fetch=bad)
            self.assertEqual(json.loads((root / "health.json").read_text()), first)
            self.assertEqual((root / "sub/all.txt").read_text().strip(), uri)
            self.assertTrue(json.loads((root / "sub/node_index.json").read_text())["nodes"][0]["published"])

    def test_mixed_sources_export_one_snapshot_with_every_origin(self):
        urls = ["https://one.example/sub?token=one", "https://two.example/sub?token=two",
                "https://timeout.example/sub", "https://empty.example/sub",
                "https://depleted.example/sub"]
        common = "trojan://secret@hk.example:443?sni=edge.example#HK%20Premium"
        alias = common.replace("HK%20Premium", "Hong%20Kong%20Alternate")
        extra = "vless://id@jp.example:8443?security=tls&type=ws&path=%2Fsub&host=edge.example#JP"
        bodies = {
            urls[0]: (common + "\nnot a valid node\n" + extra).encode(),
            urls[1]: base64.b64encode((alias + "\n").encode()),
            urls[3]: b"<html>Service unavailable</html>",
            urls[4]: common.encode(),
        }
        calls = []

        def fetch(url, timeout):
            calls.append((url, timeout))
            if url == urls[2]:
                raise requests.Timeout("a failure containing a secret token")
            headers = {"Subscription-Userinfo": "upload=5; download=5; total=10"} if url == urls[4] else {}
            return refresh.FetchResult(bodies[url], 200, headers, 12.5)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            health = refresh.refresh(root, urls, workers=3, timeout=7, fetch=fetch)
            index = json.loads((root / "sub/node_index.json").read_text())
            meta = json.loads((root / "sub/url_meta.json").read_text())
            self.assertEqual(health["refresh_status"], "partial")
            self.assertFalse(health["stale"])
            self.assertEqual((health["source_total"], health["source_alive"], health["nodes_total"]), (5, 2, 2))
            self.assertEqual(health["protocol_counts"], {"trojan": 1, "vless": 1})
            self.assertEqual({item["url"]: item["status"] for item in meta}, {
                urls[0]: "available", urls[1]: "available", urls[2]: "timeout",
                urls[3]: "invalid_payload", urls[4]: "quota_depleted",
            })
            self.assertEqual(len(calls), 5)
            self.assertTrue(all(timeout == 7 for _, timeout in calls))
            node = next(node for node in index["nodes"] if node["server"] == "hk.example")
            self.assertCountEqual([index["sources"][sid]["url"] for sid in node["source_ids"]], urls[:2])
            self.assertTrue(all(node["published"] for node in index["nodes"]))
            self.assertEqual(len((root / "sub/all.txt").read_text().splitlines()), 2)
            self.assertEqual((root / "sub/urls.txt").read_text().splitlines(), urls[:2])
            for item in meta:
                sid = hashlib.sha1(item["url"].encode()).hexdigest()[:12]
                self.assertEqual(item["id"], sid)
                provider = json.loads((root / "sub/providers" / (sid + ".json")).read_text())
                self.assertEqual(provider["available"], item["available"])
            depleted = next(item for item in meta if item["url"] == urls[4])
            self.assertEqual(depleted["nodes_total"], 0)
            self.assertEqual(depleted["parsed_nodes_total"], 1)
            self.assertEqual(depleted["traffic"]["remaining"], 0)
            proxies = yaml.safe_load((root / "sub/all.yaml").read_text())["proxies"]
            self.assertEqual(len(proxies), 2)
            self.assertEqual(health["yaml_protocol_counts"], {"trojan": 1, "vless": 1})
            self.assertEqual((root / "sub/proto/trojan.txt").read_text().strip(), common)
            self.assertEqual(len(yaml.safe_load((root / "sub/clash/vless.yaml").read_text())["proxies"]), 1)
            self.assertEqual(len((root / "sub/regions/hk/passwall2.txt").read_text().splitlines()), 1)
            self.assertEqual(proxies[1]["ws-opts"]["headers"], {"Host": "edge.example"})
            self.assertNotIn("secret token", json.dumps(health))

    def test_all_failed_refresh_keeps_provenance_but_revokes_old_exports(self):
        url = "https://one.example/sub"
        node = "trojan://pass@one.example:443#US"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            good = lambda url, timeout: refresh.FetchResult(node.encode(), 200, {}, 10)
            first = refresh.refresh(root, [url], fetch=good)
            first_nodes = json.loads((root / "sub/node_index.json").read_text())["nodes"]
            bad = lambda url, timeout: refresh.FetchResult(b"Denied", 403, {}, 10)
            failed = refresh.refresh(root, [url], fetch=bad)
            self.assertEqual((root / "sub/all.txt").read_text(), "")
            self.assertEqual(yaml.safe_load((root / "sub/all.yaml").read_text()), {"proxies": []})
            kept = json.loads((root / "sub/node_index.json").read_text())["nodes"]
            self.assertEqual([node["id"] for node in kept], [node["id"] for node in first_nodes])
            self.assertTrue(all(not node["published"] for node in kept))
            self.assertTrue(all(node["validation"]["status"] == "unverified" for node in kept))
            self.assertEqual(failed["refresh_status"], "failed")
            self.assertTrue(failed["stale"])
            self.assertEqual(failed["source_alive"], 0)
            self.assertEqual(failed["nodes_total"], 1)
            self.assertEqual(failed["nodes_verified"], 0)
            self.assertEqual(failed["validation"]["status"], "not_run")
            self.assertEqual(failed["build_time_utc"], first["build_time_utc"])
            self.assertEqual(failed["refresh_failures"][0]["status"], "http_error")
            self.assertEqual(json.loads((root / "health.json").read_text()), failed)

    def test_first_failed_refresh_writes_empty_honest_exports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bad = lambda url, timeout: refresh.FetchResult(b"proxies: []", 200, {}, 10)
            health = refresh.refresh(root, ["https://one.example/sub"], fetch=bad)
            self.assertEqual(health["refresh_status"], "failed")
            self.assertFalse(health["stale"])
            self.assertEqual(health["nodes_total"], 0)
            self.assertEqual(json.loads((root / "sub/node_index.json").read_text())["nodes"], [])
            self.assertEqual((root / "sub/all.txt").read_text(), "")
            self.assertEqual(yaml.safe_load((root / "sub/all.yaml").read_text()), {"proxies": []})
            self.assertEqual(health["refresh_failures"][0]["status"], "unsupported_format")

    def test_workers_bound_concurrent_fetches_and_deduplicate_source_urls(self):
        active = maximum = 0
        lock = threading.Lock()
        urls = ["https://source{}.example/sub".format(i) for i in range(8)]

        def fetch(url, timeout):
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(maximum, active)
            time.sleep(0.015)
            with lock:
                active -= 1
            return refresh.FetchResult(b"trojan://pass@same.example:443", 200, {}, 1)

        with tempfile.TemporaryDirectory() as directory:
            health = refresh.refresh(Path(directory), urls + urls, workers=2, fetch=fetch)
            self.assertEqual(health["source_total"], 8)
            self.assertEqual(health["nodes_total"], 1)
            self.assertEqual(maximum, 2)

    def test_http_fetch_verifies_certificates_and_uses_subscription_user_agent(self):
        response = MagicMock()
        response.status_code = 200
        response.headers = {"Subscription-Userinfo": "download=1; total=2"}
        response.iter_content.return_value = [b"trojan://pass@one.example:443"]
        response.__enter__.return_value = response
        with patch.object(requests, "get", return_value=response) as get:
            result = refresh.fetch_subscription("https://one.example/sub", 7)
        self.assertEqual(result.status_code, 200)
        self.assertIn(b"trojan://", result.content)
        self.assertEqual(get.call_args.kwargs["timeout"], 7)
        self.assertTrue(get.call_args.kwargs["verify"])
        self.assertTrue(get.call_args.kwargs["stream"])
        self.assertIn("User-Agent", get.call_args.kwargs["headers"])

    def test_yaml_conversion_keeps_transport_and_reality_or_skips_unknown_options(self):
        uri = "vless://id@[2001:db8::1]:443?security=reality&type=grpc&serviceName=proxy&sni=edge.example&pbk=key&sid=01&fp=chrome&flow=xtls-rprx-vision#Edge"
        proxy = refresh.uri_to_clash_proxy(uri)
        self.assertEqual(proxy["server"], "2001:db8::1")
        self.assertEqual(proxy["reality-opts"], {"public-key": "key", "short-id": "01"})
        self.assertEqual(proxy["grpc-opts"], {"grpc-service-name": "proxy"})
        self.assertEqual(proxy["flow"], "xtls-rprx-vision")
        self.assertIsNone(refresh.uri_to_clash_proxy(uri.replace("type=grpc", "type=quic")))
        self.assertIsNone(refresh.uri_to_clash_proxy("ss://aes-128-gcm:pass@ss.example:443?plugin=unknown"))

    def test_common_udp_and_fast_open_flags_are_retained_for_yaml_import(self):
        uris = ["ss://aes-128-gcm:pass@ss.example:443?udp=true&tfo=false",
                "trojan://pass@one.example:443?udp=0&tfo=1"]
        for uri, udp, tfo in ((uris[0], True, False), (uris[1], False, True)):
            with self.subTest(uri=uri):
                proxy = refresh.uri_to_clash_proxy(uri)
                self.assertIsNotNone(proxy)
                self.assertEqual(proxy["udp"], udp)
                self.assertEqual(proxy["tfo"], tfo)
        vmess = {"add": "one.example", "port": 443, "id": "uuid", "udp": True, "tfo": False}
        encoded = base64.b64encode(json.dumps(vmess).encode()).decode()
        proxy = refresh.uri_to_clash_proxy("vmess://" + encoded)
        self.assertIsNotNone(proxy)
        self.assertTrue(proxy["udp"])
        self.assertFalse(proxy["tfo"])
        self.assertIsNone(refresh.uri_to_clash_proxy(uris[0].replace("udp=true", "udp=maybe")))

    def test_inline_clash_sources_use_same_provenance_and_verification(self):
        body = yaml.safe_dump({"proxies": [{"name": "HK", "type": "trojan", "server": "one.example",
                                            "port": 443, "password": "secret", "udp": True}],
                               "rules": ["MATCH,DIRECT"]}).encode()
        fetch = lambda url, timeout: refresh.FetchResult(body, 200, {}, 1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            health = refresh.refresh(root, ["https://one.example/clash"], fetch=fetch)
            self.assertEqual(health["source_alive"], 1)
            self.assertEqual(health["nodes_verified"], 1)
            proxies = yaml.safe_load((root / "sub/all.yaml").read_text())["proxies"]
            self.assertTrue(proxies[0]["udp"])
            self.assertEqual(proxies[0]["password"], "secret")
            self.assertNotIn("rules", yaml.safe_load((root / "sub/all.yaml").read_text()))

    def test_expired_subscription_is_not_available(self):
        expired = int(datetime.now(timezone.utc).timestamp()) - 100
        fetch = lambda url, timeout: refresh.FetchResult(b"trojan://pass@one.example:443", 200,
                                                       {"subscription-userinfo": "expire={}".format(expired)}, 1)
        with tempfile.TemporaryDirectory() as directory:
            health = refresh.refresh(Path(directory), ["https://one.example/sub"], fetch=fetch)
            self.assertEqual(health["source_alive"], 0)
            self.assertEqual(health["refresh_failures"][0]["status"], "expired")

    def test_malformed_source_does_not_abort_other_sources(self):
        fetch = lambda url, timeout: refresh.FetchResult(b"trojan://pass@one.example:443", 200, {}, 1)
        with tempfile.TemporaryDirectory() as directory:
            health = refresh.refresh(Path(directory), ["https://[invalid/sub", "https://one.example/sub"], fetch=fetch)
            self.assertEqual(health["source_alive"], 1)
            self.assertEqual(health["refresh_failures"][0]["status"], "invalid_source")

    def test_health_is_readable_by_web_server_and_reports_next_refresh(self):
        fetch = lambda url, timeout: refresh.FetchResult(b"trojan://pass@one.example:443", 200, {}, 1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            health = refresh.refresh(root, ["https://one.example/sub"], fetch=fetch)
            self.assertEqual(stat.S_IMODE((root / "health.json").stat().st_mode), 0o644)
            next_run = datetime.fromisoformat(health["next_run_utc"])
            last_attempt = datetime.fromisoformat(health["last_attempt_utc"])
            self.assertTrue(0 <= (next_run - last_attempt).total_seconds() <= 1800)
            self.assertIn(next_run.minute, (0, 30))
            self.assertEqual(next_run.second, 0)
            self.assertEqual(health["refresh_interval_seconds"], 1800)

    def test_failure_during_legacy_directory_publication_restores_previous_data(self):
        fetch = lambda url, timeout: refresh.FetchResult(b"trojan://pass@one.example:443", 200, {}, 1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            refresh.refresh(root, ["https://one.example/sub"], fetch=fetch)
            legacy = root / "legacy"
            shutil.copytree(root / "sub", legacy)
            (root / "sub").unlink()
            legacy.rename(root / "sub")
            original = (root / "sub/all.txt").read_bytes()
            original_replace = refresh.os.replace

            def replace(source, target):
                if Path(source).name.startswith(".sub-"):
                    raise OSError("publication interrupted")
                return original_replace(source, target)

            with patch.object(refresh.os, "replace", side_effect=replace), self.assertRaises(OSError):
                refresh.refresh(root, ["https://one.example/sub"], fetch=fetch)
            self.assertEqual((root / "sub/all.txt").read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
