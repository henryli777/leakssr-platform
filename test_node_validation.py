"""Offline coverage for fail-closed Mihomo connectivity validation."""

from contextlib import ExitStack, contextmanager
from pathlib import Path
import stat
import subprocess
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import unquote, urlsplit

import requests
import yaml


MODULE_PATH = Path(__file__).with_name("node_validation.py")
if MODULE_PATH.exists():
    import node_validation as validation
else:
    validation = None


PROBES = ("https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204")


def sample_nodes(count=1):
    nodes = [{"id": "{:020x}".format(number), "uri": "trojan://secret@n{}.example:443".format(number),
              "protocol": "trojan"} for number in range(count)]
    converted = {node["uri"]: {"name": "Untrusted label", "type": "trojan", "server": "n{}.example".format(number),
                               "port": 443, "password": "secret"}
                 for number, node in enumerate(nodes)}
    return nodes, converted


class FakeResponse:
    def __init__(self, body, status_code=200):
        self.body = body
        self.status_code = status_code

    def json(self):
        if isinstance(self.body, BaseException):
            raise self.body
        return self.body


class FakeProcess:
    def __init__(self, stop_code=None, slow_stop=False):
        self.stop_code = stop_code
        self.slow_stop = slow_stop
        self.terminated = False
        self.killed = False
        self.waits = []

    def poll(self):
        return self.stop_code

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True
        self.stop_code = -9

    def wait(self, timeout):
        self.waits.append(timeout)
        if self.slow_stop and not self.killed:
            raise subprocess.TimeoutExpired("mihomo", timeout)
        self.stop_code = self.stop_code if self.stop_code is not None else 0
        return self.stop_code


class FakeSession:
    def __init__(self, engine):
        self.engine = engine
        self.trust_env = True
        self.headers = {}
        self.closed = False

    def get(self, url, **kwargs):
        self.engine.sessions_used.append(self)
        self.engine.requests.append((url, kwargs))
        path = urlsplit(url).path
        if path == "/version":
            return FakeResponse({"meta": True, "version": "v1.19.29"})
        if path == "/proxies":
            self.engine.inventory_calls += 1
            if self.engine.inventory_calls <= self.engine.inventory_waits:
                first = next(iter(self.engine.proxies), None)
                return FakeResponse({"proxies": {first: {}} if first else {}})
            self.engine.inventory_ready = True
            return FakeResponse({"proxies": self.engine.proxies})
        name = unquote(path.split("/")[2])
        if not path.endswith("/delay"):
            return FakeResponse({"extra": self.engine.history.get(name, {})})
        if not self.engine.inventory_ready:
            self.engine.delays_before_ready += 1
            return FakeResponse({"message": "Resource not found"}, 404)
        probe = kwargs["params"]["url"]
        proxy = self.engine.proxies[name]
        value = self.engine.delays.get((proxy["server"], probe), self.engine.delays.get(probe, 40))
        with self.engine.lock:
            self.engine.active += 1
            self.engine.max_active = max(self.engine.max_active, self.engine.active)
        try:
            if self.engine.probe_wait:
                time.sleep(self.engine.probe_wait)
            if isinstance(value, BaseException):
                raise value
            response = value if isinstance(value, FakeResponse) else FakeResponse({"delay": value})
            delay = response.body.get("delay") if isinstance(response.body, dict) else None
            alive = self.engine.http_status.get(probe, 204) == 204
            self.engine.history.setdefault(name, {})[probe] = {
                "alive": alive, "history": [{"time": "2026-10-12T00:00:00Z", "delay": delay}],
            }
            if self.engine.omit_history:
                self.engine.history[name] = {}
            return response
        finally:
            with self.engine.lock:
                self.engine.active -= 1

    def close(self):
        self.closed = True


class FakeEngine:
    def __init__(self, *, delays=None, http_status=None, config_code=0, startup_code=None,
                 slow_stop=False, probe_wait=0, omit_history=False, inventory_waits=0):
        self.delays = delays or {}
        self.http_status = http_status or {}
        self.config_code = config_code
        self.process = FakeProcess(startup_code, slow_stop)
        self.probe_wait = probe_wait
        self.omit_history = omit_history
        self.inventory_waits = inventory_waits
        self.inventory_calls = 0
        self.inventory_ready = inventory_waits == 0
        self.delays_before_ready = 0
        self.proxies = {}
        self.history = {}
        self.requests = []
        self.sessions = []
        self.sessions_used = []
        self.active = 0
        self.max_active = 0
        self.lock = threading.Lock()
        self.config = None
        self.config_path = None
        self.config_mode = None
        self.directory_mode = None
        self.run_kwargs = None
        self.popen_kwargs = None

    def session(self):
        session = FakeSession(self)
        self.sessions.append(session)
        return session

    def config_test(self, command, **kwargs):
        self.run_kwargs = kwargs
        self.config_path = Path(command[command.index("-f") + 1])
        self.config = yaml.safe_load(self.config_path.read_text())
        self.config_mode = stat.S_IMODE(self.config_path.stat().st_mode)
        self.directory_mode = stat.S_IMODE(self.config_path.parent.stat().st_mode)
        self.proxies = {proxy["name"]: proxy for proxy in self.config["proxies"]}
        return subprocess.CompletedProcess(command, self.config_code)

    def start(self, command, **kwargs):
        self.popen_kwargs = kwargs
        return self.process

    @contextmanager
    def installed(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(validation.shutil, "which", return_value="/safe/mihomo"))
            stack.enter_context(patch.object(validation.subprocess, "run", side_effect=self.config_test))
            stack.enter_context(patch.object(validation.subprocess, "Popen", side_effect=self.start))
            stack.enter_context(patch.object(validation.requests, "Session", side_effect=self.session))
            yield self


class NodeValidationTest(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(validation, "The real Mihomo checker module must exist")

    def validate(self, engine, count=1, **kwargs):
        nodes, converted = sample_nodes(count)
        with engine.installed():
            results, summary = validation.validate_nodes(nodes, converted, **kwargs)
        return nodes, converted, results, summary

    def test_pass_requires_both_https_204_probes_and_measured_maximum_latency(self):
        engine = FakeEngine(delays={PROBES[0]: 58, PROBES[1]: 83})
        nodes, converted, results, summary = self.validate(engine, vantage_point="43.108.37.222")
        result = results[nodes[0]["id"]]
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["latency_ms"], 83)
        self.assertEqual([probe["url"] for probe in result["probes"]], list(PROBES))
        self.assertTrue(all(probe["status"] == "passed" for probe in result["probes"]))
        self.assertTrue(result["checked_at"].endswith("Z"))
        self.assertEqual(summary["status"], "completed")
        self.assertEqual(summary["engine"], "mihomo")
        self.assertEqual(summary["engine_version"], "v1.19.29")
        self.assertEqual(summary["probe_urls"], list(PROBES))
        self.assertEqual(summary["vantage_point"], "43.108.37.222")
        self.assertEqual(summary["counts"], {"passed": 1, "failed": 0, "unsupported": 0, "unverified": 0})
        self.assertEqual(converted[nodes[0]["uri"]]["name"], "Untrusted label")
        self.assertNotIn("secret", str(results))
        self.assertNotIn("secret", str(summary))

    def test_target_status_mismatch_fails_despite_positive_delay_response(self):
        for target_status in (200, 302, 500):
            with self.subTest(target_status=target_status):
                engine = FakeEngine(http_status={PROBES[1]: target_status})
                nodes, _, results, _ = self.validate(engine)
                result = results[nodes[0]["id"]]
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["reason"], "probe_unexpected_status")
                self.assertEqual(result["probes"][1]["status"], "failed")
                self.assertIsNone(result["probes"][1]["latency_ms"])

    def test_positive_delay_without_fresh_expected_status_history_is_not_a_pass(self):
        nodes, _, results, _ = self.validate(FakeEngine(omit_history=True))
        result = results[nodes[0]["id"]]
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["reason"], "probe_unverified_status")
        self.assertIsNone(result["latency_ms"])

    def test_invalid_delays_are_never_accepted_or_fabricated(self):
        for delay in (0, -1, True, "12", None, 8001, float("nan"), float("inf")):
            with self.subTest(delay=delay):
                nodes, _, results, _ = self.validate(FakeEngine(delays={PROBES[0]: delay, PROBES[1]: delay}))
                result = results[nodes[0]["id"]]
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["reason"], "probe_invalid_delay")
                self.assertIsNone(result["latency_ms"])
                self.assertEqual(len(result["probes"]), 2)

    def test_one_timeout_keeps_node_failed_and_sanitizes_exception_text(self):
        nodes, _, results, _ = self.validate(FakeEngine(delays={PROBES[0]: requests.Timeout("password=secret")}))
        result = results[nodes[0]["id"]]
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["reason"], "probe_timeout")
        self.assertEqual(result["latency_ms"], 40)
        self.assertEqual(len(result["probes"]), 2)
        self.assertNotIn("password", str(result))

    def test_controller_errors_and_bad_json_fail_closed(self):
        for response, reason in ((FakeResponse({"error": "secret"}, 503), "probe_http_error"),
                                 (FakeResponse(ValueError("secret")), "probe_invalid_response"),
                                 (FakeResponse([1]), "probe_invalid_response"),
                                 (requests.ConnectionError("secret"), "probe_request_error")):
            with self.subTest(reason=reason):
                nodes, _, results, _ = self.validate(FakeEngine(delays={PROBES[0]: response}))
                self.assertEqual(results[nodes[0]["id"]]["status"], "failed")
                self.assertEqual(results[nodes[0]["id"]]["reason"], reason)

    def test_missing_binary_reports_unverified_and_keeps_unsupported_distinct(self):
        nodes, converted = sample_nodes(2)
        del converted[nodes[1]["uri"]]
        with patch.object(validation.shutil, "which", return_value=None):
            results, summary = validation.validate_nodes(nodes, converted)
        self.assertEqual(results[nodes[0]["id"]]["status"], "unverified")
        self.assertEqual(results[nodes[0]["id"]]["reason"], "core_unavailable")
        self.assertEqual(results[nodes[1]["id"]]["status"], "unsupported")
        self.assertEqual(summary["status"], "unavailable")
        self.assertEqual(summary["counts"]["unverified"], 1)
        self.assertEqual(summary["counts"]["unsupported"], 1)
        self.assertTrue(all(item["latency_ms"] is None for item in results.values()))

    def test_empty_or_unsupported_inputs_do_not_start_core(self):
        nodes, _ = sample_nodes()
        with patch.object(validation.subprocess, "Popen") as start:
            for selected in ([], nodes):
                results, summary = validation.validate_nodes(selected, {})
                self.assertEqual(summary["status"], "not_run")
            start.assert_not_called()
        self.assertEqual(results[nodes[0]["id"]]["status"], "unsupported")

    def test_direct_or_group_conversions_cannot_pass_as_real_nodes(self):
        nodes, converted = sample_nodes()
        for kind in ("direct", "select", "url-test", "reject"):
            with self.subTest(kind=kind):
                converted[nodes[0]["uri"]]["type"] = kind
                with patch.object(validation.subprocess, "Popen") as start:
                    results, summary = validation.validate_nodes(nodes, converted)
                self.assertEqual(results[nodes[0]["id"]]["status"], "unsupported")
                self.assertEqual(summary["status"], "not_run")
                start.assert_not_called()

    def test_private_config_and_controller_have_no_public_proxy_listeners(self):
        engine = FakeEngine()
        self.validate(engine)
        config = engine.config
        self.assertFalse(config["allow-lan"])
        self.assertFalse(config["tun"]["enable"])
        self.assertFalse(config["dns"]["enable"])
        self.assertTrue(config["external-controller"].startswith("127.0.0.1:"))
        self.assertTrue(config["secret"])
        self.assertEqual(config["rules"], ["MATCH,REJECT"])
        self.assertNotIn("proxy-providers", config)
        self.assertNotIn("rule-providers", config)
        for key in ("port", "socks-port", "mixed-port", "redir-port", "tproxy-port"):
            self.assertEqual(config.get(key, 0), 0)
        self.assertEqual(engine.config_mode, 0o600)
        self.assertEqual(engine.directory_mode, 0o700)
        self.assertEqual(engine.run_kwargs["stdout"], subprocess.DEVNULL)
        self.assertEqual(engine.run_kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(engine.popen_kwargs["stdout"], subprocess.DEVNULL)
        self.assertEqual(engine.popen_kwargs["stderr"], subprocess.DEVNULL)
        for _, kwargs in engine.requests:
            self.assertFalse(kwargs["allow_redirects"])
        self.assertTrue(all(not session.trust_env for session in engine.sessions_used))
        self.assertTrue(all(session.headers["Authorization"] == "Bearer " + config["secret"]
                            for session in engine.sessions_used))
        for url, kwargs in engine.requests:
            if url.endswith("/delay"):
                self.assertEqual(kwargs["params"]["expected"], "204")
                self.assertEqual(kwargs["params"]["timeout"], 8000)

    def test_unique_stable_proxy_names_derive_from_ids(self):
        first, second = FakeEngine(), FakeEngine()
        self.validate(first, count=3)
        self.validate(second, count=3)
        self.assertEqual(list(first.proxies), list(second.proxies))
        self.assertEqual(len(first.proxies), 3)
        self.assertTrue(all(name.startswith("node-") for name in first.proxies))

    def test_node_concurrency_is_bounded_by_workers(self):
        engine = FakeEngine(probe_wait=0.02)
        _, _, results, summary = self.validate(engine, count=8, workers=3)
        self.assertGreater(engine.max_active, 1)
        self.assertLessEqual(engine.max_active, 3)
        self.assertEqual(summary["counts"]["passed"], 8)
        self.assertEqual(len(results), 8)

    def test_config_failure_leaves_all_convertible_nodes_unverified_and_deletes_config(self):
        engine = FakeEngine(config_code=1)
        nodes, _, results, summary = self.validate(engine)
        self.assertEqual(results[nodes[0]["id"]]["reason"], "core_config_error")
        self.assertEqual(results[nodes[0]["id"]]["status"], "unverified")
        self.assertEqual(summary["status"], "unavailable")
        self.assertIsNone(engine.popen_kwargs)
        self.assertFalse(engine.config_path.exists())

    def test_start_failure_is_unverified_and_cleanup_runs(self):
        engine = FakeEngine(startup_code=1)
        nodes, _, results, summary = self.validate(engine)
        self.assertEqual(results[nodes[0]["id"]]["reason"], "core_start_failed")
        self.assertEqual(results[nodes[0]["id"]]["status"], "unverified")
        self.assertEqual(summary["status"], "unavailable")
        self.assertFalse(engine.config_path.exists())

    def test_process_and_config_are_cleaned_after_success_and_force_kill_if_needed(self):
        for slow_stop in (False, True):
            with self.subTest(slow_stop=slow_stop):
                engine = FakeEngine(slow_stop=slow_stop)
                self.validate(engine)
                self.assertTrue(engine.process.terminated)
                self.assertEqual(engine.process.killed, slow_stop)
                self.assertFalse(engine.config_path.exists())
                self.assertFalse(engine.config_path.parent.exists())
                self.assertTrue(all(session.closed for session in engine.sessions))

    def test_inherited_clash_overrides_and_hooks_are_removed_for_both_core_commands(self):
        engine = FakeEngine()
        unsafe = {"CLASH_CONFIG_STRING": "mixed-port: 7890", "CLASH_OVERRIDE_EXTERNAL_CONTROLLER": ":9090",
                  "CLASH_OVERRIDE_SECRET": "public", "CLASH_POST_UP": "unsafe command"}
        with patch.dict(validation.os.environ, unsafe):
            self.validate(engine)
        for kwargs in (engine.run_kwargs, engine.popen_kwargs):
            self.assertFalse(any(key.upper().startswith("CLASH_") for key in kwargs["env"]))

    def test_core_command_exceptions_fail_closed_and_delete_private_configuration(self):
        for stage in ("config", "start"):
            with self.subTest(stage=stage):
                nodes, converted = sample_nodes()
                engine = FakeEngine()
                with engine.installed():
                    target = "run" if stage == "config" else "Popen"
                    original = engine.config_test if stage == "config" else engine.start

                    def failure(command, **kwargs):
                        original(command, **kwargs)
                        raise OSError("credentials=secret")

                    with patch.object(validation.subprocess, target, side_effect=failure):
                        results, summary = validation.validate_nodes(nodes, converted)
                expected = "core_config_error" if stage == "config" else "core_start_failed"
                self.assertEqual(results[nodes[0]["id"]]["reason"], expected)
                self.assertEqual(results[nodes[0]["id"]]["status"], "unverified")
                self.assertEqual(summary["status"], "unavailable")
                self.assertFalse(engine.config_path.exists())
                self.assertNotIn("credentials", str(results))

    def test_startup_wait_is_bounded_and_stops_unready_process(self):
        nodes, converted = sample_nodes()
        engine = FakeEngine()
        with engine.installed(), patch.object(validation, "STARTUP_TIMEOUT_SECONDS", 0):
            results, summary = validation.validate_nodes(nodes, converted)
        self.assertEqual(results[nodes[0]["id"]]["reason"], "core_start_failed")
        self.assertEqual(summary["status"], "unavailable")
        self.assertTrue(engine.process.terminated)
        self.assertFalse(engine.config_path.exists())

    def test_startup_waits_for_all_selected_proxy_names_before_first_probe(self):
        engine = FakeEngine(inventory_waits=1)
        _, _, results, summary = self.validate(engine, count=3)
        self.assertEqual(summary["counts"]["passed"], 3)
        self.assertTrue(all(result["status"] == "passed" for result in results.values()))
        self.assertEqual(engine.inventory_calls, 2)
        self.assertEqual(engine.delays_before_ready, 0)

    def test_ready_without_required_names_keeps_version_only_behavior(self):
        engine = FakeEngine()
        with engine.installed():
            version = validation._ready(engine.process, "http://127.0.0.1:12345", "private")
        self.assertEqual(version["version"], "v1.19.29")
        self.assertEqual(engine.inventory_calls, 0)
        self.assertTrue(all(session.closed for session in engine.sessions))

    def test_missing_proxy_registry_until_deadline_is_unverified_without_probing(self):
        engine = FakeEngine(inventory_waits=100)
        with patch.object(validation, "STARTUP_TIMEOUT_SECONDS", 0.01):
            _, _, results, summary = self.validate(engine, count=3)
        self.assertEqual(summary["status"], "unavailable")
        self.assertTrue(all(result["status"] == "unverified" for result in results.values()))
        self.assertTrue(all(result["reason"] == "core_start_failed" for result in results.values()))
        self.assertGreaterEqual(engine.inventory_calls, 1)
        self.assertEqual(engine.delays_before_ready, 0)
        self.assertTrue(engine.process.terminated)
        self.assertFalse(engine.config_path.exists())

    def test_unexpected_worker_exception_cleans_process_and_removes_all_partial_passes(self):
        nodes, converted = sample_nodes(3)
        engine = FakeEngine()
        with engine.installed(), patch.object(validation, "_check_node", side_effect=RuntimeError("secret")):
            results, summary = validation.validate_nodes(nodes, converted)
        self.assertEqual(summary["status"], "unavailable")
        self.assertTrue(all(result["status"] == "unverified" for result in results.values()))
        self.assertTrue(engine.process.terminated)
        self.assertFalse(engine.config_path.exists())
        self.assertTrue(all(session.closed for session in engine.sessions))

    def test_invalid_probe_urls_and_options_are_rejected_before_core_start(self):
        nodes, converted = sample_nodes()
        for options in ({"probe_urls": ()}, {"probe_urls": ("http://example.org/generate_204",)},
                        {"probe_urls": ("https://user:pass@example.org/",)},
                        {"timeout_ms": True}, {"timeout_ms": 32768}, {"workers": 0}, {"workers": 65}):
            with self.subTest(options=options), patch.object(validation.subprocess, "Popen") as start:
                with self.assertRaises(ValueError):
                    validation.validate_nodes(nodes, converted, **options)
                start.assert_not_called()


if __name__ == "__main__":
    unittest.main()
