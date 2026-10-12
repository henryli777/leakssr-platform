"""Measure real proxy connectivity through an isolated Mihomo process."""

from concurrent.futures import ThreadPoolExecutor
import copy
from datetime import datetime, timezone
import hashlib
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
from urllib.parse import quote, urlsplit

import requests
import yaml


DEFAULT_PROBE_URLS = ("https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204")
PROXY_TYPES = {"ss", "ssr", "vmess", "vless", "trojan", "hysteria2"}
RESULT_STATUSES = ("passed", "failed", "unsupported", "unverified")
STARTUP_TIMEOUT_SECONDS = 10


def _checked_at():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _result(status, reason, checked_at, probes=None):
    probes = probes or []
    delays = [probe["latency_ms"] for probe in probes if probe["status"] == "passed"]
    return {"status": status, "checked_at": checked_at, "latency_ms": max(delays) if delays else None,
            "reason": reason, "probes": probes}


def _options(timeout_ms, workers, probe_urls):
    if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or not 1 <= timeout_ms <= 32767:
        raise ValueError("timeout_ms must be an integer between 1 and 32767")
    if isinstance(workers, bool) or not isinstance(workers, int) or not 1 <= workers <= 64:
        raise ValueError("workers must be an integer between 1 and 64")
    if isinstance(probe_urls, str):
        raise ValueError("probe_urls must contain HTTPS URLs")
    urls = tuple(probe_urls)
    if not urls:
        raise ValueError("At least one HTTPS probe is required")
    for url in urls:
        if not isinstance(url, str) or any(character.isspace() for character in url):
            raise ValueError("Invalid HTTPS probe URL")
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError("Invalid HTTPS probe URL")
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError("Invalid HTTPS probe URL")
    return tuple(dict.fromkeys(urls))


def _session(secret):
    session = requests.Session()
    session.trust_env = False
    session.headers["Authorization"] = "Bearer " + secret
    return session


def _controller_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def _private_config(proxies, port, secret):
    return {
        "allow-lan": False, "bind-address": "127.0.0.1", "external-controller": "127.0.0.1:{}".format(port),
        "secret": secret, "port": 0, "socks-port": 0, "mixed-port": 0, "redir-port": 0, "tproxy-port": 0,
        "tun": {"enable": False}, "dns": {"enable": False}, "sniffer": {"enable": False},
        "geo-auto-update": False, "geodata-mode": False, "unified-delay": False,
        "profile": {"store-selected": False, "store-fake-ip": False}, "log-level": "silent", "mode": "rule",
        "proxies": proxies, "rules": ["MATCH,REJECT"],
    }


def _ready(process, base_url, secret, required_names=()):
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    required_names = frozenset(required_names)
    session = _session(secret)
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                return None
            try:
                response = session.get(base_url + "/version", timeout=0.5, allow_redirects=False)
                version = response.json() if response.status_code == 200 else None
                if isinstance(version, dict) and version.get("meta") is True:
                    if not required_names:
                        return version
                    # The controller serves /version before Mihomo finishes registering configured proxies.
                    response = session.get(base_url + "/proxies", timeout=0.5, allow_redirects=False)
                    inventory = response.json() if response.status_code == 200 else None
                    proxies = inventory.get("proxies") if isinstance(inventory, dict) else None
                    if isinstance(proxies, dict) and required_names.issubset(proxies):
                        return version
            except (requests.RequestException, ValueError):
                pass
            time.sleep(min(0.05, max(0, deadline - time.monotonic())))
        return None
    finally:
        session.close()


def _positive_delay(value, timeout_ms):
    return (not isinstance(value, bool) and isinstance(value, (int, float)) and
            math.isfinite(value) and 0 < value <= timeout_ms)


def _probe(session, base_url, name, url, timeout_ms):
    result = {"url": url, "status": "failed", "latency_ms": None}
    endpoint = base_url + "/proxies/" + quote(name, safe="")
    try:
        response = session.get(endpoint + "/delay", params={"url": url, "timeout": timeout_ms, "expected": "204"},
                               timeout=(1, timeout_ms / 1000 + 1), allow_redirects=False)
        if response.status_code != 200:
            return result, "probe_http_error"
        body = response.json()
        if not isinstance(body, dict):
            return result, "probe_invalid_response"
        delay = body.get("delay")
        if not _positive_delay(delay, timeout_ms):
            return result, "probe_invalid_delay"
        # Mihomo v1.19.29 returns delay even on HTTP status mismatch; extra history records expected=204.
        response = session.get(endpoint, timeout=(1, 1), allow_redirects=False)
        if response.status_code != 200:
            return result, "probe_unverified_status"
        proxy = response.json()
        extra = proxy.get("extra") if isinstance(proxy, dict) else None
        record = extra.get(url) if isinstance(extra, dict) else None
        if not isinstance(record, dict):
            return result, "probe_unverified_status"
        if record.get("alive") is False:
            return result, "probe_unexpected_status"
        history = record.get("history")
        if (record.get("alive") is not True or not isinstance(history, list) or not history or
                not isinstance(history[-1], dict) or not _positive_delay(history[-1].get("delay"), timeout_ms) or
                history[-1]["delay"] != delay):
            return result, "probe_unverified_status"
        result.update(status="passed", latency_ms=delay)
        return result, "all_probes_passed"
    except requests.Timeout:
        return result, "probe_timeout"
    except requests.RequestException:
        return result, "probe_request_error"
    except (ValueError, TypeError):
        return result, "probe_invalid_response"


def _check_node(node_id, name, base_url, secret, urls, timeout_ms):
    session = _session(secret)
    try:
        outcomes = [_probe(session, base_url, name, url, timeout_ms) for url in urls]
        probes = [probe for probe, _ in outcomes]
        reason = next((reason for probe, reason in outcomes if probe["status"] != "passed"), "all_probes_passed")
        status = "passed" if all(probe["status"] == "passed" for probe in probes) else "failed"
        return node_id, _result(status, reason, _checked_at(), probes)
    finally:
        session.close()


def _stop(process):
    if process is None:
        return
    try:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
    except (OSError, subprocess.SubprocessError):
        pass


def validate_nodes(nodes, converted, *, binary="mihomo", timeout_ms=8000, workers=4,
                   probe_urls=DEFAULT_PROBE_URLS, vantage_point="unspecified"):
    """Return per-node evidence; only all successful HTTPS 204 probes make a node pass."""
    urls = _options(timeout_ms, workers, probe_urls)
    checked_at = _checked_at()
    results, selected, proxies = {}, [], []
    for node in nodes:
        node_id = node["id"]
        proxy = converted.get(node["uri"])
        if not isinstance(proxy, dict) or proxy.get("type") not in PROXY_TYPES:
            results[node_id] = _result("unsupported", "conversion_unsupported", checked_at)
            continue
        name = "node-" + hashlib.sha256(str(node_id).encode("utf-8")).hexdigest()
        generated = copy.deepcopy(proxy)
        generated["name"] = name
        proxies.append(generated)
        selected.append((node_id, name))
        results[node_id] = _result("unverified", "core_unavailable", checked_at)

    summary = {"status": "not_run", "engine": "mihomo", "checked_at": checked_at,
               "probe_urls": list(urls), "timeout_ms": timeout_ms, "vantage_point": vantage_point}

    def finish(status, reason=None):
        if reason:
            for node_id, _ in selected:
                results[node_id] = _result("unverified", reason, _checked_at())
        summary["status"] = status
        summary["counts"] = {status: sum(item["status"] == status for item in results.values())
                             for status in RESULT_STATUSES}
        return results, summary

    if not selected:
        return finish("not_run")
    executable = shutil.which(binary)
    if not executable:
        return finish("unavailable", "core_unavailable")
    process = None
    reason = "core_config_error"
    try:
        with tempfile.TemporaryDirectory(prefix="node-validation-") as directory:
            secret = secrets.token_urlsafe(32)
            port = _controller_port()
            config_path = Path(directory) / "config.yaml"
            descriptor = os.open(str(config_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as config_file:
                yaml.safe_dump(_private_config(proxies, port, secret), config_file, allow_unicode=True, sort_keys=False)
            # CLASH_CONFIG_STRING, controller overrides, and post-up/down hooks can override even explicit -f.
            environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("CLASH_")}
            command = [executable, "-d", directory, "-f", str(config_path)]
            config_test = subprocess.run(command + ["-t"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL, timeout=15, env=environment, cwd=directory)
            if config_test.returncode != 0:
                return finish("unavailable", "core_config_error")
            reason = "core_start_failed"
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, env=environment, cwd=directory)
            try:
                base_url = "http://127.0.0.1:{}".format(port)
                version = _ready(process, base_url, secret, required_names=(name for _, name in selected))
                if version is None:
                    return finish("unavailable", "core_start_failed")
                engine_version = version.get("version")
                if isinstance(engine_version, str) and re.fullmatch(r"[A-Za-z0-9.+_-]{1,80}", engine_version):
                    summary["engine_version"] = engine_version
                with ThreadPoolExecutor(max_workers=min(workers, len(selected))) as executor:
                    futures = [executor.submit(_check_node, node_id, name, base_url, secret, urls, timeout_ms)
                               for node_id, name in selected]
                    for future in futures:
                        node_id, result = future.result()
                        results[node_id] = result
                if process.poll() is not None:
                    return finish("unavailable", "core_start_failed")
                return finish("completed")
            finally:
                _stop(process)
                process = None
    except Exception:
        return finish("unavailable", reason)
    finally:
        _stop(process)
