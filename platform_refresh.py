#!/usr/bin/env python3
"""Refresh existing subscription sources without scraper keys or notifications."""

import argparse
import base64
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import time
from urllib.parse import urlsplit
import uuid

import requests
import yaml

from node_lookup import add_node_name_aliases, build_node_index, canonical_node_key, parse_node_uri
from node_validation import validate_nodes
from clash_import import parse_clash_subscription


SCRIPT_DIR = Path(__file__).resolve().parent
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
CN_TZ = timezone(timedelta(hours=8))


@dataclass
class FetchResult:
    content: bytes
    status_code: int
    headers: dict
    elapsed_ms: float


def fetch_subscription(url, timeout=12):
    """Fetch a bounded response with certificate validation enabled."""
    started = time.monotonic()
    with requests.get(url, timeout=timeout, verify=True, stream=True,
                      headers={"User-Agent": "Clash.Meta/LeakSSR-Refresh",
                               "Accept": "text/plain, application/octet-stream, */*"}) as response:
        chunks, size = [], 0
        if response.status_code == 200:
            for chunk in response.iter_content(chunk_size=65536):
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    raise ValueError("response_too_large")
                if time.monotonic() - started > timeout:
                    raise requests.Timeout("response deadline exceeded")
                chunks.append(chunk)
        return FetchResult(b"".join(chunks), response.status_code, dict(response.headers),
                           round((time.monotonic() - started) * 1000, 1))


def load_sources(path):
    """Read a JSON URL list (or metadata list), or a line-delimited URL file."""
    path = Path(path)
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix.lower() == ".json":
        values = json.loads(text)
        if isinstance(values, dict):
            values = values.get("urls", values.get("sources"))
        if not isinstance(values, list):
            raise ValueError("Sources JSON must contain a URL list")
        return values
    return [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def parse_subscription(content):
    """Accept URI feeds or conservatively supported inline Clash proxies."""
    try:
        text = content.decode("utf-8-sig")
    except UnicodeError:
        return [], "invalid_payload"
    if "://" not in text:
        encoded = re.sub(r"\s+", "", text)
        if encoded and re.fullmatch(r"[A-Za-z0-9+/_=-]+", encoded):
            try:
                text = base64.b64decode(encoded + "=" * (-len(encoded) % 4),
                                        altchars=b"-_", validate=True).decode("utf-8-sig")
            except (ValueError, UnicodeError):
                pass
    nodes, seen = [], set()
    for line in text.splitlines():
        line = line.strip()
        if line not in seen and parse_node_uri(line):
            nodes.append(line)
            seen.add(line)
    if nodes:
        return nodes, "available"
    if re.search(r"(?m)^\s*(?:proxies|proxy-providers)\s*:", text) or text.lstrip().startswith("{"):
        imported = parse_clash_subscription(text)
        return (imported, "available") if imported else ([], "unsupported_format")
    return [], "invalid_payload"


def _traffic(headers):
    value = next((value for key, value in headers.items()
                  if key.lower() == "subscription-userinfo"), "")
    values = {}
    for field in str(value).split(";"):
        key, separator, raw = field.strip().partition("=")
        if separator and key.lower() in {"upload", "download", "total", "expire"}:
            try:
                number = int(raw.strip())
                if number >= 0:
                    values[key.lower()] = number
            except ValueError:
                continue
    total = values.get("total")
    used = values.get("upload", 0) + values.get("download", 0) if values else None
    remaining = max(0, total - used) if total is not None and used is not None else None
    gb = lambda number: round(number / (1024 ** 3), 4) if number is not None else None
    return {
        "total": gb(total), "used": gb(used), "remaining": gb(remaining), "unit": "GB",
        "total_bytes": total, "used_bytes": used, "remaining_bytes": remaining,
        "expire": values.get("expire"),
    }


def _params(config):
    result = {}
    for key, value in config.get("params", []):
        if key in result and result[key] != value:
            raise ValueError("Conflicting URI options")
        result[key] = value
    return result


def _boolean(value):
    if value in (True, 1, "1", "true", "True"):
        return True
    if value in (False, 0, "0", "false", "False", ""):
        return False
    raise ValueError("Invalid boolean option")


def _transport(proxy, network, path="", host="", service="", header_type="none"):
    network = network or "tcp"
    if network not in {"tcp", "ws", "grpc", "http", "h2"}:
        raise ValueError("Unsupported transport")
    if header_type not in {"", "none"}:
        raise ValueError("Unsupported transport header")
    if network == "ws":
        proxy["network"] = "ws"
        proxy["ws-opts"] = {"path": path or "/"}
        if host:
            proxy["ws-opts"]["headers"] = {"Host": host}
    elif network == "grpc":
        if path or host:
            raise ValueError("Unsupported gRPC URI options")
        proxy["network"] = "grpc"
        proxy["grpc-opts"] = {"grpc-service-name": service}
    elif network in {"http", "h2"}:
        proxy["network"] = network
        options = {"path": [path or "/"]} if network == "http" else {"path": path or "/"}
        if host:
            if network == "http":
                options["headers"] = {"Host": host.split(",")}
            else:
                options["host"] = host.split(",")
        proxy[network + "-opts"] = options
    elif path or host or service:
        raise ValueError("Unused transport options")


def uri_to_clash_proxy(uri):
    """Convert supported connection options, skipping options we cannot retain."""
    parsed = parse_node_uri(uri)
    if not parsed:
        return None
    config = json.loads(parsed["match_key"])
    protocol = config["protocol"]
    proxy = {"name": parsed["name"], "type": protocol, "server": parsed["server"], "port": parsed["port"]}
    try:
        params = _params(config)
        for key in ("udp", "tfo"):
            if key in params:
                proxy[key] = _boolean(params.pop(key))
        if protocol == "ss":
            if params:
                return None
            proxy.update(cipher=config["cipher"], password=config["password"])
        elif protocol == "ssr":
            if set(params) - {"obfsparam", "protoparam"}:
                return None
            proxy.update(cipher=config["cipher"], password=config["password"],
                         protocol=config["ssr_protocol"], obfs=config["obfs"])
            for key, target in {"obfsparam": "obfs-param", "protoparam": "protocol-param"}.items():
                if params.get(key):
                    proxy[target] = params[key]
        elif protocol == "vmess":
            vmess = config["config"]
            if set(vmess) - {"id", "aid", "scy", "net", "tls", "type", "host", "path", "sni", "alpn", "fp", "allowInsecure", "udp", "tfo"}:
                return None
            proxy.update(uuid=vmess["id"], alterId=vmess["aid"], cipher=vmess["scy"])
            _transport(proxy, vmess["net"], vmess.get("path", ""), vmess.get("host", ""),
                       header_type=vmess.get("type", "none"))
            if vmess["tls"] not in {"", "none", "tls"}:
                return None
            if vmess["tls"] == "tls":
                proxy["tls"] = True
            for key, target in {"sni": "servername", "fp": "client-fingerprint"}.items():
                if vmess.get(key):
                    proxy[target] = vmess[key]
            if vmess.get("alpn"):
                proxy["alpn"] = vmess["alpn"].split(",") if isinstance(vmess["alpn"], str) else vmess["alpn"]
            if "allowInsecure" in vmess:
                proxy["skip-cert-verify"] = _boolean(vmess["allowInsecure"])
            for key in ("udp", "tfo"):
                if key in vmess:
                    proxy[key] = _boolean(vmess[key])
        else:
            allowed = {"sni", "peer", "insecure", "allowInsecure", "alpn", "fp"}
            if protocol in {"vless", "trojan"}:
                allowed |= {"security", "type", "network", "path", "host", "serviceName", "headerType"}
            if protocol == "vless":
                allowed |= {"encryption", "flow", "pbk", "sid"}
            if protocol == "hysteria2":
                allowed |= {"obfs", "obfs-password", "mport"}
            if set(params) - allowed or config.get("path"):
                return None
            proxy["uuid" if protocol == "vless" else "password"] = config["credentials"]
            if protocol in {"vless", "trojan"}:
                if params.get("type") and params.get("network") and params["type"] != params["network"]:
                    return None
                _transport(proxy, params.get("type", params.get("network", "tcp")),
                           params.get("path", ""), params.get("host", ""),
                           params.get("serviceName", ""), params.get("headerType", "none"))
                security = params.get("security", "tls" if protocol == "trojan" else "none")
                if security not in {"", "none", "tls", "reality"} or (protocol == "trojan" and security != "tls"):
                    return None
                if security in {"tls", "reality"}:
                    proxy["tls"] = True
                if security == "reality":
                    if not params.get("pbk"):
                        return None
                    proxy["reality-opts"] = {"public-key": params["pbk"], "short-id": params.get("sid", "")}
                elif params.get("pbk") or params.get("sid"):
                    return None
            if protocol == "vless":
                if params.get("encryption", "none") != "none":
                    return None
                if params.get("flow"):
                    proxy["flow"] = params["flow"]
            sni = params.get("sni", params.get("peer"))
            if params.get("sni") and params.get("peer") and params["sni"] != params["peer"]:
                return None
            if sni:
                proxy["servername" if protocol == "vless" else "sni"] = sni
            if params.get("fp"):
                proxy["client-fingerprint"] = params["fp"]
            if params.get("alpn"):
                proxy["alpn"] = params["alpn"].split(",")
            for key in ("insecure", "allowInsecure"):
                if key in params:
                    value = _boolean(params[key])
                    if "skip-cert-verify" in proxy and value != proxy["skip-cert-verify"]:
                        return None
                    proxy["skip-cert-verify"] = value
            if protocol == "hysteria2":
                for key in ("obfs", "obfs-password"):
                    if params.get(key):
                        proxy[key] = params[key]
                if params.get("mport"):
                    proxy["ports"] = params["mport"]
        return proxy
    except (ValueError, TypeError, KeyError):
        return None


def _source_entries(sources):
    entries, seen = [], set()
    for item in sources:
        entry = dict(item) if isinstance(item, dict) else {"url": item}
        url = entry.get("url")
        if not isinstance(url, str) or not url.strip():
            continue
        url = url.strip()
        if url not in seen:
            entry["url"] = url
            entries.append(entry)
            seen.add(url)
    return entries


def _fetch_source(entry, timeout, fetch, checked_at):
    url = entry["url"]
    sid = hashlib.sha1(url.encode("utf-8")).hexdigest()[:12]
    try:
        parts = urlsplit(url)
    except ValueError:
        parts = urlsplit("")
    meta = {
        "id": sid, "url": url, "host": parts.netloc,
        "provider": entry.get("provider") or parts.netloc,
        "source": entry.get("source") or "existing", "detail_page": "source.html?id=" + sid,
        "available": False, "status": "invalid_source", "http_status": None,
        "nodes_total": 0, "parsed_nodes_total": 0, "protocol_counts": {}, "protocols": "",
        "response_ms": None, "updated_at": checked_at, "checked_at": checked_at,
        "traffic": _traffic({}), "over_quota": False,
    }
    for field in ("first_seen", "first_seen_time"):
        if entry.get(field):
            meta[field] = entry[field]
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        return meta, []
    try:
        result = fetch(url, timeout)
        meta["http_status"] = result.status_code
        meta["response_ms"] = round(result.elapsed_ms, 1)
        meta["traffic"] = _traffic(result.headers)
        if result.status_code != 200:
            meta["status"] = "http_error"
            return meta, []
        nodes, status = parse_subscription(result.content)
        meta["status"] = status
        canonical = {parse_node_uri(node)["match_key"] for node in nodes}
        meta["parsed_nodes_total"] = len(canonical)
        traffic = meta["traffic"]
        if traffic["total_bytes"] is not None and traffic["remaining_bytes"] == 0:
            meta["status"] = "quota_depleted"
            meta["over_quota"] = True
        elif traffic["expire"] and traffic["expire"] <= int(datetime.now(timezone.utc).timestamp()):
            meta["status"] = "expired"
        if meta["status"] != "available":
            return meta, []
        counts = Counter(json.loads(key)["protocol"] for key in canonical)
        meta.update(available=True, nodes_total=len(canonical), protocol_counts=dict(sorted(counts.items())),
                    protocols=", ".join("{}:{}".format(key, value) for key, value in sorted(counts.items())))
        return meta, nodes
    except requests.Timeout:
        meta["status"] = "timeout"
    except requests.exceptions.SSLError:
        meta["status"] = "tls_error"
    except requests.RequestException:
        meta["status"] = "network_error"
    except ValueError as error:
        meta["status"] = "response_too_large" if str(error) == "response_too_large" else "invalid_payload"
    except Exception:
        meta["status"] = "fetch_error"
    return meta, []


def _write_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _atomic_json(path, data):
    descriptor, name = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
            os.fchmod(handle.fileno(), 0o644)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _read_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _region(node):
    text = " ".join(node["names"])
    hints = {
        "hk": (r"\b(?:HK|Hong[ -]?Kong)\b", "\u9999\u6e2f", "\U0001f1ed\U0001f1f0"),
        "jp": (r"\b(?:JP|Japan)\b", "\u65e5\u672c", "\U0001f1ef\U0001f1f5"),
        "us": (r"\b(?:US|USA|United States)\b", "\u7f8e\u56fd", "\U0001f1fa\U0001f1f8"),
        "sg": (r"\b(?:SG|Singapore)\b", "\u65b0\u52a0\u5761", "\U0001f1f8\U0001f1ec"),
        "tw": (r"\b(?:TW|Taiwan)\b", "\u53f0\u6e7e", "\U0001f1f9\U0001f1fc"),
        "kr": (r"\b(?:KR|Korea)\b", "\u97e9\u56fd", "\U0001f1f0\U0001f1f7"),
        "uk": (r"\b(?:UK|GB|United Kingdom)\b", "\u82f1\u56fd", "\U0001f1ec\U0001f1e7"),
        "de": (r"\b(?:DE|Germany)\b", "\u5fb7\u56fd", "\U0001f1e9\U0001f1ea"),
        "fr": (r"\b(?:FR|France)\b", "\u6cd5\u56fd", "\U0001f1eb\U0001f1f7"),
    }
    matches = [region for region, (pattern, chinese, flag) in hints.items()
               if re.search(pattern, text, re.IGNORECASE) or chinese in text or flag in text]
    return matches[0] if len(matches) == 1 else "unknown"


def _publish(output, source_nodes, metadata, index, proxies, converted, health):
    snapshots = output / ".platform-snapshots"
    snapshots.mkdir(exist_ok=True)
    generation = snapshots / uuid.uuid4().hex
    sub = generation / "sub"
    providers = sub / "providers"
    providers.mkdir(parents=True)
    _atomic_json(sub / "health.json", health)
    _write_json(sub / "node_index.json", index)
    _write_json(sub / "url_meta.json", metadata)
    published = [node for node in index["nodes"] if node.get("published")]
    published_keys = {key for node in published for key in node["match_keys"]}
    nodes = [node["uri"] for node in published]
    (sub / "all.txt").write_text("\n".join(nodes) + ("\n" if nodes else ""), encoding="utf-8")
    urls = [item["url"] for item in metadata if item.get("nodes_verified", 0) > 0]
    (sub / "urls.txt").write_text("\n".join(urls) + ("\n" if urls else ""), encoding="utf-8")
    payload = yaml.safe_dump({"proxies": proxies}, allow_unicode=True, sort_keys=False)
    (sub / "all.yaml").write_text(payload, encoding="utf-8")
    (providers / "all.yaml").write_text(payload, encoding="utf-8")
    for kind, groups in (
        ("proto", {node["protocol"] for node in index["nodes"]}),
        ("regions", {_region(node) for node in index["nodes"]}),
    ):
        for group in groups:
            selected = [node for node in published
                        if (node["protocol"] if kind == "proto" else _region(node)) == group]
            uri_file = sub / "proto" / (group + ".txt") if kind == "proto" else sub / "regions" / group / "passwall2.txt"
            yaml_file = sub / "clash" / (group + ".yaml") if kind == "proto" else sub / "regions" / group / "clash.yaml"
            uri_file.parent.mkdir(parents=True, exist_ok=True)
            yaml_file.parent.mkdir(parents=True, exist_ok=True)
            uri_file.write_text("\n".join(node["uri"] for node in selected) + ("\n" if selected else ""), encoding="utf-8")
            yaml_file.write_text(yaml.safe_dump({"proxies": [converted[node["uri"]] for node in selected
                                                           if node["uri"] in converted]},
                                              allow_unicode=True, sort_keys=False), encoding="utf-8")
    for item in metadata:
        sid = item["id"]
        lines = [uri for uri in source_nodes.get(item["url"], []) if canonical_node_key(uri) in published_keys]
        _write_json(providers / (sid + ".json"), item)
        (providers / (sid + ".txt")).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    target = output / "sub"
    health_path = output / "health.json"
    if not health_path.is_symlink() or os.readlink(health_path) != "sub/health.json":
        if target.exists() and health_path.exists():
            _atomic_json(target / "health.json", _read_json(health_path, {}))
        health_link = output / (".health-" + generation.name)
        try:
            health_link.symlink_to("sub/health.json")
            os.replace(health_link, health_path)
        finally:
            if health_link.is_symlink():
                health_link.unlink()
    # health.json follows sub so the same pointer switches counts, index, and exports.
    previous = target.resolve() if target.is_symlink() else None
    link = output / (".sub-" + generation.name)
    link.symlink_to(sub.relative_to(output), target_is_directory=True)
    if target.exists() and not target.is_symlink():
        backup = snapshots / ("legacy-" + uuid.uuid4().hex)
        backup.mkdir()
        os.replace(target, backup / "sub")
        previous = backup / "sub"
    try:
        os.replace(link, target)
    except OSError:
        if previous is not None and not target.exists() and previous.exists():
            os.replace(previous, target)
        raise
    finally:
        if link.is_symlink():
            link.unlink()
    # Keep the previous generation for in-flight readers and bound disk usage.
    keep = {generation.resolve(), previous.parent if previous else None}
    for old in snapshots.iterdir():
        if old.is_dir() and old.resolve() not in keep:
            shutil.rmtree(old)


def refresh(output_dir, sources, *, workers=8, timeout=12, fetch=None, validator=None,
            mihomo_binary="mihomo", check_timeout_ms=8000, check_workers=4,
            vantage_point="unspecified"):
    """Collect provenance, then publish only nodes that pass real proxy probes."""
    if not 1 <= workers <= 64 or timeout <= 0:
        raise ValueError("Workers must be 1..64 and timeout must be positive")
    if (isinstance(check_timeout_ms, bool) or not isinstance(check_timeout_ms, int) or
            not 1 <= check_timeout_ms <= 32767 or isinstance(check_workers, bool) or
            not isinstance(check_workers, int) or not 1 <= check_workers <= 64):
        raise ValueError("Check timeout must be 1..32767ms and check workers must be 1..64")
    output = Path(output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    with (output / ".platform-refresh.lock").open("a") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Another refresh is already running") from None
        return _refresh_locked(output, _source_entries(sources), workers, timeout, fetch or fetch_subscription,
                               validator or validate_nodes, mihomo_binary, check_timeout_ms, check_workers,
                               vantage_point)


def _refresh_locked(output, entries, workers, timeout, fetch, validator, mihomo_binary,
                    check_timeout_ms, check_workers, vantage_point):
    now = datetime.now(timezone.utc)
    checked_at = now.isoformat(timespec="seconds")
    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(lambda entry: _fetch_source(entry, timeout, fetch, checked_at), entries))
    metadata = [meta for meta, nodes in results]
    source_nodes = {meta["url"]: nodes for meta, nodes in results}
    index = build_node_index(source_nodes, metadata, published_nodes=[])
    alive = sum(item["available"] for item in metadata)
    previous_health = {}
    stale = False
    if not alive:
        previous_index = _read_json(output / "sub/node_index.json", {})
        if previous_index.get("nodes"):
            # Retain searchable origins, but never serve yesterday's successes as current.
            index = previous_index
            previous_health = _read_json(output / "health.json", {})
            stale = True
            for source in index.get("sources", {}).values():
                source_nodes.setdefault(source["url"], [])
            for node in index["nodes"]:
                for sid in node["source_ids"]:
                    if sid in index["sources"]:
                        source_nodes[index["sources"][sid]["url"]].append(node["uri"])
    proxies, aliases, used_names, converted = [], {}, set(), {}
    for node in index["nodes"]:
        proxy = uri_to_clash_proxy(node["uri"])
        if proxy is None:
            continue
        name, suffix = proxy["name"], 1
        while proxy["name"] in used_names:
            proxy["name"] = "{}_{}".format(name, suffix)
            suffix += 1
        used_names.add(proxy["name"])
        aliases[node["uri"]] = [proxy["name"]]
        proxies.append(proxy)
        converted[node["uri"]] = proxy
    add_node_name_aliases(index, aliases)
    validation = {"status": "not_run", "engine": "mihomo", "checked_at": None,
                  "probe_urls": ["https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204"],
                  "timeout_ms": check_timeout_ms, "vantage_point": vantage_point,
                  "reason": "source_refresh_failed" if not alive else "no_nodes"}
    node_results = {}
    if alive:
        try:
            node_results, validation = validator(index["nodes"], converted, binary=mihomo_binary,
                                                  timeout_ms=check_timeout_ms, workers=check_workers,
                                                  vantage_point=vantage_point)
        except Exception:
            validation.update(status="unavailable", reason="checker_error")
    for node in index["nodes"]:
        node["validation"] = node_results.get(node["id"], {
            "status": "unverified", "checked_at": None, "latency_ms": None,
            "reason": validation.get("reason", "missing_test_result"),
        })
        result = node["validation"]
        delay = result.get("latency_ms")
        node["published"] = (validation.get("status") == "completed" and result.get("status") == "passed"
                             and isinstance(delay, (int, float)) and not isinstance(delay, bool)
                             and 0 < delay <= check_timeout_ms and node["uri"] in converted)
        if result.get("status") == "passed" and not node["published"]:
            result.update(status="unverified", reason="invalid_test_result", latency_ms=None)
    verified = [node for node in index["nodes"] if node["published"]]
    passed_uris = {node["uri"] for node in verified}
    proxies = [converted[node["uri"]] for node in verified]
    counts = Counter(node["validation"]["status"] for node in index["nodes"])
    validation["counts"] = {status: counts.get(status, 0) for status in ("passed", "failed", "unsupported", "unverified")}
    index["validation"] = validation
    for item in metadata:
        sid = item["id"]
        collected = [node for node in index["nodes"] if sid in node["source_ids"]]
        item["nodes_total"] = len(collected)
        item["nodes_verified"] = sum(node["published"] for node in collected)
        item["nodes_published"] = item["nodes_verified"]
        item["nodes_failed"] = sum(node["validation"]["status"] == "failed" for node in collected)
        if sid in index["sources"]:
            index["sources"][sid].update(available=item["available"], nodes_total=item["nodes_total"],
                                           nodes_verified=item["nodes_verified"], nodes_published=item["nodes_published"])
    failures = [{"id": item["id"], "status": item["status"], "http_status": item["http_status"]}
                for item in metadata if not item["available"]]
    health = {
        "build_time_utc": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "build_time_cn": now.astimezone(CN_TZ).strftime("%Y-%m-%d %H:%M:%S CST"),
        "last_attempt_utc": checked_at, "last_attempt_cn": now.astimezone(CN_TZ).isoformat(timespec="seconds"),
        "source_total": len(entries), "source_alive": alive, "nodes_total": len(index["nodes"]),
        "protocol_counts": dict(sorted(Counter(node["protocol"] for node in index["nodes"]).items())),
        "region_counts": dict(sorted(Counter(_region(node) for node in index["nodes"]).items())),
        "region_method": "subscription_label", "yaml_nodes_total": len(proxies),
        "yaml_protocol_counts": dict(sorted(Counter(node["protocol"] for node in verified).items())),
        "yaml_region_counts": dict(sorted(Counter(_region(node) for node in verified).items())),
        "yaml_skipped_total": len(index["nodes"]) - len(converted),
        "nodes_verified": len(verified), "published_nodes_total": len(verified),
        "nodes_failed": counts.get("failed", 0),
        "nodes_unverified": counts.get("unverified", 0) + counts.get("unsupported", 0),
        "verified_protocol_counts": dict(sorted(Counter(node["protocol"] for node in verified).items())),
        "verified_region_counts": dict(sorted(Counter(_region(node) for node in verified).items())),
        "source_validated": sum(item["nodes_verified"] > 0 for item in metadata),
        "validation": validation,
        "refresh_status": "success" if alive and alive == len(entries) else "partial" if alive else "failed",
        "refresh_failures": failures, "stale": stale,
    }
    next_run = now.replace(second=0, microsecond=0) + timedelta(minutes=30 - now.minute % 30)
    health.update(next_run_utc=next_run.isoformat(timespec="seconds"),
                  next_run_cn=next_run.astimezone(CN_TZ).isoformat(timespec="seconds"),
                  refresh_interval_seconds=1800, schedule_jitter_seconds=30)
    if stale:
        health["build_time_utc"] = previous_health.get("build_time_utc") or index.get("generated_at", "unknown")
        health["build_time_cn"] = previous_health.get("build_time_cn", "unknown")
    _publish(output, source_nodes, metadata, index, proxies,
             {uri: proxy for uri, proxy in converted.items() if uri in passed_uris}, health)
    return health


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default="dist", type=Path)
    parser.add_argument("--sources", default=SCRIPT_DIR / "data/live_urls.json", type=Path)
    parser.add_argument("--workers", default=8, type=int)
    parser.add_argument("--timeout", default=12, type=float)
    parser.add_argument("--limit-sources", type=int)
    parser.add_argument("--mihomo-binary", default="mihomo")
    parser.add_argument("--check-timeout-ms", default=8000, type=int)
    parser.add_argument("--check-workers", default=4, type=int)
    parser.add_argument("--vantage-point", default="unspecified")
    args = parser.parse_args(argv)
    try:
        sources = _source_entries(load_sources(args.sources))
        if args.limit_sources is not None:
            if args.limit_sources < 1:
                parser.error("--limit-sources must be positive")
            sources = sources[:args.limit_sources]
        health = refresh(args.output_dir, sources, workers=args.workers, timeout=args.timeout,
                         mihomo_binary=args.mihomo_binary, check_timeout_ms=args.check_timeout_ms,
                         check_workers=args.check_workers, vantage_point=args.vantage_point)
    except (OSError, ValueError, RuntimeError):
        print("Refresh could not start: check source file, output permissions, and arguments.", file=sys.stderr)
        return 2
    print("Refresh {}: {}/{} parsed sources, {} collected nodes, {} verified, {} source failures{}".format(
        health["refresh_status"], health["source_alive"], health["source_total"], health["nodes_total"],
        health["nodes_verified"],
        len(health["refresh_failures"]), "; prior snapshot retained" if health["stale"] else ""))
    if health["validation"]["status"] == "unavailable":
        print("Proxy validation unavailable; no node exports published.", file=sys.stderr)
        return 2
    return 1 if health["refresh_status"] == "failed" else 0


if __name__ == "__main__":
    sys.exit(main())
