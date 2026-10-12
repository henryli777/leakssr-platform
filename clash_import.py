"""Import inline Clash proxies that can be represented by our URI converter."""

import base64
import ipaddress
import json
import re
from urllib.parse import quote, urlencode

import yaml

from node_lookup import UUID_PATTERN, parse_node_uri


MAX_PROXIES = 20000
MAX_YAML_DEPTH = 32
MAX_YAML_NODES = 500000
BASE_FIELDS = {"name", "type", "server", "port", "udp", "tfo", "tcp-fast-open"}
TLS_FIELDS = {"sni", "servername", "skip-cert-verify", "client-fingerprint", "alpn"}
TRANSPORT_FIELDS = {"network", "ws-opts", "ws-path", "ws-headers", "grpc-opts"}
PROTOCOL_FIELDS = {
    "ss": {"cipher", "password"},
    "trojan": {"password", "tls"} | TLS_FIELDS | TRANSPORT_FIELDS,
    "vmess": {"uuid", "alterId", "cipher", "tls"} | TLS_FIELDS | TRANSPORT_FIELDS,
    "vless": {"uuid", "tls", "flow", "reality-opts"} | TLS_FIELDS | TRANSPORT_FIELDS,
    "hysteria2": {"password", "obfs", "obfs-password", "ports"} | TLS_FIELDS,
}


def _text(value, allow_empty=False):
    if not isinstance(value, str) or (not value and not allow_empty) or "\0" in value:
        raise ValueError("Invalid string field")
    value.encode("utf-8")
    return value


def _boolean(value):
    if type(value) is not bool:
        raise ValueError("Invalid boolean field")
    return value


def _server(value):
    value = _text(value)
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if not value or any(char.isspace() or char in "/?#@%[]" for char in value):
        raise ValueError("Invalid server")
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        if ":" in value:
            raise ValueError("Invalid IPv6 server")
        value = value.rstrip(".").encode("idna").decode("ascii").lower()
        if not value or len(value) > 253 or any(
                len(label) > 63 or not re.fullmatch(r"[a-z0-9_-]+", label) for label in value.split(".")):
            raise ValueError("Invalid domain server")
        return value


def _safe_document(text):
    # Inspect the syntax tree before loading so aliases and duplicate keys cannot
    # alter credentials silently or expand the work beyond the input bounds.
    document = yaml.compose(text, Loader=yaml.SafeLoader)
    stack, visited = [(document, 0)], set()
    while stack:
        node, depth = stack.pop()
        if node is None:
            continue
        if depth > MAX_YAML_DEPTH or id(node) in visited or len(visited) >= MAX_YAML_NODES:
            raise ValueError("Unsupported YAML structure")
        visited.add(id(node))
        if isinstance(node, yaml.MappingNode):
            keys = set()
            for key, value in node.value:
                if not isinstance(key, yaml.ScalarNode) or key.tag != "tag:yaml.org,2002:str":
                    raise ValueError("Invalid mapping key")
                if key.value in keys:
                    raise ValueError("Duplicate mapping key")
                keys.add(key.value)
                stack.extend([(key, depth + 1), (value, depth + 1)])
        elif isinstance(node, yaml.SequenceNode):
            stack.extend((value, depth + 1) for value in node.value)
    return yaml.safe_load(text)


def _transport(proxy):
    network = proxy.get("network", "tcp")
    if network not in {"tcp", "ws", "grpc"}:
        raise ValueError("Unsupported transport")
    path = host = service = ""
    if network == "ws":
        if "grpc-opts" in proxy:
            raise ValueError("Unused gRPC options")
        options = proxy.get("ws-opts", {})
        if not isinstance(options, dict) or set(options) - {"path", "headers"}:
            raise ValueError("Unsupported WebSocket options")
        if "ws-path" in proxy and "path" in options and proxy["ws-path"] != options["path"]:
            raise ValueError("Conflicting WebSocket paths")
        if "ws-headers" in proxy and "headers" in options and proxy["ws-headers"] != options["headers"]:
            raise ValueError("Conflicting WebSocket headers")
        path = _text(proxy.get("ws-path", options.get("path", "/")))
        headers = proxy.get("ws-headers", options.get("headers", {}))
        if not isinstance(headers, dict) or set(headers) - {"Host"}:
            raise ValueError("Unsupported WebSocket headers")
        if "Host" in headers:
            host = _text(headers["Host"])
    elif network == "grpc":
        if set(proxy) & {"ws-opts", "ws-path", "ws-headers"}:
            raise ValueError("Unused WebSocket options")
        options = proxy.get("grpc-opts", {})
        if not isinstance(options, dict) or set(options) - {"grpc-service-name"}:
            raise ValueError("Unsupported gRPC options")
        service = _text(options.get("grpc-service-name", ""), allow_empty=True)
        if proxy["type"] == "vmess" and service:
            raise ValueError("VMess URI converter cannot retain gRPC service")
    elif set(proxy) & (TRANSPORT_FIELDS - {"network"}):
        raise ValueError("Unused transport options")
    return network, path, host, service


def _tls_options(proxy):
    options = {}
    if "sni" in proxy and "servername" in proxy and proxy["sni"] != proxy["servername"]:
        raise ValueError("Conflicting TLS server names")
    if "sni" in proxy or "servername" in proxy:
        options["sni"] = _text(proxy.get("sni", proxy.get("servername")))
    if "client-fingerprint" in proxy:
        options["fp"] = _text(proxy["client-fingerprint"])
    if "skip-cert-verify" in proxy:
        options["insecure"] = "1" if _boolean(proxy["skip-cert-verify"]) else "0"
    if "alpn" in proxy:
        alpn = proxy["alpn"]
        if not isinstance(alpn, list) or not alpn or len(alpn) > 32:
            raise ValueError("Invalid ALPN list")
        if any("," in _text(value) for value in alpn):
            raise ValueError("Unrepresentable ALPN value")
        options["alpn"] = ",".join(alpn)
    return options


def _flags(proxy):
    result = {}
    if "udp" in proxy:
        result["udp"] = _boolean(proxy["udp"])
    for field in ("tfo", "tcp-fast-open"):
        if field in proxy:
            _boolean(proxy[field])
    if "tfo" in proxy and "tcp-fast-open" in proxy and proxy["tfo"] != proxy["tcp-fast-open"]:
        raise ValueError("Conflicting fast-open flags")
    if "tfo" in proxy or "tcp-fast-open" in proxy:
        result["tfo"] = _boolean(proxy.get("tfo", proxy.get("tcp-fast-open")))
    return result


def _encode(value):
    return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")


def _proxy_uri(proxy):
    if not isinstance(proxy, dict):
        return None
    protocol = proxy.get("type")
    if not isinstance(protocol, str) or protocol not in PROTOCOL_FIELDS:
        return None
    if set(proxy) - BASE_FIELDS - PROTOCOL_FIELDS[protocol]:
        return None
    server = _server(proxy.get("server"))
    port = proxy.get("port")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid port")
    endpoint = "[{}]:{}".format(server.strip("[]"), port) if ":" in server else "{}:{}".format(server, port)
    name = _text(proxy.get("name", "{} {}".format(protocol.upper(), endpoint)))
    fragment = "#" + quote(name, safe="")
    flags = _flags(proxy)
    params = {key: "1" if value else "0" for key, value in flags.items()}

    if protocol == "ss":
        cipher, password = _text(proxy.get("cipher")), _text(proxy.get("password"))
        if ":" in cipher:
            raise ValueError("Invalid cipher")
        uri = "ss://{}@{}".format(_encode(cipher + ":" + password), endpoint)
    else:
        tls_options = _tls_options(proxy)
        params.update(tls_options)
        if protocol in {"vmess", "vless", "trojan"}:
            network, path, host, service = _transport(proxy)
            tls = _boolean(proxy.get("tls", protocol == "trojan"))
        if protocol in {"vmess", "vless"}:
            credential = _text(proxy.get("uuid"))
            if not UUID_PATTERN.fullmatch(credential):
                raise ValueError("Invalid UUID")
        else:
            credential = _text(proxy.get("password"))

        if protocol == "vmess":
            alter_id = proxy.get("alterId", 0)
            if type(alter_id) is not int or not 0 <= alter_id <= 65535:
                raise ValueError("Invalid alterId")
            config = {
                "v": "2", "ps": name, "add": server, "port": port,
                "id": credential, "aid": alter_id, "scy": _text(proxy.get("cipher", "auto")),
                "net": network, "tls": "tls" if tls else "", **flags,
            }
            if path:
                config["path"] = path
            if host:
                config["host"] = host
            for key in ("sni", "fp", "alpn"):
                if key in tls_options:
                    config[key] = tls_options[key]
            if "insecure" in tls_options:
                config["allowInsecure"] = proxy["skip-cert-verify"]
            uri = "vmess://" + _encode(json.dumps(config, ensure_ascii=False, separators=(",", ":")))
            return uri if parse_node_uri(uri) else None

        if protocol in {"vless", "trojan"}:
            if protocol == "trojan" and not tls:
                raise ValueError("Trojan requires TLS")
            params["security"] = "tls" if tls else "none"
            params["type"] = network
            if path:
                params["path"] = path
            if host:
                params["host"] = host
            if service:
                params["serviceName"] = service
        if protocol == "vless":
            params["encryption"] = "none"
            if "flow" in proxy:
                params["flow"] = _text(proxy["flow"])
            if "reality-opts" in proxy:
                reality = proxy["reality-opts"]
                if not tls or not isinstance(reality, dict) or set(reality) - {"public-key", "short-id"}:
                    raise ValueError("Unsupported Reality options")
                params.update(security="reality", pbk=_text(reality.get("public-key")),
                              sid=_text(reality.get("short-id", ""), allow_empty=True))
        if protocol == "hysteria2":
            for field in ("obfs", "obfs-password"):
                if field in proxy:
                    params[field] = _text(proxy[field])
            if "ports" in proxy:
                params["mport"] = _text(proxy["ports"])
        uri = "{}://{}@{}".format(protocol, quote(credential, safe=""), endpoint)

    if params:
        uri += "?" + urlencode(params)
    uri += fragment
    return uri if parse_node_uri(uri) else None


def parse_clash_subscription(text: str) -> list:
    """Return losslessly supported inline proxy URIs, without fetching providers.

    Unknown node fields, plugins, unsupported transports, and bandwidth settings
    are skipped rather than silently discarded. Rules and other config are never
    converted into nodes. Malformed, aliased, or oversized YAML yields no nodes.
    """
    if not isinstance(text, str):
        return []
    try:
        document = _safe_document(text)
        proxies = document.get("proxies") if isinstance(document, dict) else None
        if not isinstance(proxies, list) or len(proxies) > MAX_PROXIES:
            return []
    except (yaml.YAMLError, ValueError, TypeError, RecursionError, UnicodeError):
        return []
    nodes, seen = [], set()
    for proxy in proxies:
        try:
            uri = _proxy_uri(proxy)
            if uri and uri not in seen:
                nodes.append(uri)
                seen.add(uri)
        except (ValueError, TypeError, KeyError, UnicodeError):
            continue
    return nodes
