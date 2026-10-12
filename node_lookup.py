#!/usr/bin/env python3
"""Build and search offline node-to-subscription provenance indexes."""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
from typing import Dict, List, Optional
from urllib.parse import parse_qsl, unquote, urlsplit


SUPPORTED_PROTOCOLS = {"vmess", "vless", "trojan", "ss", "ssr", "hysteria2", "hy2"}
SCRIPT_DIR = Path(__file__).resolve().parent
UUID_PATTERN = re.compile(r"^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")


def _decode_base64(value: str) -> str:
    value = unquote(value)
    if not value or not re.fullmatch(r"[A-Za-z0-9+/_=-]+", value):
        raise ValueError("Invalid Base64 content")
    padded = value + "=" * (-len(value) % 4)
    return base64.b64decode(padded, altchars=b"-_", validate=True).decode("utf-8")


def _normalize_host(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Invalid server type")
    value = value.strip("[]").rstrip(".").lower()
    if not value or any(char.isspace() or char in "/?#@" for char in value):
        raise ValueError("Missing or invalid server")
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        if ":" in value:
            raise ValueError("Invalid IPv6 server")
        return value.encode("idna").decode("ascii")


def _normalize_port(value) -> int:
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]+", str(value)):
        raise ValueError("Invalid port")
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError("Invalid port")
    return port


def _endpoint(server: str, port: int) -> str:
    return "[{}]:{}".format(server, port) if ":" in server else "{}:{}".format(server, port)


def _query_pairs(query: str) -> list:
    return sorted([list(pair) for pair in parse_qsl(query, keep_blank_values=True)])


def _serialize_key(config: dict) -> str:
    key = json.dumps(config, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    key.encode("utf-8")
    return key


def _uri_result(uri: str, name: str, config: dict) -> dict:
    protocol = config["protocol"]
    server, port = config["server"], config["port"]
    name = name or "{} {}".format(protocol.upper(), _endpoint(server, port))
    name.encode("utf-8")
    return {
        "protocol": protocol,
        "name": name,
        "server": server,
        "port": port,
        "uri": uri,
        "match_key": _serialize_key(config),
    }


def _parse_ss(uri: str, rest: str, name: str) -> dict:
    if "@" in rest:
        parsed = urlsplit("ss://" + rest)
        auth = unquote(parsed.netloc.rsplit("@", 1)[0])
        if ":" not in auth:
            auth = _decode_base64(auth)
        server, port = _normalize_host(parsed.hostname or ""), _normalize_port(parsed.port)
        params = _query_pairs(parsed.query)
    else:
        encoded, separator, query = rest.partition("?")
        decoded = _decode_base64(encoded.rstrip("/"))
        auth, address = decoded.rsplit("@", 1)
        parsed = urlsplit("ss://" + address)
        server, port = _normalize_host(parsed.hostname or ""), _normalize_port(parsed.port)
        params = _query_pairs(parsed.query) + (_query_pairs(query) if separator else [])
        params.sort()
    cipher, password = auth.split(":", 1)
    if not cipher or not password:
        raise ValueError("Missing Shadowsocks credentials")
    return _uri_result(uri, name, {
        "protocol": "ss", "server": server, "port": port,
        "cipher": cipher, "password": password, "params": params,
    })


def _parse_vmess(uri: str, rest: str, name: str) -> dict:
    config = json.loads(_decode_base64(rest))
    if not isinstance(config, dict) or not isinstance(config.get("id"), str) or not config["id"]:
        raise ValueError("Missing VMess configuration")
    server, port = _normalize_host(config.get("add", "")), _normalize_port(config.get("port", 443))
    name = name or str(config.get("ps") or "")
    connection = {key: value for key, value in config.items() if key not in {"ps", "v", "add", "port"}}
    aid = connection.get("aid", 0)
    if isinstance(aid, bool) or not re.fullmatch(r"[0-9]+", str(aid)):
        raise ValueError("Invalid VMess alterId")
    connection["aid"] = int(aid)
    for key, default in {"net": "tcp", "scy": "auto", "tls": ""}.items():
        connection.setdefault(key, default)
    if UUID_PATTERN.fullmatch(connection["id"]):
        connection["id"] = connection["id"].lower()
    return _uri_result(uri, name, {
        "protocol": "vmess", "server": server, "port": port, "config": connection,
    })


def _parse_ssr(uri: str, rest: str, name: str) -> dict:
    decoded = _decode_base64(rest)
    address, _, query = decoded.partition("/?")
    address = address.rstrip("/")
    server, port, protocol, cipher, obfs, password = address.rsplit(":", 5)
    server, port = _normalize_host(server), _normalize_port(port)
    password = _decode_base64(password)
    if not protocol or not cipher or not obfs or not password:
        raise ValueError("Missing SSR configuration")
    params = []
    for key, value in parse_qsl(query, keep_blank_values=True):
        if key == "remarks":
            name = name or _decode_base64(value)
        elif key != "group":
            if key in {"obfsparam", "protoparam"} and value:
                value = _decode_base64(value)
            params.append([key, value])
    return _uri_result(uri, name, {
        "protocol": "ssr", "server": server, "port": port,
        "ssr_protocol": protocol, "cipher": cipher, "obfs": obfs,
        "password": password, "params": sorted(params),
    })


def parse_node_uri(uri: str) -> Optional[dict]:
    """Decode a supported URI without losing connection options or credentials."""
    if not isinstance(uri, str):
        return None
    uri = uri.strip()
    connection, _, fragment = uri.partition("#")
    if any(char.isspace() for char in connection) or re.search(r"%(?![0-9A-Fa-f]{2})", uri):
        return None
    try:
        protocol, rest = connection.split("://", 1)
        protocol = protocol.lower()
        if protocol not in SUPPORTED_PROTOCOLS:
            return None
        name = unquote(fragment)
        if protocol == "ss":
            return _parse_ss(uri, rest, name)
        if protocol == "vmess":
            return _parse_vmess(uri, rest, name)
        if protocol == "ssr":
            return _parse_ssr(uri, rest, name)
        if protocol == "hy2":
            protocol = "hysteria2"
        parsed = urlsplit(protocol + "://" + rest)
        if "@" not in parsed.netloc:
            return None
        credentials = unquote(parsed.netloc.rsplit("@", 1)[0])
        if not credentials:
            return None
        if protocol == "vless" and UUID_PATTERN.fullmatch(credentials):
            credentials = credentials.lower()
        return _uri_result(uri, name, {
            "protocol": protocol, "server": _normalize_host(parsed.hostname or ""),
            "port": _normalize_port(parsed.port if parsed.port is not None else 443),
            "credentials": credentials, "path": "" if parsed.path == "/" else parsed.path,
            "params": _query_pairs(parsed.query),
        })
    except (ValueError, TypeError, KeyError, UnicodeError):
        return None


def canonical_node_key(uri: str) -> Optional[str]:
    """Return a deterministic connection identity, excluding display labels."""
    parsed = parse_node_uri(uri)
    return parsed["match_key"] if parsed else None


def build_node_index(
    source_nodes: Dict[str, List[str]],
    source_meta: Optional[List[dict]] = None,
    published_nodes: Optional[List[str]] = None,
) -> dict:
    """Retain all aliases and source URLs even when subscription nodes deduplicate."""
    metadata = {item["url"]: item for item in source_meta or [] if isinstance(item, dict) and item.get("url")}
    published_keys = None if published_nodes is None else {
        key for key in (canonical_node_key(uri) for uri in published_nodes) if key
    }
    sources, connections = {}, {}
    for url in sorted(source_nodes):
        if not isinstance(url, str) or not url:
            continue
        sid = hashlib.sha1(url.encode("utf-8")).hexdigest()[:12]
        meta = metadata.get(url, {})
        source_keys = set()
        try:
            host = urlsplit(url).netloc
        except ValueError:
            host = ""
        sources[sid] = {
            "id": sid, "url": url,
            "provider": meta.get("provider") or meta.get("host") or host,
            "detail_page": meta.get("detail_page") or "source.html?id=" + sid,
            "available": meta.get("available", True), "nodes_total": 0,
        }
        for uri in source_nodes[url]:
            parsed = parse_node_uri(uri)
            if not parsed:
                continue
            key = parsed["match_key"]
            source_keys.add(key)
            if key not in connections:
                connections[key] = {
                    "id": hashlib.sha256(key.encode("utf-8")).hexdigest()[:20],
                    "protocol": parsed["protocol"], "name": parsed["name"], "names": [],
                    "server": parsed["server"], "port": parsed["port"],
                    "uri": parsed["uri"], "uris": [], "source_ids": [],
                    "published": published_keys is None or key in published_keys,
                    "match_keys": [key], "search_text": "",
                }
            node = connections[key]
            for field, value in (("names", parsed["name"]), ("uris", parsed["uri"]), ("source_ids", sid)):
                if value not in node[field]:
                    node[field].append(value)
        sources[sid]["nodes_total"] = len(source_keys)
    for key, node in connections.items():
        node["search_text"] = "\n".join([
            node["protocol"], node["server"], str(node["port"]), _endpoint(node["server"], node["port"]),
            *node["names"], *node["uris"], *(unquote(uri) for uri in node["uris"]), key,
        ]).lower()
    return {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sources": sources,
        "nodes": sorted(connections.values(), key=lambda node: (node["protocol"], node["server"], node["port"], node["id"])),
    }


def add_node_name_aliases(index: dict, aliases: Dict[str, List[str]]) -> None:
    """Attach exact exported labels to the corresponding existing connections."""
    connections = {
        key: node for node in index.get("nodes", []) for key in node.get("match_keys", [])
    }
    for uri, labels in aliases.items():
        node = connections.get(canonical_node_key(uri))
        if node is None:
            continue
        for label in labels:
            if isinstance(label, str) and label and label not in node["names"]:
                try:
                    label.encode("utf-8")
                except UnicodeError:
                    continue
                node["names"].append(label)
                node["search_text"] += "\n" + label.lower()


def search_node_index(index: dict, query: str) -> List[dict]:
    """Match a full connection URI, an endpoint, or all case-insensitive keywords."""
    query = query.strip()
    if not query:
        return []
    key, endpoint, server = None, None, None
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", query) or re.match(
        r"^(?:" + "|".join(SUPPORTED_PROTOCOLS) + r"):", query, re.IGNORECASE
    ):
        key = canonical_node_key(query)
        if key is None:
            return []
    elif re.fullmatch(r"(?:\[[^\]]+\]|[^\s:]+):[0-9]+", query):
        try:
            parsed = urlsplit("node://" + query)
            endpoint = (_normalize_host(parsed.hostname or ""), _normalize_port(parsed.port))
        except (ValueError, UnicodeError):
            return []
    else:
        try:
            server = ipaddress.ip_address(query.strip("[]")).compressed
        except ValueError:
            pass
    terms = unquote(query).lower().split()
    matches = []
    for node in index.get("nodes", []):
        if key is not None:
            matched = key in node.get("match_keys", [])
        elif endpoint is not None:
            matched = (node.get("server"), node.get("port")) == endpoint
        elif server is not None:
            matched = node.get("server") == server
        else:
            matched = all(term in node.get("search_text", "").lower() for term in terms)
        if matched:
            matches.append({
                **node,
                "sources": [index["sources"][sid] for sid in node.get("source_ids", []) if sid in index.get("sources", {})],
            })
    return matches


def _subscription_lines(text: str) -> List[str]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if any(re.match(r"^(?:" + "|".join(SUPPORTED_PROTOCOLS) + r")://", line, re.IGNORECASE) for line in lines):
        return lines
    try:
        return [line.strip() for line in _decode_base64("".join(lines)).splitlines() if line.strip()]
    except (ValueError, UnicodeError):
        return []


def rebuild_node_index(providers_dir) -> dict:
    """Reconstruct provenance from provider metadata and node files, without HTTP."""
    directory = Path(providers_dir)
    source_nodes, metadata = {}, []
    current_sources = None
    try:
        manifest = json.loads((directory.parent / "url_meta.json").read_text(encoding="utf-8"))
        if isinstance(manifest, list):
            current_sources = {
                item["url"]: item for item in manifest
                if isinstance(item, dict) and isinstance(item.get("url"), str)
            }
    except (OSError, ValueError, UnicodeError):
        pass
    for meta_path in sorted(directory.glob("*.json")):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            if not isinstance(meta, dict) or not isinstance(meta.get("url"), str) or not meta["url"]:
                continue
            if current_sources is not None:
                meta["available"] = current_sources[meta["url"]].get("available") if meta["url"] in current_sources else False
            else:
                meta.setdefault("available", None)
            text_path = meta_path.with_suffix(".txt")
            try:
                lines = _subscription_lines(text_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError):
                lines = []
            source_nodes.setdefault(meta["url"], []).extend(lines)
            metadata.append(meta)
        except (OSError, ValueError, UnicodeError):
            continue
    published_nodes, exports_found = [], False
    for filename in ("all.txt", "good.txt"):
        try:
            published_nodes.extend(_subscription_lines((directory.parent / filename).read_text(encoding="utf-8")))
            exports_found = True
        except (OSError, UnicodeError):
            continue
    index = build_node_index(source_nodes, metadata, published_nodes if exports_found else None)
    if not exports_found:
        for node in index["nodes"]:
            node["published"] = None
    return index


def _default_sub_dir() -> Path:
    dist = SCRIPT_DIR / "dist" / "sub"
    return dist if dist.is_dir() else SCRIPT_DIR / "sub"


def main(argv=None) -> int:
    sub_dir = _default_sub_dir()
    parser = argparse.ArgumentParser(description="Find original subscription URLs for a node, offline")
    parser.add_argument("query", nargs="*", help="Node name, server[:port], UUID fragment, or full URI")
    parser.add_argument("--index", type=Path, default=sub_dir / "node_index.json")
    parser.add_argument("--json", action="store_true", help="Print matches with original source metadata as JSON")
    parser.add_argument("--rebuild", action="store_true", help="Rebuild from provider .json/.txt pairs")
    parser.add_argument("--providers-dir", type=Path, default=sub_dir / "providers")
    parser.add_argument("--output", type=Path, help="Index destination for --rebuild; defaults to --index")
    args = parser.parse_args(argv)
    try:
        if args.rebuild:
            index = rebuild_node_index(args.providers_dir)
            output = args.output or args.index
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            if not args.query:
                summary = {"index": str(output), "nodes": len(index["nodes"]), "sources": len(index["sources"])}
                print(json.dumps(summary) if args.json else "Wrote {} nodes from {} sources to {}".format(summary["nodes"], summary["sources"], output))
                return 0
        else:
            index = json.loads(args.index.read_text(encoding="utf-8"))
            if not isinstance(index, dict) or not isinstance(index.get("nodes"), list) or not isinstance(index.get("sources"), dict):
                raise ValueError("Invalid node index")
        matches = search_node_index(index, " ".join(args.query))
        if args.json:
            print(json.dumps(matches, ensure_ascii=False, indent=2))
        elif not matches:
            print("No matching nodes.")
        else:
            for node in matches:
                print("{} ({}, {})".format(node["name"], node["protocol"], _endpoint(node["server"], node["port"])))
                for source in node["sources"]:
                    print("  {}".format(source["url"]))
        return 0
    except (OSError, ValueError) as error:
        print("node_lookup: {}".format(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
