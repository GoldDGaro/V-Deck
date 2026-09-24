"""Import a reviewed VLESS/REALITY client subset, never arbitrary Xray services."""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import uuid
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from .errors import VDeckError


def _fail() -> VDeckError:
    return VDeckError(
        "XRAY_CONFIG_UNSUPPORTED",
        "Import one VLESS + Reality TCP/RAW client with no flow or xtls-rprx-vision",
    )


def _uri(text: str) -> dict[str, Any]:
    uri = urlsplit(text.strip())
    query = parse_qs(uri.query, keep_blank_values=True)
    if uri.scheme != "vless" or uri.password or not uri.hostname or not uri.port:
        raise _fail()
    allowed = {"security", "type", "encryption", "flow", "sni", "fp", "pbk", "sid", "spx", "headerType"}
    if set(query) - allowed or any(len(values) != 1 for values in query.values()):
        raise _fail()
    values = {key: value[0] for key, value in query.items()}
    if values.get("headerType", "none") != "none":
        raise _fail()
    return {
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": uri.hostname,
                            "port": uri.port,
                            "users": [
                                {
                                    "id": unquote(uri.username or ""),
                                    "encryption": values.get("encryption", "none"),
                                    "flow": values.get("flow", ""),
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": {
                    "network": values.get("type", "tcp"),
                    "security": values.get("security", ""),
                    "realitySettings": {
                        "serverName": values.get("sni", ""),
                        "fingerprint": values.get("fp", "chrome"),
                        "publicKey": values.get("pbk", ""),
                        "shortId": values.get("sid", ""),
                        "spiderX": values.get("spx", ""),
                    },
                },
            }
        ]
    }


def normalize_xray(text: str) -> tuple[dict[str, Any], list[str], list[str]]:
    """Return only an allowlisted outbound and literal DNS addresses.

    Local proxy listeners, routing, API, paths, log destinations, socket options
    and direct outbounds from GUI exports are not executed. Multiple proxies
    and unsupported transports are rejected instead of guessing a selection.
    """
    try:
        raw = _uri(text) if text.strip().startswith("vless://") else json.loads(text)
        outbounds = raw["outbounds"]
        if not isinstance(outbounds, list) or not all(isinstance(item, dict) for item in outbounds):
            raise _fail()
        proxies = [item for item in outbounds if item.get("protocol") not in {"freedom", "blackhole", "dns"}]
        if len(proxies) != 1 or proxies[0].get("protocol") != "vless":
            raise _fail()
        outbound = proxies[0]
        servers = outbound["settings"]["vnext"]
        if len(servers) != 1 or len(servers[0]["users"]) != 1:
            raise _fail()
        server, user = servers[0], servers[0]["users"][0]
        host, port = server["address"], server["port"]
        if not isinstance(host, str) or not host or len(host) > 253:
            raise _fail()
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", host):
                raise _fail() from None
        if type(port) is not int or not 1 <= port <= 65535:
            raise _fail()
        identity = str(uuid.UUID(user["id"]))
        flow = user.get("flow", "")
        if flow not in {"", "xtls-rprx-vision"} or user.get("encryption", "none") != "none":
            raise _fail()
        stream = outbound["streamSettings"]
        if stream.get("network", "tcp") not in {"tcp", "raw"} or stream.get("security") != "reality":
            raise _fail()
        transport = stream.get("tcpSettings", stream.get("rawSettings", {}))
        if transport and transport != {"header": {"type": "none"}}:
            raise _fail()
        reality = stream["realitySettings"]
        public_key = reality.get("publicKey", reality.get("password", ""))
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", public_key):
            raise _fail()
        if len(base64.urlsafe_b64decode(public_key + "=")) != 32:
            raise _fail()
        sni, sid = reality["serverName"], reality.get("shortId", "")
        if not isinstance(sni, str) or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", sni):
            raise _fail()
        if not isinstance(sid, str) or len(sid) > 16 or len(sid) % 2 or not re.fullmatch(r"[a-fA-F0-9]*", sid):
            raise _fail()
        fingerprint = reality.get("fingerprint", "chrome")
        if fingerprint not in {
            "chrome",
            "firefox",
            "safari",
            "ios",
            "android",
            "edge",
            "360",
            "qq",
            "random",
            "randomized",
        }:
            raise _fail()
        spider = reality.get("spiderX", "")
        if not isinstance(spider, str) or len(spider) > 2048 or any(ord(c) < 32 for c in spider):
            raise _fail()
        # Fail closed on security options we cannot preserve faithfully.
        if set(reality) - {"show", "serverName", "fingerprint", "publicKey", "password", "shortId", "spiderX"}:
            raise _fail()
        clean = {
            "protocol": "vless",
            "tag": "vpn",
            "settings": {
                "vnext": [
                    {"address": host, "port": port, "users": [{"id": identity, "encryption": "none", "flow": flow}]}
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverName": sni,
                    "fingerprint": fingerprint,
                    "publicKey": public_key,
                    "shortId": sid,
                    "spiderX": spider,
                    "show": False,
                },
            },
        }
        dns = raw.get("dns", {}).get("servers", [])
        # Domain-specific DNS policies from client apps are not portable here.
        # Use their plain IP resolvers if supplied, otherwise documented defaults.
        servers_dns: list[str] = []
        for value in dns:
            if isinstance(value, str):
                try:
                    servers_dns.append(str(ipaddress.ip_address(value)))
                except ValueError:
                    continue
        endpoint = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        return clean, [endpoint], list(dict.fromkeys(servers_dns))[:3] or ["1.1.1.1", "8.8.8.8"]
    except VDeckError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, IndexError, OverflowError, RecursionError):
        raise _fail() from None
