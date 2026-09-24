"""Premium subscription storage and gateway bridge; no credentials cross RPC."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .atomic import atomic_write_bytes, atomic_write_json, read_json
from .binaries import BinaryManager
from .errors import VDeckError
from .models import ConnectionMetadata, Protocol
from .parsers import _decode_amnezia_container, parse_amnezia_vpn
from .runner import child_environment
from .security import MAX_CONFIG_BYTES, secure_mkdir, secure_write
from .storage import VDeckStore, utc_now


class PremiumManager:
    def __init__(self, store: VDeckStore, binaries: BinaryManager):
        self.store = store
        self.binaries = binaries
        self.root = store.root / "premium"
        secure_mkdir(self.root)

    def _path(self, subscription_id: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{32}", subscription_id):
            raise VDeckError("PREMIUM_ID_INVALID", "Invalid subscription identifier")
        return self.root / f"{subscription_id}.json"

    def _load(self, subscription_id: str) -> dict[str, Any]:
        value = read_json(self._path(subscription_id), None)
        if not isinstance(value, dict):
            raise VDeckError("PREMIUM_NOT_FOUND", "Subscription was not found")
        return value

    @staticmethod
    def _public(value: dict[str, Any]) -> dict[str, Any]:
        return {key: value.get(key) for key in ("id", "locations", "country", "connection_id")}

    def subscriptions(self) -> list[dict[str, Any]]:
        return [self._public(self._load(path.stem)) for path in sorted(self.root.glob("*.json"))]

    def _log_attempts(self, operation: str, response: dict[str, Any]) -> None:
        attempts = response.get("attempts")
        if not self.store.logger or not isinstance(attempts, list):
            return
        for index, item in enumerate(attempts[:24], 1):
            if not isinstance(item, dict):
                continue
            safe: dict[str, Any] = {}
            allowed = {
                "route": {"direct", "catalogue", "mirror"},
                "stage": {"DNS", "TCP", "TLS", "REQUEST", "RESPONSE_HEADERS", "RESPONSE_BODY"},
                "family": {"IPv4", "IPv6"},
            }
            for field, values in allowed.items():
                safe[field] = (
                    item.get(field) if isinstance(item.get(field), str) and item[field] in values else "unknown"
                )
            host = item.get("host")
            safe["host"] = host if isinstance(host, str) and re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host) else "redacted"
            code = item.get("code")
            safe["code"] = (
                code if isinstance(code, str) and re.fullmatch(r"(?:OK|PREMIUM_[A-Z_]{1,50})", code) else "INVALID"
            )
            for field in ("elapsed_ms", "dns_ms", "tcp_ms", "tls_ms", "status"):
                value = item.get(field)
                safe[field] = value if type(value) is int and 0 <= value <= 120000 else None
            safe["written"] = item.get("written") is True
            self.store.logger.info(
                "premium transport operation=%s attempt=%s tls_profile=classic details=%s", operation, index, safe
            )

    async def _request(self, operation: str, value: dict[str, Any], country: str = "") -> dict[str, Any]:
        # app_version is the upstream API compatibility version, not our plugin
        # version. cli_name/User-Agent explicitly identify this third-party client.
        payload = {
            "os_version": "linux",
            "app_version": "5.0.1.5",
            "cli_name": "V-Deck",
            "app_language": "en",
            "installation_uuid": value["installation_uuid"],
            "service_type": value["service_type"],
            "service_protocol": "awg",
            "user_country_code": value["user_country_code"],
            "auth_data": {"api_key": value["api_key"]},
        }
        if country:
            payload["server_country_code"] = country
        if operation == "config":
            payload["is_connect_event"] = True
        if self.store.logger:
            self.store.logger.info("premium API started stage=%s subscription=%s", operation, value["id"])
        process = await asyncio.create_subprocess_exec(
            str(self.binaries.path("premium-api")),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=child_environment(bundled=True),
        )
        try:
            stdout, _ = await asyncio.wait_for(
                process.communicate(json.dumps({"operation": operation, "payload": payload}).encode()), 55
            )
        except (asyncio.TimeoutError, asyncio.CancelledError) as exc:
            if process.returncode is None:
                process.kill()
            await process.wait()
            if isinstance(exc, asyncio.TimeoutError):
                if self.store.logger:
                    self.store.logger.warning(
                        "premium helper timeout stage=%s exit_code=%s", operation, process.returncode
                    )
                raise VDeckError("PREMIUM_HELPER_TIMEOUT", "Premium API helper exceeded its deadline") from exc
            raise
        try:
            if process.returncode or len(stdout) > 2 * MAX_CONFIG_BYTES:
                raise ValueError()
            response = json.loads(stdout)
            if not isinstance(response, dict):
                raise ValueError()
        except (ValueError, TypeError) as exc:
            raise VDeckError("PREMIUM_HELPER_FAILED", "Premium API helper failed") from exc
        self._log_attempts(operation, response)
        code = response.get("code")
        if self.store.logger:
            self.store.logger.info(
                "premium API returned stage=%s code=%s http_status=%s exit_code=%s",
                operation,
                code if isinstance(code, str) and re.fullmatch(r"[A-Z_]{2,64}", code) else "INVALID",
                response.get("status") if isinstance(response.get("status"), int) else None,
                process.returncode,
            )
        if code != "OK":
            safe_code = (
                code if isinstance(code, str) and re.fullmatch(r"PREMIUM_[A-Z_]{1,50}", code) else "PREMIUM_API_FAILED"
            )
            raise VDeckError(safe_code, "Unable to retrieve Premium data")
        if not isinstance(response.get("data"), dict):
            raise VDeckError("PREMIUM_RESPONSE_INVALID", "Invalid Premium response")
        return response

    @staticmethod
    def _locations(data: dict[str, Any]) -> list[dict[str, str]]:
        result = []
        countries = data.get("available_countries")
        if not isinstance(countries, list):
            raise VDeckError("PREMIUM_RESPONSE_INVALID", "Premium locations are missing")
        for item in countries[:256]:
            if not isinstance(item, dict) or not isinstance(item.get("available_protocols"), list):
                continue
            if "awg" not in item["available_protocols"]:
                continue
            code, name = item.get("server_country_code"), item.get("server_country_name")
            if isinstance(code, str) and re.fullmatch(r"[A-Za-z0-9_-]{2,32}", code) and isinstance(name, str):
                result.append({"code": code, "name": "".join(c for c in name[:100] if c.isprintable())})
        if not result:
            raise VDeckError("PREMIUM_NO_AWG_LOCATIONS", "No AmneziaWG locations are available")
        return result

    async def import_subscription(self, source: Path) -> dict[str, Any]:
        doc = _decode_amnezia_container(source.read_text(encoding="utf-8-sig"))
        auth, config = doc.get("auth_data"), doc.get("api_config")
        if not isinstance(auth, dict) or not isinstance(config, dict):
            raise VDeckError(
                "PREMIUM_SUBSCRIPTION_INVALID", "Select a Premium subscription key, not a VPN configuration"
            )
        key, service, country = auth.get("api_key"), config.get("service_type"), config.get("user_country_code")
        if (
            not isinstance(key, str)
            or not 8 <= len(key) <= 4096
            or not isinstance(service, str)
            or not isinstance(country, str)
        ):
            raise VDeckError("PREMIUM_SUBSCRIPTION_INVALID", "Invalid Premium subscription key")
        subscription_id = hashlib.sha256(key.encode()).hexdigest()[:32]
        value = read_json(self._path(subscription_id), None)
        if not isinstance(value, dict):
            value = {
                "id": subscription_id,
                "installation_uuid": str(uuid.uuid4()),
                "api_key": key,
                "service_type": service,
                "user_country_code": country,
                "connection_id": None,
                "country": None,
            }
        response = await self._request("account_info", value)
        value["locations"] = self._locations(response["data"])
        atomic_write_json(self._path(subscription_id), value)
        return self._public(value)

    async def locations(self, subscription_id: str) -> dict[str, Any]:
        value = self._load(subscription_id)
        response = await self._request("account_info", value)
        value["locations"] = self._locations(response["data"])
        atomic_write_json(self._path(subscription_id), value)
        return self._public(value)

    async def _download(self, value: dict[str, Any], country: str) -> None:
        response = await self._request("config", value, country)
        config, private = response["data"].get("config"), response.get("private_key")
        if (
            not isinstance(config, str)
            or not isinstance(private, str)
            or not re.fullmatch(r"[A-Za-z0-9+/]{43}=", private)
        ):
            raise VDeckError("PREMIUM_RESPONSE_INVALID", "Premium configuration is missing")
        doc = _decode_amnezia_container(config)
        document = json.dumps(doc).replace("$WIREGUARD_CLIENT_PRIVATE_KEY", private)
        # The parser accepts an uncompressed base64 JSON container too.
        vpn = "vpn://" + base64.urlsafe_b64encode(document.encode()).decode()
        parsed = parse_amnezia_vpn(vpn)
        if parsed.protocol != Protocol.AMNEZIAWG.value:
            raise VDeckError("PREMIUM_PROTOCOL_UNSUPPORTED", "Premium configuration is not AmneziaWG")
        api = doc.get("api_config", {})
        public = api.get("public_key", {}) if isinstance(api, dict) else {}
        expires = public.get("expires_at") if isinstance(public, dict) else None
        try:
            expiry = datetime.fromisoformat(str(expires).replace("Z", "+00:00"))
            if expiry.tzinfo is None:
                raise ValueError()
        except ValueError:
            expiry = datetime.now(timezone.utc) + timedelta(hours=1)
        value.update(vpn=vpn, country=country, expires_at=expiry.isoformat())

    def _materialize(self, value: dict[str, Any], metadata: ConnectionMetadata) -> None:
        # One atomic subscription record is authoritative. These derived files
        # are rebuilt under the manager lock before start, including after crash.
        parsed = parse_amnezia_vpn(value["vpn"])
        directory = self.store.connection_dir(metadata.id)
        atomic_write_bytes(directory / "config", parsed.runtime_config.encode())
        atomic_write_json(
            directory / "runtime-info.json",
            {
                "interface_addresses": parsed.interface_addresses,
                "dns_servers": parsed.dns_servers,
                "mtu": parsed.mtu,
                "allowed_ips": parsed.allowed_ips,
                "endpoints": parsed.endpoints,
            },
        )
        metadata.premium_id = value["id"]
        metadata.premium_country = value["country"]
        metadata.updated_at = utc_now()
        self.store.update_metadata(metadata)

    async def select(self, subscription_id: str, country: str) -> ConnectionMetadata:
        value = self._load(subscription_id)
        if country not in {item["code"] for item in value.get("locations", [])}:
            raise VDeckError("PREMIUM_LOCATION_INVALID", "Select an available location")
        await self._download(value, country)
        metadata = next((m for m in self.store.list() if m.premium_id == subscription_id), None)
        if metadata is None:
            with tempfile.TemporaryDirectory(prefix=".premium-", dir=self.root) as temporary:
                source = Path(temporary) / "premium.vpn"
                secure_write(source, value["vpn"].encode())
                metadata = self.store.import_connection(Protocol.AMNEZIAWG, source, "Amnezia Premium")
            metadata.premium_id = subscription_id
            self.store.update_metadata(metadata)
        value["connection_id"] = metadata.id
        atomic_write_json(self._path(subscription_id), value)
        self._materialize(value, metadata)
        return metadata

    async def prepare(self, metadata: ConnectionMetadata, *, recovery: bool = False) -> None:
        if not metadata.premium_id:
            return
        value = self._load(metadata.premium_id)
        if not value.get("vpn"):
            raise VDeckError("PREMIUM_CONFIG_MISSING", "Select a Premium location again")
        try:
            expires = datetime.fromisoformat(value["expires_at"])
            expired = expires <= datetime.now(timezone.utc) + timedelta(seconds=60)
        except (ValueError, TypeError, KeyError):
            expired = True
        if expired and not recovery:
            await self._download(value, value["country"])
            atomic_write_json(self._path(metadata.premium_id), value)
        self._materialize(value, metadata)
