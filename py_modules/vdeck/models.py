"""Persistent and runtime data models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Protocol(str, Enum):
    AMNEZIAWG = "amneziawg"
    WIREGUARD = "wireguard"
    OPENVPN = "openvpn"


class ConnectionState(str, Enum):
    DISCONNECTED = "DISCONNECTED"
    CONNECTING = "CONNECTING"
    CONNECTED = "CONNECTED"
    DISCONNECTING = "DISCONNECTING"
    RECOVERING = "RECOVERING"
    ERROR = "ERROR"


class DesiredState(str, Enum):
    OFF = "OFF"
    ON = "ON"


class CheckStatus(str, Enum):
    OK = "OK"
    WARNING = "WARNING"
    ERROR = "ERROR"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"


@dataclass
class ConnectionMetadata:
    id: str
    display_name: str
    protocol: str
    created_at: str
    updated_at: str
    last_used_at: str | None = None
    last_ping_ms: int | None = None
    source_format: str = ""
    requires_username_password: bool = False
    requires_key_passphrase: bool = False
    migration_source: str | None = None
    import_error: str | None = None

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ConnectionMetadata:
        known = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{key: val for key, val in value.items() if key in known})

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PersistentState:
    schema_version: int = 1
    desired_state: str = DesiredState.OFF.value
    active_connection_id: str | None = None
    last_active_connection_id: str | None = None
    auto_connect: bool = False
    kill_switch: bool = False
    kill_switch_warning_seen: bool = False
    language: str = "automatic"

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> PersistentState:
        known = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{key: val for key, val in value.items() if key in known})

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RuntimeState:
    state: str = ConnectionState.DISCONNECTED.value
    connection_id: str | None = None
    interface: str | None = None
    started_at: str | None = None
    established_once: bool = False
    error_code: str | None = None
    error_message: str | None = None
    recovery_attempt: int = 0
    boot_id: str | None = None
    process: dict[str, Any] = field(default_factory=dict)
    owned_routes: list[dict[str, Any]] = field(default_factory=list)
    endpoint_cache: dict[str, list[str]] = field(default_factory=dict)
    firewall_active: bool = False
    ipv6_guard: bool = False
    stage: str | None = None

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> RuntimeState:
        known = {f.name for f in cls.__dataclass_fields__.values()}
        normalized = {key: val for key, val in value.items() if key in known}
        raw_cache = normalized.get("endpoint_cache")
        normalized["endpoint_cache"] = (
            {
                str(endpoint): [str(address) for address in addresses]
                for endpoint, addresses in raw_cache.items()
                if isinstance(addresses, list)
            }
            if isinstance(raw_cache, dict)
            else {}
        )
        if not isinstance(normalized.get("boot_id"), str | type(None)):
            normalized["boot_id"] = None
        return cls(**normalized)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
