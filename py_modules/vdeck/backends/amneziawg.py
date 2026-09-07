"""AmneziaWG 3.1 userspace backend."""

from pathlib import Path

from .wireguard import WireGuardBackend


class AmneziaWGBackend(WireGuardBackend):
    protocol_id = "amneziawg"
    tool_name = "awg"
    userspace_name = "amneziawg-go"
    force_userspace = True
    uapi_directory = Path("/var/run/amneziawg")
