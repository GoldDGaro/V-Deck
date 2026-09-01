"""OpenVPN backend using its structured management interface."""

from __future__ import annotations

import asyncio
import secrets
import socket
from contextlib import suppress
from pathlib import Path
from typing import Any

from ..errors import VDeckError
from ..models import ConnectionMetadata, RuntimeState
from ..network import interface_name
from ..runner import OwnedProcess, process_matches
from ..security import secure_write
from .base import VPNBackend


def _reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        return int(server.getsockname()[1])


def _management_request(port: int, password: str, command: str, timeout: float = 3) -> str:
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as client:
        client.settimeout(timeout)
        received = client.recv(4096).decode(errors="replace")
        if "ENTER PASSWORD" in received:
            client.sendall((password + "\n").encode())
            received += client.recv(4096).decode(errors="replace")
        client.sendall((command + "\n").encode())
        chunks: list[str] = []
        while True:
            try:
                chunk = client.recv(8192)
            except TimeoutError:
                break
            if not chunk:
                break
            text = chunk.decode(errors="replace")
            chunks.append(text)
            if "\nEND\n" in "".join(chunks) or "SUCCESS:" in text or "ERROR:" in text:
                break
        client.sendall(b"quit\n")
        return "".join(chunks)


class OpenVPNBackend(VPNBackend):
    protocol_id = "openvpn"

    async def _request(self, runtime: RuntimeState, command: str) -> str:
        management = runtime.process.get("management", {})
        password_file = Path(str(management["password_file"]))
        password = password_file.read_text(encoding="utf-8").strip()
        return await asyncio.to_thread(_management_request, int(management["port"]), password, command)

    async def start(self, metadata: ConnectionMetadata, runtime: RuntimeState) -> dict[str, Any]:
        directory = self.connection_dir(metadata)
        credentials = directory / "credentials"
        if metadata.requires_username_password and not (credentials / "auth").is_file():
            raise VDeckError("CREDENTIALS_REQUIRED", "OpenVPN username and password are required")
        if metadata.requires_key_passphrase and not (credentials / "passphrase").is_file():
            raise VDeckError("PASSPHRASE_REQUIRED", "The OpenVPN private key requires a passphrase")
        interface = interface_name(metadata.id)
        runtime.interface = interface
        management_dir = self.context.store.runtime / metadata.id
        management_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        port = _reserve_port()
        management_password = secrets.token_urlsafe(24)
        password_file = management_dir / "management-password"
        secure_write(password_file, (management_password + "\n").encode())
        args = self.context.binaries.command(
            "openvpn",
            "--config",
            str(directory / "config"),
            "--cd",
            str(directory),
            "--dev",
            interface,
            "--dev-type",
            "tun",
            "--management",
            "127.0.0.1",
            str(port),
            str(password_file),
            "--management-query-passwords",
            "--auth-nocache",
            "--script-security",
            "1",
            "--writepid",
            str(management_dir / "openvpn.pid"),
            "--verb",
            "3",
        )
        if (credentials / "auth").is_file():
            args += ["--auth-user-pass", str(credentials / "auth")]
        if (credentials / "passphrase").is_file():
            args += ["--askpass", str(credentials / "passphrase")]
        log_path = self.context.store.logs / f"{metadata.id}.log"
        try:
            owned = await self.context.runner.start(args, cwd=directory, stdout_path=log_path)
        except VDeckError as exc:
            if metadata.requires_key_passphrase:
                with suppress(OSError):
                    startup_log = log_path.read_text(encoding="utf-8", errors="replace")[-20_000:].lower()
                    if "cannot load private key" in startup_log or "bad decrypt" in startup_log:
                        raise VDeckError(
                            "PASSPHRASE_INVALID", "OpenVPN could not unlock the encrypted private key"
                        ) from exc
            raise
        runtime.process = owned.to_dict()
        runtime.process["management"] = {"port": port, "password_file": str(password_file)}
        self.context.store.save_runtime(runtime)
        try:
            deadline = asyncio.get_running_loop().time() + 30
            while asyncio.get_running_loop().time() < deadline:
                if not process_matches(owned):
                    if metadata.requires_key_passphrase:
                        with suppress(OSError):
                            startup_log = log_path.read_text(encoding="utf-8", errors="replace")[-20_000:].lower()
                            if "cannot load private key" in startup_log or "bad decrypt" in startup_log:
                                raise VDeckError(
                                    "PASSPHRASE_INVALID", "OpenVPN could not unlock the encrypted private key"
                                )
                    raise VDeckError("OPENVPN_EXITED", "OpenVPN exited before the tunnel was established")
                try:
                    state = await self._request(runtime, "state")
                except (OSError, KeyError, ValueError):
                    await asyncio.sleep(0.25)
                    continue
                lowered_state = state.lower()
                if (
                    "auth_failed" in lowered_state
                    or "auth-failure" in lowered_state
                    or "verification failed" in lowered_state
                ):
                    raise VDeckError("OPENVPN_AUTH_FAILED", "OpenVPN authentication failed")
                if ",CONNECTED,SUCCESS," in state:
                    info = self.context.store.parsed_runtime_info(metadata.id)
                    full = any(str(item) in {"0.0.0.0/0", "::/0"} for item in info.get("allowed_ips", []))
                    await self.context.dns.apply(interface, list(info.get("dns_servers", [])), full)
                    return await self.status(metadata, runtime)
                await asyncio.sleep(0.5)
            raise VDeckError("OPENVPN_CONNECT_TIMEOUT", "OpenVPN did not confirm a connected state")
        except Exception:
            await self.stop(metadata, runtime)
            raise

    async def stop(self, metadata: ConnectionMetadata | None, runtime: RuntimeState) -> None:
        if runtime.process:
            with suppress(OSError, KeyError, ValueError):
                await self._request(runtime, "signal SIGTERM")
            with suppress(KeyError, TypeError, ValueError):
                await self.context.runner.stop(OwnedProcess.from_dict(runtime.process))
        await self.context.dns.cleanup(runtime.interface)
        removed_interface = runtime.interface
        interface_left = False
        if runtime.interface:
            await self.context.runner.run(["ip", "link", "delete", "dev", runtime.interface], check=False, timeout=5)
            interface_left = await self.context.inspector.interface_exists(runtime.interface)
        management = runtime.process.get("management", {})
        password_file = Path(str(management.get("password_file", "")))
        if password_file.name == "management-password":
            password_file.unlink(missing_ok=True)
        runtime.process = {}
        runtime.interface = None
        runtime.owned_routes = []
        self.context.store.save_runtime(runtime)
        if interface_left:
            raise VDeckError("INTERFACE_STOP_FAILED", f"Unable to remove VPN interface {removed_interface}")

    async def status(self, metadata: ConnectionMetadata, runtime: RuntimeState) -> dict[str, Any]:
        try:
            state = await self._request(runtime, "state")
            status = await self._request(runtime, "status 3")
        except (OSError, KeyError, ValueError):
            return {"connected": False, "tunnel": False, "interface": runtime.interface}
        connected = ",CONNECTED,SUCCESS," in state
        rx = tx = 0
        for line in status.splitlines():
            if line.startswith("BYTECOUNT,"):
                values = line.split(",")
                if len(values) >= 3:
                    rx, tx = int(values[1]), int(values[2])
            elif line.startswith("TCP/UDP read bytes,"):
                rx = int(line.rsplit(",", 1)[-1] or 0)
            elif line.startswith("TCP/UDP write bytes,"):
                tx = int(line.rsplit(",", 1)[-1] or 0)
        return {
            "connected": connected,
            "tunnel": connected,
            "interface": runtime.interface,
            "management_state": "CONNECTED" if connected else "CONNECTING",
            "rx_bytes": rx,
            "tx_bytes": tx,
        }
