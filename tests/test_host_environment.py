from __future__ import annotations

import os
import unittest
from unittest.mock import AsyncMock, Mock, patch

from vdeck.dns import DnsManager
from vdeck.errors import VDeckError
from vdeck.runner import CommandResult, CommandRunner, OwnedProcess, child_environment


class HostEnvironmentTests(unittest.IsolatedAsyncioTestCase):
    async def test_all_host_commands_restore_original_path_without_mutating_python(self):
        child = Mock(returncode=0, communicate=AsyncMock(return_value=(b"active", b"")))
        inherited = {"LD_LIBRARY_PATH": "/tmp/_MEIdecky/lib", "LD_LIBRARY_PATH_ORIG": "/host/lib"}
        with (
            patch.dict(os.environ, inherited),
            patch("vdeck.runner.asyncio.create_subprocess_exec", AsyncMock(return_value=child)) as spawn,
        ):
            for command in ("systemctl", "resolvectl", "nmcli", "ip", "nft", "ping", "busctl"):
                await CommandRunner().run([command, "--version"])
                environment = spawn.call_args.kwargs["env"]
                self.assertEqual(environment["LD_LIBRARY_PATH"], "/host/lib")
                self.assertEqual(environment["LC_ALL"], "C")
                self.assertNotIn("_MEI", environment["LD_LIBRARY_PATH"])
            self.assertEqual(os.environ["LD_LIBRARY_PATH"], inherited["LD_LIBRARY_PATH"])

    async def test_without_orig_pyinstaller_paths_are_removed_but_host_paths_survive(self):
        for original in (None, "", "/safe/lib"):
            with self.subTest(original=original), patch.dict(os.environ, {}, clear=True):
                os.environ["LD_LIBRARY_PATH"] = os.pathsep.join(("/tmp/_MEI123", "/host/lib"))
                if original is not None:
                    os.environ["LD_LIBRARY_PATH_ORIG"] = original
                result = child_environment()
                self.assertEqual(
                    result.get("LD_LIBRARY_PATH"), {None: "/host/lib", "": None, "/safe/lib": "/safe/lib"}[original]
                )

    async def test_onedir_root_and_preload_are_not_inherited(self):
        with (
            patch.dict(
                os.environ, {"LD_LIBRARY_PATH": "/decky/_internal", "LD_PRELOAD": "/tmp/_MEI123/libx.so"}, clear=True
            ),
            patch("vdeck.runner.sys._MEIPASS", "/decky/_internal", create=True),
        ):
            result = child_environment()
            self.assertNotIn("LD_LIBRARY_PATH", result)
            self.assertNotIn("LD_PRELOAD", result)

    async def test_vpn_binaries_have_an_independent_environment_for_run_and_start(self):
        child = Mock(returncode=0, communicate=AsyncMock(return_value=(b"", b"")))
        with (
            patch.dict(os.environ, {"LD_LIBRARY_PATH": "/tmp/_MEI123", "LD_LIBRARY_PATH_ORIG": "/host/lib"}),
            patch("vdeck.runner.asyncio.create_subprocess_exec", AsyncMock(return_value=child)) as spawn,
        ):
            await CommandRunner().run(["awg", "show"], bundled=True)
            self.assertNotIn("LD_LIBRARY_PATH", spawn.call_args.kwargs["env"])
            child.returncode = None
            child.pid = 42
            with patch("vdeck.runner.inspect_process", return_value=OwnedProcess(42, "1", "/vpn", [])):
                await CommandRunner().start(["amneziawg-go", "--foreground", "vdeck-12345678"], bundled=True)
            self.assertNotIn("LD_LIBRARY_PATH", spawn.call_args.kwargs["env"])

    async def test_loader_error_is_never_an_inactive_service_even_with_check_false(self):
        for check in (False, True):
            child = Mock(
                returncode=127,
                communicate=AsyncMock(
                    return_value=(b"", b"systemctl: symbol lookup error: libsystemd.so: undefined symbol")
                ),
            )
            with patch("vdeck.runner.asyncio.create_subprocess_exec", AsyncMock(return_value=child)):
                with self.assertRaises(VDeckError) as raised:
                    await CommandRunner().run(["systemctl", "is-active", "NetworkManager"], check=check)
                self.assertEqual(raised.exception.code, "COMMAND_LOADER_FAILED")
                self.assertIn("exit_code=127", raised.exception.details)

    async def test_dns_probe_does_not_convert_loader_error_to_inactive(self):
        error = VDeckError("COMMAND_LOADER_FAILED", "Loader failed")
        manager = DnsManager(Mock(run=AsyncMock(side_effect=error)))
        with self.assertRaises(VDeckError) as raised:
            await manager.environment()
        self.assertEqual(raised.exception.code, "COMMAND_LOADER_FAILED")
        manager.runner.run = AsyncMock(
            return_value=CommandResult(("systemctl",), 127, "", "error while loading shared libraries: libx.so")
        )
        with self.assertRaises(VDeckError) as raised:
            await manager.environment()
        self.assertEqual(raised.exception.code, "COMMAND_LOADER_FAILED")

    async def test_real_inactive_service_remains_supported(self):
        result = CommandResult(("systemctl",), 3, "inactive", "")
        manager = DnsManager(Mock(run=AsyncMock(return_value=result)))
        returned = await manager._command(["systemctl", "is-active", "systemd-resolved"])
        self.assertEqual(returned.returncode, 3)
