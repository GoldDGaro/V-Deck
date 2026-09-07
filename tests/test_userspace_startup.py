from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from vdeck.backends.amneziawg import AmneziaWGBackend
from vdeck.backends.wireguard import WireGuardBackend
from vdeck.models import RuntimeState
from vdeck.runner import CommandResult, OwnedProcess


class UserspaceForegroundContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_awg_and_wg_fallback_request_foreground(self):
        for backend_type in (AmneziaWGBackend, WireGuardBackend):
            with self.subTest(backend=backend_type.__name__):
                runner = SimpleNamespace(
                    is_alive=Mock(return_value=True),
                    exit_code=Mock(return_value=None),
                    start=AsyncMock(return_value=OwnedProcess(12345, "ticks", "/bin/backend", [])),
                    run=AsyncMock(return_value=CommandResult((), 1, "", "kernel unavailable")),
                )
                context = SimpleNamespace(
                    runner=runner,
                    binaries=SimpleNamespace(command=lambda name, *args: [name, *args]),
                    inspector=SimpleNamespace(interface_exists=AsyncMock(return_value=True)),
                    store=SimpleNamespace(save_runtime=Mock(), logger=Mock()),
                )
                backend = backend_type(context)
                backend._socket_identity = Mock(return_value=None)
                backend._uapi_ready = AsyncMock(return_value=True)
                await backend._create_interface("vdeck-12345678", RuntimeState(), Path("unused.log"))
                args, options = runner.start.call_args
                self.assertEqual(args[0], [backend.userspace_name, "--foreground", "vdeck-12345678"])
                self.assertEqual(options["env"]["WG_PROCESS_FOREGROUND"], "1")
