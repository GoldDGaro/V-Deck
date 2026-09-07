from __future__ import annotations

import asyncio
import logging
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from vdeck.errors import VDeckError
from vdeck.runner import CommandRunner


class RealChildProcessTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.logger = logging.getLogger("vdeck-real-child-test")
        self.runner = CommandRunner(self.logger)
        self.owned = []

    async def asyncTearDown(self):
        for owned in self.owned:
            await self.runner.stop(owned, grace_seconds=0.5)

    async def test_live_child_identity_is_saved_before_start_returns_and_reaped_on_stop(self):
        owned = await self.runner.start(
            [sys.executable, "-c", "import time; time.sleep(60)"], on_started=self.owned.append
        )
        self.assertEqual(self.owned, [owned])
        self.assertTrue(self.runner.is_alive(owned))
        child = self.runner._processes[owned.pid][1]
        await self.runner.stop(owned, grace_seconds=0.5)
        self.assertIsNotNone(child.returncode)
        self.assertFalse(self.runner.is_alive(owned))
        self.assertNotIn(owned.pid, self.runner._processes)

    async def test_zero_and_nonzero_early_exits_are_logged_and_reaped(self):
        async def startup_grace(seconds):
            # Synchronize on actual child completion, not a CPU-load-dependent
            # 300 ms guess. This tests the early-exit branch deterministically.
            child = self.runner._processes[self.owned[-1].pid][1]
            await asyncio.wait_for(child.wait(), 15)

        for code in (0, 7):
            with (
                self.subTest(code=code),
                patch("vdeck.runner.asyncio.sleep", startup_grace),
                self.assertLogs(self.logger, level="INFO") as captured,
            ):
                with self.assertRaises(VDeckError) as raised:
                    await self.runner.start(
                        [sys.executable, "-c", f"raise SystemExit({code})"], on_started=self.owned.append
                    )
                self.assertEqual(raised.exception.code, "PROCESS_START_FAILED")
                self.assertIn(f"exit_code={code}", raised.exception.details)
                self.assertIn(f"exit_code={code}", "\n".join(captured.output))
                self.assertFalse(self.runner.is_alive(self.owned[-1]))

    async def test_cancel_run_kills_and_reaps_command(self):
        create = asyncio.create_subprocess_exec
        created = asyncio.Event()
        children = []

        async def capture(*args, **kwargs):
            child = await create(*args, **kwargs)
            children.append(child)
            created.set()
            return child

        with patch("vdeck.runner.asyncio.create_subprocess_exec", capture):
            task = asyncio.create_task(self.runner.run([sys.executable, "-c", "import time; time.sleep(60)"]))
            await asyncio.wait_for(created.wait(), 15)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertIsNotNone(children[0].returncode)

    async def test_cancel_during_startup_does_not_orphan_child(self):
        def cancel(owned):
            self.owned.append(owned)
            asyncio.current_task().cancel()

        task = asyncio.create_task(
            self.runner.start([sys.executable, "-c", "import time; time.sleep(60)"], on_started=cancel)
        )
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertFalse(self.runner.is_alive(self.owned[0]))
        self.assertIsNotNone(self.runner.exit_code(self.owned[0]))

    async def test_wrong_identity_cannot_stop_live_child(self):
        owned = await self.runner.start(
            [sys.executable, "-c", "import time; time.sleep(60)"], on_started=self.owned.append
        )
        await self.runner.stop(replace(owned, start_ticks="different-process"), grace_seconds=0.1)
        self.assertTrue(self.runner.is_alive(owned))

    async def test_failed_pid_persistence_reaps_the_new_child(self):
        def fail_to_persist(owned):
            self.owned.append(owned)
            raise OSError("Synthetic persistence failure")

        with self.assertRaises(OSError):
            await self.runner.start([sys.executable, "-c", "import time; time.sleep(60)"], on_started=fail_to_persist)
        self.assertFalse(self.runner.is_alive(self.owned[0]))

    async def test_failed_config_command_never_logs_unlabelled_key_or_stdin(self):
        child = Mock(
            returncode=1, communicate=AsyncMock(return_value=(b"dump-raw-private-key", b"invalid key: raw-key"))
        )
        with (
            patch("vdeck.runner.asyncio.create_subprocess_exec", AsyncMock(return_value=child)) as spawn,
            self.assertLogs(self.logger, level="WARNING") as captured,
            self.assertRaises(VDeckError) as raised,
        ):
            await self.runner.run(["awg", "setconf", "vdeck-12345678", "/dev/stdin"], input_text="config-secret")
        self.assertEqual(spawn.call_args.kwargs["env"]["LC_ALL"], "C")
        text = "\n".join(captured.output) + str(raised.exception.details)
        self.assertIn("exit_code=1", text)
        self.assertIn("output withheld", text)
        for secret in ("dump-raw-private-key", "raw-key", "config-secret"):
            self.assertNotIn(secret, text)

    async def test_native_stdout_and_stderr_never_write_config_or_server_secrets(self):
        with tempfile.TemporaryDirectory() as directory, self.assertLogs(self.logger, level="INFO") as captured:
            path = Path(directory) / "native.log"
            script = (
                "import sys,time; print('AUTH_FAILED,arbitrary-unlabelled-password', flush=True); "
                "print('Permission denied PrivateKey=top-secret', file=sys.stderr, flush=True); "
                "print('naked-private-key-material', flush=True); time.sleep(0.3)"
            )
            owned = await self.runner.start([sys.executable, "-c", script], stdout_path=path)
            self.owned.append(owned)
            await asyncio.wait_for(self.runner._processes[owned.pid][1].wait(), 10)
            await self.runner.stop(owned)
            text = path.read_text() + "\n".join(captured.output)
            self.assertIn("auth_failed", text)
            self.assertIn("permission denied", text)
            for secret in ("arbitrary-unlabelled-password", "top-secret", "naked-private-key-material"):
                self.assertNotIn(secret, text)
            self.assertFalse(self.runner._output_tasks)

    async def test_network_command_failure_logs_exit_and_sanitized_stderr(self):
        child = Mock(
            returncode=2, communicate=AsyncMock(return_value=(b"unlogged-output", b"route failed PrivateKey=secret"))
        )
        with (
            patch("vdeck.runner.asyncio.create_subprocess_exec", AsyncMock(return_value=child)),
            self.assertLogs(self.logger, level="WARNING") as captured,
            self.assertRaises(VDeckError),
        ):
            await self.runner.run(["ip", "-4", "route", "add", "10.0.0.0/24", "dev", "vdeck-12345678"])
        text = "\n".join(captured.output)
        self.assertIn("exit_code=2", text)
        self.assertIn("route failed", text)
        self.assertNotIn("secret", text)
        self.assertNotIn("unlogged-output", text)

    async def test_native_error_flood_is_coalesced_without_losing_count(self):
        stream = asyncio.StreamReader()
        stream.feed_data(b"network is unreachable\n" * 1500)
        stream.feed_eof()
        process = Mock(stdout=stream, pid=1234)
        with tempfile.TemporaryDirectory() as directory, self.assertLogs(self.logger, level="INFO") as captured:
            await self.runner._drain_output(process, "amneziawg-go", Path(directory) / "native.log")
            output = "\n".join(captured.output)
            self.assertIn("repeated=1499", output)
            self.assertEqual(len(captured.output), 2)


if __name__ == "__main__":
    unittest.main()
