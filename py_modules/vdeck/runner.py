"""Safe command and process execution abstractions."""

from __future__ import annotations

import asyncio
import os
import signal
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .errors import VDeckError
from .security import sanitize


@dataclass
class CommandResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


@dataclass
class OwnedProcess:
    pid: int
    start_ticks: str
    executable: str
    args: list[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "pid": self.pid,
            "start_ticks": self.start_ticks,
            "executable": self.executable,
            "args": self.args,
        }

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> OwnedProcess:
        pid_value = value["pid"]
        args_value = value.get("args", [])
        if not isinstance(pid_value, int | str) or not isinstance(args_value, list):
            raise ValueError("Invalid owned-process record")
        return cls(
            pid=int(pid_value),
            start_ticks=str(value["start_ticks"]),
            executable=str(value["executable"]),
            args=[str(item) for item in args_value],
        )


class CommandRunner:
    async def run(
        self,
        args: Sequence[str],
        *,
        input_text: str | None = None,
        timeout: float = 15,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        check: bool = True,
    ) -> CommandResult:
        if not args or any(not isinstance(item, str) or "\x00" in item for item in args):
            raise VDeckError("COMMAND_INVALID", "Invalid command arguments")
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)
        process = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE if input_text is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=merged_env,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(None if input_text is None else input_text.encode("utf-8")), timeout
            )
        except asyncio.TimeoutError as exc:
            process.kill()
            await process.wait()
            raise VDeckError("COMMAND_TIMEOUT", f"Command timed out: {Path(args[0]).name}") from exc
        result = CommandResult(
            tuple(args), process.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace")
        )
        if check and result.returncode != 0:
            message = sanitize(result.stderr or result.stdout).strip()[-800:]
            raise VDeckError("COMMAND_FAILED", f"{Path(args[0]).name} failed", message)
        return result

    async def start(
        self,
        args: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        stdout_path: Path | None = None,
    ) -> OwnedProcess:
        if not args:
            raise VDeckError("COMMAND_INVALID", "Empty process command")
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)
        stream = stdout_path.open("ab", buffering=0) if stdout_path else asyncio.subprocess.DEVNULL
        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=stream,
                stderr=stream,
                cwd=cwd,
                env=merged_env,
                start_new_session=True,
            )
        finally:
            if stdout_path and hasattr(stream, "close"):
                stream.close()
        await asyncio.sleep(0.05)
        if process.returncode is not None:
            raise VDeckError("PROCESS_START_FAILED", f"{Path(args[0]).name} exited during startup")
        return inspect_process(process.pid, expected_executable=str(Path(args[0]).resolve()), args=list(args))

    async def stop(self, owned: OwnedProcess, grace_seconds: float = 5) -> None:
        if not process_matches(owned):
            return
        try:
            os.kill(owned.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        deadline = asyncio.get_running_loop().time() + grace_seconds
        while asyncio.get_running_loop().time() < deadline:
            if not process_matches(owned):
                return
            await asyncio.sleep(0.1)
        if process_matches(owned):
            os.kill(owned.pid, getattr(signal, "SIGKILL", signal.SIGTERM))
            deadline = asyncio.get_running_loop().time() + 2
            while asyncio.get_running_loop().time() < deadline:
                if not process_matches(owned):
                    return
                await asyncio.sleep(0.05)
            if process_matches(owned):
                raise VDeckError("PROCESS_STOP_FAILED", f"Unable to stop {Path(owned.executable).name}")


def _proc_fields(pid: int) -> tuple[str, str]:
    stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    end = stat.rfind(")")
    fields = stat[end + 2 :].split()
    start_ticks = fields[19]
    executable = str(Path(f"/proc/{pid}/exe").resolve(strict=True))
    return start_ticks, executable


def inspect_process(pid: int, *, expected_executable: str, args: list[str]) -> OwnedProcess:
    if os.name == "nt":
        return OwnedProcess(pid, "windows", expected_executable, args)
    try:
        start_ticks, executable = _proc_fields(pid)
    except OSError as exc:
        raise VDeckError("PROCESS_INSPECTION_FAILED", "Unable to verify the started process") from exc
    return OwnedProcess(pid, start_ticks, executable, args)


def process_matches(owned: OwnedProcess) -> bool:
    if os.name == "nt":
        try:
            os.kill(owned.pid, 0)
            return True
        except OSError:
            return False
    try:
        start_ticks, executable = _proc_fields(owned.pid)
        return start_ticks == owned.start_ticks and Path(executable).resolve() == Path(owned.executable).resolve()
    except OSError:
        return False
