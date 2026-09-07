"""Safe command and process execution abstractions."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import signal
import sys
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .errors import VDeckError
from .security import sanitize, secure_write


def native_output_summary(raw: bytes) -> str:
    """Native output is untrusted: even AUTH_FAILED reasons can echo passwords.

    Emit only recognized literal diagnostics, not arbitrary server/config text.
    Exit status, stage and Python traceback are logged separately.
    """
    lowered = raw.lower()
    known = (
        "auth_failed",
        "auth-failure",
        "cannot load private key",
        "bad decrypt",
        "options error",
        "unrecognized option",
        "permission denied",
        "operation not permitted",
        "no such file or directory",
        "address already in use",
        "cannot allocate memory",
        "network is unreachable",
        "no route to host",
        "connection refused",
        "connection reset",
        "connection timed out",
        "unsupported",
        "failed to create tun",
        "failed to create uapi",
        "failed to open tun",
        "failed to configure",
        "tls error",
        "tls handshake failed",
        "certificate verify failed",
        "verify error",
        "initialization sequence completed",
        "exiting due to fatal error",
        "sigterm",
        "sigint",
        "error while loading shared libraries",
        "symbol lookup error",
    )
    return "; ".join(token for token in known if token.encode() in lowered) or "NATIVE_OUTPUT_WITHHELD"


def child_environment(overrides: Mapping[str, str] | None = None, *, bundled: bool = False) -> dict[str, str]:
    """Keep Decky's frozen Python libraries out of both host and VPN children.

    Host programs recover their pre-PyInstaller loader path. Our independently
    built VPN executables do not use either Decky's or the host override libs.
    Never mutate os.environ: Python still needs its own frozen environment.
    """
    result = os.environ.copy()
    bundle_root = str(getattr(sys, "_MEIPASS", "")).replace("\\", "/").rstrip("/")

    def clean_paths(value: str) -> str:
        def external(part: str) -> bool:
            normalized = part.replace("\\", "/")
            return bool(part) and not (
                re.search(r"(?:^|/)_MEI[^/]*(?:/|$)", normalized)
                or bundle_root
                and (normalized == bundle_root or normalized.startswith(bundle_root + "/"))
            )

        return os.pathsep.join(part for part in value.split(os.pathsep) if external(part))

    for key in ("LD_LIBRARY_PATH", "LIBPATH"):
        original = result.pop(key + "_ORIG", None)
        value = "" if bundled else original if original is not None else result.get(key, "")
        cleaned = clean_paths(value)
        if cleaned:
            result[key] = cleaned
        else:
            result.pop(key, None)
    if bundled:
        result.pop("LD_PRELOAD", None)
    for key in ("PATH", "LD_PRELOAD"):
        if key in result:
            cleaned = clean_paths(result[key])
            if cleaned:
                result[key] = cleaned
            else:
                result.pop(key, None)
    if overrides:
        result.update(overrides)
    # Explicit flags may not accidentally reintroduce the frozen loader paths.
    for key in ("LD_LIBRARY_PATH", "LIBPATH", "LD_PRELOAD", "PATH"):
        if key in result:
            cleaned = clean_paths(result[key])
            if cleaned:
                result[key] = cleaned
            else:
                result.pop(key, None)
    result["LC_ALL"] = "C"
    return result


@dataclass
class CommandResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


def check_loader_error(result: CommandResult) -> None:
    """Loader failure is not an inactive service or a missing network object."""
    if result.returncode and re.search(
        r"error while loading shared libraries|symbol lookup error|"
        r"version [`'\"].*not found|cannot open shared object file",
        result.stderr,
        re.IGNORECASE,
    ):
        raise VDeckError(
            "COMMAND_LOADER_FAILED",
            "A system or VPN executable could not load its libraries; see technical log",
            f"binary={Path(result.args[0]).name} exit_code={result.returncode} loader failure",
        )


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
    def __init__(self, logger: logging.Logger | None = None):
        self.logger = logger or logging.getLogger(__name__)
        self._processes: dict[int, tuple[OwnedProcess, asyncio.subprocess.Process]] = {}
        self._output_tasks: dict[int, asyncio.Task[None]] = {}

    async def _drain_output(self, process: asyncio.subprocess.Process, binary: str, path: Path) -> None:
        handler = RotatingFileHandler(path, maxBytes=128 * 1024, backupCount=1, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        pending = b""
        last_summary = ""
        repeated = 0
        last_emit = 0.0

        def emit(summary: str) -> None:
            self.logger.info("native output binary=%s pid=%s stderr_summary=%s", binary, process.pid, summary)
            handler.emit(logging.LogRecord(binary, logging.INFO, "", 0, summary, (), None))

        def record(raw: bytes) -> None:
            nonlocal last_summary, repeated, last_emit
            summary = native_output_summary(raw)
            now = asyncio.get_running_loop().time()
            if summary == last_summary and now - last_emit < 5:
                repeated += 1
                return
            if repeated:
                emit(f"{last_summary}; repeated={repeated}")
                repeated = 0
            emit(summary)
            last_summary, last_emit = summary, now

        try:
            assert process.stdout is not None
            while chunk := await process.stdout.read(4096):
                pending += chunk
                while b"\n" in pending or len(pending) >= 8192:
                    raw, separator, rest = pending.partition(b"\n")
                    pending = rest if separator else b""
                    record(raw)
            if pending:
                record(pending)
        finally:
            if repeated:
                emit(f"{last_summary}; repeated={repeated}")
            handler.close()

    async def _finish_output(self, pid: int) -> None:
        task = self._output_tasks.pop(pid, None)
        if task:
            try:
                await asyncio.wait_for(task, 2)
            except (Exception, asyncio.CancelledError) as exc:
                self.logger.warning("native output reader stopped pid=%s exception=%s", pid, type(exc).__name__)

    def is_alive(self, owned: OwnedProcess) -> bool:
        tracked = self._processes.get(owned.pid)
        if tracked:
            record, process = tracked
            return record == owned and process.returncode is None and (os.name == "nt" or process_matches(owned))
        return process_matches(owned)

    def exit_code(self, owned: OwnedProcess) -> int | None:
        tracked = self._processes.get(owned.pid)
        return tracked[1].returncode if tracked and tracked[0] == owned else None

    async def run(
        self,
        args: Sequence[str],
        *,
        input_text: str | None = None,
        timeout: float = 15,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        check: bool = True,
        bundled: bool = False,
    ) -> CommandResult:
        if not args or any(not isinstance(item, str) or "\x00" in item for item in args):
            raise VDeckError("COMMAND_INVALID", "Invalid command arguments")
        merged_env = child_environment(env, bundled=bundled)
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
        except (asyncio.TimeoutError, asyncio.CancelledError) as exc:
            if process.returncode is None:
                process.kill()
            await process.wait()
            if isinstance(exc, asyncio.CancelledError):
                raise
            self.logger.warning("command timed out binary=%s timeout=%s", Path(args[0]).name, timeout)
            raise VDeckError("COMMAND_TIMEOUT", f"Command timed out: {Path(args[0]).name}") from exc
        result = CommandResult(
            tuple(args), process.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace")
        )
        if result.returncode != 0:
            binary = Path(args[0]).name
            # wg/awg setconf may echo a malformed raw key; dump stdout contains
            # keys without labels. Never expose their output or config stdin.
            safe_commands = {"ip", "nft", "ping", "nmcli", "resolvectl", "systemctl", "busctl"}
            message = sanitize(result.stderr).strip()[-800:] if binary in safe_commands else "output withheld"
            self.logger.log(
                logging.WARNING,
                "command failed binary=%s exit_code=%d stderr=%s",
                binary,
                result.returncode,
                message,
            )
            check_loader_error(result)
            if check:
                raise VDeckError("COMMAND_FAILED", f"{binary} failed", f"exit_code={result.returncode} {message}")
        return result

    async def start(
        self,
        args: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        stdout_path: Path | None = None,
        on_started: Callable[[OwnedProcess], None] | None = None,
        bundled: bool = False,
    ) -> OwnedProcess:
        if not args or any(not isinstance(item, str) or "\x00" in item for item in args):
            raise VDeckError("COMMAND_INVALID", "Invalid process command")
        merged_env = child_environment(env, bundled=bundled)
        if stdout_path:
            # Truncate old raw logs; only classified output may reach disk now.
            secure_write(stdout_path, b"")
        process = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE if stdout_path else asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.STDOUT if stdout_path else asyncio.subprocess.DEVNULL,
            cwd=cwd,
            env=merged_env,
            start_new_session=True,
        )
        if stdout_path:
            self._output_tasks[process.pid] = asyncio.create_task(
                self._drain_output(process, Path(args[0]).name, stdout_path)
            )
        try:
            owned = inspect_process(process.pid, expected_executable=str(Path(args[0]).resolve()), args=list(args))
            self._processes[owned.pid] = (owned, process)
            # Persist the exact child identity before the startup grace period.
            # Otherwise a crash/cancellation in this window leaves no cleanup record.
            if on_started:
                on_started(owned)
            await asyncio.sleep(0.05)
            if process.returncode is not None:
                raise VDeckError("PROCESS_START_FAILED", f"{Path(args[0]).name} exited during startup")
            return owned
        except BaseException as exc:
            if isinstance(exc, VDeckError) and exc.code == "PROCESS_INSPECTION_FAILED":
                # Let the child watcher publish an exit that raced /proc inspection.
                with suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(asyncio.shield(process.wait()), 0.05)
            exited_before_cleanup = process.returncode is not None
            # Reap even a very early exit; never leave a just-spawned child behind
            # if inspection, persistence, or the caller is cancelled.
            if process.returncode is None:
                with suppress(ProcessLookupError):
                    process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), 2)
                except asyncio.TimeoutError:
                    with suppress(ProcessLookupError):
                        process.kill()
                    await process.wait()
            else:
                await process.wait()
            await self._finish_output(process.pid)
            self.logger.info(
                "process exited binary=%s pid=%s exit_code=%s reason=%s",
                Path(args[0]).name,
                process.pid,
                process.returncode,
                exc.code if isinstance(exc, VDeckError) else type(exc).__name__,
            )
            if on_started is None:
                self._processes.pop(process.pid, None)
            if isinstance(exc, VDeckError) and (
                exc.code == "PROCESS_START_FAILED"
                or (exc.code == "PROCESS_INSPECTION_FAILED" and exited_before_cleanup)
            ):
                raise VDeckError(
                    "PROCESS_START_FAILED",
                    f"{Path(args[0]).name} exited during startup",
                    f"pid={process.pid} exit_code={process.returncode}",
                ) from exc
            raise

    async def stop(self, owned: OwnedProcess, grace_seconds: float = 5) -> None:
        tracked = self._processes.get(owned.pid)
        if tracked and tracked[0] == owned:
            process = tracked[1]
            if process.returncode is None and self.is_alive(owned):
                with suppress(ProcessLookupError):
                    process.terminate()
            try:
                await asyncio.wait_for(asyncio.shield(process.wait()), grace_seconds)
            except asyncio.TimeoutError as exc:
                if not self.is_alive(owned):
                    raise VDeckError("PROCESS_STOP_FAILED", "Process identity changed; refusing to signal it") from exc
                with suppress(ProcessLookupError):
                    process.kill()
                await asyncio.wait_for(process.wait(), 2)
            self.logger.info(
                "process stopped binary=%s pid=%s exit_code=%s",
                Path(owned.executable).name,
                owned.pid,
                process.returncode,
            )
            self._processes.pop(owned.pid, None)
            await self._finish_output(owned.pid)
            return
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
    if Path(executable).resolve() != Path(expected_executable).resolve():
        raise VDeckError("PROCESS_INSPECTION_FAILED", "Started executable does not match the requested binary")
    return OwnedProcess(pid, start_ticks, executable, args)


def process_matches(owned: OwnedProcess) -> bool:
    if os.name == "nt":
        # Windows test children are checked through their retained subprocess
        # handle. os.kill(pid, 0) is NOT a harmless liveness probe on Windows.
        return False
    try:
        start_ticks, executable = _proc_fields(owned.pid)
        return start_ticks == owned.start_ticks and Path(executable).resolve() == Path(owned.executable).resolve()
    except OSError:
        return False
