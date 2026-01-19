import logging
import os
import re
import resource
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import psutil

logger = logging.getLogger("fuzzer")

# ---------------------------------------------------------------------------- #
#                               Helper Functions                               #
# ---------------------------------------------------------------------------- #


# build a table mapping all non-printable characters to None
LINE_BREAK_CHARACTERS = set(["\n", "\r"])
NO_PRINT_TRANS_TABLE = {
    i: None
    for i in range(0, sys.maxunicode + 1)
    if not chr(i).isprintable() and not chr(i) in LINE_BREAK_CHARACTERS
}


# ---------------------------------------------------------------------------- #


def make_printable(data: str) -> str:
    """Replace non-printable characters in a string."""
    return data.translate(NO_PRINT_TRANS_TABLE)


# ---------------------------------------------------------------------------- #


def make_utf8(data: bytes | None) -> str:
    return "" if data is None else data.decode("utf-8", errors="ignore")


# ---------------------------------------------------------------------------- #


def stdout_and_stderr_to_printable(
    stdout_bytes: bytes | None, stderr_bytes: bytes | None
) -> tuple[str, str]:
    stdout, stdin = [make_printable(make_utf8(x)) for x in [stdout_bytes, stderr_bytes]]
    return (stdout, stdin)


# ---------------------------------------------------------------------------- #


def generate_preexec_fn_memory_limit(limit_memory: int | None) -> Callable[[], Any] | None:
    if limit_memory is None:
        return None
    max_virtual_memory = limit_memory * 1024 * 1024  # limit_memory in MB
    return lambda: resource.setrlimit(
        resource.RLIMIT_AS, (max_virtual_memory, resource.RLIM_INFINITY)
    )


# ---------------------------------------------------------------------------- #


def remove_ansi_escape_sequences(string: str) -> str:
    ansi_escape_pattern = re.compile(r"(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]")
    return ansi_escape_pattern.sub("", string)


# ---------------------------------------------------------------------------- #
#                            Execution Status Class                            #
# ---------------------------------------------------------------------------- #


@dataclass
class ExecStatus:
    command: str
    stdout: str
    stderr: str
    stdout_raw: bytes | None
    stderr_raw: bytes | None
    returncode: int
    delta_time: float
    is_timeout: bool = False
    env: dict[str, str] | None = None
    cwd: Path | None = None

    def is_failure(self):
        return not self.returncode == 0

    def is_failure_strict(self):
        return self.is_failure() or len(self.stderr) > 0

    def __str__(self):
        return f"""
command   : {self.command}
returncode: {self.returncode}
stdout:
{self.stdout}
stderr:
{self.stderr}
time: {self.delta_time}s
"""

    def to_script(self, ignore_cwd: bool = False) -> str:
        script_lines = ["#!/usr/bin/env bash", ""]
        if self.cwd and ignore_cwd is False:
            script_lines.append(f"cd {self.cwd.absolute()}")
        env_prefix = ""
        if self.env:
            env_prefix = (" ".join(f"{key}='{val}'" for key, val in self.env.items())) + " "
        script_lines.append(f"{env_prefix}{self.command}")
        script_lines.append("")
        return "\n".join(script_lines)


# ---------------------------------------------------------------------------- #
#                       Core Command Invocation Function                       #
# ---------------------------------------------------------------------------- #


def invoke_command(
    command: list[str],
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: float | None = None,
    memory: int | None = None,
    is_log_debug: bool = True,
    explicit_clean_zombies=False,
    abort_on_stderr_regexes: list[str] | None = None,
) -> ExecStatus:

    # ------------------------- debug initial information ------------------------ #

    logger.info("run command: " + " ".join(command))
    logger.debug(f"  - cwd     : {cwd}")
    logger.debug(f"  - env     : {env}")
    logger.debug(f"  - timeout : {timeout}")
    logger.debug(f"  - memory  : {memory}")

    # ------------ combine current environment with passed environment ----------- #

    combined_env = None
    if env is not None:
        combined_env = os.environ.copy()
        for key in env:
            combined_env[key] = env[key]

    # ----------------- preprocessing for zombie process cleanup ----------------- #

    pre_call_active_children = None
    if explicit_clean_zombies:
        pre_call_active_children = set(p.pid for p in psutil.Process().children(recursive=True))

    # ------------------------------ call subprocess ----------------------------- #

    start_time = time.time()
    is_timeout = False
    if not abort_on_stderr_regexes:
        try:
            complete_proc = subprocess.run(
                command,
                close_fds=True,
                shell=False,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=-1,
                cwd=cwd,
                preexec_fn=generate_preexec_fn_memory_limit(memory),
                timeout=timeout,
                env=combined_env,
            )
            stdout_bytes, stderr_bytes = complete_proc.stdout, complete_proc.stderr
            returncode = complete_proc.returncode
        except subprocess.TimeoutExpired as timeErr:
            stdout_bytes, stderr_bytes = timeErr.stdout, timeErr.stderr
            returncode = 124  # timeout return status
            is_timeout = True
    else:
        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []
        abort_patterns = [re.compile(p) for p in abort_on_stderr_regexes]
        abort_event = threading.Event()
        abort_timestamp: list[float | None] = [None]

        def _read_stream(stream, chunks: list[bytes], *, check_abort: bool):
            try:
                for raw_line in iter(stream.readline, b""):
                    chunks.append(raw_line)
                    if check_abort and (not abort_event.is_set()):
                        line = remove_ansi_escape_sequences(make_utf8(raw_line))
                        if any(p.search(line) for p in abort_patterns):
                            abort_event.set()
                            abort_timestamp[0] = time.time()
            finally:
                try:
                    stream.close()
                except Exception:
                    pass

        # Create a new process group so we can terminate children (rustc/cc1plus) promptly.
        mem_preexec = generate_preexec_fn_memory_limit(memory)

        def _preexec():
            os.setsid()
            if mem_preexec is not None:
                mem_preexec()

        proc = subprocess.Popen(
            command,
            close_fds=True,
            shell=False,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            cwd=cwd,
            preexec_fn=_preexec,
            env=combined_env,
        )
        assert proc.stdout is not None
        assert proc.stderr is not None

        stdout_thread = threading.Thread(target=_read_stream, args=(proc.stdout, stdout_chunks), kwargs={"check_abort": False})
        stderr_thread = threading.Thread(target=_read_stream, args=(proc.stderr, stderr_chunks), kwargs={"check_abort": True})
        stdout_thread.start()
        stderr_thread.start()

        killed = False
        kill_started: float | None = None
        try:
            while True:
                # Give the compiler a brief grace period to print full diagnostics after
                # the first error line, then terminate the whole process group.
                if abort_event.is_set() and (not killed):
                    ts = abort_timestamp[0]
                    if ts is not None and (time.time() - ts) >= 1.0:
                        try:
                            os.killpg(proc.pid, signal.SIGTERM)
                        except Exception:
                            proc.terminate()
                        killed = True
                        kill_started = time.time()

                try:
                    returncode = proc.wait(timeout=0.2)
                    break
                except subprocess.TimeoutExpired:
                    if killed and kill_started is not None and (time.time() - kill_started) > 2.0:
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except Exception:
                            proc.kill()
                        returncode = proc.wait(timeout=2)
                        break

                    if timeout is not None and (time.time() - start_time) > timeout:
                        is_timeout = True
                        try:
                            os.killpg(proc.pid, signal.SIGTERM)
                        except Exception:
                            proc.terminate()
                        try:
                            returncode = proc.wait(timeout=2)
                        except Exception:
                            try:
                                os.killpg(proc.pid, signal.SIGKILL)
                            except Exception:
                                proc.kill()
                            returncode = 124
                        break
        finally:
            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)

        stdout_bytes = b"".join(stdout_chunks)
        stderr_bytes = b"".join(stderr_chunks)
        if abort_event.is_set() and returncode == 0:
            returncode = 1

    end_time = time.time()
    delta_time = end_time - start_time

    # ------------------------------ process output ------------------------------ #

    stdout, stderr = stdout_and_stderr_to_printable(stdout_bytes, stderr_bytes)
    command_as_str = " ".join(command)

    # --------------------------- debug process output --------------------------- #

    logger.info(f"  => exit {returncode}")
    if is_log_debug:
        logger.debug("========== START STDOUT ==========")
        logger.debug(stdout)
        logger.debug("=========== END STDOUT ===========")

        logger.debug("========== START STDERR ==========")
        logger.debug(stderr)
        logger.debug("=========== END STDERR ===========")

    # ---------------------- build execute status and return --------------------- #

    status = ExecStatus(
        command_as_str,
        stdout,
        stderr,
        stdout_bytes,
        stderr_bytes,
        returncode,
        delta_time,
        is_timeout,
        env,
        cwd,
    )

    # ----------------- postprocessing for zombie process cleanup ---------------- #

    if explicit_clean_zombies:
        assert pre_call_active_children is not None, "unexpected value of child process list"

        post_call_active_children = psutil.Process().children(recursive=True)
        possible_zombies = [
            p for p in post_call_active_children if p.pid not in pre_call_active_children
        ]

        for possible_zombie in possible_zombies:
            z_pid = possible_zombie.pid
            logger.debug(f"possible zombie detected, waiting for {z_pid} ...")
            try:
                if possible_zombie.status() == psutil.STATUS_ZOMBIE:
                    possible_zombie.wait()
                elif possible_zombie.is_running():
                    possible_zombie.terminate()
                    possible_zombie.wait(timeout=5)
            except (psutil.NoSuchProcess, psutil.TimeoutExpired):
                logger.error(f"unable to clean up possible zombie {z_pid}")

    return status
