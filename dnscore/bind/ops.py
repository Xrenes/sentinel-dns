"""Run BIND's tools with fixed argument lists and install generated files without ever leaving a broken one live."""
from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path

from ..config import BindLayout

Runner = Callable[[Sequence[str], float], "subprocess.CompletedProcess[str]"]
COMMAND_TIMEOUT = 30.0
FILE_MODE = 0o644  # named reads these through its group; nothing in them is secret


class BindError(Exception):
    """stage: "check" (a BIND tool rejected the file), "reload" (named did not apply it) or "query"."""

    def __init__(self, stage: str, message: str, output: str = "") -> None:
        super().__init__(message)
        self.stage = stage
        self.output = output


def run_command(args: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
    """Run a BIND tool: a fixed argument list (never a shell string) with a time limit."""
    return subprocess.run(list(args), capture_output=True, text=True, timeout=timeout, check=False)


def _combined_output(result: subprocess.CompletedProcess[str]) -> str:
    return "\n".join(part.strip() for part in (result.stdout or "", result.stderr or "") if part.strip())


def run_tool(runner: Runner, args: Sequence[str], *, stage: str, failure: str,
             timeout: float = COMMAND_TIMEOUT) -> str:
    """Run a tool and return its output; raise BindError(stage) carrying the tool's own message on failure."""
    try:
        result = runner(args, timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise BindError(stage, f"{failure}: {error}") from None
    output = _combined_output(result)
    if result.returncode != 0:
        raise BindError(stage, f"{failure}: {output or f'exit code {result.returncode}'}", output)
    return output


def rndc_command(layout: BindLayout, *command: str) -> list[str]:
    extra = ["-c", str(layout.rndc_conf)] if layout.rndc_conf else []
    return [layout.rndc, *extra, *command]


def write_text(path: Path, text: str) -> None:
    """Write a whole file readable by named (run.py's umask 077 would otherwise hide it from group bind)."""
    path.write_text(text, encoding="utf-8", newline="\n")
    os.chmod(path, FILE_MODE)


def candidate_path(path: Path) -> Path:
    return path.with_name(path.name + ".new")


def is_current(path: Path, text: str) -> bool:
    return path.exists() and path.read_text(encoding="utf-8") == text


def swap_in(candidate: Path, path: Path) -> None:
    """Replace `path` atomically with `candidate`, keeping the previous version as <name>.bak."""
    if path.exists():
        shutil.copy2(path, path.with_name(path.name + ".bak"))
    os.replace(candidate, path)


def install_file(path: Path, text: str, *, check: Callable[[Path], object]) -> bool:
    """Validate `text` as a candidate file, then swap it in. False when the file already holds this text.

    A failed check leaves the live file untouched and re-raises.
    """
    if is_current(path, text):
        return False
    candidate = candidate_path(path)
    write_text(candidate, text)
    try:
        check(candidate)
    except Exception:
        candidate.unlink(missing_ok=True)
        raise
    swap_in(candidate, path)
    return True
