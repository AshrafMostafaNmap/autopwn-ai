"""Run allowlisted recon binaries safely: argv only (no shell), bounded time and
output, vault placeholders injected locally and redacted in what gets logged.
"""
from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from functools import lru_cache

from ..govern.vault import Vault

# Curated, non-destructive recon/detection binaries. Nothing else may run.
ALLOWED_BINARIES = frozenset({
    # network / host discovery
    "nmap", "masscan",
    # web recon / fuzzing / templates
    "httpx", "subfinder", "amass", "nuclei", "ffuf", "whatweb", "katana", "gau", "waybackurls", "naabu",
    # dns / tls / transport
    "dig", "host", "dnsx", "openssl", "curl",
    # mobile static
    "aapt", "aapt2", "apktool", "jadx",
})

_MAX_OUTPUT = 1_000_000          # cap captured stdout/stderr (1 MB) to bound memory


@lru_cache(maxsize=128)
def which(binary: str) -> str | None:
    """Absolute path of `binary` if installed (AutoPwn's bin dir, ~/go/bin, then
    PATH), else None. Cached; `which.cache_clear()` after installing."""
    from .installer import resolve
    return resolve(binary)


def available(binary: str) -> bool:
    return which(binary) is not None


@dataclass
class CommandResult:
    ok: bool
    binary: str
    argv_redacted: list[str]         # safe to log/store (secrets → placeholders)
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_ms: float = 0.0
    timed_out: bool = False
    error: str = ""
    skipped: bool = False            # binary not installed

    @classmethod
    def unavailable(cls, binary: str) -> CommandResult:
        return cls(ok=False, binary=binary, argv_redacted=[binary],
                   error=f"'{binary}' is not installed", skipped=True)

    @classmethod
    def refused(cls, binary: str, reason: str) -> CommandResult:
        return cls(ok=False, binary=binary, argv_redacted=[binary], error=reason)


def run(
    binary: str,
    args: list[str],
    *,
    timeout: float = 120.0,
    input_text: str | None = None,
    vault: Vault | None = None,
    cwd: str | None = None,
) -> CommandResult:
    """Run an allowlisted binary safely. `args` may contain vault placeholders;
    their real values are injected locally just before exec and never logged."""
    if binary not in ALLOWED_BINARIES:
        return CommandResult.refused(binary, f"'{binary}' is not in the allowlist")
    path = which(binary)
    if path is None:
        return CommandResult.unavailable(binary)

    # argv for logging = redacted; argv for exec = real values injected locally.
    argv_display = [binary, *args]
    if vault is not None:
        argv_display = [vault.redact(a) for a in argv_display]
        exec_args = [vault.inject(a) for a in args]
    else:
        exec_args = list(args)

    started = time.time()
    try:
        proc = subprocess.run(
            [path, *exec_args],
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return CommandResult(ok=False, binary=binary, argv_redacted=argv_display,
                             duration_ms=round((time.time() - started) * 1000, 1),
                             timed_out=True, error=f"timed out after {timeout}s")
    except Exception as e:
        return CommandResult(ok=False, binary=binary, argv_redacted=argv_display,
                             error=f"{type(e).__name__}: {e}")

    return CommandResult(
        ok=proc.returncode == 0,
        binary=binary,
        argv_redacted=argv_display,
        returncode=proc.returncode,
        stdout=(proc.stdout or "")[:_MAX_OUTPUT],
        stderr=(proc.stderr or "")[:_MAX_OUTPUT],
        duration_ms=round((time.time() - started) * 1000, 1),
    )
