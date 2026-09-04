"""The two supported ways to *use* a secret without revealing it.

Both live in the daemon process: the value is loaded, spent, and dropped,
and only value-free results travel back to the caller.
"""

import os
import re
import subprocess
from pathlib import Path

from . import config, redact, store
from .errors import NotFoundError, ValidationError
from .names import validate_env_var, validate_secret_name

PLACEHOLDER_PATTERN = re.compile(r"\{\{\s*secret:([a-z0-9][a-z0-9._-]{0,63})\s*\}\}")
MAX_OUTPUT_CHARS = 200_000

# Destinations an agent must not be able to reach with a rendered template.
# Writing a private key to ~/.ssh is legitimate; granting yourself login,
# a shell hook or a launch agent is not.
FORBIDDEN_BASENAMES = {
    "authorized_keys", "authorized_keys2", "sudoers", "crontab",
    ".zshrc", ".zshenv", ".zprofile", ".zlogin", ".bashrc", ".bash_profile",
    ".bash_login", ".profile", ".cshrc", ".login", ".hushlogin",
}
FORBIDDEN_PARTS = {"LaunchAgents", "LaunchDaemons", "StartupItems", "init.d",
                   "systemd", "cron.d"}


def _load(names) -> dict:
    """Return {name: value} for every requested secret, or raise NotFoundError."""
    values = {}
    for name in names:
        validate_secret_name(name)
        try:
            values[name] = store.get(name)
        except NotFoundError as exc:
            raise NotFoundError(f"secret '{name}' is not stored yet") from exc
    return values


def _truncate(text: str) -> str:
    """Cap captured output so a runaway command cannot flood the caller."""
    if len(text) <= MAX_OUTPUT_CHARS:
        return text
    return text[:MAX_OUTPUT_CHARS] + "\n[output truncated by sil]"


def _check_destination(target) -> None:
    """Refuse destinations that would turn a file write into code execution."""
    if ".." in target.parts:
        raise ValidationError("path must not contain '..'")
    if target.name in FORBIDDEN_BASENAMES:
        raise ValidationError(f"refusing to write to {target.name}")
    if FORBIDDEN_PARTS.intersection(target.parts):
        raise ValidationError(
            f"refusing to write inside {sorted(FORBIDDEN_PARTS.intersection(target.parts))[0]}")
    if target.is_symlink():
        raise ValidationError("refusing to write through a symlink")


def _check_mode(mode: int) -> int:
    """Refuse any permission bit that would let another account read the secret."""
    if not isinstance(mode, int) or mode & 0o077:
        raise ValidationError(
            "mode must not grant group or other access; use 0o600 or 0o400")
    return mode


def run(command, env_map: dict, *, cwd: str = "", shell: bool = False,
        timeout: float = config.RUN_TIMEOUT_SECONDS) -> dict:
    """Run a command with secrets injected as environment variables.

    `env_map` maps an environment variable name to a stored secret name.
    Output is redacted before it is returned.
    """
    if shell and not isinstance(command, str):
        raise ValidationError("shell mode needs command to be a string")
    if not shell and not (isinstance(command, list) and command):
        raise ValidationError("command must be a non-empty argv list")
    pairs = {validate_env_var(var): validate_secret_name(name)
             for var, name in env_map.items()}
    values = _load(pairs.values())
    environment = dict(os.environ)
    environment.update({var: values[name] for var, name in pairs.items()})
    try:
        completed = subprocess.run(
            command, shell=shell, cwd=cwd or None, env=environment,
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "exit_code": None, "timed_out": True,
            "stdout": "", "stderr": f"timed out after {timeout}s",
            "injected": sorted(pairs), "scrubbed": [],
        }
    except (FileNotFoundError, PermissionError, OSError) as exc:
        raise ValidationError(f"cannot run command: {exc}") from exc
    # Redact first, truncate second: a value straddling the truncation
    # boundary would otherwise survive as an unmatchable fragment.
    stdout = _truncate(redact.redact(completed.stdout, values))
    stderr = _truncate(redact.redact(completed.stderr, values))
    return {
        "exit_code": completed.returncode,
        "timed_out": False,
        "stdout": stdout,
        "stderr": stderr,
        "injected": sorted(pairs),
        "scrubbed": sorted(set(redact.leaks(completed.stdout + completed.stderr,
                                            values))),
    }


def render(template: str) -> tuple:
    """Substitute {{secret:name}} placeholders, returning (text, names)."""
    names = sorted(set(PLACEHOLDER_PATTERN.findall(template)))
    if not names:
        raise ValidationError(
            "template contains no {{secret:name}} placeholder")
    values = _load(names)
    text = PLACEHOLDER_PATTERN.sub(lambda m: values[m.group(1)], template)
    return text, names


def materialize(path: str, template: str, *, mode: int = config.OWNER_ONLY_FILE,
                append: bool = False) -> dict:
    """Write a rendered template to disk with owner-only permissions."""
    if not path:
        raise ValidationError("path is required")
    target = Path(path).expanduser()
    if not target.is_absolute():
        raise ValidationError("path must be absolute")
    _check_mode(mode)
    _check_destination(target)
    text, names = render(template)
    target.parent.mkdir(parents=True, exist_ok=True)
    # O_NOFOLLOW: never write the secret through a symlink someone else planted.
    flags = (os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW
             | (os.O_APPEND if append else os.O_TRUNC))
    try:
        handle = os.open(target, flags, mode)
    except OSError as exc:
        raise ValidationError(f"cannot write to {target}: {exc}") from exc
    with os.fdopen(handle, "a" if append else "w") as stream:
        stream.write(text)
    os.chmod(target, mode)
    return {
        "path": str(target),
        "bytes_written": len(text.encode()),
        "secrets_used": names,
        "mode": oct(mode),
        "appended": append,
    }
