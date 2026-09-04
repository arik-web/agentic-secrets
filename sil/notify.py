"""Push a settled request out to whoever asked for it.

Two shapes, both value-free: run a local command, or POST to a loopback URL.
Neither can carry the secret - only its name, state and fingerprint.
"""

import json
import subprocess
import threading
import urllib.error
import urllib.parse
import urllib.request

from .errors import ValidationError

COMMAND_TIMEOUT_SECONDS = 20
WEBHOOK_TIMEOUT_SECONDS = 10
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}
ENV_PREFIX = "SIL_"


def validate(spec) -> dict:
    """Validate a notify spec from an untrusted payload."""
    if spec is None:
        return {}
    if not isinstance(spec, dict):
        raise ValidationError("notify must be an object")
    clean = {}
    command = spec.get("command")
    if command is not None:
        if not isinstance(command, list) or not command or \
                not all(isinstance(part, str) for part in command):
            raise ValidationError("notify.command must be a non-empty argv array")
        clean["command"] = command
    webhook = spec.get("webhook")
    if webhook is not None:
        clean["webhook"] = _validate_webhook(webhook)
    if not clean:
        raise ValidationError("notify needs a command or a webhook")
    return clean


def _validate_webhook(url) -> str:
    """Only loopback URLs are allowed: a webhook must not become an exfil path."""
    if not isinstance(url, str):
        raise ValidationError("notify.webhook must be a string")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "http" or parsed.hostname not in LOOPBACK_HOSTS:
        raise ValidationError(
            "notify.webhook must be an http:// URL on 127.0.0.1 or localhost")
    return url


def dispatch(spec: dict, event: dict, log=None) -> None:
    """Fire the notification in the background; never raise into the paste path."""
    if not spec:
        return
    thread = threading.Thread(target=_deliver, args=(spec, event, log),
                              daemon=True)
    thread.start()


def _deliver(spec: dict, event: dict, log) -> None:
    """Run the configured notifications, recording failures only."""
    if spec.get("command"):
        _run_command(spec["command"], event, log)
    if spec.get("webhook"):
        _post_webhook(spec["webhook"], event, log)


def _environment(event: dict) -> dict:
    """Build the SIL_* variables handed to a notify command."""
    import os
    extra = {f"{ENV_PREFIX}{key.upper()}": str(value)
             for key, value in event.items()}
    return {**os.environ, **extra}


def _run_command(command: list, event: dict, log) -> None:
    """Run the caller's command with the event in its environment."""
    try:
        subprocess.run(command, env=_environment(event), capture_output=True,
                       timeout=COMMAND_TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        _note(log, f"notify command failed: {type(exc).__name__}")


def _post_webhook(url: str, event: dict, log) -> None:
    """POST the event as JSON to a loopback listener."""
    request = urllib.request.Request(
        url, data=json.dumps(event).encode(), method="POST",
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=WEBHOOK_TIMEOUT_SECONDS):
            pass
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        _note(log, f"notify webhook failed: {type(exc).__name__}")


def _note(log, message: str) -> None:
    """Record a delivery failure if the daemon gave us a logger."""
    if callable(log):
        log(message)
