"""Start, stop and supervise the local broker process."""

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

from . import auth, config
from .api import Api
from .server import SecretServer

START_TIMEOUT_SECONDS = 10.0
POLL_SECONDS = 0.15


def probe() -> dict | None:
    """Return the daemon's health payload, or None when it is not running."""
    try:
        with urllib.request.urlopen(f"{config.base_url()}/healthz", timeout=2) as res:
            return json.loads(res.read())
    except (urllib.error.URLError, OSError, json.JSONDecodeError, TimeoutError):
        return None


def is_running() -> bool:
    """Return True when a daemon answers on the configured port."""
    return probe() is not None


def serve() -> None:
    """Run the broker in the foreground until interrupted."""
    config.ensure_home()
    auth.read_token()
    server = SecretServer(log_path=config.LOG_FILE)
    _write_runtime(os.getpid())
    server.log(f"listening on {config.base_url()}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        config.RUNTIME_FILE.unlink(missing_ok=True)


def _write_runtime(pid: int) -> None:
    """Record the running pid and port for `sil status` and `sil stop`."""
    config.ensure_home()
    config.RUNTIME_FILE.write_text(json.dumps({
        "pid": pid, "port": config.port(), "started_at": time.time(),
    }))
    config.RUNTIME_FILE.chmod(config.OWNER_ONLY_FILE)


def ensure_running() -> dict:
    """Start the daemon if needed and return its health payload."""
    health = probe()
    if health:
        return health
    config.ensure_home()
    log = open(config.LOG_FILE, "a")
    subprocess.Popen(
        [sys.executable, "-m", "sil.daemon", "serve"],
        cwd=str(_package_parent()), stdout=log, stderr=log,
        stdin=subprocess.DEVNULL, start_new_session=True,
        env={**os.environ, "PYTHONPATH": str(_package_parent())},
    )
    deadline = time.time() + START_TIMEOUT_SECONDS
    while time.time() < deadline:
        health = probe()
        if health:
            return health
        time.sleep(POLL_SECONDS)
    raise RuntimeError(
        f"daemon did not come up within {START_TIMEOUT_SECONDS}s; "
        f"see {config.LOG_FILE}")


def _package_parent():
    """Return the directory that contains the `sil` package."""
    from pathlib import Path
    return Path(__file__).resolve().parent.parent


def stop() -> bool:
    """Ask a running daemon to exit. Return True when one was stopped."""
    if not is_running():
        return False
    request = urllib.request.Request(
        f"{config.base_url()}/api/shutdown", method="POST", data=b"{}",
        headers={"Authorization": f"Bearer {auth.read_token()}",
                 "Content-Type": "application/json"})
    try:
        urllib.request.urlopen(request, timeout=5).read()
    except (urllib.error.URLError, OSError, TimeoutError):
        return False
    config.RUNTIME_FILE.unlink(missing_ok=True)
    return True


def main(argv=None) -> int:
    """Entry point for `python -m sil.daemon`."""
    parser = argparse.ArgumentParser(prog="sil.daemon")
    parser.add_argument("action", choices=["serve", "stop", "status"])
    args = parser.parse_args(argv)
    if args.action == "serve":
        serve()
        return 0
    if args.action == "stop":
        print("stopped" if stop() else "not running")
        return 0
    health = probe()
    print(json.dumps(health, indent=2) if health else "not running")
    return 0 if health else 1


if __name__ == "__main__":
    sys.exit(main())
