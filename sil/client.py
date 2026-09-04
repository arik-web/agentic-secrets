"""Thin HTTP client used by the CLI and the MCP server."""

import json
import urllib.error
import urllib.request

from . import auth, config, daemon
from .errors import DaemonUnavailableError, SilError

DEFAULT_TIMEOUT = 30.0


class Client:
    """Talks to the local broker, starting it on demand."""

    def __init__(self, autostart: bool = True):
        self.autostart = autostart

    def _ensure(self) -> None:
        """Make sure a daemon is listening before the first call."""
        if not self.autostart:
            return
        try:
            daemon.ensure_running()
        except RuntimeError as exc:
            raise DaemonUnavailableError(str(exc)) from exc

    def call(self, method: str, path: str, payload: dict | None = None,
             timeout: float = DEFAULT_TIMEOUT) -> dict:
        """Perform one API call and return the decoded JSON body."""
        self._ensure()
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(
            f"{config.base_url()}{path}", data=data, method=method,
            headers={"Authorization": f"Bearer {auth.read_token()}",
                     "Content-Type": "application/json",
                     "Host": f"{config.HOST}:{config.port()}"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            try:
                message = json.loads(body).get("error", body)
            except json.JSONDecodeError:
                message = body
            error = SilError(message)
            error.status = exc.code
            raise error from exc
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise DaemonUnavailableError(
                f"cannot reach the broker at {config.base_url()}: {exc}") from exc

    # --- convenience wrappers ---------------------------------------

    def health(self) -> dict:
        """Return daemon health."""
        return self.call("GET", "/healthz")

    def request_secret(self, **payload) -> dict:
        """Ask the human for a secret."""
        wait = float(payload.get("wait", config.DEFAULT_WAIT_SECONDS))
        return self.call("POST", "/api/request", payload, timeout=wait + 20)

    def request_status(self, request_id: str) -> dict:
        """Return the state of one request."""
        return self.call("GET", f"/api/request/{request_id}")

    def cancel_request(self, request_id: str) -> dict:
        """Withdraw a request."""
        return self.call("POST", f"/api/request/{request_id}/cancel", {})

    def wait_for(self, request_id: str, seconds: float) -> dict:
        """Block until a request settles."""
        return self.call("POST", f"/api/request/{request_id}/wait",
                         {"wait": seconds}, timeout=seconds + 20)

    def events(self, since: int = 0, wait: float = 0) -> dict:
        """Read settled-request events, optionally long-polling for the next."""
        return self.call("GET", f"/api/events?since={int(since)}&wait={wait}",
                         timeout=float(wait) + 20)

    def list_secrets(self) -> dict:
        """List stored secret metadata."""
        return self.call("GET", "/api/secrets")

    def describe(self, name: str) -> dict:
        """Describe one stored secret."""
        return self.call("GET", f"/api/secrets/{name}")

    def delete(self, name: str) -> dict:
        """Delete one stored secret."""
        return self.call("DELETE", f"/api/secrets/{name}")

    def run(self, **payload) -> dict:
        """Run a command with secrets in its environment."""
        timeout = float(payload.get("timeout", config.RUN_TIMEOUT_SECONDS))
        return self.call("POST", "/api/run", payload, timeout=timeout + 20)

    def materialize(self, **payload) -> dict:
        """Write a rendered secret template to a file."""
        return self.call("POST", "/api/materialize", payload)
