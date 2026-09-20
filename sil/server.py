"""HTTP plumbing around `Api`. Binds loopback only and never logs a value."""

import json
import re
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import auth, config, pages, store
from .api import Api
from .errors import SilError, ValidationError

REQUEST_ID_ROUTE = re.compile(r"^/api/request/([0-9a-f]{16})(/wait|/cancel)?$")
SECRET_ROUTE = re.compile(r"^/api/secrets/([a-z0-9][a-z0-9._-]{0,63})$")
PASTE_ROUTE = re.compile(r"^/paste/([A-Za-z0-9_-]{16,128})$")


class Handler(BaseHTTPRequestHandler):
    """Route one request. `server.api` holds the shared Api instance."""

    server_version = "sil"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        """Log method and path only - never a query string or body."""
        self.server.log(f"{self.command} {self.path.split('?')[0]} {args[1] if len(args) > 1 else ''}")

    # --- helpers -----------------------------------------------------

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        """Write a complete response with hardening headers."""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; "
                         "script-src 'unsafe-inline'; form-action 'self'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict) -> None:
        """Send a JSON response."""
        self._send(status, json.dumps(payload).encode(), "application/json")

    def _html(self, status: int, markup: str) -> None:
        """Send an HTML response."""
        self._send(status, markup.encode(), "text/html; charset=utf-8")

    def _body(self) -> dict:
        """Parse and return the JSON request body."""
        length = int(self.headers.get("Content-Length") or 0)
        if length > config.MAX_BODY_BYTES:
            raise ValidationError("request body is too large")
        if not length:
            return {}
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"body is not valid JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise ValidationError("body must be a JSON object")
        return payload

    def _form(self) -> dict:
        """Parse and return a urlencoded form body."""
        length = int(self.headers.get("Content-Length") or 0)
        if length > config.MAX_BODY_BYTES:
            raise ValidationError("form body is too large")
        raw = self.rfile.read(length).decode("utf-8", "replace")
        parsed = urllib.parse.parse_qs(raw, keep_blank_values=True)
        return {key: values[0] for key, values in parsed.items()}

    def _host_ok(self) -> bool:
        """Reject DNS-rebinding attempts by pinning the Host header."""
        host = (self.headers.get("Host") or "").lower()
        allowed = {f"{config.HOST}:{config.port()}", f"localhost:{config.port()}"}
        return host in allowed

    def _authed(self) -> bool:
        """Return True when the caller presented the API token."""
        return auth.check_header(self.headers.get("Authorization", ""))

    # --- dispatch ----------------------------------------------------

    def do_GET(self):
        """Handle every GET route."""
        self._dispatch("GET")

    def do_POST(self):
        """Handle every POST route."""
        self._dispatch("POST")

    def do_DELETE(self):
        """Handle every DELETE route."""
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        """Resolve the route and translate SilError into a status code."""
        path = urllib.parse.urlparse(self.path).path
        if not self._host_ok():
            self._json(421, {"error": "unexpected Host header"})
            return
        try:
            if path.startswith("/api/") and not self._authed():
                self._json(401, {"error": "missing or bad bearer token"})
                return
            handled = self._route(method, path)
            if not handled:
                self._json(404, {"error": f"no route for {method} {path}"})
        except SilError as exc:
            self._fail(exc.status, str(exc), path)
        except Exception as exc:  # noqa: BLE001 - never leak a traceback
            self.server.log(f"unhandled error on {path}: {type(exc).__name__}")
            self._fail(500, f"internal error: {type(exc).__name__}", path)

    def _fail(self, status: int, message: str, path: str) -> None:
        """Render an error as HTML for browser routes, JSON otherwise."""
        if path.startswith("/paste"):
            self._html(status, pages.result("Cannot continue", message, ok=False))
        else:
            self._json(status, {"error": message})

    def _route(self, method: str, path: str) -> bool:
        """Run the matching route. Return False when nothing matched."""
        api = self.server.api
        if method == "GET" and path == "/healthz":
            self._json(200, api.health())
            return True
        if method == "GET" and path == "/":
            self._html(200, pages.console(api.registry.open_requests(),
                                          store.backend_name(),
                                          len(store.list_secrets())))
            return True
        if paste := PASTE_ROUTE.match(path):
            return self._route_paste(method, paste.group(1))
        return self._route_api(method, path)

    def _route_paste(self, method: str, token: str) -> bool:
        """Serve and accept the human-facing paste form."""
        api = self.server.api
        if method == "GET":
            request = api.registry.by_token(token)
            self._html(200, pages.paste_form({**request.public(),
                                              "token": token},
                                             store.backend_label()))
            return True
        if method == "POST":
            form = self._form()
            if form.get("action") == "cancel":
                api.decline(token)
                self._html(200, pages.result(
                    "Declined", "The agent was told you said no.", ok=False))
                return True
            values = {key[len("field."):]: value
                      for key, value in form.items() if key.startswith("field.")}
            stored = api.submit(token, values)
            names = ", ".join(entry["name"] for entry in stored["stored"])
            self._html(200, pages.result(
                "Saved", f"{names} - now in your {stored['backend']}."))
            return True
        return False

    def _route_api(self, method: str, path: str) -> bool:
        """Run the authenticated JSON routes."""
        api = self.server.api
        if method == "POST" and path == "/api/request":
            self._json(200, api.create_request(self._body()))
            return True
        if method == "GET" and path == "/api/requests":
            self._json(200, api.open_requests())
            return True
        if method == "GET" and path == "/api/events":
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            self._json(200, api.read_events(query.get("since", ["0"])[0],
                                            query.get("wait", ["0"])[0]))
            return True
        if match := REQUEST_ID_ROUTE.match(path):
            return self._route_request(method, match.group(1), match.group(2))
        if method == "GET" and path == "/api/secrets":
            self._json(200, api.list_secrets())
            return True
        if match := SECRET_ROUTE.match(path):
            name = match.group(1)
            if method == "GET":
                self._json(200, api.describe_secret(name))
                return True
            if method == "DELETE":
                self._json(200, api.delete_secret(name))
                return True
            return False
        if method == "POST" and path == "/api/run":
            self._json(200, api.run(self._body()))
            return True
        if method == "POST" and path == "/api/materialize":
            self._json(200, api.materialize(self._body()))
            return True
        if method == "POST" and path == "/api/shutdown":
            self._json(200, {"stopping": True})
            self.server.request_stop()
            return True
        return False

    def _route_request(self, method: str, request_id: str, suffix) -> bool:
        """Handle the /api/request/<id>[...] family."""
        api = self.server.api
        if method == "GET" and not suffix:
            self._json(200, api.request_status(request_id))
            return True
        if method == "POST" and suffix == "/wait":
            self._json(200, api.wait(request_id, self._body().get("wait")))
            return True
        if method == "POST" and suffix == "/cancel":
            self._json(200, api.cancel_request(request_id))
            return True
        return False


class SecretServer(ThreadingHTTPServer):
    """Loopback HTTP server holding the shared Api instance."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, api: Api | None = None, port: int | None = None,
                 log_path=None):
        super().__init__((config.HOST, port if port is not None else config.port()),
                         Handler)
        self.log_path = log_path
        self.api = api or Api(log=self.log)

    def log(self, line: str) -> None:
        """Append one line to the daemon log; drop it if that fails."""
        if not self.log_path:
            return
        try:
            with open(self.log_path, "a") as handle:
                handle.write(line + "\n")
        except OSError:
            pass

    def request_stop(self) -> None:
        """Ask the serving loop to exit without blocking this handler."""
        import threading
        threading.Thread(target=self.shutdown, daemon=True).start()
