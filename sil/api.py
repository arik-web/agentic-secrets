"""Transport-free API surface. Every method returns value-free JSON data."""

import time

from . import (__version__, browser, config, consume, events, fields,
               notify, pending, store)
from .errors import ConflictError, ValidationError
from .names import clean_label, validate_secret_name


def _as_float(value, field: str, default: float, maximum: float) -> float:
    """Coerce and clamp a numeric field from an untrusted payload."""
    if value is None:
        return default
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{field} must be a number") from exc
    if number < 0:
        raise ValidationError(f"{field} must not be negative")
    return min(number, maximum)


def _as_mode(value) -> int:
    """Coerce a file mode from a payload, accepting '0o600', '600' or 384."""
    if value is None:
        return config.OWNER_ONLY_FILE
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 8)
        except ValueError as exc:
            raise ValidationError(f"mode is not an octal string: {value!r}") from exc
    raise ValidationError("mode must be an octal string or an integer")


class Api:
    """The daemon's behaviour, independent of HTTP."""

    def __init__(self, registry: pending.PendingRegistry | None = None,
                 event_log: events.EventLog | None = None, log=None):
        self.events = event_log or events.EventLog()
        self.log = log
        self.registry = registry or pending.PendingRegistry()
        self.registry._on_settle = self._on_settle
        self.started_at = time.time()

    def _on_settle(self, request) -> None:
        """Publish the settled request and push it to whoever asked to be told."""
        event = self.events.publish(request.public())
        notify.dispatch(request.notify, event, self.log)

    def health(self) -> dict:
        """Return liveness plus the facts a caller needs to trust the daemon."""
        return {
            "ok": True,
            "version": __version__,
            "backend": store.backend_name(),
            "url": config.base_url(),
            "uptime_seconds": round(time.time() - self.started_at, 1),
            "open_requests": len(self.registry.open_requests()),
            "secrets_held": len(store.list_secrets()),
            "event_cursor": self.events.cursor,
        }

    def create_request(self, payload: dict) -> dict:
        """Ask the human for a secret; optionally block until they answer."""
        name = validate_secret_name(payload.get("name"))
        wanted = fields.resolve(name, payload.get("fields"),
                                payload.get("preset"))
        overwrite = bool(payload.get("overwrite", False))
        held = [target for target in fields.secret_names(wanted)
                if store.exists(target)]
        if held and not overwrite and len(held) == len(wanted):
            return {
                "state": "already_stored",
                "name": name,
                "stored": held,
                "detail": (f"{', '.join(held)} already stored; "
                           "pass overwrite=true to replace"),
                "secrets": [store.describe(target) for target in held],
            }
        request = self.registry.create(
            notify=notify.validate(payload.get("notify")),
            fields=wanted,
            name=name,
            purpose=clean_label(payload.get("purpose"), "purpose"),
            hint=clean_label(payload.get("hint"), "hint"),
            target=clean_label(payload.get("target"), "target"),
            requested_by=clean_label(payload.get("requested_by"),
                                     "requested_by", "an agent"),
            ttl=_as_float(payload.get("ttl"), "ttl", config.REQUEST_TTL_SECONDS,
                          config.REQUEST_TTL_SECONDS),
        )
        opened = "skipped"
        if payload.get("open_browser", True):
            opened = browser.open_url(request.url())
        result = {**request.public(), "opened_with": opened}
        wait = _as_float(payload.get("wait"), "wait", config.DEFAULT_WAIT_SECONDS,
                         config.MAX_WAIT_SECONDS)
        if wait:
            return {**self.wait(request.id, wait), "opened_with": opened}
        return result

    def wait(self, request_id: str, seconds) -> dict:
        """Block until the request settles or the wait budget runs out."""
        budget = _as_float(seconds, "wait", config.DEFAULT_WAIT_SECONDS,
                           config.MAX_WAIT_SECONDS)
        request = self.registry.by_id(request_id)
        request.settled.wait(timeout=budget)
        return request.public()

    def request_status(self, request_id: str) -> dict:
        """Return the current state of one request."""
        return self.registry.by_id(request_id).public()

    def cancel_request(self, request_id: str) -> dict:
        """Withdraw a request the agent no longer needs."""
        request = self.registry.by_id(request_id)
        return self.registry.settle(
            request, pending.STATE_CANCELLED,
            detail="cancelled by the requester").public()

    def open_requests(self) -> dict:
        """Return every request still waiting on a human."""
        return {"requests": self.registry.open_requests(),
                "event_cursor": self.events.cursor}

    def read_events(self, since, wait) -> dict:
        """Return settled-request events after `since`, optionally blocking.

        This is the signal for an agent that did not stay blocked on the
        original request: poll it, or long-poll it, from any process.
        """
        cursor = int(_as_float(since, "since", 0, 2 ** 53))
        budget = _as_float(wait, "wait", 0, config.MAX_WAIT_SECONDS)
        found = (self.events.wait(cursor, budget) if budget
                 else self.events.since(cursor))
        return {"events": found,
                "cursor": found[-1]["seq"] if found else cursor,
                "event_cursor": self.events.cursor}

    def submit(self, token: str, values: dict) -> dict:
        """Accept the pasted fields from the web form and store each one."""
        request = self.registry.by_token(token)
        if request.is_expired:
            raise ConflictError("this request timed out; ask the agent to retry")
        entered = self._collect(request, values)
        stored = [store.put(field["secret_name"], value,
                            purpose=request.purpose, target=request.target,
                            requested_by=request.requested_by)
                  for field, value in entered]
        request.stored = [meta["name"] for meta in stored]
        self.registry.settle(
            request, pending.STATE_FULFILLED,
            detail=f"stored {len(stored)} field(s)",
            fingerprint=stored[0]["fingerprint"] if len(stored) == 1 else "")
        return {"name": request.name, "backend": stored[0]["backend"],
                "stored": [{"name": meta["name"],
                            "fingerprint": meta["fingerprint"],
                            "length": meta["length"]} for meta in stored]}

    @staticmethod
    def _collect(request, values: dict) -> list:
        """Pair every field with the value the human typed, or complain."""
        entered = []
        missing = []
        for field in request.fields:
            raw = (values or {}).get(field["name"], "")
            cleaned = raw.strip() if isinstance(raw, str) else ""
            if not cleaned:
                if field["required"]:
                    missing.append(field["label"])
                continue
            entered.append((field, cleaned))
        if missing:
            raise ValidationError(f"still needed: {', '.join(missing)}")
        if not entered:
            raise ValidationError("nothing was pasted")
        return entered

    def decline(self, token: str) -> dict:
        """Record that the human refused this request."""
        request = self.registry.by_token(token)
        return self.registry.settle(
            request, pending.STATE_CANCELLED,
            detail="declined by the human").public()

    def list_secrets(self) -> dict:
        """Return metadata for every known secret."""
        return {"secrets": store.list_secrets(),
                "backend": store.backend_name()}

    def describe_secret(self, name: str) -> dict:
        """Return metadata for one secret."""
        return store.describe(validate_secret_name(name))

    def delete_secret(self, name: str) -> dict:
        """Forget a secret."""
        store.delete(validate_secret_name(name))
        return {"name": name, "deleted": True}

    def run(self, payload: dict) -> dict:
        """Run a command with secrets injected into its environment."""
        env_map = payload.get("env") or {}
        if not isinstance(env_map, dict) or not env_map:
            raise ValidationError("env must map ENV_VAR -> secret name")
        return consume.run(
            payload.get("command"), env_map,
            cwd=payload.get("cwd") or "",
            shell=bool(payload.get("shell", False)),
            timeout=_as_float(payload.get("timeout"), "timeout",
                              config.RUN_TIMEOUT_SECONDS,
                              config.RUN_TIMEOUT_SECONDS),
        )

    def materialize(self, payload: dict) -> dict:
        """Write a rendered template containing secrets to a private file."""
        return consume.materialize(
            payload.get("path"), payload.get("template") or "",
            mode=_as_mode(payload.get("mode")),
            append=bool(payload.get("append", False)),
        )
