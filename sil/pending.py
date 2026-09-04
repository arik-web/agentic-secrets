"""In-memory registry of secrets the daemon is currently asking a human for.

Pending requests never touch disk: an unanswered request holds no secret, and
an answered one is written straight through to the store.
"""

import secrets as pysecrets
import threading
import time

from . import config
from .errors import ConflictError, NotFoundError

STATE_PENDING = "pending"
STATE_FULFILLED = "fulfilled"
STATE_CANCELLED = "cancelled"
STATE_EXPIRED = "expired"


class PendingRequest:
    """One outstanding ask for a human to paste a value."""

    def __init__(self, name: str, purpose: str, hint: str, target: str,
                 requested_by: str, ttl: float, notify: dict | None = None,
                 fields: list | None = None):
        self.id = pysecrets.token_hex(8)
        self.token = pysecrets.token_urlsafe(32)
        self.name = name
        self.purpose = purpose
        self.hint = hint
        self.target = target
        self.requested_by = requested_by
        self.notify = notify or {}
        self.fields = fields or []
        self.created_at = time.time()
        self.expires_at = self.created_at + ttl
        self.state = STATE_PENDING
        self.detail = ""
        self.fingerprint = ""
        self.stored = []
        self.settled = threading.Event()

    @property
    def is_expired(self) -> bool:
        """Return True once the request has outlived its TTL."""
        return self.state == STATE_PENDING and time.time() > self.expires_at

    def url(self) -> str:
        """Return the single-use URL a human opens to answer this request."""
        return f"{config.base_url()}/paste/{self.token}"

    def public(self) -> dict:
        """Return a value-free view safe to hand to any caller."""
        state = STATE_EXPIRED if self.is_expired else self.state
        return {
            "request_id": self.id,
            "name": self.name,
            "purpose": self.purpose,
            "hint": self.hint,
            "target": self.target,
            "requested_by": self.requested_by,
            "state": state,
            "detail": self.detail,
            "fingerprint": self.fingerprint,
            "fields": [{key: field[key] for key in
                        ("name", "label", "hint", "kind", "required",
                         "secret_name")}
                       for field in self.fields],
            "stored": list(self.stored),
            "url": self.url() if state == STATE_PENDING else "",
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }


class PendingRegistry:
    """Thread-safe collection of pending requests, keyed by id and by token."""

    def __init__(self, on_settle=None):
        self._lock = threading.Lock()
        self._by_id = {}
        self._by_token = {}
        self._on_settle = on_settle

    def create(self, *, name: str, purpose: str = "", hint: str = "",
               target: str = "", requested_by: str = "", notify: dict = None,
               fields: list = None,
               ttl: float = config.REQUEST_TTL_SECONDS) -> PendingRequest:
        """Register and return a new pending request."""
        request = PendingRequest(name, purpose, hint, target, requested_by, ttl,
                                 notify, fields)
        with self._lock:
            expired = self._sweep_locked()
            self._by_id[request.id] = request
            self._by_token[request.token] = request
        self._announce(expired)
        return request

    def by_id(self, request_id: str) -> PendingRequest:
        """Return a request by id or raise NotFoundError."""
        with self._lock:
            request = self._by_id.get(request_id)
        if request is None:
            raise NotFoundError(f"no request {request_id}")
        return request

    def by_token(self, token: str) -> PendingRequest:
        """Return a request by its single-use token or raise NotFoundError."""
        with self._lock:
            request = self._by_token.get(token)
        if request is None:
            raise NotFoundError("this paste link is unknown or already used")
        return request

    def open_requests(self) -> list:
        """Return the public view of every still-pending request."""
        with self._lock:
            expired = self._sweep_locked()
            open_now = [r.public() for r in self._by_id.values()
                        if r.state == STATE_PENDING]
        self._announce(expired)
        return open_now

    def settle(self, request: PendingRequest, state: str, *, detail: str = "",
               fingerprint: str = "") -> PendingRequest:
        """Move a request out of the pending state and wake its waiters."""
        with self._lock:
            if request.state != STATE_PENDING:
                raise ConflictError(
                    f"request {request.id} is already {request.state}")
            request.state = state
            request.detail = detail
            request.fingerprint = fingerprint
            self._by_token.pop(request.token, None)
        request.settled.set()
        self._announce([request])
        return request

    def _announce(self, settled: list) -> None:
        """Hand every newly settled request to the daemon's settle hook."""
        if not self._on_settle:
            return
        for request in settled:
            self._on_settle(request)

    def _sweep_locked(self) -> list:
        """Expire stale requests and return them. Caller must hold the lock."""
        expired = []
        for request in list(self._by_id.values()):
            if request.is_expired:
                request.state = STATE_EXPIRED
                request.detail = "timed out waiting for a human"
                self._by_token.pop(request.token, None)
                request.settled.set()
                expired.append(request)
            if request.state != STATE_PENDING and \
                    time.time() - request.created_at > config.REQUEST_TTL_SECONDS * 4:
                self._by_id.pop(request.id, None)
        return expired
