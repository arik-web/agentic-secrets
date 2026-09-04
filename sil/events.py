"""A durable, value-free log of everything that settled, plus a long-poll wait.

This is how an agent that did *not* stay blocked on `secret_request` finds out
that the human answered: it reads from a cursor, or waits on one.
"""

import json
import threading
import time
from collections import deque

from . import config

EVENT_FILE = config.HOME_DIR / "events.jsonl"
MEMORY_LIMIT = 500
FIELDS = ("request_id", "name", "state", "detail", "fingerprint", "target",
          "purpose", "requested_by", "stored")


class EventLog:
    """Append-only sequence of settled requests, shared by every listener."""

    def __init__(self, path=EVENT_FILE, limit: int = MEMORY_LIMIT):
        self.path = path
        self._lock = threading.Condition()
        self._events = deque(maxlen=limit)
        self._sequence = 0

    @property
    def cursor(self) -> int:
        """Return the sequence number of the newest event."""
        with self._lock:
            return self._sequence

    def publish(self, request: dict) -> dict:
        """Record one settled request and wake everybody waiting."""
        event = {field: request.get(field, "") for field in FIELDS}
        with self._lock:
            self._sequence += 1
            event["seq"] = self._sequence
            event["at"] = time.time()
            self._events.append(event)
            self._lock.notify_all()
        self._persist(event)
        return event

    def since(self, cursor: int) -> list:
        """Return every event newer than `cursor`, oldest first."""
        with self._lock:
            return [event for event in self._events if event["seq"] > cursor]

    def wait(self, cursor: int, timeout: float) -> list:
        """Block until an event newer than `cursor` arrives, or time runs out."""
        deadline = time.monotonic() + timeout
        with self._lock:
            while True:
                newer = [e for e in self._events if e["seq"] > cursor]
                if newer:
                    return newer
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return []
                self._lock.wait(remaining)

    def _persist(self, event: dict) -> None:
        """Append the event to disk. A logging failure must not break a paste."""
        try:
            config.ensure_home()
            with open(self.path, "a") as handle:
                handle.write(json.dumps(event) + "\n")
            self.path.chmod(config.OWNER_ONLY_FILE)
        except OSError:
            pass
