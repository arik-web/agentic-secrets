"""The agent must learn that the human answered, without polling blindly."""

import json
import os
import threading
import time
import unittest
import urllib.parse
import urllib.request

from support import cleanup, isolate

HOME = isolate()

from sil import config, events, notify, store  # noqa: E402
from sil.api import Api  # noqa: E402
from sil.client import Client  # noqa: E402
from sil.errors import ValidationError  # noqa: E402
from sil.server import SecretServer  # noqa: E402

SERVER = None
THREAD = None


def setUpModule():
    """Boot one daemon for the module."""
    global SERVER, THREAD
    SERVER = SecretServer(Api())
    THREAD = threading.Thread(target=SERVER.serve_forever, daemon=True)
    THREAD.start()


def tearDownModule():
    """Stop the daemon and drop the throwaway home."""
    SERVER.shutdown()
    SERVER.server_close()
    THREAD.join(timeout=5)
    cleanup(HOME)


def paste_soon(url: str, value: str, delay: float = 0.15) -> None:
    """Simulate the human saving the form a moment from now."""
    def submit():
        time.sleep(delay)
        body = urllib.parse.urlencode({"action": "save",
                                       "field.value": value}).encode()
        urllib.request.urlopen(urllib.request.Request(
            url, data=body, method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"}),
            timeout=5).read()
    threading.Thread(target=submit, daemon=True).start()


class EventLog(unittest.TestCase):
    """The log is the durable half of the signal."""

    def setUp(self):
        self.log = events.EventLog(path=config.HOME_DIR / "unit-events.jsonl")

    def test_publish_assigns_an_increasing_cursor(self):
        first = self.log.publish({"request_id": "a", "name": "x",
                                  "state": "fulfilled"})
        second = self.log.publish({"request_id": "b", "name": "y",
                                   "state": "cancelled"})
        self.assertEqual((first["seq"], second["seq"]), (1, 2))
        self.assertEqual(self.log.cursor, 2)

    def test_since_returns_only_newer_events(self):
        self.log.publish({"request_id": "a", "name": "x", "state": "fulfilled"})
        self.log.publish({"request_id": "b", "name": "y", "state": "expired"})
        self.assertEqual([e["name"] for e in self.log.since(1)], ["y"])

    def test_wait_returns_empty_when_nothing_arrives(self):
        self.assertEqual(self.log.wait(0, 0.05), [])

    def test_wait_wakes_on_a_publish(self):
        def later():
            time.sleep(0.1)
            self.log.publish({"request_id": "c", "name": "z",
                              "state": "fulfilled"})
        threading.Thread(target=later, daemon=True).start()
        found = self.log.wait(0, 5)
        self.assertEqual(found[0]["name"], "z")

    def test_events_are_persisted_to_disk(self):
        self.log.publish({"request_id": "a", "name": "x", "state": "fulfilled"})
        written = json.loads(open(self.log.path).readline())
        self.assertEqual(written["name"], "x")


class NotifySpec(unittest.TestCase):
    """A notify spec is caller input, so it is validated like any other."""

    def test_accepts_a_command_and_a_loopback_webhook(self):
        spec = notify.validate({"command": ["/bin/echo", "hi"],
                                "webhook": "http://127.0.0.1:9/x"})
        self.assertEqual(spec["command"], ["/bin/echo", "hi"])

    def test_rejects_a_webhook_that_leaves_this_machine(self):
        for url in ["http://evil.example/x", "https://127.0.0.1/x",
                    "http://198.51.100.1/x", "file:///etc/passwd"]:
            with self.assertRaises(ValidationError):
                notify.validate({"webhook": url})

    def test_rejects_a_command_that_is_not_an_argv_array(self):
        for command in ["rm -rf /", [], [1, 2], {"a": 1}]:
            with self.assertRaises(ValidationError):
                notify.validate({"command": command})

    def test_rejects_an_empty_spec(self):
        with self.assertRaises(ValidationError):
            notify.validate({})

    def test_absent_spec_is_fine(self):
        self.assertEqual(notify.validate(None), {})


class Signalling(unittest.TestCase):
    """End to end: paste in the browser, agent finds out."""

    def setUp(self):
        self.client = Client(autostart=False)

    def tearDown(self):
        for entry in store.list_secrets():
            store.delete(entry["name"])

    def test_a_blocking_request_returns_as_soon_as_it_is_saved(self):
        opened = self.client.request_secret(name="sig.one", wait=0)
        paste_soon(opened["url"], "blocking-value")
        started = time.time()
        settled = self.client.wait_for(opened["request_id"], 10)
        self.assertEqual(settled["state"], "fulfilled")
        self.assertLess(time.time() - started, 5)

    def test_a_second_listener_is_woken_by_the_event_feed(self):
        cursor = self.client.events()["event_cursor"]
        opened = self.client.request_secret(name="sig.two", wait=0)
        paste_soon(opened["url"], "event-value")
        found = self.client.events(since=cursor, wait=10)["events"]
        self.assertEqual(found[0]["name"], "sig.two")
        self.assertEqual(found[0]["state"], "fulfilled")

    def test_events_never_carry_the_value(self):
        cursor = self.client.events()["event_cursor"]
        opened = self.client.request_secret(name="sig.three", wait=0)
        paste_soon(opened["url"], "leaky-value-here")
        found = self.client.events(since=cursor, wait=10)["events"]
        self.assertNotIn("leaky-value-here", json.dumps(found))

    def test_a_notify_command_runs_when_the_human_saves(self):
        marker = os.path.join(HOME, "notified.txt")
        opened = self.client.request_secret(
            name="sig.four", wait=0,
            notify={"command": ["/bin/sh", "-c",
                                f'printf "%s %s" "$SIL_NAME" "$SIL_STATE" > {marker}']})
        paste_soon(opened["url"], "command-value")
        for _ in range(100):
            if os.path.exists(marker):
                break
            time.sleep(0.05)
        self.assertEqual(open(marker).read(), "sig.four fulfilled")

    def test_a_declined_request_signals_too(self):
        cursor = self.client.events()["event_cursor"]
        opened = self.client.request_secret(name="sig.five", wait=0)
        body = urllib.parse.urlencode({"action": "cancel"}).encode()
        urllib.request.urlopen(urllib.request.Request(
            opened["url"], data=body, method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"}),
            timeout=5).read()
        found = self.client.events(since=cursor, wait=5)["events"]
        self.assertEqual(found[0]["state"], "cancelled")

    def test_an_expired_request_signals_too(self):
        cursor = self.client.events()["event_cursor"]
        self.client.request_secret(name="sig.six", wait=0, ttl=0.5)
        time.sleep(0.7)
        self.client.call("GET", "/api/requests")
        found = self.client.events(since=cursor)["events"]
        self.assertEqual([e["state"] for e in found], ["expired"])

    def test_health_reports_the_cursor_so_a_client_can_start_fresh(self):
        self.assertIn("event_cursor", self.client.health())


if __name__ == "__main__":
    unittest.main()
