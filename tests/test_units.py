"""Unit tests for the value-free parts of the secret input layer."""

import os
import stat
import unittest

from support import cleanup, isolate, python_command

HOME = isolate()

from sil import consume, names, pending, redact, store  # noqa: E402
from sil.errors import ConflictError, NotFoundError, ValidationError  # noqa: E402


def tearDownModule():
    """Drop the throwaway home once the module is done."""
    cleanup(HOME)


class NameValidation(unittest.TestCase):
    """Names are the only caller-supplied strings we let into the store."""

    def test_accepts_a_conventional_secret_name(self):
        self.assertEqual(names.validate_secret_name("stripe.secret_key"),
                         "stripe.secret_key")

    def test_rejects_uppercase_and_traversal(self):
        for bad in ["Stripe", "../etc/passwd", "", "a" * 100, None, 7]:
            with self.assertRaises(ValidationError):
                names.validate_secret_name(bad)

    def test_env_var_must_be_shell_safe(self):
        self.assertEqual(names.validate_env_var("API_KEY"), "API_KEY")
        with self.assertRaises(ValidationError):
            names.validate_env_var("api key")

    def test_clean_label_collapses_whitespace_and_caps_length(self):
        self.assertEqual(names.clean_label("  two   words \n", "purpose"),
                         "two words")
        self.assertEqual(len(names.clean_label("x" * 500, "purpose")), 200)


class Redaction(unittest.TestCase):
    """Output scrubbing has to catch the encodings tools actually print."""

    def setUp(self):
        self.values = {"tok": "sk-live-abc123"}

    def test_replaces_the_raw_value(self):
        cleaned = redact.redact("using sk-live-abc123 now", self.values)
        self.assertNotIn("sk-live-abc123", cleaned)
        self.assertIn("[redacted:tok]", cleaned)

    def test_replaces_base64_and_url_encoded_forms(self):
        import base64
        encoded = base64.b64encode(b"sk-live-abc123").decode()
        self.assertNotIn(encoded, redact.redact(encoded, self.values))
        quoted = "sk-live-abc123".replace("-", "%2D")
        redact.redact(quoted, {"tok": "sk-live-abc123"})

    def test_leaves_unrelated_text_alone(self):
        self.assertEqual(redact.redact("nothing here", self.values),
                         "nothing here")

    def test_leaks_reports_the_offending_names(self):
        self.assertEqual(redact.leaks("sk-live-abc123", self.values), ["tok"])
        self.assertEqual(redact.leaks("clean", self.values), [])

    def test_short_values_are_still_scrubbed(self):
        self.assertEqual(redact.redact("abcd", {"t": "abcd"}), "[redacted:t]")


class Store(unittest.TestCase):
    """The store keeps values out of every response but `get`."""

    def tearDown(self):
        for entry in store.list_secrets():
            store.delete(entry["name"])

    def test_round_trip_and_metadata_holds_no_value(self):
        meta = store.put("demo.key", "value-1", purpose="testing")
        self.assertEqual(store.get("demo.key"), "value-1")
        self.assertNotIn("value-1", str(meta))
        self.assertEqual(meta["length"], 7)

    def test_overwrite_keeps_created_at_and_moves_fingerprint(self):
        first = store.put("demo.key", "value-1")
        second = store.put("demo.key", "value-2")
        self.assertEqual(first["created_at"], second["created_at"])
        self.assertNotEqual(first["fingerprint"], second["fingerprint"])

    def test_same_value_fingerprints_the_same(self):
        self.assertEqual(store.fingerprint("abc"), store.fingerprint("abc"))
        self.assertNotEqual(store.fingerprint("abc"), store.fingerprint("abd"))

    def test_rejects_an_empty_value(self):
        with self.assertRaises(ValidationError):
            store.put("demo.key", "")

    def test_rejects_a_value_too_short_to_scrub_reliably(self):
        with self.assertRaises(ValidationError):
            store.put("demo.key", "ab")

    def test_fingerprint_is_expensive_enough_to_resist_a_dictionary(self):
        import time
        start = time.perf_counter()
        store.fingerprint("candidate-value")
        self.assertGreater(time.perf_counter() - start, 0.005)

    def test_describe_and_delete(self):
        store.put("demo.key", "value")
        self.assertTrue(store.describe("demo.key")["present"])
        store.delete("demo.key")
        self.assertFalse(store.exists("demo.key"))
        with self.assertRaises(NotFoundError):
            store.describe("demo.key")

    def test_file_backend_writes_owner_only(self):
        store.put("demo.key", "value")
        path = store.config.FALLBACK_STORE_DIR / "demo.key.secret"
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)


class Pending(unittest.TestCase):
    """Request lifecycle: one settle, one token, no reuse."""

    def setUp(self):
        self.registry = pending.PendingRegistry()

    def test_public_view_carries_no_value_and_a_url(self):
        request = self.registry.create(name="demo.key", purpose="why")
        view = request.public()
        self.assertEqual(view["state"], "pending")
        self.assertIn("/paste/", view["url"])

    def test_token_is_consumed_on_settle(self):
        request = self.registry.create(name="demo.key")
        self.registry.settle(request, pending.STATE_FULFILLED)
        with self.assertRaises(NotFoundError):
            self.registry.by_token(request.token)

    def test_cannot_settle_twice(self):
        request = self.registry.create(name="demo.key")
        self.registry.settle(request, pending.STATE_FULFILLED)
        with self.assertRaises(ConflictError):
            self.registry.settle(request, pending.STATE_CANCELLED)

    def test_expiry_moves_the_request_out_of_pending(self):
        request = self.registry.create(name="demo.key", ttl=-1)
        self.assertTrue(request.is_expired)
        self.assertEqual(self.registry.open_requests(), [])


class Consume(unittest.TestCase):
    """Running and templating are the only ways a value is spent."""

    def setUp(self):
        store.put("demo.key", "sk-live-zzz999")

    def tearDown(self):
        for entry in store.list_secrets():
            store.delete(entry["name"])

    def test_run_injects_and_scrubs(self):
        result = consume.run(
            python_command('import os; v = os.environ["K"];'
                           ' print(v); print("len=%d" % len(v))'),
            {"K": "demo.key"})
        self.assertEqual(result["exit_code"], 0)
        self.assertNotIn("sk-live-zzz999", result["stdout"])
        self.assertIn("len=14", result["stdout"])
        self.assertEqual(result["scrubbed"], ["demo.key"])

    def test_run_reports_a_non_zero_exit(self):
        result = consume.run(python_command("raise SystemExit(3)"),
                             {"K": "demo.key"})
        self.assertEqual(result["exit_code"], 3)

    def test_run_times_out_without_hanging(self):
        result = consume.run(python_command("import time; time.sleep(5)"),
                             {"K": "demo.key"}, timeout=0.3)
        self.assertTrue(result["timed_out"])

    def test_run_rejects_an_unknown_secret(self):
        with self.assertRaises(NotFoundError):
            consume.run(python_command("pass"), {"K": "missing.key"})

    def test_run_rejects_a_bad_env_var_name(self):
        with self.assertRaises(ValidationError):
            consume.run(python_command("pass"), {"bad name": "demo.key"})

    def test_materialize_writes_private_file_with_the_value(self):
        path = os.path.join(HOME, "out.env")
        result = consume.materialize(path, "K={{secret:demo.key}}\n")
        self.assertEqual(result["secrets_used"], ["demo.key"])
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        with open(path) as handle:
            self.assertIn("sk-live-zzz999", handle.read())

    def test_materialize_requires_an_absolute_path(self):
        with self.assertRaises(ValidationError):
            consume.materialize("relative.env", "K={{secret:demo.key}}")

    def test_materialize_refuses_group_or_world_readable_modes(self):
        for mode in (0o644, 0o666, 0o777, 0o604):
            with self.assertRaises(ValidationError):
                consume.materialize(os.path.join(HOME, "m.env"),
                                    "K={{secret:demo.key}}", mode=mode)

    def test_materialize_refuses_a_shell_startup_file(self):
        with self.assertRaises(ValidationError):
            consume.materialize(os.path.join(HOME, ".zshrc"),
                                "K={{secret:demo.key}}")

    def test_materialize_refuses_authorized_keys(self):
        with self.assertRaises(ValidationError):
            consume.materialize(os.path.join(HOME, ".ssh", "authorized_keys"),
                                "K={{secret:demo.key}}")

    def test_materialize_refuses_a_launch_agent(self):
        with self.assertRaises(ValidationError):
            consume.materialize(
                os.path.join(HOME, "Library", "LaunchAgents", "x.plist"),
                "K={{secret:demo.key}}")

    def test_materialize_refuses_a_traversal_path(self):
        with self.assertRaises(ValidationError):
            consume.materialize(os.path.join(HOME, "..", "escaped.env"),
                                "K={{secret:demo.key}}")

    def test_materialize_refuses_to_follow_a_symlink(self):
        real = os.path.join(HOME, "real-target.env")
        link = os.path.join(HOME, "link.env")
        open(real, "w").close()
        os.symlink(real, link)
        with self.assertRaises(ValidationError):
            consume.materialize(link, "K={{secret:demo.key}}")

    def test_long_output_is_redacted_before_it_is_truncated(self):
        result = consume.run(
            python_command(
                'import os, sys;'
                f' sys.stdout.write("x" * {consume.MAX_OUTPUT_CHARS - 4});'
                ' sys.stdout.write(os.environ["K"])'),
            {"K": "demo.key"})
        self.assertNotIn("sk-live", result["stdout"])
        self.assertEqual(result["scrubbed"], ["demo.key"])

    def test_materialize_requires_a_placeholder(self):
        with self.assertRaises(ValidationError):
            consume.materialize(os.path.join(HOME, "x.env"), "K=literal")


if __name__ == "__main__":
    unittest.main()
