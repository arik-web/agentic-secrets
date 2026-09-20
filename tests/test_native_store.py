"""Live OS keystore tests, against whichever backend this host actually has.

One contract, three implementations: Security.framework on macOS, libsecret on
Linux, Credential Manager on Windows. The suite that used to cover only the
Keychain now runs unchanged on all three, and skips only where there is no
keystore at all (a headless box, or CI without a session bus).
"""

import os
import unittest

from support import cleanup, isolate

HOME = isolate()

from sil import store  # noqa: E402
from sil.errors import NotFoundError, StorageError  # noqa: E402

SERVICE = "sil.selftest"
ACCOUNT = "unittest"


def _native():
    """Return (name, module) for this host's keystore, or (None, None)."""
    for name, module in store.NATIVE_BACKENDS:
        if module.is_available():
            return name, module
    return None, None


BACKEND_NAME, BACKEND = _native()


def tearDownModule():
    """Drop the throwaway home."""
    cleanup(HOME)


@unittest.skipUnless(BACKEND is not None,
                     "no OS keystore available on this host")
class NativeKeystore(unittest.TestCase):
    """Values must survive a write/read/update/delete cycle in the keystore."""

    def setUp(self):
        """Other test modules pin the file backend; this one needs the real one."""
        self.forced = os.environ.pop("SIL_FORCE_FILE_BACKEND", None)

    def tearDown(self):
        if self.forced is not None:
            os.environ["SIL_FORCE_FILE_BACKEND"] = self.forced
        try:
            BACKEND.delete_password(SERVICE, ACCOUNT)
        except NotFoundError:
            pass

    def test_round_trip(self):
        BACKEND.set_password(SERVICE, ACCOUNT, "first-value")
        self.assertEqual(BACKEND.get_password(SERVICE, ACCOUNT), "first-value")

    def test_set_twice_updates_in_place(self):
        BACKEND.set_password(SERVICE, ACCOUNT, "first-value")
        BACKEND.set_password(SERVICE, ACCOUNT, "second-value")
        self.assertEqual(BACKEND.get_password(SERVICE, ACCOUNT), "second-value")

    def test_unicode_and_multiline_survive(self):
        secret = "line-one\nlíne-twö 🔐\n"
        BACKEND.set_password(SERVICE, ACCOUNT, secret)
        self.assertEqual(BACKEND.get_password(SERVICE, ACCOUNT), secret)

    def test_missing_item_raises_not_found(self):
        with self.assertRaises(NotFoundError):
            BACKEND.get_password(SERVICE, "no-such-account")

    def test_delete_removes_the_item(self):
        BACKEND.set_password(SERVICE, ACCOUNT, "gone-soon")
        BACKEND.delete_password(SERVICE, ACCOUNT)
        with self.assertRaises(NotFoundError):
            BACKEND.get_password(SERVICE, ACCOUNT)

    def test_deleting_an_absent_item_raises_not_found(self):
        with self.assertRaises(NotFoundError):
            BACKEND.delete_password(SERVICE, "no-such-account")

    def test_store_uses_the_native_backend_end_to_end(self):
        self.assertEqual(store.backend_name(), BACKEND_NAME)
        store.put("native.probe", "kc-value")
        try:
            self.assertEqual(store.get("native.probe"), "kc-value")
            self.assertTrue(store.describe("native.probe")["present"])
            self.assertEqual(store.describe("native.probe")["backend"],
                             BACKEND_NAME)
        finally:
            store.delete("native.probe")

    def test_backend_label_is_human_readable(self):
        self.assertIn(store.backend_name(), store.BACKEND_LABELS)
        self.assertTrue(store.backend_label())


@unittest.skipUnless(BACKEND_NAME == "wincred",
                     "Credential Manager blob limit is Windows-only")
class WindowsBlobLimit(unittest.TestCase):
    """Windows caps a credential blob far below this package's 64 KiB ceiling.

    The value must be refused with an explanation rather than silently
    truncated - a half-stored private key is worse than a failed paste.
    """

    def test_oversized_value_is_refused_clearly(self):
        oversized = "x" * (BACKEND.MAX_BLOB_BYTES // 2 + 1)
        with self.assertRaises(StorageError) as caught:
            BACKEND.set_password(SERVICE, ACCOUNT, oversized)
        self.assertIn("limit", str(caught.exception))


class BackendSelection(unittest.TestCase):
    """Backend choice must be explicit and overridable on every platform."""

    def setUp(self):
        self.forced = os.environ.pop("SIL_FORCE_FILE_BACKEND", None)
        self.named = os.environ.pop("SIL_BACKEND", None)

    def tearDown(self):
        for key, value in (("SIL_FORCE_FILE_BACKEND", self.forced),
                           ("SIL_BACKEND", self.named)):
            os.environ.pop(key, None)
            if value is not None:
                os.environ[key] = value

    def test_force_file_backend_wins(self):
        os.environ["SIL_FORCE_FILE_BACKEND"] = "1"
        self.assertEqual(store.backend_name(), "file")

    def test_named_file_backend_wins(self):
        os.environ["SIL_BACKEND"] = "file"
        self.assertEqual(store.backend_name(), "file")

    def test_unknown_backend_is_rejected(self):
        os.environ["SIL_BACKEND"] = "nonesuch"
        with self.assertRaises(StorageError):
            store.backend_name()

    def test_backend_unavailable_here_is_rejected(self):
        """Naming another platform's keystore must fail loudly, not fall back."""
        absent = [name for name, module in store.NATIVE_BACKENDS
                  if not module.is_available()]
        if not absent:
            self.skipTest("every backend is available, which cannot happen")
        os.environ["SIL_BACKEND"] = absent[0]
        with self.assertRaises(StorageError):
            store.backend_name()


if __name__ == "__main__":
    unittest.main()
