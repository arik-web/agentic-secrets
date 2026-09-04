"""Live macOS Keychain tests. Skipped anywhere the Keychain is unavailable."""

import os
import sys
import unittest

from support import cleanup, isolate

HOME = isolate()

from sil import keychain, store  # noqa: E402
from sil.errors import NotFoundError  # noqa: E402

SERVICE = "sil.selftest"
ACCOUNT = "unittest"


def tearDownModule():
    """Drop the throwaway home."""
    cleanup(HOME)


@unittest.skipUnless(sys.platform == "darwin" and keychain.is_available(),
                     "requires a macOS Keychain")
class Keychain(unittest.TestCase):
    """Values must survive a write/read/update/delete cycle in the Keychain."""

    def setUp(self):
        """Other test modules pin the file backend; this one needs the real one."""
        self.forced = os.environ.pop("SIL_FORCE_FILE_BACKEND", None)

    def tearDown(self):
        if self.forced is not None:
            os.environ["SIL_FORCE_FILE_BACKEND"] = self.forced
        try:
            keychain.delete_password(SERVICE, ACCOUNT)
        except NotFoundError:
            pass

    def test_round_trip(self):
        keychain.set_password(SERVICE, ACCOUNT, "first-value")
        self.assertEqual(keychain.get_password(SERVICE, ACCOUNT), "first-value")

    def test_set_twice_updates_in_place(self):
        keychain.set_password(SERVICE, ACCOUNT, "first-value")
        keychain.set_password(SERVICE, ACCOUNT, "second-value")
        self.assertEqual(keychain.get_password(SERVICE, ACCOUNT), "second-value")

    def test_unicode_and_multiline_survive(self):
        secret = "line-one\nlíne-twö 🔐\n"
        keychain.set_password(SERVICE, ACCOUNT, secret)
        self.assertEqual(keychain.get_password(SERVICE, ACCOUNT), secret)

    def test_missing_item_raises_not_found(self):
        with self.assertRaises(NotFoundError):
            keychain.get_password(SERVICE, "no-such-account")

    def test_delete_removes_the_item(self):
        keychain.set_password(SERVICE, ACCOUNT, "gone-soon")
        keychain.delete_password(SERVICE, ACCOUNT)
        with self.assertRaises(NotFoundError):
            keychain.get_password(SERVICE, ACCOUNT)

    def test_store_uses_the_keychain_backend_end_to_end(self):
        self.assertEqual(store.backend_name(), "keychain")
        store.put("keychain.probe", "kc-value")
        try:
            self.assertEqual(store.get("keychain.probe"), "kc-value")
            self.assertTrue(store.describe("keychain.probe")["present"])
        finally:
            store.delete("keychain.probe")


if __name__ == "__main__":
    unittest.main()
