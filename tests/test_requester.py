"""The asking session is found from process ancestry, never from the agent's word alone."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from support import isolate

isolate()

from sil import requester  # noqa: E402


class Detect(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        (self.home / "sessions").mkdir()
        (self.home / "billboard-identity").mkdir()
        self.saved = requester.CLAUDE_HOME
        requester.CLAUDE_HOME = self.home
        os.environ.pop("BILLBOARD_AGENT", None)

    def tearDown(self):
        requester.CLAUDE_HOME = self.saved

    def test_finds_the_session_and_its_billboard_label_up_the_tree(self):
        parent = os.getppid()
        (self.home / "sessions" / f"{parent}.json").write_text(json.dumps(
            {"pid": parent, "name": "tagent-e0", "cwd": "/w/Tagent"}))
        (self.home / "billboard-identity" / f"{parent}.json").write_text(json.dumps(
            {"label": "Billboard-dev", "purpose": "Billboard features"}))
        got = requester.detect()
        self.assertEqual(got["session"], "tagent-e0")
        self.assertEqual(got["label"], "Billboard-dev")
        self.assertEqual(requester.describe(got),
                         "tagent-e0 - Billboard-dev (Billboard features) in /w/Tagent")

    def test_nothing_found_is_empty_never_a_guess(self):
        self.assertEqual(requester.detect(), {})

    def test_clean_keeps_only_known_string_keys(self):
        self.assertEqual(requester.clean({"agent": " a \n b ", "evil": "x", "pid": 3}),
                         {"agent": "a b"})
        self.assertEqual(requester.clean("nope"), {})


if __name__ == "__main__":
    unittest.main()
