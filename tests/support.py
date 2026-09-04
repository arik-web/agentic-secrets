"""Shared test setup: an isolated SIL_HOME and the file backend."""

import os
import shutil
import sys
import tempfile

TEST_PORT = "7771"


def isolate() -> str:
    """Point the package at a throwaway home and return its path."""
    home = tempfile.mkdtemp(prefix="sil-test-")
    os.environ["SIL_HOME"] = home
    os.environ["SIL_PORT"] = TEST_PORT
    os.environ["SIL_FORCE_FILE_BACKEND"] = "1"
    os.environ["SIL_BROWSER"] = "/usr/bin/true"
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if root not in sys.path:
        sys.path.insert(0, root)
    for module in [name for name in sys.modules if name.startswith("sil")]:
        del sys.modules[module]
    return home


def cleanup(home: str) -> None:
    """Remove a throwaway home."""
    shutil.rmtree(home, ignore_errors=True)
