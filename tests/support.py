"""Shared test setup: an isolated SIL_HOME, the file backend, portable commands."""

import os
import shutil
import stat
import sys
import tempfile

TEST_PORT = "7771"

# Tests that need to run a child process use the Python interpreter running the
# suite, not /bin/sh: it is the one executable guaranteed to exist and behave
# identically on macOS, Linux and Windows.
PYTHON = sys.executable


def python_command(snippet: str) -> list:
    """Return an argv that runs `snippet` in this interpreter."""
    return [PYTHON, "-c", snippet]


def noop_executable(home: str) -> str:
    """Create and return a program that accepts any argument and exits 0.

    Stands in for a browser in tests. `/usr/bin/true` was used before, which
    does not exist on Windows, so the program is written per-platform instead.
    """
    if os.name == "nt":
        path = os.path.join(home, "noop.cmd")
        with open(path, "w") as handle:
            handle.write("@exit /b 0\r\n")
        return path
    path = os.path.join(home, "noop.sh")
    with open(path, "w") as handle:
        handle.write("#!/bin/sh\nexit 0\n")
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP)
    return path


def isolate() -> str:
    """Point the package at a throwaway home and return its path."""
    home = tempfile.mkdtemp(prefix="sil-test-")
    os.environ["SIL_HOME"] = home
    os.environ["SIL_PORT"] = TEST_PORT
    os.environ["SIL_FORCE_FILE_BACKEND"] = "1"
    os.environ["SIL_BROWSER"] = noop_executable(home)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if root not in sys.path:
        sys.path.insert(0, root)
    for module in [name for name in sys.modules if name.startswith("sil")]:
        del sys.modules[module]
    return home


def cleanup(home: str) -> None:
    """Remove a throwaway home."""
    shutil.rmtree(home, ignore_errors=True)
