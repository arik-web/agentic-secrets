"""Put the paste form in front of the human, in its own small window.

A chromeless "app window" is preferred on every platform: it has no address
bar, no tabs and no session history, so the paste page cannot be navigated away
from or mistaken for an ordinary browser tab. Chromium-family browsers all
support `--app=URL` for this. Everything else degrades to a normal browser tab,
which still works - it is just less obviously a dialog.
"""

import os
import shutil
import subprocess
import sys
import webbrowser

# macOS: bundles are launched through `open -na`, not by binary path.
CHROME_APPS_MACOS = [
    "/Applications/Google Chrome.app",
    "/Applications/Brave Browser.app",
    "/Applications/Microsoft Edge.app",
    "/Applications/Arc.app",
]

# Linux: whatever is on PATH. Ordered most- to least-common on desktop distros.
CHROME_BINARIES_LINUX = [
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "brave",
    "brave-browser",
    "microsoft-edge",
    "microsoft-edge-stable",
    "vivaldi",
    "vivaldi-stable",
]

# Windows: PATH rarely has them, so the usual install locations are tried too.
CHROME_BINARIES_WINDOWS = [
    r"%ProgramFiles%\Google\Chrome\Application\chrome.exe",
    r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe",
    r"%LocalAppData%\Google\Chrome\Application\chrome.exe",
    r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe",
    r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe",
    r"%ProgramFiles%\BraveSoftware\Brave-Browser\Application\brave.exe",
]

WINDOW_SIZE = "620,760"
LAUNCH_TIMEOUT_SECONDS = 10


def _app_arguments(url: str) -> list:
    """Return the chromium flags that make a bare, single-purpose window."""
    return [f"--app={url}", f"--window-size={WINDOW_SIZE}"]


def _spawn_detached(argv: list) -> bool:
    """Start a browser that keeps running after we return.

    Unlike macOS's `open`, a Linux or Windows browser binary is the process
    itself: it does not exit once the window is up. It therefore cannot be
    waited on, only launched and let go. A browser already running will hand
    the URL to the existing instance and exit immediately - which is a success,
    not a failure, so the exit status is deliberately not inspected.
    """
    try:
        subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=(os.name != "nt"),
        )
        return True
    except (OSError, ValueError):
        return False


def _chrome_app_window_macos(url: str) -> bool:
    """Open a chromeless app window on macOS; True when a launch succeeded."""
    for app in CHROME_APPS_MACOS:
        try:
            subprocess.run(
                ["open", "-na", app, "--args", *_app_arguments(url)],
                check=True, capture_output=True,
                timeout=LAUNCH_TIMEOUT_SECONDS,
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                FileNotFoundError):
            continue
    return False


def _chrome_app_window_linux(url: str) -> bool:
    """Open a chromeless app window on Linux; True when a launch succeeded."""
    for name in CHROME_BINARIES_LINUX:
        binary = shutil.which(name)
        if binary and _spawn_detached([binary, *_app_arguments(url)]):
            return True
    return False


def _chrome_app_window_windows(url: str) -> bool:
    """Open a chromeless app window on Windows; True when a launch succeeded."""
    for template in CHROME_BINARIES_WINDOWS:
        path = os.path.expandvars(template)
        # An unset variable expands to itself, leaving a literal % behind.
        if "%" in path or not os.path.isfile(path):
            continue
        if _spawn_detached([path, *_app_arguments(url)]):
            return True
    return False


def _app_window(url: str) -> bool:
    """Try for a chromeless window using whatever this platform offers."""
    if sys.platform == "darwin":
        return _chrome_app_window_macos(url)
    if sys.platform == "win32":
        return _chrome_app_window_windows(url)
    if sys.platform.startswith("linux"):
        return _chrome_app_window_linux(url)
    return False


def _platform_opener(url: str) -> bool:
    """Hand the URL to the desktop's own handler; True when one ran."""
    if sys.platform == "darwin" and shutil.which("open"):
        subprocess.run(["open", url], check=False, capture_output=True)
        return True
    if sys.platform.startswith("linux") and shutil.which("xdg-open"):
        # xdg-open can block for as long as the browser runs, so it is spawned
        # rather than waited on, exactly like a browser binary.
        return _spawn_detached(["xdg-open", url])
    return False


def open_url(url: str) -> str:
    """Open `url` for the human and return how it was opened."""
    override = os.environ.get("SIL_BROWSER")
    if override:
        try:
            subprocess.run([override, url], check=True, capture_output=True,
                           timeout=LAUNCH_TIMEOUT_SECONDS)
            return f"custom:{override}"
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                FileNotFoundError):
            pass
    if _app_window(url):
        return "app-window"
    if _platform_opener(url):
        return "default-browser"
    if webbrowser.open(url):
        return "webbrowser"
    return "none"
