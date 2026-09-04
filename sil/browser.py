"""Put the paste form in front of the human, in its own small window."""

import os
import shutil
import subprocess
import sys
import webbrowser

CHROME_APPS = [
    "/Applications/Google Chrome.app",
    "/Applications/Brave Browser.app",
    "/Applications/Microsoft Edge.app",
    "/Applications/Arc.app",
]
WINDOW_SIZE = "620,760"


def _chrome_app_window(url: str) -> bool:
    """Open a chromeless app window; return True when the launch succeeded."""
    for app in CHROME_APPS:
        try:
            subprocess.run(
                ["open", "-na", app, "--args", f"--app={url}",
                 f"--window-size={WINDOW_SIZE}"],
                check=True, capture_output=True, timeout=10,
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                FileNotFoundError):
            continue
    return False


def open_url(url: str) -> str:
    """Open `url` for the human and return how it was opened."""
    override = os.environ.get("SIL_BROWSER")
    if override:
        try:
            subprocess.run([override, url], check=True, capture_output=True,
                           timeout=10)
            return f"custom:{override}"
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                FileNotFoundError):
            pass
    if sys.platform == "darwin":
        if _chrome_app_window(url):
            return "app-window"
        if shutil.which("open"):
            subprocess.run(["open", url], check=False, capture_output=True)
            return "default-browser"
    if webbrowser.open(url):
        return "webbrowser"
    return "none"
