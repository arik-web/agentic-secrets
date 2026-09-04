"""Static configuration and filesystem locations for the secret input layer."""

import os
from pathlib import Path

APP_NAME = "secret-input-layer"
KEYCHAIN_SERVICE_PREFIX = "sil"

HOST = "127.0.0.1"
DEFAULT_PORT = 7717

HOME_DIR = Path(os.environ.get("SIL_HOME", Path.home() / ".secret-input-layer"))
TOKEN_FILE = HOME_DIR / "api-token"
RUNTIME_FILE = HOME_DIR / "daemon.json"
LOG_FILE = HOME_DIR / "daemon.log"
FALLBACK_STORE_DIR = HOME_DIR / "store"

OWNER_ONLY_FILE = 0o600
OWNER_ONLY_DIR = 0o700

REQUEST_TTL_SECONDS = 15 * 60
WAIT_POLL_SECONDS = 0.25
DEFAULT_WAIT_SECONDS = 300
MAX_WAIT_SECONDS = 900
MAX_SECRET_BYTES = 64 * 1024
MAX_BODY_BYTES = 256 * 1024
MIN_SECRET_LENGTH = 4
MIN_REDACTABLE_ENCODING_LENGTH = 4
RUN_TIMEOUT_SECONDS = 600

REDACTION_PLACEHOLDER = "[redacted:{name}]"


def port() -> int:
    """Return the port the daemon should bind, honouring SIL_PORT."""
    raw = os.environ.get("SIL_PORT")
    return int(raw) if raw else DEFAULT_PORT


def base_url() -> str:
    """Return the daemon base URL."""
    return f"http://{HOST}:{port()}"


def ensure_home() -> Path:
    """Create the private home directory if missing and return it."""
    HOME_DIR.mkdir(parents=True, exist_ok=True)
    HOME_DIR.chmod(OWNER_ONLY_DIR)
    return HOME_DIR
