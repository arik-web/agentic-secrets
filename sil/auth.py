"""The shared bearer token that gates the daemon's API.

Any process running as this user can read the token file. That is the intended
trust boundary: it keeps *other* origins - a web page, another user - out.
"""

import hmac
import os
import secrets as pysecrets

from . import config


def read_token() -> str:
    """Return the API token, creating one on first use."""
    config.ensure_home()
    if config.TOKEN_FILE.exists():
        token = config.TOKEN_FILE.read_text().strip()
        if token:
            return token
    token = pysecrets.token_urlsafe(32)
    fd = os.open(config.TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                 config.OWNER_ONLY_FILE)
    with os.fdopen(fd, "w") as handle:
        handle.write(token)
    config.TOKEN_FILE.chmod(config.OWNER_ONLY_FILE)
    return token


def check_header(header: str) -> bool:
    """Return True when an Authorization header carries the right token."""
    if not header or not header.startswith("Bearer "):
        return False
    return hmac.compare_digest(header[7:].strip(), read_token())
