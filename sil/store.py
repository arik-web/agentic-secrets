"""Secret persistence: Keychain when available, private files otherwise.

Values only ever leave this module through `get`. Everything else in the
package works from the metadata index, which never contains a secret value.
"""

import hashlib
import json
import os
import secrets as pysecrets
import sys
import tempfile
import threading
import time
from pathlib import Path

from . import config, keychain
from .errors import NotFoundError, StorageError, ValidationError
from .names import validate_secret_name

INDEX_FILE = config.HOME_DIR / "index.json"
SALT_FILE = config.HOME_DIR / "fingerprint-salt"
FINGERPRINT_LENGTH = 12
SCRYPT_COST = 2 ** 14
SCRYPT_BLOCK = 8
SCRYPT_PARALLEL = 1
SCRYPT_MAX_MEMORY = 64 * 1024 * 1024

# The store is reached from several daemon threads at once; index.json and the
# fallback files are rewritten whole, so every write is serialised.
_WRITE_LOCK = threading.RLock()


def _service_for(name: str) -> str:
    """Return the keychain service string for a secret name."""
    return f"{config.KEYCHAIN_SERVICE_PREFIX}.{name}"


def _account() -> str:
    """Return the keychain account string; one per local user."""
    return os.environ.get("USER", "sil")


def _write_private(path: Path, text: str) -> None:
    """Write text to path with owner-only permissions, atomically.

    The temporary file is created with an unpredictable name via mkstemp, which
    is O_EXCL by construction: a co-resident process cannot pre-create it as a
    symlink and have us write the plaintext through it.
    """
    config.ensure_home()
    with _WRITE_LOCK:
        handle_fd, tmp_name = tempfile.mkstemp(dir=str(path.parent),
                                               prefix=f".{path.name}.")
        try:
            with os.fdopen(handle_fd, "w") as handle:
                handle.write(text)
            os.chmod(tmp_name, config.OWNER_ONLY_FILE)
            os.replace(tmp_name, path)
        except BaseException:
            os.unlink(tmp_name)
            raise


def _salt() -> bytes:
    """Return the per-install fingerprint salt, creating it on first use."""
    if SALT_FILE.exists():
        return bytes.fromhex(SALT_FILE.read_text().strip())
    salt = pysecrets.token_bytes(16)
    _write_private(SALT_FILE, salt.hex())
    return salt


def fingerprint(value: str) -> str:
    """Return a salted digest so callers can compare two values without reading one.

    A deliberately slow KDF, not a bare HMAC. The salt file is readable by
    anything running as this user - including the agent - so a single hash pass
    would turn the fingerprint into an offline brute-force oracle for a
    low-entropy secret. scrypt makes that search expensive.
    """
    digest = hashlib.scrypt(value.encode(), salt=_salt(), n=SCRYPT_COST,
                            r=SCRYPT_BLOCK, p=SCRYPT_PARALLEL, dklen=16,
                            maxmem=SCRYPT_MAX_MEMORY)
    return digest.hex()[:FINGERPRINT_LENGTH]


def _read_index() -> dict:
    """Return the metadata index, or an empty index when it does not exist."""
    if not INDEX_FILE.exists():
        return {}
    try:
        return json.loads(INDEX_FILE.read_text())
    except json.JSONDecodeError as exc:
        raise StorageError(f"index.json is corrupt: {exc}") from exc


def _write_index(index: dict) -> None:
    """Persist the metadata index with owner-only permissions."""
    _write_private(INDEX_FILE, json.dumps(index, indent=2, sort_keys=True))


def backend_name() -> str:
    """Return the active storage backend identifier.

    SIL_FORCE_FILE_BACKEND=1 pins the private-file backend; tests and hosts
    without a Keychain use it.
    """
    if os.environ.get("SIL_FORCE_FILE_BACKEND") == "1":
        return "file"
    if keychain.is_available():
        return "keychain"
    return "file"


def _fallback_path(name: str) -> Path:
    """Return the private file path used when the Keychain is unavailable."""
    config.FALLBACK_STORE_DIR.mkdir(parents=True, exist_ok=True)
    config.FALLBACK_STORE_DIR.chmod(config.OWNER_ONLY_DIR)
    return config.FALLBACK_STORE_DIR / f"{name}.secret"


def _backend_put(name: str, value: str) -> None:
    """Write the value into the active backend."""
    if backend_name() == "keychain":
        keychain.set_password(_service_for(name), _account(), value)
        return
    _write_private(_fallback_path(name), value)


def _backend_get(name: str) -> str:
    """Read the value from the active backend."""
    if backend_name() == "keychain":
        return keychain.get_password(_service_for(name), _account())
    path = _fallback_path(name)
    if not path.exists():
        raise NotFoundError(f"no stored value for {name}")
    return path.read_text()


def _backend_delete(name: str) -> None:
    """Remove the value from the active backend, ignoring an absent value."""
    if backend_name() == "keychain":
        try:
            keychain.delete_password(_service_for(name), _account())
        except NotFoundError:
            pass
        return
    path = _fallback_path(name)
    if path.exists():
        path.unlink()


def put(name: str, value: str, *, purpose: str = "", target: str = "",
        requested_by: str = "") -> dict:
    """Store a secret value and return its (value-free) metadata."""
    validate_secret_name(name)
    if not isinstance(value, str) or value == "":
        raise ValidationError("secret value must be a non-empty string")
    if len(value) < config.MIN_SECRET_LENGTH:
        raise ValidationError(
            f"secret value must be at least {config.MIN_SECRET_LENGTH} "
            "characters, so that it can be reliably scrubbed from output")
    if len(value.encode()) > config.MAX_SECRET_BYTES:
        raise ValidationError("secret value is larger than the 64 KiB limit")
    with _WRITE_LOCK:
        _backend_put(name, value)
        return _record(name, value, purpose, target, requested_by)


def _record(name: str, value: str, purpose: str, target: str,
            requested_by: str) -> dict:
    """Update the metadata index for a stored value. Caller holds the lock."""
    index = _read_index()
    now = time.time()
    existing = index.get(name, {})
    index[name] = {
        "name": name,
        "purpose": purpose or existing.get("purpose", ""),
        "target": target or existing.get("target", ""),
        "requested_by": requested_by or existing.get("requested_by", ""),
        "backend": backend_name(),
        "platform": sys.platform,
        "length": len(value),
        "fingerprint": fingerprint(value),
        "created_at": existing.get("created_at", now),
        "updated_at": now,
    }
    _write_index(index)
    return index[name]


def get(name: str) -> str:
    """Return the raw secret value. The only value-returning call in the package."""
    validate_secret_name(name)
    return _backend_get(name)


def exists(name: str) -> bool:
    """Return True when a value is stored under this name."""
    validate_secret_name(name)
    try:
        _backend_get(name)
    except NotFoundError:
        return False
    return True


def describe(name: str) -> dict:
    """Return metadata for one secret, raising NotFoundError when unknown."""
    validate_secret_name(name)
    entry = _read_index().get(name)
    if entry is None:
        raise NotFoundError(f"no secret named {name}")
    return {**entry, "present": exists(name)}


def list_secrets() -> list:
    """Return metadata for every known secret, newest update first."""
    entries = [{**entry, "present": exists(name)}
               for name, entry in _read_index().items()]
    return sorted(entries, key=lambda item: item.get("updated_at", 0), reverse=True)


def delete(name: str) -> None:
    """Forget a secret entirely: value and metadata."""
    validate_secret_name(name)
    with _WRITE_LOCK:
        _backend_delete(name)
        index = _read_index()
        index.pop(name, None)
        _write_index(index)
