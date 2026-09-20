"""Linux Secret Service access through libsecret.

The counterpart to `keychain.py` on freedesktop systems: GNOME Keyring, KWallet
and anything else that owns `org.freedesktop.secrets` on the session bus.

We bind libsecret's C API rather than shelling out to `secret-tool`, for the
same reason `keychain.py` binds Security.framework: a library call cannot leak
the value into a process argument list, and it does not depend on a separate
binary being installed. (`secret-tool` would in fact take the value on stdin,
but it still has to be present, and its absence is not something we want to
discover at the moment a human is waiting on a paste window.)
"""

import ctypes
import ctypes.util
import os
import sys

from .errors import NotFoundError, StorageError

SCHEMA_NAME = "org.secretinputlayer.Secret"

# SecretSchemaAttributeType
ATTRIBUTE_STRING = 0

# SecretSchemaFlags. DONT_MATCH_NAME keeps us compatible with items written by
# other tools against the same attributes; we match on attributes alone.
SCHEMA_NONE = 0

# libsecret's header fixes the attribute table at 32 entries, and the struct is
# passed by pointer, so the layout has to match exactly or the library reads
# past our allocation.
MAX_ATTRIBUTES = 32

_LIBRARY = None
_GLIB = None


class _SchemaAttribute(ctypes.Structure):
    """One entry of SecretSchema.attributes."""

    _fields_ = [("name", ctypes.c_char_p), ("type", ctypes.c_int)]


class _Schema(ctypes.Structure):
    """Mirror of libsecret's SecretSchema, including its reserved tail."""

    _fields_ = [
        ("name", ctypes.c_char_p),
        ("flags", ctypes.c_int),
        ("attributes", _SchemaAttribute * MAX_ATTRIBUTES),
        ("reserved", ctypes.c_int),
        ("reserved1", ctypes.c_void_p),
        ("reserved2", ctypes.c_void_p),
        ("reserved3", ctypes.c_void_p),
        ("reserved4", ctypes.c_void_p),
        ("reserved5", ctypes.c_void_p),
        ("reserved6", ctypes.c_void_p),
        ("reserved7", ctypes.c_void_p),
    ]


class _GError(ctypes.Structure):
    """Mirror of GLib's GError, so we can read `message` before freeing it."""

    _fields_ = [
        ("domain", ctypes.c_uint32),
        ("code", ctypes.c_int),
        ("message", ctypes.c_char_p),
    ]


def is_available() -> bool:
    """Return True when the Secret Service backend can be used on this host."""
    if not sys.platform.startswith("linux"):
        return False
    # A headless box can have libsecret installed and no service to talk to.
    # Loading the library proves nothing about that, so this deliberately does
    # not probe the bus here - `store.backend_name()` falls back to files when
    # a real call fails, which is the only honest test.
    if not (os.environ.get("DBUS_SESSION_BUS_ADDRESS")
            or os.path.exists(f"/run/user/{os.getuid()}/bus")):
        return False
    try:
        _libsecret()
    except StorageError:
        return False
    return True


def _libsecret():
    """Load and memoise libsecret with argtypes applied."""
    global _LIBRARY
    if _LIBRARY is not None:
        return _LIBRARY
    path = ctypes.util.find_library("secret-1")
    if not path:
        raise StorageError("libsecret not found on this host")
    try:
        lib = ctypes.cdll.LoadLibrary(path)
    except OSError as exc:
        raise StorageError(f"libsecret could not be loaded: {exc}") from exc
    _declare(lib)
    _LIBRARY = lib
    return lib


def _glib():
    """Load and memoise GLib, needed only to free a GError."""
    global _GLIB
    if _GLIB is not None:
        return _GLIB
    path = ctypes.util.find_library("glib-2.0")
    if not path:
        raise StorageError("glib-2.0 not found on this host")
    lib = ctypes.cdll.LoadLibrary(path)
    lib.g_error_free.argtypes = [ctypes.POINTER(_GError)]
    lib.g_error_free.restype = None
    _GLIB = lib
    return lib


def _declare(lib) -> None:
    """Apply argtypes/restype so ctypes does not truncate pointers.

    The three *_sync entry points are variadic: the attribute name/value pairs
    follow, terminated by a NULL. argtypes is therefore set only for the fixed
    prefix, and the variadic tail is passed positionally.
    """
    schema_p = ctypes.POINTER(_Schema)
    error_pp = ctypes.POINTER(ctypes.POINTER(_GError))
    void_p = ctypes.c_void_p
    char_p = ctypes.c_char_p

    lib.secret_password_store_sync.restype = ctypes.c_int
    lib.secret_password_lookup_sync.restype = void_p
    lib.secret_password_clear_sync.restype = ctypes.c_int
    lib.secret_password_free.argtypes = [void_p]
    lib.secret_password_free.restype = None
    # Deliberately NOT setting argtypes on the variadic functions: ctypes
    # refuses extra positional arguments once argtypes is declared, and the
    # attribute pairs are exactly that.
    _ = (schema_p, error_pp, char_p)


def _schema() -> _Schema:
    """Build the SecretSchema describing our two attributes."""
    schema = _Schema()
    schema.name = SCHEMA_NAME.encode()
    schema.flags = SCHEMA_NONE
    schema.attributes[0] = _SchemaAttribute(b"service", ATTRIBUTE_STRING)
    schema.attributes[1] = _SchemaAttribute(b"account", ATTRIBUTE_STRING)
    schema.attributes[2] = _SchemaAttribute(None, 0)
    return schema


def _consume_error(error_p, operation: str) -> None:
    """Raise StorageError carrying a GError's message, then free it."""
    if not error_p:
        return
    try:
        message = error_p.contents.message
        detail = message.decode(errors="replace") if message else "unknown error"
    finally:
        _glib().g_error_free(error_p)
    raise StorageError(f"{operation}: {detail}")


def set_password(service: str, account: str, secret: str) -> None:
    """Create or replace the Secret Service item holding `secret`.

    libsecret's store is upsert by attribute match, so unlike the Keychain
    there is no duplicate-item case to handle separately.
    """
    lib = _libsecret()
    schema = _schema()
    error = ctypes.POINTER(_GError)()
    label = f"{service} ({account})"
    ok = lib.secret_password_store_sync(
        ctypes.byref(schema),
        None,                       # collection: NULL = the default keyring
        label.encode(),
        secret.encode(),
        None,                       # GCancellable
        ctypes.byref(error),
        b"service", service.encode(),
        b"account", account.encode(),
        None,
    )
    _consume_error(error, "store secret")
    if not ok:
        raise StorageError("store secret: libsecret reported failure")


def get_password(service: str, account: str) -> str:
    """Return the stored secret, raising NotFoundError when absent."""
    lib = _libsecret()
    schema = _schema()
    error = ctypes.POINTER(_GError)()
    raw = lib.secret_password_lookup_sync(
        ctypes.byref(schema),
        None,
        ctypes.byref(error),
        b"service", service.encode(),
        b"account", account.encode(),
        None,
    )
    _consume_error(error, "read secret")
    if not raw:
        raise NotFoundError(f"no secret service item for {account}")
    try:
        return ctypes.string_at(raw).decode()
    finally:
        # Frees with gcr's non-pageable allocator, which also zeroes the page.
        lib.secret_password_free(raw)


def delete_password(service: str, account: str) -> None:
    """Remove the item, raising NotFoundError when absent."""
    lib = _libsecret()
    schema = _schema()
    error = ctypes.POINTER(_GError)()
    removed = lib.secret_password_clear_sync(
        ctypes.byref(schema),
        None,
        ctypes.byref(error),
        b"service", service.encode(),
        b"account", account.encode(),
        None,
    )
    _consume_error(error, "delete secret")
    if not removed:
        raise NotFoundError(f"no secret service item for {account}")
