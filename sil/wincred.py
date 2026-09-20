"""Windows Credential Manager access through advapi32.

The third sibling of `keychain.py` and `secretservice.py`. Same reasoning for
binding the C API directly: a secret handed to a library call never appears in
a process argument list, and nothing extra has to be installed.

Values are stored as generic credentials, so they show up under
Control Panel > Credential Manager > Windows Credentials like any other.

A caveat that has no equivalent on the other two platforms: Windows caps a
credential blob at CRED_MAX_CREDENTIAL_BLOB_SIZE, which is 2560 bytes - and the
blob is UTF-16, so roughly 1280 characters. That is smaller than the 64 KiB the
rest of this package allows, and smaller than a typical RSA private key. Rather
than silently truncate, `set_password` refuses an oversized value and says so.
"""

import ctypes
import sys

from .errors import NotFoundError, StorageError

CRED_TYPE_GENERIC = 1

# Survives a reboot and roams with the user profile where one is configured.
CRED_PERSIST_LOCAL_MACHINE = 2

ERROR_NOT_FOUND = 1168
ERROR_NO_SUCH_LOGON_SESSION = 1312
ERROR_INVALID_PARAMETER = 87

# wincred.h: CRED_MAX_CREDENTIAL_BLOB_SIZE (5 * 512)
MAX_BLOB_BYTES = 5 * 512

_LIBRARY = None


class _FileTime(ctypes.Structure):
    _fields_ = [("dwLowDateTime", ctypes.c_uint32),
                ("dwHighDateTime", ctypes.c_uint32)]


class _Credential(ctypes.Structure):
    """Mirror of CREDENTIALW from wincred.h. Field order is load-bearing."""

    _fields_ = [
        ("Flags", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
        ("TargetName", ctypes.c_wchar_p),
        ("Comment", ctypes.c_wchar_p),
        ("LastWritten", _FileTime),
        ("CredentialBlobSize", ctypes.c_uint32),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_char)),
        ("Persist", ctypes.c_uint32),
        ("AttributeCount", ctypes.c_uint32),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", ctypes.c_wchar_p),
        ("UserName", ctypes.c_wchar_p),
    ]


def is_available() -> bool:
    """Return True when the Credential Manager backend can be used."""
    if sys.platform != "win32":
        return False
    try:
        _advapi()
    except StorageError:
        return False
    return True


def _advapi():
    """Load and memoise advapi32 with argtypes applied."""
    global _LIBRARY
    if _LIBRARY is not None:
        return _LIBRARY
    try:
        lib = ctypes.WinDLL("advapi32", use_last_error=True)
    except (OSError, AttributeError) as exc:
        raise StorageError(f"advapi32 could not be loaded: {exc}") from exc
    _declare(lib)
    _LIBRARY = lib
    return lib


def _declare(lib) -> None:
    """Apply argtypes/restype so ctypes does not truncate pointers."""
    lib.CredWriteW.argtypes = [ctypes.POINTER(_Credential), ctypes.c_uint32]
    lib.CredWriteW.restype = ctypes.c_bool
    lib.CredReadW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32,
                              ctypes.c_uint32,
                              ctypes.POINTER(ctypes.POINTER(_Credential))]
    lib.CredReadW.restype = ctypes.c_bool
    lib.CredDeleteW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32,
                                ctypes.c_uint32]
    lib.CredDeleteW.restype = ctypes.c_bool
    lib.CredFree.argtypes = [ctypes.c_void_p]
    lib.CredFree.restype = None


def _target(service: str, account: str) -> str:
    """Return the TargetName identifying one stored value.

    Both parts are in the name because Credential Manager has a single
    key - there is no service/account pair as on the other two platforms.
    """
    return f"{service}:{account}"


def _fail(operation: str, code: int) -> StorageError:
    """Build a StorageError describing a Win32 error code."""
    if code == ERROR_NO_SUCH_LOGON_SESSION:
        return StorageError(
            f"{operation}: no logon session credential store available "
            "(this happens under a service account or an SSH session)")
    message = ctypes.FormatError(code) if hasattr(ctypes, "FormatError") else ""
    detail = f": {message}" if message else ""
    return StorageError(f"{operation}: Win32 error {code}{detail}")


def set_password(service: str, account: str, secret: str) -> None:
    """Create or replace the credential holding `secret`."""
    lib = _advapi()
    blob = secret.encode("utf-16-le")
    if len(blob) > MAX_BLOB_BYTES:
        raise StorageError(
            f"store secret: value is {len(blob)} bytes encoded, over the "
            f"{MAX_BLOB_BYTES}-byte Windows credential limit "
            f"(about {MAX_BLOB_BYTES // 2} characters). Windows cannot hold a "
            "secret this large in Credential Manager.")
    buffer = ctypes.create_string_buffer(blob, len(blob))
    credential = _Credential()
    credential.Flags = 0
    credential.Type = CRED_TYPE_GENERIC
    credential.TargetName = _target(service, account)
    credential.Comment = "secret-input-layer"
    credential.CredentialBlobSize = len(blob)
    credential.CredentialBlob = ctypes.cast(
        buffer, ctypes.POINTER(ctypes.c_char))
    credential.Persist = CRED_PERSIST_LOCAL_MACHINE
    credential.AttributeCount = 0
    credential.Attributes = None
    credential.TargetAlias = None
    credential.UserName = account
    if not lib.CredWriteW(ctypes.byref(credential), 0):
        raise _fail("store secret", ctypes.get_last_error())


def get_password(service: str, account: str) -> str:
    """Return the stored secret, raising NotFoundError when absent."""
    lib = _advapi()
    pointer = ctypes.POINTER(_Credential)()
    if not lib.CredReadW(_target(service, account), CRED_TYPE_GENERIC, 0,
                         ctypes.byref(pointer)):
        code = ctypes.get_last_error()
        if code == ERROR_NOT_FOUND:
            raise NotFoundError(f"no credential for {account}")
        raise _fail("read secret", code)
    try:
        record = pointer.contents
        raw = ctypes.string_at(record.CredentialBlob,
                               record.CredentialBlobSize)
        return raw.decode("utf-16-le")
    finally:
        lib.CredFree(pointer)


def delete_password(service: str, account: str) -> None:
    """Remove the credential, raising NotFoundError when absent."""
    lib = _advapi()
    if not lib.CredDeleteW(_target(service, account), CRED_TYPE_GENERIC, 0):
        code = ctypes.get_last_error()
        if code == ERROR_NOT_FOUND:
            raise NotFoundError(f"no credential for {account}")
        raise _fail("delete secret", code)
