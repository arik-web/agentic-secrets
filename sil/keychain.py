"""macOS Keychain access through Security.framework.

We bind the C API directly instead of shelling out to /usr/bin/security so the
secret value never appears in a process argument list.
"""

import ctypes
import ctypes.util
import sys

from .errors import NotFoundError, StorageError

ERR_SUCCESS = 0
ERR_ITEM_NOT_FOUND = -25300
ERR_DUPLICATE_ITEM = -25299
ERR_USER_CANCELED = -128

_LIBRARY = None


def is_available() -> bool:
    """Return True when the Keychain backend can be used on this host."""
    if sys.platform != "darwin":
        return False
    try:
        _security()
    except StorageError:
        return False
    return True


def _security():
    """Load and memoise the Security framework with argtypes applied."""
    global _LIBRARY
    if _LIBRARY is not None:
        return _LIBRARY
    path = ctypes.util.find_library("Security")
    if not path:
        raise StorageError("Security.framework not found on this host")
    lib = ctypes.cdll.LoadLibrary(path)
    _declare(lib)
    _LIBRARY = lib
    return lib


def _declare(lib) -> None:
    """Apply argtypes/restype so ctypes does not truncate pointers."""
    void_p = ctypes.c_void_p
    u32 = ctypes.c_uint32
    char_p = ctypes.c_char_p
    lib.SecKeychainAddGenericPassword.argtypes = [
        void_p, u32, char_p, u32, char_p, u32, void_p,
        ctypes.POINTER(void_p),
    ]
    lib.SecKeychainAddGenericPassword.restype = ctypes.c_int32
    lib.SecKeychainFindGenericPassword.argtypes = [
        void_p, u32, char_p, u32, char_p,
        ctypes.POINTER(u32), ctypes.POINTER(void_p), ctypes.POINTER(void_p),
    ]
    lib.SecKeychainFindGenericPassword.restype = ctypes.c_int32
    lib.SecKeychainItemModifyAttributesAndData.argtypes = [
        void_p, void_p, u32, void_p,
    ]
    lib.SecKeychainItemModifyAttributesAndData.restype = ctypes.c_int32
    lib.SecKeychainItemDelete.argtypes = [void_p]
    lib.SecKeychainItemDelete.restype = ctypes.c_int32
    lib.SecKeychainItemFreeContent.argtypes = [void_p, void_p]
    lib.SecKeychainItemFreeContent.restype = ctypes.c_int32
    lib.CFRelease = _cf_release_handle()


def _cf_release_handle():
    """Return CFRelease bound from CoreFoundation."""
    path = ctypes.util.find_library("CoreFoundation")
    if not path:
        raise StorageError("CoreFoundation not found on this host")
    core = ctypes.cdll.LoadLibrary(path)
    core.CFRelease.argtypes = [ctypes.c_void_p]
    core.CFRelease.restype = None
    return core.CFRelease


def _fail(operation: str, status: int) -> StorageError:
    """Build a StorageError describing a non-zero OSStatus."""
    if status == ERR_USER_CANCELED:
        return StorageError(f"{operation}: keychain access denied by the user")
    return StorageError(f"{operation}: keychain OSStatus {status}")


def set_password(service: str, account: str, secret: str) -> None:
    """Create or replace the keychain item holding `secret`."""
    lib = _security()
    service_b = service.encode()
    account_b = account.encode()
    # create_string_buffer keeps the bytes alive in a named local for the whole
    # FFI call; a bare cast() of a temporary would not, and ctypes does not
    # track that reference for us.
    raw = secret.encode()
    data = ctypes.create_string_buffer(raw, len(raw))
    item = ctypes.c_void_p()
    status = lib.SecKeychainAddGenericPassword(
        None, len(service_b), service_b, len(account_b), account_b,
        len(raw), ctypes.cast(data, ctypes.c_void_p), ctypes.byref(item),
    )
    if status == ERR_SUCCESS:
        if item:
            lib.CFRelease(item)
        return
    if status != ERR_DUPLICATE_ITEM:
        raise _fail("store secret", status)
    _replace_password(lib, service_b, account_b, raw)


def _replace_password(lib, service_b: bytes, account_b: bytes, data: bytes) -> None:
    """Overwrite the data of an existing keychain item."""
    item = ctypes.c_void_p()
    length = ctypes.c_uint32()
    blob = ctypes.c_void_p()
    status = lib.SecKeychainFindGenericPassword(
        None, len(service_b), service_b, len(account_b), account_b,
        ctypes.byref(length), ctypes.byref(blob), ctypes.byref(item),
    )
    if status != ERR_SUCCESS:
        raise _fail("locate existing secret", status)
    try:
        lib.SecKeychainItemFreeContent(None, blob)
        buffer = ctypes.create_string_buffer(data, len(data))
        status = lib.SecKeychainItemModifyAttributesAndData(
            item, None, len(data), ctypes.cast(buffer, ctypes.c_void_p),
        )
        if status != ERR_SUCCESS:
            raise _fail("update secret", status)
    finally:
        if item:
            lib.CFRelease(item)


def get_password(service: str, account: str) -> str:
    """Return the stored secret, raising NotFoundError when absent."""
    lib = _security()
    service_b = service.encode()
    account_b = account.encode()
    length = ctypes.c_uint32()
    blob = ctypes.c_void_p()
    item = ctypes.c_void_p()
    status = lib.SecKeychainFindGenericPassword(
        None, len(service_b), service_b, len(account_b), account_b,
        ctypes.byref(length), ctypes.byref(blob), ctypes.byref(item),
    )
    if status == ERR_ITEM_NOT_FOUND:
        raise NotFoundError(f"no keychain item for {account}")
    if status != ERR_SUCCESS:
        raise _fail("read secret", status)
    try:
        raw = ctypes.string_at(blob, length.value)
        return raw.decode()
    finally:
        lib.SecKeychainItemFreeContent(None, blob)
        if item:
            lib.CFRelease(item)


def delete_password(service: str, account: str) -> None:
    """Remove the keychain item, raising NotFoundError when absent."""
    lib = _security()
    service_b = service.encode()
    account_b = account.encode()
    length = ctypes.c_uint32()
    blob = ctypes.c_void_p()
    item = ctypes.c_void_p()
    status = lib.SecKeychainFindGenericPassword(
        None, len(service_b), service_b, len(account_b), account_b,
        ctypes.byref(length), ctypes.byref(blob), ctypes.byref(item),
    )
    if status == ERR_ITEM_NOT_FOUND:
        raise NotFoundError(f"no keychain item for {account}")
    if status != ERR_SUCCESS:
        raise _fail("locate secret for delete", status)
    try:
        lib.SecKeychainItemFreeContent(None, blob)
        status = lib.SecKeychainItemDelete(item)
        if status != ERR_SUCCESS:
            raise _fail("delete secret", status)
    finally:
        if item:
            lib.CFRelease(item)
