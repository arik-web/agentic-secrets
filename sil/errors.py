"""Error types shared across the secret input layer."""


class SilError(Exception):
    """Base class for every expected failure in this package."""

    status = 500


class ValidationError(SilError):
    """Caller supplied something malformed."""

    status = 400


class NotFoundError(SilError):
    """The named secret or request does not exist."""

    status = 404


class ConflictError(SilError):
    """The requested state transition is not allowed right now."""

    status = 409


class StorageError(SilError):
    """The backing keystore refused an operation."""

    status = 500


class DaemonUnavailableError(SilError):
    """The local daemon is not reachable."""

    status = 503
