"""Validation for the identifiers callers hand us."""

import re

from .errors import ValidationError

NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
ENV_VAR_PATTERN = re.compile(r"^[A-Z_][A-Z0-9_]{0,63}$")
MAX_LABEL_LENGTH = 200


def validate_secret_name(name: object) -> str:
    """Return a validated secret name or raise ValidationError."""
    if not isinstance(name, str) or not NAME_PATTERN.match(name):
        raise ValidationError(
            "secret name must match [a-z0-9][a-z0-9._-]{0,63}, got: "
            f"{name!r}"
        )
    return name


def validate_env_var(var: object) -> str:
    """Return a validated environment variable name or raise."""
    if not isinstance(var, str) or not ENV_VAR_PATTERN.match(var):
        raise ValidationError(
            f"env var must match [A-Z_][A-Z0-9_]{{0,63}}, got: {var!r}"
        )
    return var


def clean_label(value: object, field: str, default: str = "") -> str:
    """Return a trimmed single-line label, or raise if it is not a string."""
    if value is None:
        return default
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be a string")
    collapsed = " ".join(value.split())
    return collapsed[:MAX_LABEL_LENGTH]
