"""What a single ask is made of: one or more named fields.

A request stores one secret per field, so `api_key` and `api_secret` end up as
two independent entries the agent can reference separately.
"""

from .errors import ValidationError
from .names import clean_label, validate_secret_name

KIND_SECRET = "secret"
KIND_TEXT = "text"
KIND_MULTILINE = "multiline"
KINDS = {KIND_SECRET, KIND_TEXT, KIND_MULTILINE}

MAX_FIELDS = 12

PRESETS = {
    "token": [
        {"name": "token", "label": "Token"},
    ],
    "api_key": [
        {"name": "api_key", "label": "API key"},
    ],
    "api_key_secret": [
        {"name": "api_key", "label": "API key"},
        {"name": "api_secret", "label": "API secret"},
    ],
    "username_password": [
        {"name": "username", "label": "Username", "kind": KIND_TEXT},
        {"name": "password", "label": "Password"},
    ],
    "oauth_client": [
        {"name": "client_id", "label": "Client ID", "kind": KIND_TEXT},
        {"name": "client_secret", "label": "Client secret"},
    ],
    "connection_string": [
        {"name": "url", "label": "Connection string"},
    ],
    "private_key": [
        {"name": "private_key", "label": "Private key (paste the whole block)",
         "kind": KIND_MULTILINE},
    ],
    "aws_keys": [
        {"name": "access_key_id", "label": "Access key ID", "kind": KIND_TEXT},
        {"name": "secret_access_key", "label": "Secret access key"},
    ],
    "basic_auth_totp": [
        {"name": "username", "label": "Username", "kind": KIND_TEXT},
        {"name": "password", "label": "Password"},
        {"name": "totp_seed", "label": "TOTP seed", "required": False},
    ],
}


def resolve(group: str, spec, preset) -> list:
    """Return the field list for a request, from an explicit spec or a preset.

    With neither, the request is a single unnamed field stored under `group` -
    the original one-secret-per-request behaviour.
    """
    if spec is not None and preset:
        raise ValidationError("pass fields or preset, not both")
    if preset is not None:
        if preset not in PRESETS:
            raise ValidationError(
                f"unknown preset {preset!r}; try one of {sorted(PRESETS)}")
        return [_build(group, field, compound=True) for field in PRESETS[preset]]
    if spec is None:
        return [_build(group, {"name": "value", "label": group},
                       compound=False)]
    if not isinstance(spec, list) or not spec:
        raise ValidationError("fields must be a non-empty array")
    if len(spec) > MAX_FIELDS:
        raise ValidationError(f"at most {MAX_FIELDS} fields per request")
    fields = [_build(group, _as_field(item), compound=True) for item in spec]
    names = [field["name"] for field in fields]
    if len(set(names)) != len(names):
        raise ValidationError("field names must be unique")
    return fields


def _as_field(item) -> dict:
    """Accept either a bare field name or a full field object."""
    if isinstance(item, str):
        return {"name": item}
    if isinstance(item, dict):
        return item
    raise ValidationError("each field must be a name or an object")


def _build(group: str, item: dict, compound: bool) -> dict:
    """Validate one field and compute the secret name it will be stored under."""
    name = validate_secret_name(item.get("name"))
    kind = item.get("kind", KIND_SECRET)
    if kind not in KINDS:
        raise ValidationError(f"field kind must be one of {sorted(KINDS)}")
    secret_name = f"{group}.{name}" if compound else group
    validate_secret_name(secret_name)
    return {
        "name": name,
        "label": clean_label(item.get("label"), "field label", name),
        "hint": clean_label(item.get("hint"), "field hint"),
        "kind": kind,
        "required": bool(item.get("required", True)),
        "secret_name": secret_name,
    }


def secret_names(fields: list) -> list:
    """Return the store names a field list will write to."""
    return [field["secret_name"] for field in fields]


def public(fields: list) -> list:
    """Return the value-free view of a field list."""
    return [{key: field[key] for key in
             ("name", "label", "hint", "kind", "required", "secret_name")}
            for field in fields]
