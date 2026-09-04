"""Scrub secret values out of text before it is handed back to a caller.

This is a guardrail, not a sandbox: a process that receives a secret in its
environment can always transform it before printing. Redaction stops the
accidental leak (a tool echoing its config), not a determined one.
"""

import base64
import json
import urllib.parse

from . import config


def _encodings(value: str) -> list:
    """Return the common textual encodings of a secret value."""
    raw = value.encode()
    derived = [
        base64.b64encode(raw).decode(),
        base64.b64encode(raw).decode().rstrip("="),
        base64.urlsafe_b64encode(raw).decode().rstrip("="),
        urllib.parse.quote(value, safe=""),
        json.dumps(value)[1:-1],
    ]
    # The raw value is always scrubbed, however short. Only the derived forms
    # carry a length floor, because a short base64 fragment matches noise.
    seen = [value]
    for form in derived:
        if len(form) >= config.MIN_REDACTABLE_ENCODING_LENGTH and form not in seen:
            seen.append(form)
    return seen


def redact(text: str, values: dict) -> str:
    """Replace every occurrence of each secret in `values` with a placeholder.

    `values` maps a secret name to its raw value.
    """
    if not text or not values:
        return text
    cleaned = text
    for name, value in values.items():
        if not value:
            continue
        placeholder = config.REDACTION_PLACEHOLDER.format(name=name)
        for form in _encodings(value):
            cleaned = cleaned.replace(form, placeholder)
    return cleaned


def leaks(text: str, values: dict) -> list:
    """Return the names whose value still appears in `text`."""
    if not text:
        return []
    found = []
    for name, value in values.items():
        if value and any(form in text for form in _encodings(value)):
            found.append(name)
    return found
