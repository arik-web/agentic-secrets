"""Tool schemas and dispatch for the MCP server, kept out of the transport."""

from . import config
from .client import Client
from .errors import ValidationError

SECRET_NAME = {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,63}$"}

TOOLS = [
    {
        "name": "secret_request",
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
        "title": "Ask the human for a secret",
        "description": (
            "Open a local browser form so the human can paste a secret "
            "(API key, password, token). The value is stored in the macOS "
            "Keychain and is NEVER returned to you. Blocks until the human "
            "answers or `wait` seconds pass. Use this instead of asking for a "
            "secret in chat."),
        "inputSchema": {
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": {**SECRET_NAME,
                         "description": "stable id, e.g. 'openai.api_key'"},
                "purpose": {"type": "string",
                            "description": "why you need it - shown to the human"},
                "target": {"type": "string",
                           "description": "where it will be used, e.g. '.env'"},
                "hint": {"type": "string",
                         "description": "one line shown above the whole form"},
                "preset": {
                    "type": "string",
                    "enum": ["token", "api_key", "api_key_secret",
                             "username_password", "oauth_client",
                             "connection_string", "private_key", "aws_keys",
                             "basic_auth_totp"],
                    "description": (
                        "ask for a known credential shape in one window. "
                        "api_key_secret gives two boxes stored as "
                        "<name>.api_key and <name>.api_secret"),
                },
                "fields": {
                    "type": "array",
                    "description": (
                        "custom multi-field ask; each field is stored as its "
                        "own secret named <name>.<field>. Use instead of "
                        "preset, never with it"),
                    "items": {
                        "type": ["string", "object"],
                        "properties": {
                            "name": SECRET_NAME,
                            "label": {"type": "string",
                                      "description": "what the human sees"},
                            "hint": {"type": "string"},
                            "kind": {"type": "string",
                                     "enum": ["secret", "text", "multiline"],
                                     "default": "secret",
                                     "description": (
                                         "text is not masked (a username); "
                                         "multiline is for a key block")},
                            "required": {"type": "boolean", "default": True},
                        },
                    },
                },
                "requested_by": {"type": "string",
                                 "description": "your agent name"},
                "overwrite": {"type": "boolean", "default": False,
                              "description": "replace an existing value"},
                "wait": {"type": "number", "default": config.DEFAULT_WAIT_SECONDS,
                         "description": "seconds to block; 0 returns at once"},
                "notify": {
                    "type": "object",
                    "description": (
                        "how to signal you the moment the human answers - use "
                        "this when you pass wait: 0 and will not stay blocked"),
                    "properties": {
                        "command": {"type": "array", "items": {"type": "string"},
                                    "description": (
                                        "argv run on settle; the event is in "
                                        "SIL_NAME, SIL_STATE, SIL_FINGERPRINT, "
                                        "SIL_REQUEST_ID - never the value")},
                        "webhook": {"type": "string",
                                    "description": "http:// URL on 127.0.0.1 to POST the event to"},
                    },
                },
            },
        },
    },
    {
        "name": "secret_status",
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
        "title": "Check a pending secret request",
        "description": "Poll a request created with wait=0.",
        "inputSchema": {
            "type": "object", "required": ["request_id"],
            "properties": {"request_id": {"type": "string"}},
        },
    },
    {
        "name": "secret_wait",
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
        "title": "Wait for a pending secret request",
        "description": (
            "Block until a specific request is answered, declined or expires. "
            "Use after a wait: 0 request when you are still in the same turn."),
        "inputSchema": {
            "type": "object", "required": ["request_id"],
            "properties": {
                "request_id": {"type": "string"},
                "wait": {"type": "number",
                         "default": config.DEFAULT_WAIT_SECONDS},
            },
        },
    },
    {
        "name": "secret_events",
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
        "title": "Read or wait for settled secret requests",
        "description": (
            "Every request that was answered, declined or expired, newest "
            "last, with a cursor. Pass `wait` to block until the next one. "
            "This is how an agent that did not stay blocked - or a different "
            "agent entirely - learns that the human pasted something."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "since": {"type": "number", "default": 0,
                          "description": "cursor from a previous call"},
                "wait": {"type": "number", "default": 0,
                         "description": "seconds to block for the next event"},
            },
        },
    },
    {
        "name": "secret_list",
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
        "title": "List stored secrets",
        "description": "Names and metadata only - no values.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "secret_describe",
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
        "title": "Describe one stored secret",
        "description": "Metadata for one secret: purpose, length, fingerprint.",
        "inputSchema": {"type": "object", "required": ["name"],
                        "properties": {"name": SECRET_NAME}},
    },
    {
        "name": "secret_delete",
        "annotations": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": False},
        "title": "Delete a stored secret",
        "description": "Forget a secret's value and metadata.",
        "inputSchema": {"type": "object", "required": ["name"],
                        "properties": {"name": SECRET_NAME}},
    },
    {
        "name": "secret_run",
        "annotations": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
        "title": "Run a command with secrets in its environment",
        "description": (
            "Run a command with stored secrets injected as environment "
            "variables. Output is scrubbed of the secret values before it "
            "reaches you. This is how you USE a secret."),
        "inputSchema": {
            "type": "object", "required": ["command", "env"],
            "properties": {
                "command": {"description": "argv array, or a string with shell=true",
                            "type": ["array", "string"],
                            "items": {"type": "string"}},
                "env": {"type": "object",
                        "description": "map ENV_VAR -> stored secret name",
                        "additionalProperties": {"type": "string"}},
                "cwd": {"type": "string"},
                "shell": {"type": "boolean", "default": False},
                "timeout": {"type": "number",
                            "default": config.RUN_TIMEOUT_SECONDS},
            },
        },
    },
    {
        "name": "secret_write_file",
        "annotations": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": False},
        "title": "Write secrets into a file",
        "description": (
            "Render a template containing {{secret:name}} placeholders into a "
            "file with 0600 permissions - e.g. a .env or a config file. The "
            "rendered content is not returned to you."),
        "inputSchema": {
            "type": "object", "required": ["path", "template"],
            "properties": {
                "path": {"type": "string", "description": "absolute path"},
                "template": {"type": "string",
                             "description": "text with {{secret:name}} markers"},
                "append": {"type": "boolean", "default": False},
                "mode": {"type": "string", "default": "0o600"},
            },
        },
    },
    {
        "name": "secret_health",
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
        "title": "Secret broker health",
        "description": "Check the local broker is up and which store it uses.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def dispatch(name: str, arguments: dict, client: Client | None = None) -> dict:
    """Run one tool call and return its value-free result."""
    api = client or Client()
    arguments = arguments or {}
    if name == "secret_request":
        return api.request_secret(**arguments)
    if name == "secret_status":
        return api.request_status(arguments["request_id"])
    if name == "secret_wait":
        return api.wait_for(arguments["request_id"],
                            float(arguments.get("wait",
                                                config.DEFAULT_WAIT_SECONDS)))
    if name == "secret_events":
        return api.events(since=arguments.get("since", 0),
                          wait=arguments.get("wait", 0))
    if name == "secret_list":
        return api.list_secrets()
    if name == "secret_describe":
        return api.describe(arguments["name"])
    if name == "secret_delete":
        return api.delete(arguments["name"])
    if name == "secret_run":
        return api.run(**arguments)
    if name == "secret_write_file":
        return api.materialize(**arguments)
    if name == "secret_health":
        return api.health()
    raise ValidationError(f"unknown tool: {name}")
