"""Minimal MCP server over stdio - JSON-RPC 2.0, no third-party packages.

Kept dependency-free on purpose: every agent runtime on this machine
(Claude Code, Codex, Hermes) can spawn `sil mcp` with the system python.
"""

import json
import sys

from . import __version__, mcp_tools
from .errors import SilError

PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "secret-input-layer", "version": __version__}
INVALID_PARAMS = -32602
METHOD_NOT_FOUND = -32601
INTERNAL_ERROR = -32603
PARSE_ERROR = -32700

INSTRUCTIONS = (
    "Never ask the user to type a secret into the chat. Call secret_request "
    "instead: it opens a local paste window and stores the value in the "
    "Keychain. You will never see the value. Use secret_run to execute a "
    "command with the secret in its environment, or secret_write_file to "
    "write it into a config file."
)


def _result(request_id, payload: dict) -> dict:
    """Wrap a successful JSON-RPC result."""
    return {"jsonrpc": "2.0", "id": request_id, "result": payload}


def _error(request_id, code: int, message: str) -> dict:
    """Wrap a JSON-RPC error."""
    return {"jsonrpc": "2.0", "id": request_id,
            "error": {"code": code, "message": message}}


def _tool_payload(data: dict, is_error: bool = False) -> dict:
    """Shape a tools/call result the way MCP clients expect."""
    return {
        "content": [{"type": "text",
                     "text": json.dumps(data, indent=2, sort_keys=True)}],
        "structuredContent": data,
        "isError": is_error,
    }


def handle(message: dict) -> dict | None:
    """Handle one JSON-RPC message; return None for notifications."""
    method = message.get("method")
    request_id = message.get("id")
    params = message.get("params") or {}
    if method is None:
        return None
    if method.startswith("notifications/"):
        return None
    if method == "initialize":
        return _result(request_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": SERVER_INFO,
            "instructions": INSTRUCTIONS,
        })
    if method == "ping":
        return _result(request_id, {})
    if method == "tools/list":
        return _result(request_id, {"tools": mcp_tools.TOOLS})
    if method == "tools/call":
        return _call_tool(request_id, params)
    return _error(request_id, METHOD_NOT_FOUND, f"unknown method: {method}")


def _call_tool(request_id, params: dict) -> dict:
    """Run one tool, converting failures into a tool-level error result."""
    name = params.get("name")
    if not name:
        return _error(request_id, INVALID_PARAMS, "tools/call needs a name")
    try:
        data = mcp_tools.dispatch(name, params.get("arguments") or {})
    except SilError as exc:
        return _result(request_id, _tool_payload(
            {"error": str(exc), "tool": name}, is_error=True))
    except (TypeError, KeyError) as exc:
        return _result(request_id, _tool_payload(
            {"error": f"bad arguments: {exc}", "tool": name}, is_error=True))
    except Exception as exc:  # noqa: BLE001 - a tool must not kill the server
        return _result(request_id, _tool_payload(
            {"error": f"{type(exc).__name__}: {exc}", "tool": name},
            is_error=True))
    return _result(request_id, _tool_payload(data))


def serve_stdio(stdin=None, stdout=None) -> None:
    """Read newline-delimited JSON-RPC from stdin until EOF."""
    source = stdin or sys.stdin
    sink = stdout or sys.stdout
    for line in source:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            _emit(sink, _error(None, PARSE_ERROR, str(exc)))
            continue
        try:
            response = handle(message)
        except Exception as exc:  # noqa: BLE001 - stay alive for the next call
            response = _error(message.get("id"), INTERNAL_ERROR,
                              f"{type(exc).__name__}: {exc}")
        if response is not None:
            _emit(sink, response)


def _emit(sink, payload: dict) -> None:
    """Write one JSON-RPC message and flush."""
    sink.write(json.dumps(payload) + "\n")
    sink.flush()


if __name__ == "__main__":
    serve_stdio()
