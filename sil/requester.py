"""Who is asking: the agent session behind a request, found without trusting the agent.

A paste window that says only "asked by an agent" is how the human ends up not knowing which
secret to paste. The caller's `requested_by` is free text and is often left out, so the client
also looks itself up: it walks its own process ancestry to the first process that has a Claude
Code session record (`~/.claude/sessions/<pid>.json`), and adds the billboard label/purpose the
human gave that session (`~/.claude/billboard-identity/<pid>.json`) when one exists.

Everything here is best effort and never raises: no record found is an empty dict, and the form
then says plainly that the asker could not be identified.
"""

import json
import os
import subprocess
from pathlib import Path

CLAUDE_HOME = Path(os.environ.get("SIL_CLAUDE_HOME") or Path.home() / ".claude")
MAX_HOPS = 12
FIELD_LIMIT = 200


def _parent(pid: int) -> int:
    """Parent pid via ps (portable across macOS/Linux), 0 when unknown."""
    try:
        out = subprocess.run(["ps", "-o", "ppid=", "-p", str(pid)], capture_output=True,
                             text=True, timeout=2).stdout.strip()
        return int(out) if out else 0
    except (OSError, ValueError, subprocess.SubprocessError):
        return 0


def _read(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _clip(value) -> str:
    return " ".join(str(value or "").split())[:FIELD_LIMIT]


def detect(start_pid: int | None = None) -> dict:
    """The asking session, as display strings. {} when nothing is found."""
    pid = start_pid or os.getpid()
    for _ in range(MAX_HOPS):
        if pid <= 1:
            break
        session = _read(CLAUDE_HOME / "sessions" / f"{pid}.json")
        if session:
            ident = _read(CLAUDE_HOME / "billboard-identity" / f"{pid}.json")
            out = {
                "agent": _clip(os.environ.get("BILLBOARD_AGENT") or session.get("name")),
                "session": _clip(session.get("name")),
                "label": _clip(ident.get("label")),
                "session_purpose": _clip(ident.get("purpose")),
                "project": _clip(session.get("cwd")),
                "client": "claude-code",
                "pid": str(pid),
            }
            return {k: v for k, v in out.items() if v}
        pid = _parent(pid)
    agent = _clip(os.environ.get("BILLBOARD_AGENT"))
    return {"agent": agent, "project": _clip(os.getcwd())} if agent else {}


def clean(value) -> dict:
    """Server side: keep only known string keys, each clipped to one line."""
    if not isinstance(value, dict):
        return {}
    keys = ("agent", "session", "label", "session_purpose", "project", "client", "pid")
    return {k: _clip(value[k]) for k in keys if isinstance(value.get(k), str) and value[k].strip()}


def describe(value: dict) -> str:
    """One line for the form: 'tagent-e0 - Billboard-dev (Billboard features) in /path'."""
    if not value:
        return ""
    who = value.get("agent") or value.get("session") or "unknown session"
    if value.get("label") and value["label"] != who:
        who = f"{who} - {value['label']}"
    if value.get("session_purpose"):
        who = f"{who} ({value['session_purpose']})"
    if value.get("project"):
        who = f"{who} in {value['project']}"
    return who
