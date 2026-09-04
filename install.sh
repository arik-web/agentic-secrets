#!/usr/bin/env bash
# Install the secret input layer and wire it into every agent found on this host.
# Idempotent: safe to re-run. Every config file is backed up before it is edited.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${SIL_BIN_DIR:-$HOME/.local/bin}"
STAMP="$(date +%Y%m%d-%H%M%S)"
PY="${SIL_PYTHON:-python3}"

say() { printf '  %s\n' "$*"; }
head_line() { printf '\n%s\n' "$*"; }

backup() { [ -f "$1" ] && cp "$1" "$1.bak-sil-$STAMP" && say "backed up $(basename "$1")"; }

head_line "launchers -> $BIN_DIR"
mkdir -p "$BIN_DIR"

cat > "$BIN_DIR/sil" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH="$ROOT\${PYTHONPATH:+:\$PYTHONPATH}"
exec "$PY" -m sil.cli "\$@"
EOF

cat > "$BIN_DIR/sil-mcp" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH="$ROOT\${PYTHONPATH:+:\$PYTHONPATH}"
exec "$PY" -m sil.mcp_server
EOF

chmod +x "$BIN_DIR/sil" "$BIN_DIR/sil-mcp"
say "sil, sil-mcp"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) say "WARNING: $BIN_DIR is not on your PATH" ;;
esac

head_line "Claude Code"
if command -v claude >/dev/null 2>&1; then
  if "$PY" - <<'PYEOF'
import json
import os
import sys

path = os.path.expanduser("~/.claude.json")
try:
    servers = json.load(open(path)).get("mcpServers", {})
except (OSError, json.JSONDecodeError):
    servers = {}
sys.exit(0 if "secret-input-layer" in servers else 1)
PYEOF
  then
    say "MCP server already registered at user scope"
  else
    claude mcp add --scope user secret-input-layer -- "$BIN_DIR/sil-mcp" >/dev/null
    say "MCP server registered at user scope"
  fi
else
  say "claude CLI not found - skipped"
fi
mkdir -p "$HOME/.claude/skills/secret-input" "$HOME/.claude/commands"
cp "$ROOT/skills/secret-input/SKILL.md" "$HOME/.claude/skills/secret-input/SKILL.md"
cp "$ROOT/commands/secret.md" "$HOME/.claude/commands/secret.md"
say "skill + /secret command installed"

head_line "Codex"
CODEX="$HOME/.codex/config.toml"
if [ -f "$CODEX" ]; then
  if grep -q '^\[mcp_servers.secret-input-layer\]' "$CODEX"; then
    say "already wired"
  else
    backup "$CODEX"
    cat >> "$CODEX" <<EOF

[mcp_servers.secret-input-layer]
command = "$BIN_DIR/sil-mcp"
startup_timeout_sec = 30.0
# Read-only tools (list, describe, health, status, wait, events) carry
# readOnlyHint and auto-approve; anything that stores, runs or writes prompts.
default_tools_approval_mode = "writes"

# The paste window IS the human's consent, so do not also prompt in the terminal.
[mcp_servers.secret-input-layer.tools.secret_request]
approval_mode = "approve"
EOF
    say "added [mcp_servers.secret-input-layer] with approval modes"
  fi
  mkdir -p "$HOME/.codex/skills/secret-input"
  cp "$ROOT/skills/secret-input/SKILL.md" "$HOME/.codex/skills/secret-input/SKILL.md"
  say "skill installed"
else
  say "no ~/.codex/config.toml - skipped"
fi

head_line "Hermes"
HERMES="$HOME/.hermes/config.yaml"
if [ -f "$HERMES" ]; then
  if grep -q 'secret-input-layer:' "$HERMES"; then
    say "already wired"
  else
    backup "$HERMES"
    SIL_BIN="$BIN_DIR" "$PY" - "$HERMES" <<'PYEOF'
import os
import sys

path = sys.argv[1]
launcher = os.path.join(os.environ["SIL_BIN"], "sil-mcp")
lines = open(path).read().splitlines(keepends=True)
block = ["  secret-input-layer:\n",
         f"    command: {launcher}\n",
         "    enabled: true\n"]
for index, line in enumerate(lines):
    if line.rstrip() == "mcp_servers:":
        lines[index + 1:index + 1] = block
        open(path, "w").writelines(lines)
        print("  inserted under mcp_servers")
        break
else:
    with open(path, "a") as handle:
        handle.write("mcp_servers:\n" + "".join(block))
    print("  appended a new mcp_servers block")
PYEOF
  fi
  if [ -d "$HOME/.hermes/skills" ]; then
    mkdir -p "$HOME/.hermes/skills/secret-input"
    cp "$ROOT/skills/secret-input/SKILL.md" "$HOME/.hermes/skills/secret-input/SKILL.md"
    say "skill installed"
  fi
else
  say "no ~/.hermes/config.yaml - skipped"
fi

head_line "verify"
"$BIN_DIR/sil" start >/dev/null
"$BIN_DIR/sil" status
head_line "done - restart your agents so they pick up the new MCP server."
