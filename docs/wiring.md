# Wiring the broker into each agent

`install.sh` does all of this. This file is what it does, and how to undo it.

Every agent points at the same launcher, so there is one broker and one
Keychain entry per secret no matter who asked.

```
~/.local/bin/sil-mcp     MCP server over stdio
~/.local/bin/sil         the CLI
```

## Claude Code

Two ways; the installer uses the first.

**User-scope MCP server** — available in every project:

```bash
claude mcp add --scope user secret-input-layer -- "$HOME/.local/bin/sil-mcp"
```

Plus the skill and slash command:

```
~/.claude/skills/secret-input/SKILL.md
~/.claude/commands/secret.md
```

**As a plugin** — this repo is a valid plugin and marketplace:

```bash
claude plugin marketplace add "<path to this repo>"
claude plugin install secret-input-layer@secret-input-layer
```

Remove with `claude mcp remove --scope user secret-input-layer`.

## Codex

`~/.codex/config.toml`:

```toml
[mcp_servers.secret-input-layer]
command = "/Users/YOU/.local/bin/sil-mcp"
startup_timeout_sec = 30.0
default_tools_approval_mode = "writes"

[mcp_servers.secret-input-layer.tools.secret_request]
approval_mode = "approve"
```

`writes` auto-approves the tools that advertise `readOnlyHint` — `secret_list`,
`secret_describe`, `secret_health`, `secret_status`, `secret_wait`,
`secret_events` — and prompts for `secret_run`, `secret_write_file` and
`secret_delete`, which is what you want. `secret_request` is set to `approve`
on purpose: the paste window on your screen *is* the consent, so a second
prompt in the terminal only adds friction. Without this block Codex refuses
every call in non-interactive `codex exec` with "MCP approval required".

Also copy the skill to `~/.codex/skills/secret-input/SKILL.md` so the model
knows to reach for it.

## Hermes

`~/.hermes/config.yaml`, under the existing `mcp_servers:` key:

```yaml
mcp_servers:
  secret-input-layer:
    command: /Users/YOU/.local/bin/sil-mcp
    enabled: true
```

## Checking it actually works

Config being present is not the same as the agent being able to call it.

```bash
hermes mcp test secret-input-layer     # connects, lists the 10 tools
codex mcp get secret-input-layer       # shows the registered command
codex exec "Call secret_health and reply with its backend and version."
hermes chat --oneshot -Q -q "Call secret_health and reply with its backend and version."
claude mcp list | grep secret-input-layer
```

All four were run on this machine; Codex and Hermes both returned
`keychain 0.3.x` from a real tool call.

## Waking an agent that is not blocked

Everything that settles — saved, declined, or timed out — is published to a
value-free feed and appended to `~/.secret-input-layer/events.jsonl`.

```bash
sil events --wait 300                  # block until the next one
sil wait <request_id> --seconds 300    # block on one request
curl -s -H "Authorization: Bearer $(cat ~/.secret-input-layer/api-token)" \
     -H "Host: 127.0.0.1:7717" \
     "http://127.0.0.1:7717/api/events?since=0&wait=300"
```

Or have the broker push, by passing `notify` on the request:

```json
{"name": "stripe.secret_key", "wait": 0,
 "notify": {"command": ["/usr/bin/osascript", "-e",
                        "display notification \"secret ready\""],
            "webhook": "http://127.0.0.1:9100/secret-ready"}}
```

The command gets `SIL_NAME`, `SIL_STATE`, `SIL_FINGERPRINT`, `SIL_REQUEST_ID`
in its environment — never the value. Webhooks are restricted to `127.0.0.1`
and `localhost` on purpose: a notification must not become an exfiltration
channel.

## Anything else

- **CLI**: `sil request <name> --purpose "..."`, then `sil run --env VAR=<name> -- cmd`.
- **HTTP**: `POST http://127.0.0.1:7717/api/request` with
  `Authorization: Bearer $(cat ~/.secret-input-layer/api-token)` and
  `Host: 127.0.0.1:7717`. Routes are listed in `sil/server.py`.

## Undo

```bash
sil stop
claude mcp remove --scope user secret-input-layer
rm ~/.local/bin/sil ~/.local/bin/sil-mcp
rm -rf ~/.claude/skills/secret-input ~/.claude/commands/secret.md
# then drop the block from ~/.codex/config.toml and ~/.hermes/config.yaml
```

Config files are backed up as `<file>.bak-sil-<timestamp>` before any edit.
