# Secret Input Layer

Agents need secrets. You do not want to paste secrets into a chat.

This is a local broker. An agent asks for a named secret; a small window opens
on your screen; you paste the value; it lands in your **macOS Keychain**. The
agent is told *that it worked* — never *what it is*. Then the agent uses it
without reading it: injected into a command's environment, or rendered into a
`0600` config file.

Works for Claude Code, Codex, Hermes, or anything that can speak MCP, run a
CLI, or make an HTTP request to loopback.

## Install

```bash
./install.sh          # launchers in ~/.local/bin, wiring for every agent found
./run-tests.sh        # 79 tests
```

## The flow

```
agent            broker (127.0.0.1)          you
  |  secret_request("stripe.secret_key")      |
  |------------------------------------------>|  window opens
  |                                           |  paste ────────► Keychain
  |<-- {state: fulfilled, fingerprint: 7a1e}  |
  |  secret_run(["stripe","balance"], {SK: "stripe.secret_key"})
  |<-- stdout, with the value scrubbed out    |
```

## Being told when it lands

`secret_request` blocks and returns the instant you hit Save — for most work
that is the whole story. When the agent cannot stay blocked:

- `secret_events` — long-poll the settle feed from any process, any agent, any
  later turn. Events carry name, state and fingerprint; never a value.
- `notify` on the request — an argv `command` or a loopback `webhook` fired on
  settle, so something can wake an agent whose turn already ended:

```bash
sil request stripe.secret_key --wait 0 \
  --notify-webhook http://127.0.0.1:9100/secret-ready

sil events --since 0 --wait 300        # or just block here
```

Declines and timeouts signal too — you are never left waiting on a window the
human already closed.

## Using it as an agent

| Tool | What it does |
|---|---|
| `secret_request` | Opens the paste window. Blocks until you answer. Returns state + fingerprint. |
| `secret_status` | Polls a request created with `wait: 0`. |
| `secret_wait` | Blocks on one request until it is answered, declined or expires. |
| `secret_events` | The feed of everything that settled, with a cursor. Pass `wait` to long-poll — this is how an agent that did not stay blocked, or a *different* agent, finds out. |
| `secret_list` / `secret_describe` | Names and metadata. Never values. |
| `secret_run` | Runs a command with secrets in its environment; output is scrubbed. |
| `secret_write_file` | Renders `{{secret:name}}` into a `0600` file. |
| `secret_delete` | Forgets a secret. |
| `secret_health` | Is the broker up, and which store is it using. |

## Using it as a human

```bash
sil status                          # is the broker up
sil request stripe.secret_key --purpose "charge the test account"
sil paste github.pat                # type it here instead of the browser
sil list                            # names, lengths, fingerprints
sil run --env SK=stripe.secret_key -- stripe balance retrieve
sil write ~/app/.env --template 'STRIPE_KEY={{secret:stripe.secret_key}}'
sil rm stripe.secret_key
```

## More than one box

Most credentials are a pair. Ask once:

```bash
sil request kraken --preset api_key_secret --purpose "place a test order"
sil request pg.prod --field host --field user --field password
```

Presets: `token`, `api_key`, `api_key_secret`, `username_password`,
`oauth_client`, `connection_string`, `private_key`, `aws_keys`,
`basic_auth_totp`. Each box is stored as its own secret — `kraken.api_key`,
`kraken.api_secret` — so `secret_run` and `{{secret:...}}` reference them
independently. A username renders as a plain text box; a private key gets a
textarea; optional boxes may be left blank.

## Naming

`<system>.<what>`, lowercase: `openai.api_key`, `postgres.prod_url`,
`github.pat`. Stable names mean you paste once and every agent reuses it.

## What protects what

- **Values never cross the API.** `get` exists in one module; no route returns it.
- **Keychain**, through `Security.framework` directly — the value is never a
  process argument, so it cannot be read out of `ps`.
- **Loopback only**, plus a bearer token in `~/.secret-input-layer/api-token`
  (`0600`) and a pinned `Host` header, so no web page can reach the broker.
- **One-shot paste links.** A used or expired link is gone; requests expire in
  15 minutes.
- **Output scrubbing** on `secret_run`, covering raw, base64 and URL-encoded
  forms of the value — applied before truncation, so nothing survives at the
  size boundary.
- **Write destinations are constrained.** `secret_write_file` refuses modes that
  grant group or other access, refuses to follow a symlink, and refuses shell
  startup files, `authorized_keys`, `sudoers` and `LaunchAgents` — the paths
  that would turn a file write into code execution.
- **Fingerprints use scrypt, not a bare hash.** The salt is readable by anything
  running as you, so a single-pass digest of a short secret would be a free
  offline oracle.

### What it does not protect against

An agent that already runs shell commands as you can read your Keychain by
other means. The broker and the agent run as the same OS user: an agent can
point `secret_write_file` at a path it is then allowed to `cat`, or run a
command that transforms the value before printing it. This layer removes the
secret from **the transcript** and from casual command output — that is the
threat it is built for. It is a guardrail, not a sandbox. `secret_run`
deliberately reports which secrets it had to scrub.

Minimum secret length is 4 characters, because anything shorter cannot be
scrubbed from output without also mangling ordinary text.

## Where things live

```
~/.secret-input-layer/
  api-token          bearer token for the local API (0600)
  index.json         metadata: names, purposes, lengths, fingerprints (no values)
  fingerprint-salt   so fingerprints cannot be brute-forced back to a value
  daemon.log         method + path only, never a body
```

Secret values live in the login Keychain under service `sil.<name>`. On a host
without a Keychain they fall back to `0600` files in
`~/.secret-input-layer/store/` — the daemon reports which backend is live in
`sil status`.

## Layout

| Path | What |
|---|---|
| `sil/keychain.py` | `Security.framework` bindings |
| `sil/store.py` | persistence + metadata index |
| `sil/pending.py` | outstanding asks, one-shot tokens |
| `sil/consume.py` | the two ways a value is spent |
| `sil/api.py` | behaviour, transport-free |
| `sil/server.py` | loopback HTTP + the paste form |
| `sil/mcp_server.py` | MCP over stdio, zero dependencies |
| `sil/cli.py` | the `sil` command |
| `docs/wiring.md` | per-agent configuration |

Python 3.9+, standard library only.
