---
name: secret-input
description: Use whenever a task needs a credential the human has not given you - an API key, token, password, connection string, private key, or 2FA seed. Also use when a command fails with an auth error, when a .env or config file needs a real value, or when you are about to write a placeholder like YOUR_API_KEY_HERE. Never ask for a secret in the chat.
---

# Secret input layer

The human will not paste secrets into the transcript. Ask through the broker.

## The rule

**Never** type, request, echo, log, or guess a secret value. If a task needs
one, call the tool. You are told that it worked - never what it is.

## Flow

1. `secret_list` - it may already be stored. Reuse it.
2. `secret_request` with a stable `name` (`openai.api_key`, `pg.prod_url`),
   a plain-language `purpose`, and the `target` where it will land.
   A paste window opens on the human's screen; the call blocks until they
   answer or `wait` seconds pass.

   **Ask for everything you need in one window.** A credential is rarely one
   string. Use `preset` for a known shape, or `fields` for anything else -
   each field is stored as its own secret named `<name>.<field>`:

   | preset | boxes shown | stored as |
   |---|---|---|
   | `api_key_secret` | API key, API secret | `<name>.api_key`, `<name>.api_secret` |
   | `username_password` | Username (plain), Password | `<name>.username`, `<name>.password` |
   | `oauth_client` | Client ID, Client secret | `<name>.client_id`, `<name>.client_secret` |
   | `aws_keys` | Access key ID, Secret access key | `<name>.access_key_id`, `<name>.secret_access_key` |
   | `token`, `api_key`, `connection_string`, `private_key` | one box | `<name>.<field>` |
   | `basic_auth_totp` | Username, Password, TOTP seed (optional) | three names |

   Custom: `fields: ["host", "port", {"name": "password", "kind": "secret"}]`.
   `kind` is `secret` (masked), `text` (a username - not masked) or
   `multiline` (a key block). `required: false` makes a box optional.
   Never send two requests for two halves of one credential.
3. Know when it landed. `secret_request` already blocks and returns the
   moment the human hits Save - that is the signal, and it is the normal case.
   If you passed `wait: 0`:
   - `secret_wait` - block on that one request.
   - `secret_events` - long-poll the feed of everything that settled; works
     from a different agent, a different process, a later turn. Keep the
     `cursor` it returns and pass it back as `since`.
   - `notify` on the original request - a `command` argv or a loopback
     `webhook` fired on settle, for when your turn will end before the human
     answers. It carries `SIL_NAME`, `SIL_STATE`, `SIL_FINGERPRINT`,
     `SIL_REQUEST_ID` - never the value.
4. Use it:
   - `secret_run` - run a command with the secret in its environment.
     Output comes back with the value scrubbed.
   - `secret_write_file` - render `{{secret:name}}` into a 0600 file
     (`.env`, a config file, a credentials file).

## Waiting well

Do not spin. `secret_request` with a `wait` is one call that returns when the
human is done. If you must go async, long-poll `secret_events` rather than
calling `secret_status` in a loop.

## Naming

`<system>.<what>`, lowercase, dots or dashes: `stripe.secret_key`,
`github.pat`, `postgres.prod_url`. Stable names mean the human pastes once.

## States you will get back

- `fulfilled` - stored. Proceed.
- `already_stored` - it exists. Use it; pass `overwrite: true` only if the
  human said it is stale.
- `cancelled` - the human declined. Do not re-ask; ask what to do instead.
- `expired` - nobody was at the screen. Say so and offer to retry.

## Do not

- Do not print a secret name plus its value into a file you also `cat`.
- Do not work around a `cancelled` request.
- Do not use `secret_run` to exfiltrate a value (`echo $TOKEN | base64`).
  Redaction is a guardrail, not a permission.
