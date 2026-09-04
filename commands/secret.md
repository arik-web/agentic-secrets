---
description: Ask the human for a secret through the local paste window
argument-hint: <secret-name> [purpose]
allowed-tools: mcp__secret-input-layer__secret_request, mcp__secret-input-layer__secret_list, mcp__secret-input-layer__secret_health
---

Request the secret `$1` from the human using `secret_request`.

- `name`: `$1`
- `purpose`: `$2` (if empty, infer it from the current task and say so)
- `requested_by`: your agent name
- `wait`: 300

Do not ask for the value in chat. Report only the returned state and
fingerprint. If the state is `already_stored`, say so and use the existing
secret rather than asking again.
