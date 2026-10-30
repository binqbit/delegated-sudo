---
name: delegated-sudo
description: Use when a user offers an agent temporary privileged command access through delegated-sudo, or supplies a delegation token and permitted commands. Interpret command scope, handle tokens, and execute authorized operations without ordinary sudo access.
---

# Delegated sudo

Use `delegated-sudo exec` instead of ordinary `sudo` for commands the user has
authorized. A token enables execution; it does not expand the user's permission.
Ask only for missing token or scope information, never the system password.

## Understand the permission

Follow both the user's instructions and the grant's restrictions, whichever is
narrower. A token is opaque: its text does not reveal its scope. Use the scope
the user supplies; do not probe other commands to discover access.

| User permission / grant scope | Allowed invocation |
| --- | --- |
| Only `docker compose up -d` / `Scope: EXACT docker compose up -d` | Exactly that executable and those arguments, in that order. No added flags, service names, or changed subcommands. |
| `docker compose up -d` with additional arguments allowed / `Scope: PREFIX docker compose up -d *` | Keep the entire prefix; append zero or more arguments within the user's stated limits, e.g. `docker compose up -d web`. Do not change the prefix to `compose down` or insert flags into it. |
| Explicit permission for any Docker operation / `Scope: ANY arguments and subcommands` for `docker` | Choose Docker arguments and subcommands needed for the authorized task. This does not authorize another executable. |

A specific command without permission to vary arguments means exact access.
If permission to vary arguments leaves the fixed part unclear, clarify that boundary.
`Commands: docker` alone does not establish broad access; use its `Scope:` detail.
Creation and renewal instead show `- command:` with the full command scope:
`docker compose up -d` is exact, `docker compose *` allows extra arguments after
`compose`, and `docker *` allows any arguments for Docker.
The final `*` in a prefix scope marks permission to append arguments: omit it
from execution; it is not a shell glob or a placeholder inside an argument.

## Call the command

```text
delegated-sudo exec [--token-stdin] -- EXECUTABLE ARGUMENT...
```

Replace the placeholders with the permitted executable name or its recorded
absolute path and separate arguments. Brackets describe an optional flag.
Put wrapper options before `--` and command options after the executable.
Do not pass the whole invocation as one quoted string. In shell-based tools,
quote each argument that needs it: `'release candidate'` is one argument, while
`release candidate` is two. Prefer an argument array when the tool supports one.

Run from the intended working directory; the command inherits it.

Do not append shell chains, substitutions, or a shell wrapper to obtain additional
execution.
The CLI rejects `;`, `&`, `|`, `<`, `>`, backticks, `$(`, `${`, and control characters
in command arguments, even when quoted. Allowed program options or configuration
files can also execute code; keep their effects within the authorized task.

## Supply or save the token

Use the raw token: `dst_` followed by 64 lowercase hexadecimal characters.
A grant name or token hash cannot authenticate. Do not include the
`- token:` label, quotes, or spaces around the token.

With a terminal (PTY):

```bash
delegated-sudo exec -- docker compose up -d
```

Wait for `Delegation token:`, then send the token and a newline as terminal input.
Echo is disabled before the prompt. Do not put the token in command text,
arguments, environment variables, or output; tool input may still be recorded.

For automation, use `--token-stdin` and supply the token plus a newline through
the tool's stdin pipe, or use a private token file:

```bash
delegated-sudo exec --token-stdin -- docker compose up -d < /private/path/deploy.token
```

For repeated calls, you may save the supplied token as one plain-text line ending
in a newline. Create an agent-owned file with mode `0600` inside a private `0700`
directory outside the repository; restrict access from creation, not afterward.
Write through a file/stdin interface without embedding the secret in shell code.
Reuse a user-provided private file when available. Remove temporary token files
you created after use; do not copy tokens into documentation or agent memory.

The example's `<` supplies stdin to the wrapper; it is not a delegated argument.
Only stdin's first line is consumed as the token; remaining input reaches the
command. A token-only file leaves the command at EOF. Do not use `--token-stdin`
on an echoing PTY. Supply the token on every invocation; there is no token login
session.

If access expires, is revoked/deleted, or the command is rejected, report the
rejection and request valid access for the required operation. Renewing a grant
replaces its token immediately; the previous token no longer authenticates.
Do not fall back to ordinary sudo or create, inspect, extend, revoke, or delete
grants as part of this execution skill.
