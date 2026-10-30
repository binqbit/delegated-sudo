---
name: delegated-sudo
description: Automatically use this skill whenever a task concerns delegated-sudo or delegated permissions to execute commands, including grant setup, tokens, usage, renewal, and troubleshooting. Help users manage grants and use them for authorized privileged work.
---

# Delegated sudo

This skill supports two tasks: help the user grant access, then use that access
for the requested work. A grant has a unique name, command scope, optional working
directory restriction, expiration, and a secret bearer token. The name is for
administration; the token authenticates execution. Possession of a token does not
expand the user's instructions or authorize grant administration.

Never request the system password. The user enters it directly into ordinary
sudo when needed. Grant management reuses the normal sudo credential cache;
do not reset it with `sudo -k` or require a fresh login.

## Help the user create or manage a grant

Prepare concrete commands for the user to run in their own terminal. Do not run
these administrative examples merely because the user authorized a delegated
task. When local tools are available, check `delegated-sudo --help` to confirm
that the installed version supports the proposed syntax. Help needs no sudo and
shows the complete command guide. If an installed version lacks a required
option, explain that it needs updating; do not silently remove the restriction.

Use the task context to determine the required command, working directory,
lifetime, and grant name. Suggest a descriptive name and a suitable duration
when unspecified. Ask about missing choices that change the intended permission,
such as exact invocation versus multiple subcommands or one directory versus its
descendants. Do not ask again for scope already provided.

Prefer the narrowest scope that fully supports the authorized task. For exactly
`docker compose up -d` in `/srv/app` for one hour, give this ready-to-run command:

```bash
sudo delegated-sudo grant create compose-up --ttl 60m --dir /srv/app -- docker compose up -d
```

When the user authorizes multiple Compose operations in that project and its
subdirectories, a prefix grant can be appropriate:

```bash
sudo delegated-sudo grant create compose-codex --ttl 1d --dir /srv/app --recursive --allow-args -- docker compose
```

`--allow-args` permits additional arguments after the fixed `docker compose`
prefix; the resulting grant displays `docker compose *`. Prefer this flag in
shell commands so the command scope cannot be changed by shell glob expansion.
It cannot be combined with `--commands`. If the installed version lacks this
flag, use the interactive command-entry form below instead.

`--recursive` independently extends `--dir` to include that directory and all
descendants; it requires a directory and does not change command arguments.
Prefer this form so no directory wildcard passes through the shell. For an
installed version without `--recursive`, the equivalent `--dir '/srv/app/*'`
is supported: quote the whole path. Never give the user a bare shell star; it
may become filenames before delegated-sudo starts.

For interactive command entry with the same directory-tree scope, give the user
the launch command and prompt input separately. The quoted path also works with
versions that lack `--recursive`:

```bash
sudo delegated-sudo grant create compose-codex --ttl 1d --dir '/srv/app/*'
```

Then enter at `Command:`:

```text
docker compose *
```

The star needs no quotes or escaping at this prompt. Command arguments containing
spaces still need grouping, for example `docker compose --file 'a b.yml' *`.

Use broad executable access only when the user's task calls for those full
capabilities, for example:

```bash
sudo delegated-sudo grant create maintenance --ttl 2h --commands docker,systemctl
```

`--commands` cannot be combined with a command after `--`. It also accepts `--dir`.
Names are unique and case-sensitive; quote names containing spaces. TTL accepts
positive integers with `s`, `m`, `h`, or `d`, up to 30 days (`30d`).

`--dir /srv/app` permits only that directory. Add `--recursive` to permit its
descendants; output represents that scope as `/srv/app/*`. Omitting `--dir`
leaves the working directory unrestricted. Relative paths are resolved at
creation, and the directory must exist. This checks the
initial working directory, not the files the program can access: for example,
Docker's `-f /other/compose.yml` can still select another file when arguments allow
it. Do not describe a directory grant as a filesystem sandbox.

Creation displays the information needed to use the grant:

```text
delegated-sudo grant compose-codex:
- command: docker compose *
- dir: /srv/app/*
- token: <secret token>
- expires: <date and time in UTC>
```

Ask the user to supply the token through the available private input/file
mechanism and provide any missing command, directory, or expiration information.
Never repeat the secret in the response. `dir: any` means no directory restriction.
A token alone does not reveal its permissions.

For inspection or lifecycle changes, provide the relevant command for the user:

```bash
sudo delegated-sudo grant list
sudo delegated-sudo grant show compose-codex
sudo delegated-sudo grant extend compose-codex --ttl 1d
sudo delegated-sudo grant revoke compose-codex
sudo delegated-sudo grant delete compose-codex
```

`show` supplies scope and expiration without exposing a token. `extend` renews an
active or expired grant from the current time, preserving its name, command, and
directory scope. It prints a new token and immediately invalidates the old one;
the user must supply the replacement before the agent can continue. `revoke`
disables access but retains the record; revoked grants cannot be extended.
`delete` removes the grant and frees its name. Changing command or directory
scope requires a new grant; do not widen permissions as an automatic retry.

## Use a grant supplied by the user

### Interpret the permission

Follow both the user's instructions and the grant's restrictions, whichever is
narrower. Use the supplied scope; do not probe unrelated commands to discover
what the token allows. If scope is missing, ask for it or give the user the
`grant show NAME` command above.

| Supplied command scope | Allowed invocation |
| --- | --- |
| `docker compose up -d` | Exactly those arguments, in that order. No added flags, service names, or changed subcommands. |
| `docker compose up -d *` | Preserve the entire prefix; append zero or more arguments within the user's stated limits, e.g. `docker compose up -d web`. |
| `docker *` or explicit broad Docker access | Choose Docker arguments needed for the authorized task. This does not authorize another executable or unrelated Docker actions. |

In detailed inspection, `Scope: EXACT`, `Scope: PREFIX`, and `Scope: ANY` express
these policies. `Commands: docker` alone does not establish broad access; use
its `Scope:` detail. In creation/renewal output, `- command:` includes the full
scope. Omit the final `*` from execution; it marks permission to append arguments.

Read `- dir:` (or `Directory:` in inspection). Set the execution tool's working
directory to the intended permitted folder: the exact path, or that path and its
descendants for `/*`. `any` imposes no grant directory restriction. The wrapper
inherits cwd and never changes it automatically. Symlinks and `..` cannot make an
outside location count as inside. If the recorded root directory was replaced,
a new grant is needed; renewal preserves the original directory binding.

### Execute and supply the token

Use this entry point without a leading sudo:

```text
delegated-sudo exec [--token-stdin] -- EXECUTABLE ARGUMENT...
```

Put wrapper options before `--` and command options after the executable. Use the
granted executable name or recorded path. Preserve argument boundaries; do not
pass the entire invocation as one quoted string. Prefer an argument array when
the tool supports one. In shell tools, quote individual arguments as needed.

Use the raw token: `dst_` followed by 64 lowercase hexadecimal characters.
A grant name or token hash cannot authenticate. Exclude the `- token:` label,
quotes, and surrounding spaces. Never put tokens in command arguments,
environment variables, shell code, or visible output.

With a terminal (PTY):

```bash
delegated-sudo exec -- docker compose up -d
```

Wait for `Delegation token:`, then send the token and a newline as terminal input.
Echo is disabled before the prompt; tool input may still be recorded. Do not use
`--token-stdin` on an echoing PTY.

For automation, supply the token plus newline through the tool's stdin pipe, or
use a private token file:

```bash
delegated-sudo exec --token-stdin -- docker compose up -d < /private/path/deploy.token
```

Only stdin's first line is consumed as the token; remaining input reaches the
command. The example's `<` is a caller-side redirect, not a delegated argument.
A token-only file leaves the command at EOF. Supply the token on every call;
there is no token login session.

For repeated calls, reuse a user-provided private file when available. If a file
is needed, use the established private credentials workspace, or an agent-owned
private temporary directory if none exists. Create the directory with mode `0700`
and the file with `0600`, containing one token line. Keep it out
of version control; in a repository, verify that its destination is ignored and
untracked before writing. Use a file/stdin interface without embedding the secret
in shell code. Remove disposable token files you created after use; preserve
user-owned or explicitly retained files. Never copy tokens into logs,
documentation, or agent memory.

The CLI executes one program directly. It rejects `;`, `&`, `|`, `<`, `>`,
backticks, `$(`, `${`, and control characters in received command arguments,
even when quoted. Do not add shell chains, substitutions, or wrappers to obtain
extra execution. Program options, configuration, and file access must also stay
within the user's authorization; a matching invocation is not permission for
unrelated effects.

### Handle rejection

If a call fails, report the actual failure. Distinguish a denied invocation from
a permitted program that ran and returned its own error. For a wrong cwd or an
argument mismatch, correct the call only within the already agreed scope. For
expiration or a lost/rotated token, help the user renew or provide valid access
using the first section. Revoked/deleted grants or a changed command/directory
scope require a new grant. Do not fall back to ordinary sudo, administer grants
using the token, or circumvent the restriction. Expiration, rotation, revocation,
and deletion prevent new launches; they do not stop already-running processes.
