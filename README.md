# delegated-sudo

Give an agent or another local process temporary permission to run selected
commands as root, without sharing your system password.

An administrator creates a **named grant**: a permitted command, an expiration
time, and a random secret token. The holder presents that token on each execution.
The application checks the grant and runs the permitted command directly.
Only token hashes are stored; the secret is shown once when the grant is created or renewed.

The application is a single Rust binary. This build targets NixOS and uses
ordinary sudo to obtain root privileges. Installation must establish the access
rules below before token execution can work.

## Help

Run without arguments or request help to see every command, including all grant
operations, descriptions, and practical examples in one place:

```bash
delegated-sudo
delegated-sudo --help
```

`-h` and `help` show the same complete guide. Help does not require sudo.

## Required access rules

System authorization and delegation have separate responsibilities:

| Who | Entry point | Required system authorization |
| --- | --- | --- |
| Intended token users | The installed `delegated-sudo` binary followed by `exec ...` | May run this entry point as root without a system password; a valid token is still required |
| Trusted administrators | `delegated-sudo grant create/list/show/extend/revoke/delete` | Ordinary administrative sudo access, including its normal credential cache |

Your installation or configuration must enforce these conditions:

- Authorize the exact trusted binary and its `exec` entry point. Do not give
  token users unrestricted sudo, passwordless `grant` access, or permission to
  replace the binary. They do not need membership in an administrator group.
- Use ordinary sudo authentication and its configured credential cache for grant
  management. Do not force reauthentication or reset the existing sudo session.
  The system verifies the administrator's password; this application handles only
  delegation tokens. An existing root session already has administrative authority.
- Apply the rules to the paths users actually invoke, including supported
  aliases. Keep the installed binary and authorization rules synchronized, and
  check that broader rules do not override the intended restrictions.
- Keep grant storage owned by root and inaccessible to other users. Users must
  neither edit grants nor gain access by changing storage permissions.
- Keep token input and creation output out of terminal/session recordings and
  sudo I/O logs. Do not allow callers to override the privileged environment.

The application validates grants; it does not install or repair the host's sudo
policy. Deployment scripts may differ, but these authorization conditions must
remain the same.

## Grant a command

Every grant requires a unique name. Use a short descriptive name such as
`docker-compose-codex`, or quote a name containing spaces: `"Docker Compose Codex"`.
Names are case-sensitive, accept up to 80 characters, and cannot start with a dash
or contain control characters, invisible formatting, or leading/trailing whitespace.

To enter a command naturally, start creation without a command argument:

```bash
sudo delegated-sudo grant create docker-compose-codex --ttl 30d
```

At the `Command:` prompt, enter:

```text
docker compose *
```

The final `*` permits zero or more additional arguments. At this prompt it needs
no quotes or escaping and is never expanded to filenames. Quotes group arguments
containing spaces, such as `docker compose --file 'a b.yml' *`. This input is parsed
as arguments; it does not execute a shell, substitute variables, or expand globs.
Interactive entry requires a terminal.

For scripts or a single shell command, provide the invocation after `--`:

```bash
sudo delegated-sudo grant create deploy --ttl 60m -- docker compose up -d
sudo delegated-sudo grant create compose --ttl 30d --allow-args -- docker compose
```

The first grant permits exactly `docker compose up -d`. Changed subcommands,
flags, argument order, or additional arguments are rejected. The second permits
any arguments after `docker compose`. Use `--allow-args` for a one-line command so
the calling shell has no star to expand. A final quoted or escaped `*` is also
supported, but a bare `*` on a Bash/Zsh command line becomes filenames before this
application starts. Those filenames are indistinguishable from intentional
literal arguments. For a bare star, use the interactive `Command:` prompt above.
Neither `--allow-args` nor the marker belongs in the command used for execution.

For a holder trusted with every operation of an executable, use the broader mode:

```bash
sudo delegated-sudo grant create maintenance --commands docker,systemctl --ttl 30d
```

This permits arbitrary subcommands and arguments, subject to the shell-syntax
restriction below. It cannot be combined with an exact or prefix command.

Commands must be available in the system profile or supplied by an absolute Nix
store path. Each grant records the executable's resolved identity; a replacement
from the holder's PATH cannot take its place. The application cannot grant itself.

Creation prints a compact block:

```text
delegated-sudo grant docker-compose-codex:
- command: docker compose *
- dir: any
- token: <secret token>
- expires: <expiration date and time in UTC>
```

The command includes the complete fixed arguments and any final `*` marker.
The `- dir:` field always shows where execution is allowed: `/path` for that exact
directory, `/path/*` for it and all descendants, or `any` for no directory restriction.
Pass the token privately to its intended holder. Anyone who obtains it can use
it; tokens are not tied to a username or process. The name identifies the grant
for administration; only its secret token authorizes execution.

## Restrict the working directory

Add `--dir` to any creation form to limit where the holder may launch the command:

```bash
sudo delegated-sudo grant create project --ttl 30d --dir /srv/app --allow-args -- docker compose
sudo delegated-sudo grant create project-tree --ttl 30d --dir /srv/app --recursive --allow-args -- docker compose
```

`--dir /srv/app` permits only that directory. Add `--recursive` to permit the
directory itself and all descendants, at any depth, without a shell wildcard.
`--recursive` requires `--dir`. The equivalent legacy form `--dir '/srv/app/*'`
is also supported; quote that pattern so the shell does not expand it.
Without `--dir`, any working directory is allowed. Relative paths are resolved
from the administrator's working directory at creation; output shows the
canonical absolute path, with `/*` for a recursive scope.

Execution checks the holder's actual current directory and refuses a launch
outside the permitted scope. It does not change directories automatically.
`..` components and symlinks cannot make an outside location count as inside.
The allowed directory must exist at creation. Its identity is recorded: removing
or replacing that directory requires a new grant; renewal does not rebind it.

This restriction checks the initial working directory. It does not sandbox file
access or prevent the allowed program from changing directories or accessing
other paths through its arguments or configuration.

## Use and manage grants

The bundled [delegated-sudo skill](skills/delegated-sudo/SKILL.md) explains how an
agent helps you prepare a grant and then uses the token within its permitted scope.

Run the permitted command without a leading `sudo`:

```bash
delegated-sudo exec docker compose up -d
```

The application elevates through its configured entry point and asks for
`Delegation token:` with hidden input. Use the executable name or its recorded
executable path. The command inherits the working directory and standard streams
and runs with a clean root environment.

For automation, supply the token as stdin's first line:

```bash
delegated-sudo exec --token-stdin docker compose up -d < /private/path/token
```

Remaining stdin is passed to the command. Tokens are not accepted in command
arguments or environment variables. Keep token files private.

Administrators manage grants by their unique names:

```bash
sudo delegated-sudo grant list
sudo delegated-sudo grant show docker-compose-codex
sudo delegated-sudo grant extend docker-compose-codex --ttl 30d
sudo delegated-sudo grant revoke docker-compose-codex
sudo delegated-sudo grant delete docker-compose-codex
```

`list` shows names, full permitted commands, expiration times in UTC, and
`active`, `expired`, or `revoked` status. It uses a compact table when fields fit
and labeled rows for narrow terminals or long names/commands. When any grant has
a directory restriction, the list includes a `DIR` column or `Directory:` line;
`any` means unrestricted. `show` also gives the directory scope,
the recorded executable paths and exact argument policy. Neither exposes tokens
or hashes.

TTL accepts a positive integer followed by `s`, `m`, `h`, or `d`, up to **30 days**
(`30d`). A day is 24 hours; the maximum is a fixed duration, not a calendar month.
`extend` sets expiration to the current time plus the supplied TTL, whether the
grant is active or expired. It issues and displays a new token; the previous token
immediately stops working. The name, command scope, directory scope, and original
creation time stay unchanged. A revoked grant cannot be renewed.

`revoke` disables a grant but keeps it visible for inspection. `delete` removes
its record and invalidates its token; its name can then be used for a new grant.
Expired grants remain visible until deleted. To change command scope, delete the
grant and create a new one with the desired command.

When upgrading from the old ID-based format, existing unnamed grants are removed
on the first access to storage by the new version. Their tokens stop working.
Create replacement grants with explicit names; there is no ID-based management.

## What the grant controls

The application launches one executable directly, without a shell. It rejects
`;`, `&`, `|`, `<`, `>`, backticks, `$(`, `${`, and control characters in received
commands and arguments, including quoted literal occurrences. A calling shell
processes its own operators first: an unquoted `&&` starts a separate command
in that shell and receives no privileges from the grant.

Argument matching controls the invocation, not everything the allowed program
can do. Docker, interpreters, and other administration tools can provide full
root access. Extra parameters, working directories, and configuration files can
also change an operation's effects. Trust the holder with those capabilities;
use exact grants and administrator-controlled inputs when the scope must be narrow.

Expiration, renewal, revocation, and deletion prevent new launches with old or
inactive tokens. They do not stop existing
processes or undo changes. Grants follow the system clock and remain tied to the
recorded executable version; if it is removed, create a new grant for its replacement.

## Build

Requires Rust 1.85 or newer and Linux 5.11 or newer:

```bash
cargo build --release --locked
cargo test --locked
```

The binary is `target/release/delegated-sudo`. Building it alone does not grant
system privileges; installation must also provide the authorization described above.
