# delegated-sudo

Give an agent or another local process temporary permission to run selected
commands as root, without sharing your system password.

An administrator creates a **grant**: a permitted command, an expiration time,
and a random secret token. The holder presents that token on each execution.
The application checks the grant and runs the permitted command directly.
Only token hashes are stored; the secret is shown once when the grant is created.

The application is a single Rust binary. This build targets NixOS and uses
ordinary sudo to obtain root privileges. Installation must establish the access
rules below before token execution can work.

## Required access rules

System authorization and delegation have separate responsibilities:

| Who | Entry point | Required system authorization |
| --- | --- | --- |
| Intended token users | The installed `delegated-sudo` binary followed by `exec ...` | May run this entry point as root without a system password; a valid token is still required |
| Trusted administrators | `delegated-sudo grant create/list/show/extend/revoke` | Ordinary administrative sudo access, with fresh system authentication for each invocation |

Your installation or configuration must enforce these conditions:

- Authorize the exact trusted binary and its `exec` entry point. Do not give
  token users unrestricted sudo, passwordless `grant` access, or permission to
  replace the binary. They do not need membership in an administrator group.
- Require fresh system authentication for grant management even when sudo has
  cached credentials. The system verifies the administrator's password; this
  application handles only delegation tokens. An existing root session already
  has administrative authority.
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

Prefer a grant for the exact operation the holder needs:

```bash
sudo delegated-sudo grant create --ttl 60m -- docker compose up -d
```

This permits exactly `docker compose up -d`. Changed subcommands, flags, argument
order, or additional arguments are rejected.

To permit extra parameters after a fixed beginning, add a final quoted `'*'`:

```bash
sudo delegated-sudo grant create --ttl 60m -- docker compose up -d '*'
```

This also permits `docker compose up -d my-service`, while the fixed beginning
must still match. Quote the star so your shell does not expand it. It belongs in
the grant definition, not in the command used to execute the operation.

For a holder trusted with every operation of an executable, use the broader mode:

```bash
sudo delegated-sudo grant create --commands docker,systemctl --ttl 60m
```

This permits arbitrary subcommands and arguments, subject to the shell-syntax
restriction below. It cannot be combined with an exact or prefix command.

Commands must be available in the system profile or supplied by an absolute Nix
store path. Each grant records the executable's resolved identity; a replacement
from the holder's PATH cannot take its place. The application cannot grant itself.

Creation prints the grant ID, permitted command scope, expiration, and token.
Pass the token privately to its intended holder. Anyone who obtains it can use
it; tokens are not tied to a username or process.

## Use and manage grants

For agent integration, use the bundled [delegated-sudo skill](skills/delegated-sudo/SKILL.md).

Run the permitted command without a leading `sudo`:

```bash
delegated-sudo exec docker compose up -d
```

The application elevates through its configured entry point and asks for
`Delegation token:` with hidden input. Use the granted name or its recorded
executable path. The command inherits the working directory and standard streams
and runs with a clean root environment.

For automation, supply the token as stdin's first line:

```bash
delegated-sudo exec --token-stdin docker compose up -d < /private/path/token
```

Remaining stdin is passed to the command. Tokens are not accepted in command
arguments or environment variables. Keep token files private.

Administrators can inspect, extend, or revoke grants:

```bash
sudo delegated-sudo grant list
sudo delegated-sudo grant show dg_REPLACE_WITH_GRANT_ID
sudo delegated-sudo grant extend dg_REPLACE_WITH_GRANT_ID --ttl 30m
sudo delegated-sudo grant revoke dg_REPLACE_WITH_GRANT_ID
```

TTL accepts a positive integer followed by `s`, `m`, `h`, or `d`, up to seven
days. Extension adds time to the existing expiration, with at most seven days
remaining. Expired or revoked grants cannot be reactivated. To narrow a grant
or replace a lost token, revoke it and create another. Inspection never reveals
the token or its hash.

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

Expiration and revocation prevent new launches. They do not stop existing
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
