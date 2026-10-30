//! Argument parsing and conversion into application requests.

use crate::model::Request;
use clap::{Parser, Subcommand};
use std::io::{self, IsTerminal, Write};

const OVERVIEW: &str = r#"delegated-sudo - temporary root access for named commands

Create a named grant as an administrator, then share its secret token with the
holder. The holder uses that token to execute the permitted command as root.

CREATE A GRANT (ordinary sudo authorization)

  Interactive command entry:
    sudo delegated-sudo grant create <NAME> --ttl <TTL>
    Enter the command at the Command: prompt. A final * allows extra arguments.
    Example:
      sudo delegated-sudo grant create compose-codex --ttl 30d
      Command: docker compose *
    At this prompt, the star needs no quotes or escaping.

  Exact command:
    sudo delegated-sudo grant create <NAME> --ttl <TTL> -- <COMMAND> [ARGUMENTS...]
    Only this executable and these exact arguments are permitted.
    Example:
      sudo delegated-sudo grant create deploy --ttl 60m -- docker compose up -d

  Command with additional arguments allowed:
    sudo delegated-sudo grant create <NAME> --ttl <TTL> --allow-args -- <COMMAND> [ARGUMENTS...]
    Keep the fixed beginning; the holder may append zero or more arguments.
    Example:
      sudo delegated-sudo grant create compose-codex --ttl 30d --allow-args -- docker compose
    No star is needed. A literal final * is also supported at the interactive
    prompt or as \* / '*' in a shell command. A bare shell * expands to filenames
    before delegated-sudo receives it; use --allow-args for one-line commands.

  All operations of selected executables:
    sudo delegated-sudo grant create <NAME> --ttl <TTL> --commands <EXECUTABLES>
    Comma-separated executables; allow any arguments and subcommands, subject to
    the shell-syntax restriction below.
    Example:
      sudo delegated-sudo grant create maintenance --ttl 1d --commands docker,systemctl

  Creation displays the command, directory scope, secret token, and expiration.
  The dir field is a path, PATH/* for a directory tree, or any if unrestricted.

  Optional working-directory restriction (with any creation form):
    --dir <PATH>                Permit launches only from this existing directory.
    --dir <PATH> --recursive    Permit this directory and all its descendants.
    Examples:
      sudo delegated-sudo grant create project --ttl 30d --dir /srv/app
      sudo delegated-sudo grant create project-tree --ttl 30d --dir /srv/app --recursive
      Command: docker compose *
    No directory star is needed. A quoted --dir '/srv/app/*' remains supported.
    --recursive requires --dir. The displayed directory scope remains /srv/app/*.
    Without --dir, the holder may launch from any working directory.
    The command runs in the holder's current directory; it is never moved.
    Paths are checked after resolving ../ and symlinks; locations outside the
    permitted scope are refused. This checks the initial working directory,
    not filesystem access by the command; it is not a filesystem sandbox.

MANAGE GRANTS BY NAME (ordinary sudo authorization)

  sudo delegated-sudo grant list
    List all grants with their commands, directory restrictions, expiration, and status.
    Expired and revoked grants remain visible. Tokens are never listed.

  sudo delegated-sudo grant show <NAME>
    Inspect command and directory scope, executable paths, expiration, and status.
    Secret tokens are never shown.
    Example: sudo delegated-sudo grant show compose-codex

  sudo delegated-sudo grant extend <NAME> --ttl <TTL>
    Set a new lifetime FROM NOW for an active or expired grant and show a new token.
    The previous token stops working. Name, command, and directory scope stay the same.
    Example: sudo delegated-sudo grant extend compose-codex --ttl 30d

  sudo delegated-sudo grant revoke <NAME>
    Disable the token and keep the grant visible. Revoked grants cannot be extended.
    Example: sudo delegated-sudo grant revoke compose-codex

  sudo delegated-sudo grant delete <NAME>
    Delete the grant, invalidate its token, and make its name available again.
    Example: sudo delegated-sudo grant delete compose-codex

EXECUTE A GRANTED COMMAND (no leading sudo)

  delegated-sudo exec [--] <COMMAND> [ARGUMENTS...]
    Enter the secret at the hidden Delegation token: prompt.
    Example: delegated-sudo exec -- docker compose up -d

  delegated-sudo exec --token-stdin [--] <COMMAND> [ARGUMENTS...]
    Read the token from stdin's first line; remaining input goes to the command.
    Example: delegated-sudo exec --token-stdin -- docker compose up -d < /private/path/token

  Use the granted executable name or its recorded path. Omit the grant's final *.
  Commands run directly; shell operators and substitutions are rejected.
  Supply the token on every invocation; do not put it in arguments or environment.

NAMES AND LIFETIMES

  NAME is required and unique, case-sensitive, and 1-80 characters long.
  Quote spaces, for example "Docker Compose Codex". No leading dash, surrounding
  whitespace, control characters, or invisible formatting.
  TTL is a positive integer followed by s, m, h, or d: 60m, 2h, 7d, 30d.
  Maximum: 30 days (30d). Expiration dates are displayed in UTC.
  Grant administration reuses the ordinary sudo credential cache.

HELP (no sudo required)

  delegated-sudo              Show this complete guide.
  delegated-sudo --help       Show this complete guide.
  delegated-sudo -h           Show this complete guide.
  delegated-sudo help         Show this complete guide.
  delegated-sudo --version    Show the installed version (also -V).
"#;

#[derive(Debug, Parser)]
#[command(
    name = "delegated-sudo",
    version,
    about = "Run root commands with an expiring command-scoped delegation token",
    arg_required_else_help = true,
    override_help = OVERVIEW
)]
pub(super) struct Cli {
    #[command(subcommand)]
    pub action: Action,
}

#[derive(Debug, Subcommand)]
pub(super) enum Action {
    /// Administer grants using normal sudo/root authorization.
    #[command(arg_required_else_help = true, override_help = OVERVIEW)]
    Grant {
        #[command(subcommand)]
        operation: GrantCommand,
    },
    /// Execute a command with a delegation token.
    Exec {
        /// Read the token from stdin's first line; the command receives the rest.
        #[arg(long)]
        token_stdin: bool,
        /// Configured executable name, followed by arguments passed unchanged.
        #[arg(required = true, num_args = 1.., trailing_var_arg = true)]
        command: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub(super) enum GrantCommand {
    /// Grant an exact invocation, an argument prefix, or broad executable access.
    Create {
        /// Unique grant name, used by every management command.
        name: String,
        /// Allow arguments/subcommands for these executables; shell syntax is rejected.
        #[arg(long, value_name = "EXECUTABLES", conflicts_with = "command")]
        commands: Option<String>,
        /// Permit additional arguments after the fixed command; no final star is needed.
        #[arg(long, conflicts_with = "commands")]
        allow_args: bool,
        /// Lifetime from now, such as 60m or 30d (maximum 30 days).
        #[arg(long)]
        ttl: String,
        /// Permit this directory only; add --recursive to include descendants.
        #[arg(long = "dir", value_name = "PATH")]
        directory: Option<String>,
        /// Include all descendants of --dir without a shell star.
        #[arg(long, requires = "directory")]
        recursive: bool,
        /// Command after --; omit to enter it interactively with a literal final *.
        #[arg(last = true, num_args = 1.., value_name = "COMMAND")]
        command: Vec<String>,
    },
    /// List grants without their secret tokens.
    List,
    /// Show a grant's command scope and expiration without its token.
    Show { name: String },
    /// Disable a grant and keep its record for inspection.
    Revoke { name: String },
    /// Delete a grant and invalidate its token; the name becomes available again.
    Delete { name: String },
    /// Reset an active or expired grant's lifetime from now and issue a new token.
    Extend {
        name: String,
        /// New lifetime from now, up to 30d; the previous token stops working.
        #[arg(long)]
        ttl: String,
    },
}

fn parse_command_line(line: &str) -> io::Result<Vec<String>> {
    if line.chars().any(char::is_control) {
        return Err(io::Error::other(
            "Command must not contain control characters",
        ));
    }
    let command = shlex::split(line)
        .ok_or_else(|| io::Error::other("Command has an unfinished quote or escape"))?;
    if command.first().is_none_or(String::is_empty) {
        return Err(io::Error::other("A command is required"));
    }
    Ok(command)
}

fn read_command() -> io::Result<Vec<String>> {
    if !io::stdin().is_terminal() {
        return Err(io::Error::other(
            "Provide -- COMMAND... or --commands EXECUTABLES; interactive command input requires a terminal",
        ));
    }
    let mut stdout = io::stdout().lock();
    writeln!(
        stdout,
        "Enter a command; a final * permits additional arguments."
    )?;
    write!(stdout, "Command: ")?;
    stdout.flush()?;
    let mut line = String::new();
    if io::stdin().read_line(&mut line)? == 0 {
        return Err(io::Error::other(
            "Command input ended before a command was entered",
        ));
    }
    parse_command_line(line.strip_suffix('\n').unwrap_or(&line))
}

fn directory_scope(directory: Option<String>, recursive: bool) -> io::Result<Option<String>> {
    if !recursive {
        return Ok(directory);
    }
    let mut directory = directory.ok_or_else(|| io::Error::other("--recursive requires --dir"))?;
    if directory.is_empty() {
        return Err(io::Error::other("--dir must not be empty"));
    }
    if !directory.ends_with("/*") {
        while directory.len() > 1 && directory.ends_with('/') {
            directory.pop();
        }
        if directory.ends_with('/') {
            directory.push('*');
        } else {
            directory.push_str("/*");
        }
    }
    Ok(Some(directory))
}

impl GrantCommand {
    pub(super) fn into_request(self) -> io::Result<Request> {
        Ok(match self {
            GrantCommand::Create {
                name,
                commands: Some(commands),
                ttl,
                directory,
                recursive,
                ..
            } => Request::Create {
                name,
                commands: commands.split(',').map(String::from).collect(),
                ttl,
                directory: directory_scope(directory, recursive)?,
            },
            GrantCommand::Create {
                name,
                commands: None,
                ttl,
                directory,
                recursive,
                allow_args,
                mut command,
            } => {
                let directory = directory_scope(directory, recursive)?;
                if command.is_empty() {
                    command = read_command()?;
                }
                if allow_args && !command.last().is_some_and(|argument| argument == "*") {
                    command.push("*".into());
                }
                let mut command = command.into_iter();
                Request::CreateCommand {
                    name,
                    command: command
                        .next()
                        .expect("command input must contain an executable"),
                    arguments: command.collect(),
                    ttl,
                    directory,
                }
            }
            GrantCommand::List => Request::List { cursor: None },
            GrantCommand::Show { name } => Request::Show { name },
            GrantCommand::Revoke { name } => Request::Revoke { name },
            GrantCommand::Delete { name } => Request::Delete { name },
            GrantCommand::Extend { name, ttl } => Request::Extend { name, ttl },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_preserves_every_argument_after_executable() {
        let parsed = Cli::try_parse_from([
            "delegated-sudo",
            "exec",
            "--token-stdin",
            "docker",
            "compose",
            "--file",
            "a b.yml",
            "$(literal)",
            "--token-stdin",
            "--",
        ])
        .unwrap();
        match parsed.action {
            Action::Exec {
                token_stdin,
                command,
            } => {
                assert!(token_stdin);
                assert_eq!(
                    command,
                    [
                        "docker",
                        "compose",
                        "--file",
                        "a b.yml",
                        "$(literal)",
                        "--token-stdin",
                        "--"
                    ]
                );
            }
            _ => panic!("wrong action"),
        }
    }

    #[test]
    fn command_grants_preserve_argument_boundaries_and_flags() {
        let parsed = Cli::try_parse_from([
            "delegated-sudo",
            "grant",
            "create",
            "docker-compose-codex",
            "--ttl",
            "60m",
            "--",
            "docker",
            "compose",
            "--file",
            "a b.yml",
            "up",
            "-d",
            "--ttl",
            "literal",
            "",
            "*",
        ])
        .unwrap();
        let Action::Grant { operation } = parsed.action else {
            panic!("wrong action")
        };
        let Request::CreateCommand {
            name,
            command,
            arguments,
            ttl,
            directory,
        } = operation.into_request().unwrap()
        else {
            panic!("wrong scope")
        };
        assert_eq!(name, "docker-compose-codex");
        assert_eq!(command, "docker");
        assert_eq!(
            arguments,
            [
                "compose", "--file", "a b.yml", "up", "-d", "--ttl", "literal", "", "*"
            ]
        );
        assert_eq!(ttl, "60m");
        assert!(directory.is_none());
    }

    #[test]
    fn allow_args_grants_a_fixed_prefix_without_a_shell_star() {
        let parsed = Cli::try_parse_from([
            "delegated-sudo",
            "grant",
            "create",
            "compose-codex",
            "--ttl",
            "30d",
            "--allow-args",
            "--",
            "docker",
            "compose",
            "--file",
            "a b.yml",
            "",
        ])
        .unwrap();
        let Action::Grant { operation } = parsed.action else {
            panic!("wrong action")
        };
        let Request::CreateCommand {
            command, arguments, ..
        } = operation.into_request().unwrap()
        else {
            panic!("wrong scope")
        };
        assert_eq!(command, "docker");
        let crate::model::ArgumentPolicy::Prefix(prefix) =
            crate::policy::argument_policy(arguments)
        else {
            panic!("additional arguments were not enabled")
        };
        assert_eq!(prefix, ["compose", "--file", "a b.yml", ""]);
    }

    #[test]
    fn allow_args_does_not_duplicate_a_literal_prefix_marker() {
        let parsed = Cli::try_parse_from([
            "delegated-sudo",
            "grant",
            "create",
            "compose-codex",
            "--ttl",
            "30d",
            "--allow-args",
            "--",
            "docker",
            "compose",
            "*",
        ])
        .unwrap();
        let Action::Grant { operation } = parsed.action else {
            panic!("wrong action")
        };
        let Request::CreateCommand { arguments, .. } = operation.into_request().unwrap() else {
            panic!("wrong scope")
        };
        let crate::model::ArgumentPolicy::Prefix(prefix) =
            crate::policy::argument_policy(arguments)
        else {
            panic!("additional arguments were not enabled")
        };
        assert_eq!(prefix, ["compose"]);
    }

    #[test]
    fn allow_args_cannot_be_combined_with_broad_executable_access() {
        assert!(
            Cli::try_parse_from([
                "delegated-sudo",
                "grant",
                "create",
                "maintenance",
                "--ttl",
                "1d",
                "--allow-args",
                "--commands",
                "docker,systemctl",
            ])
            .is_err()
        );
    }

    #[test]
    fn allow_args_after_the_separator_remains_a_literal_command_argument() {
        let parsed = Cli::try_parse_from([
            "delegated-sudo",
            "grant",
            "create",
            "exact-command",
            "--ttl",
            "1h",
            "--",
            "docker",
            "compose",
            "--allow-args",
        ])
        .unwrap();
        let Action::Grant { operation } = parsed.action else {
            panic!("wrong action")
        };
        let Request::CreateCommand { arguments, .. } = operation.into_request().unwrap() else {
            panic!("wrong scope")
        };
        let crate::model::ArgumentPolicy::Exact(arguments) =
            crate::policy::argument_policy(arguments)
        else {
            panic!("a command argument unexpectedly broadened the grant")
        };
        assert_eq!(arguments, ["compose", "--allow-args"]);
    }

    #[test]
    fn recursive_directory_normalization_preserves_the_requested_root() {
        for (input, expected) in [
            ("/srv/app", "/srv/app/*"),
            ("/srv/app/", "/srv/app/*"),
            ("/srv/app///", "/srv/app/*"),
            ("/srv/app/*", "/srv/app/*"),
            ("/srv/my app", "/srv/my app/*"),
            (".", "./*"),
            ("/", "/*"),
            ("///", "/*"),
        ] {
            assert_eq!(
                directory_scope(Some(input.into()), true)
                    .unwrap()
                    .as_deref(),
                Some(expected)
            );
        }
        assert_eq!(directory_scope(None, false).unwrap(), None);
        assert_eq!(
            directory_scope(Some("/srv/app/".into()), false)
                .unwrap()
                .as_deref(),
            Some("/srv/app/")
        );
    }

    #[test]
    fn recursive_requires_a_nonempty_directory() {
        assert!(
            Cli::try_parse_from([
                "delegated-sudo",
                "grant",
                "create",
                "project",
                "--ttl",
                "1h",
                "--recursive",
                "--commands",
                "id",
            ])
            .is_err()
        );
        let Action::Grant { operation } = Cli::try_parse_from([
            "delegated-sudo",
            "grant",
            "create",
            "project",
            "--ttl",
            "1h",
            "--dir",
            "",
            "--recursive",
            "--commands",
            "id",
        ])
        .unwrap()
        .action
        else {
            panic!("wrong action")
        };
        assert!(operation.into_request().is_err());
        assert!(directory_scope(None, true).is_err());
        assert!(directory_scope(Some(String::new()), true).is_err());
    }

    #[test]
    fn recursive_works_with_exact_prefix_broad_and_interactive_creation() {
        for allow_args in [false, true] {
            let mut arguments = vec![
                "delegated-sudo",
                "grant",
                "create",
                "project",
                "--ttl",
                "1h",
                "--dir",
                "/srv/app",
                "--recursive",
            ];
            if allow_args {
                arguments.push("--allow-args");
            }
            arguments.extend(["--", "docker", "compose"]);
            let Action::Grant { operation } = Cli::try_parse_from(arguments).unwrap().action else {
                panic!("wrong action")
            };
            let Request::CreateCommand {
                directory,
                arguments,
                ..
            } = operation.into_request().unwrap()
            else {
                panic!("wrong scope")
            };
            assert_eq!(directory.as_deref(), Some("/srv/app/*"));
            if allow_args {
                assert_eq!(arguments, ["compose", "*"]);
            } else {
                assert_eq!(arguments, ["compose"]);
            }
        }
        let Action::Grant { operation } = Cli::try_parse_from([
            "delegated-sudo",
            "grant",
            "create",
            "project",
            "--ttl",
            "1h",
            "--dir",
            "/srv/app",
            "--recursive",
            "--commands",
            "docker,systemctl",
        ])
        .unwrap()
        .action
        else {
            panic!("wrong action")
        };
        let Request::Create {
            directory,
            commands,
            ..
        } = operation.into_request().unwrap()
        else {
            panic!("wrong scope")
        };
        assert_eq!(directory.as_deref(), Some("/srv/app/*"));
        assert_eq!(commands, ["docker", "systemctl"]);

        let Action::Grant {
            operation:
                GrantCommand::Create {
                    directory,
                    recursive,
                    command,
                    ..
                },
        } = Cli::try_parse_from([
            "delegated-sudo",
            "grant",
            "create",
            "project",
            "--ttl",
            "1h",
            "--dir",
            "/srv/app",
            "--recursive",
        ])
        .unwrap()
        .action
        else {
            panic!("wrong action")
        };
        assert!(recursive && command.is_empty());
        assert_eq!(
            directory_scope(directory, recursive).unwrap().as_deref(),
            Some("/srv/app/*")
        );
    }

    #[test]
    fn recursive_after_the_separator_remains_a_literal_command_argument() {
        let Action::Grant { operation } = Cli::try_parse_from([
            "delegated-sudo",
            "grant",
            "create",
            "project",
            "--ttl",
            "1h",
            "--dir",
            "/srv/app",
            "--",
            "docker",
            "compose",
            "--recursive",
        ])
        .unwrap()
        .action
        else {
            panic!("wrong action")
        };
        let Request::CreateCommand {
            directory,
            arguments,
            ..
        } = operation.into_request().unwrap()
        else {
            panic!("wrong scope")
        };
        assert_eq!(directory.as_deref(), Some("/srv/app"));
        assert_eq!(arguments, ["compose", "--recursive"]);
    }

    #[test]
    fn directory_scope_is_optional_and_does_not_consume_command_flags() {
        for path in ["/srv/app", "/srv/app/*", "/srv/project with spaces/*"] {
            let parsed = Cli::try_parse_from([
                "delegated-sudo",
                "grant",
                "create",
                "project",
                "--ttl",
                "30d",
                "--dir",
                path,
                "--",
                "docker",
                "compose",
                "--dir",
                "command-option",
                "*",
            ])
            .unwrap();
            let Action::Grant { operation } = parsed.action else {
                panic!("wrong action")
            };
            let Request::CreateCommand {
                directory,
                arguments,
                ..
            } = operation.into_request().unwrap()
            else {
                panic!("wrong scope")
            };
            assert_eq!(directory.as_deref(), Some(path));
            assert_eq!(arguments, ["compose", "--dir", "command-option", "*"]);
        }
        assert!(
            Cli::try_parse_from([
                "delegated-sudo",
                "grant",
                "create",
                "project",
                "--ttl",
                "30d",
                "--dir",
            ])
            .is_err()
        );
    }

    #[test]
    fn broad_and_interactive_creation_accept_directory_scope() {
        let parsed = Cli::try_parse_from([
            "delegated-sudo",
            "grant",
            "create",
            "project",
            "--ttl",
            "30d",
            "--dir",
            "/srv/app/*",
            "--commands",
            "docker,systemctl",
        ])
        .unwrap();
        let Action::Grant { operation } = parsed.action else {
            panic!("wrong action")
        };
        let Request::Create {
            directory,
            commands,
            ..
        } = operation.into_request().unwrap()
        else {
            panic!("wrong scope")
        };
        assert_eq!(directory.as_deref(), Some("/srv/app/*"));
        assert_eq!(commands, ["docker", "systemctl"]);

        let parsed = Cli::try_parse_from([
            "delegated-sudo",
            "grant",
            "create",
            "project",
            "--ttl",
            "30d",
            "--dir",
            "/srv/app",
        ])
        .unwrap();
        let Action::Grant {
            operation: GrantCommand::Create {
                directory, command, ..
            },
        } = parsed.action
        else {
            panic!("wrong action")
        };
        assert_eq!(directory.as_deref(), Some("/srv/app"));
        assert!(command.is_empty());
    }

    #[test]
    fn create_requires_a_name_and_unambiguous_scope() {
        for arguments in [
            vec!["delegated-sudo", "grant", "create", "--ttl", "60m"],
            vec![
                "delegated-sudo",
                "grant",
                "create",
                "demo",
                "--ttl",
                "60m",
                "docker",
                "compose",
            ],
            vec![
                "delegated-sudo",
                "grant",
                "create",
                "demo",
                "--ttl",
                "60m",
                "--commands",
                "docker",
                "--",
                "docker",
                "compose",
            ],
        ] {
            assert!(Cli::try_parse_from(arguments).is_err());
        }
        let parsed = Cli::try_parse_from([
            "delegated-sudo",
            "grant",
            "create",
            "demo",
            "--ttl",
            "1m",
            "--",
            "id",
        ])
        .unwrap();
        let Action::Grant { operation } = parsed.action else {
            panic!("wrong action")
        };
        assert!(
            matches!(operation.into_request().unwrap(), Request::CreateCommand { arguments, .. } if arguments.is_empty())
        );
    }

    #[test]
    fn omitting_scope_selects_interactive_command_entry() {
        let parsed = Cli::try_parse_from([
            "delegated-sudo",
            "grant",
            "create",
            "Docker Compose Codex",
            "--ttl",
            "30d",
        ])
        .unwrap();
        let Action::Grant {
            operation:
                GrantCommand::Create {
                    name,
                    commands,
                    command,
                    ..
                },
        } = parsed.action
        else {
            panic!("wrong action")
        };
        assert_eq!(name, "Docker Compose Codex");
        assert!(commands.is_none() && command.is_empty());
    }

    #[test]
    fn interactive_command_keeps_star_and_argument_boundaries_without_evaluation() {
        assert_eq!(
            parse_command_line("docker compose *").unwrap(),
            ["docker", "compose", "*"]
        );
        assert_eq!(
            parse_command_line("docker compose --file 'a b.yml' \"\" *").unwrap(),
            ["docker", "compose", "--file", "a b.yml", "", "*"]
        );
        assert_eq!(
            parse_command_line("echo $HOME *.yml").unwrap(),
            ["echo", "$HOME", "*.yml"]
        );
        for command in [
            "",
            "  ",
            "''",
            "docker 'unfinished",
            "docker \\",
            "docker\ncompose",
            "docker\tcompose",
        ] {
            assert!(parse_command_line(command).is_err(), "accepted {command:?}");
        }
    }

    #[test]
    fn management_commands_use_the_supplied_name() {
        for action in ["show", "revoke", "delete", "extend"] {
            let mut arguments = vec!["delegated-sudo", "grant", action, "Docker Compose Codex"];
            if action == "extend" {
                arguments.extend(["--ttl", "30d"]);
            }
            let Action::Grant { operation } = Cli::try_parse_from(arguments).unwrap().action else {
                panic!("wrong action")
            };
            let name = match operation.into_request().unwrap() {
                Request::Show { name }
                | Request::Revoke { name }
                | Request::Delete { name }
                | Request::Extend { name, .. } => name,
                _ => panic!("wrong request"),
            };
            assert_eq!(name, "Docker Compose Codex");
        }
    }

    #[test]
    fn broad_grants_require_the_explicit_commands_option() {
        let parsed = Cli::try_parse_from([
            "delegated-sudo",
            "grant",
            "create",
            "docker-compose-codex",
            "--ttl",
            "60m",
            "--commands",
            "docker,systemctl",
        ])
        .unwrap();
        let Action::Grant { operation } = parsed.action else {
            panic!("wrong action")
        };
        let Request::Create { commands, .. } = operation.into_request().unwrap() else {
            panic!("wrong scope")
        };
        assert_eq!(commands, ["docker", "systemctl"]);
    }
}
