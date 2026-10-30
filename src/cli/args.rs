//! Argument parsing and conversion into application requests.

use crate::model::Request;
use clap::{Parser, Subcommand};
use std::io::{self, IsTerminal, Write};

#[derive(Debug, Parser)]
#[command(
    name = "delegated-sudo",
    about = "Run root commands with an expiring command-scoped delegation token"
)]
pub(super) struct Cli {
    #[command(subcommand)]
    pub action: Action,
}

#[derive(Debug, Subcommand)]
pub(super) enum Action {
    /// Administer grants using normal sudo/root authorization.
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
        /// Lifetime from now, such as 60m or 30d (maximum 30 days).
        #[arg(long)]
        ttl: String,
        /// Permit this directory only, or PATH/* for it and all descendants.
        #[arg(long = "dir", value_name = "PATH")]
        directory: Option<String>,
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

impl GrantCommand {
    pub(super) fn into_request(self) -> io::Result<Request> {
        Ok(match self {
            GrantCommand::Create {
                name,
                commands: Some(commands),
                ttl,
                directory,
                ..
            } => Request::Create {
                name,
                commands: commands.split(',').map(String::from).collect(),
                ttl,
                directory,
            },
            GrantCommand::Create {
                name,
                commands: None,
                ttl,
                directory,
                mut command,
            } => {
                if command.is_empty() {
                    command = read_command()?;
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
