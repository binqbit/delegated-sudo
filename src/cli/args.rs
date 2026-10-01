//! Argument parsing and conversion into application requests.

use crate::model::Request;
use clap::{Parser, Subcommand};

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
        /// Allow arguments/subcommands for these executables; shell syntax is rejected.
        #[arg(
            long,
            value_name = "EXECUTABLES",
            required_unless_present = "command",
            conflicts_with = "command"
        )]
        commands: Option<String>,
        /// Grant lifetime, such as 60m or 2h.
        #[arg(long)]
        ttl: String,
        /// Executable and arguments after --; quote a final '*' to allow extra arguments.
        #[arg(last = true, num_args = 1.., value_name = "COMMAND", required_unless_present = "commands")]
        command: Vec<String>,
    },
    /// List grants without their secret tokens.
    List,
    Show {
        grant_id: String,
    },
    Revoke {
        grant_id: String,
    },
    /// Add time to an active grant's existing expiration.
    Extend {
        grant_id: String,
        #[arg(long)]
        ttl: String,
    },
}

impl From<GrantCommand> for Request {
    fn from(operation: GrantCommand) -> Self {
        match operation {
            GrantCommand::Create {
                commands: Some(commands),
                ttl,
                ..
            } => Self::Create {
                commands: commands.split(',').map(String::from).collect(),
                ttl,
            },
            GrantCommand::Create {
                commands: None,
                ttl,
                command,
            } => {
                let mut command = command.into_iter();
                Self::CreateCommand {
                    command: command
                        .next()
                        .expect("clap requires a command without --commands"),
                    arguments: command.collect(),
                    ttl,
                }
            }
            GrantCommand::List => Self::List { cursor: None },
            GrantCommand::Show { grant_id } => Self::Show { id: grant_id },
            GrantCommand::Revoke { grant_id } => Self::Revoke { id: grant_id },
            GrantCommand::Extend { grant_id, ttl } => Self::Extend { id: grant_id, ttl },
        }
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
            command,
            arguments,
            ttl,
        } = operation.into()
        else {
            panic!("wrong scope")
        };
        assert_eq!(command, "docker");
        assert_eq!(
            arguments,
            [
                "compose", "--file", "a b.yml", "up", "-d", "--ttl", "literal", "", "*"
            ]
        );
        assert_eq!(ttl, "60m");
    }

    #[test]
    fn create_requires_one_unambiguous_scope() {
        for arguments in [
            vec!["delegated-sudo", "grant", "create", "--ttl", "60m"],
            vec!["delegated-sudo", "grant", "create", "--ttl", "60m", "--"],
            vec![
                "delegated-sudo",
                "grant",
                "create",
                "--ttl",
                "60m",
                "docker",
                "compose",
            ],
            vec![
                "delegated-sudo",
                "grant",
                "create",
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
            matches!(Request::from(operation), Request::CreateCommand { arguments, .. } if arguments.is_empty())
        );
    }

    #[test]
    fn broad_grants_require_the_explicit_commands_option() {
        let parsed = Cli::try_parse_from([
            "delegated-sudo",
            "grant",
            "create",
            "--ttl",
            "60m",
            "--commands",
            "docker,systemctl",
        ])
        .unwrap();
        let Action::Grant { operation } = parsed.action else {
            panic!("wrong action")
        };
        let Request::Create { commands, .. } = operation.into() else {
            panic!("wrong scope")
        };
        assert_eq!(commands, ["docker", "systemctl"]);
    }
}
