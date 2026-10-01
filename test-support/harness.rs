//! CLI invocations and assertions that keep credentials out of failures.

use crate::Result;
use crate::process::{Account, capture, configure};
use std::io;
use std::process::{Command, Output};

pub(crate) const CLI: &str = "/run/current-system/sw/bin/delegated-sudo";
const SUDO: &str = "/run/wrappers/bin/sudo";
pub(crate) const DATABASE: &str = "/var/lib/delegated-sudo/grants.sqlite3";
pub(crate) const PROBE: &str = "delegated-sudo-check";

pub(crate) fn check(condition: bool, message: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(message).into())
    }
}

// Deliberately no Debug implementation: assertion failures must not print tokens.
pub(crate) struct SecretGrant {
    pub(crate) id: String,
    pub(crate) token: String,
}

#[derive(Clone)]
pub(crate) struct Harness {
    pub(crate) agent: Account,
    pub(crate) admin: Account,
}

impl Harness {
    pub(crate) fn cli(
        &self,
        arguments: &[&str],
        root: bool,
        token: Option<&str>,
    ) -> Result<Output> {
        self.cli_with(arguments, root, token, b"", &[])
    }

    pub(crate) fn cli_with(
        &self,
        arguments: &[&str],
        root: bool,
        token: Option<&str>,
        stdin: &[u8],
        environment: &[(&str, &str)],
    ) -> Result<Output> {
        let mut command = if root {
            let mut command = Command::new(SUDO);
            command.args(["-n", "-u", "root", "--", CLI]);
            command
        } else {
            Command::new(CLI)
        };
        command
            .env_clear()
            .env("PATH", "/run/current-system/sw/bin:/run/wrappers/bin")
            .env("HOME", &self.agent.home)
            .envs(environment.iter().copied())
            .current_dir(&self.agent.home);
        let input = if let Some(token) = token {
            check(
                arguments.first() == Some(&"exec"),
                "token supplied to non-exec test operation",
            )?;
            command.args(["exec", "--token-stdin"]);
            command.args(&arguments[1..]);
            [token.as_bytes(), b"\n", stdin].concat()
        } else {
            command.args(arguments);
            stdin.to_vec()
        };
        configure(&mut command, (!root).then_some(&self.agent));
        capture(command, &input)
    }

    pub(crate) fn create(&self, commands: &str, ttl: &str) -> Result<SecretGrant> {
        let output = succeeded(self.cli(
            &["grant", "create", "--commands", commands, "--ttl", ttl],
            true,
            None,
        )?)?;
        Self::creation_response(output)
    }

    pub(crate) fn create_command(&self, command: &[&str], ttl: &str) -> Result<SecretGrant> {
        let mut arguments = vec!["grant", "create", "--ttl", ttl, "--"];
        arguments.extend_from_slice(command);
        Self::creation_response(succeeded(self.cli(&arguments, true, None)?)?)
    }

    fn creation_response(output: String) -> Result<SecretGrant> {
        let field = |prefix: &str| {
            output
                .lines()
                .find_map(|line| line.strip_prefix(prefix))
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| io::Error::other("missing creation field"))
        };
        Ok(SecretGrant {
            id: field("Grant ID:")?,
            token: field("Token:")?,
        })
    }

    pub(crate) fn sudo(
        &self,
        account: &Account,
        arguments: &[&str],
        stdin: &[u8],
    ) -> Result<Output> {
        let mut command = Command::new(SUDO);
        command
            .args(arguments)
            .env_clear()
            .env("PATH", "/run/current-system/sw/bin:/run/wrappers/bin")
            .env("HOME", &account.home)
            .current_dir(&account.home);
        configure(&mut command, Some(account));
        capture(command, stdin)
    }
}

pub(crate) fn succeeded(output: Output) -> Result<String> {
    // Deliberately omit captured stdout and stderr from errors. They may include
    // an administrative creation response or echoed test credentials.
    check(
        output.status.success(),
        "an expected-success subprocess failed",
    )?;
    Ok(String::from_utf8(output.stdout)?)
}

pub(crate) fn denied(output: Output) -> Result<()> {
    check(!output.status.success(), "a forbidden operation succeeded")?;
    check(
        !output.stderr.is_empty(),
        "rejection did not explain its reason",
    )
}
