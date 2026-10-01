//! CLI orchestration and the narrowly scoped sudo re-execution boundary.

mod args;
mod output;
mod token;

use crate::application;
use crate::model::{AdminResponse, Request};
use args::{Action, Cli};
use clap::Parser;
use std::collections::HashSet;
use std::error::Error;
use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const SUDO: &str = "/run/wrappers/bin/sudo";

fn display_administration(mut request: Request) -> Result<i32> {
    let mut writer = io::stdout().lock();
    let mut seen_cursors = HashSet::new();
    let mut printed = false;
    loop {
        match application::administer(request)? {
            AdminResponse::Created { grant, token } => {
                output::grant(&mut writer, &grant, Some(token.expose()))?;
                return Ok(0);
            }
            AdminResponse::Grant(grant) => {
                output::grant(&mut writer, &grant, None)?;
                return Ok(0);
            }
            AdminResponse::List {
                grants,
                next_cursor,
            } => {
                for grant in grants {
                    if printed {
                        writeln!(writer)?;
                    }
                    output::grant(&mut writer, &grant, None)?;
                    printed = true;
                }
                let Some(cursor) = next_cursor else {
                    if !printed {
                        writeln!(writer, "No delegation grants.")?;
                    }
                    return Ok(0);
                };
                if !seen_cursors.insert(cursor.clone()) {
                    return Err(io::Error::other("The store repeated a pagination cursor").into());
                }
                request = Request::List {
                    cursor: Some(cursor),
                };
            }
        }
    }
}

fn elevation_command(executable: &Path, token_stdin: bool, command: &[String]) -> Command {
    let mut sudo = Command::new(SUDO);
    sudo.arg("-n").arg("--").arg(executable).arg("exec");
    if token_stdin {
        sudo.arg("--token-stdin");
    }
    // End delegated-sudo's options so every command argument survives the hop.
    sudo.arg("--").args(command);
    sudo
}

pub fn run() -> Result<i32> {
    let cli = Cli::parse();
    // SAFETY: getuid/geteuid do not accept pointers or mutate process state.
    let (uid, effective_uid) = unsafe { (libc::getuid(), libc::geteuid()) };
    if uid != effective_uid {
        return Err(
            io::Error::other("Run delegated-sudo through sudo; do not install it setuid").into(),
        );
    }
    match cli.action {
        Action::Grant { operation } => {
            if uid != 0 {
                return Err(io::Error::other(
                    "Grant administration requires root; use sudo delegated-sudo grant ...",
                )
                .into());
            }
            display_administration(operation.into())
        }
        Action::Exec {
            token_stdin,
            command,
        } => {
            if uid != 0 {
                // No credential has been read. sudo authorizes the installed
                // executable's exec entrypoint; root still validates the token.
                return Err(
                    elevation_command(&std::env::current_exe()?, token_stdin, &command)
                        .exec()
                        .into(),
                );
            }
            let token = token::read(token_stdin)?;
            match application::execute(&token, &command[0], &command[1..])? {}
        }
    }
}
