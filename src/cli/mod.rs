//! CLI orchestration and the narrowly scoped sudo re-execution boundary.

mod args;
mod output;
mod style;
mod token;

use crate::application;
use crate::model::{AdminResponse, Request};
use args::{Action, Cli};
use clap::Parser;
use clap::error::ErrorKind;
use std::collections::HashSet;
use std::error::Error;
use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use style::{Role, Theme};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const SUDO: &str = "/run/wrappers/bin/sudo";

fn display_administration(mut request: Request) -> Result<i32> {
    let mut writer = io::stdout().lock();
    let theme = Theme::stdout();
    let mut seen_cursors = HashSet::new();
    let mut listed_grants = Vec::new();
    loop {
        match application::administer(request)? {
            AdminResponse::Created { grant, token } => {
                output::issued_grant(&mut writer, &grant, token.expose(), theme)?;
                return Ok(0);
            }
            AdminResponse::Extended { grant, token } => {
                writeln!(
                    writer,
                    "Grant renewed. The previous token is no longer valid."
                )?;
                output::issued_grant(&mut writer, &grant, token.expose(), theme)?;
                return Ok(0);
            }
            AdminResponse::Deleted { name } => {
                writeln!(writer, "Deleted grant: {}", theme.paint(Role::Name, &name))?;
                return Ok(0);
            }
            AdminResponse::Grant(grant) => {
                output::grant(&mut writer, &grant, theme)?;
                return Ok(0);
            }
            AdminResponse::List {
                grants,
                next_cursor,
            } => {
                listed_grants.extend(grants);
                let Some(cursor) = next_cursor else {
                    output::list(&mut writer, &listed_grants, output::terminal_width(), theme)?;
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
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
            ) =>
        {
            // Opening the CLI without an operation is a successful request for
            // guidance. It must not authenticate, prompt for a token, or open storage.
            let result = io::stdout()
                .lock()
                .write_all(Theme::stdout().help(&error.to_string()).as_bytes());
            match result {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {}
                Err(error) => return Err(error.into()),
            }
            return Ok(0);
        }
        Err(error) => error.exit(),
    };
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
            display_administration(operation.into_request()?)
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
