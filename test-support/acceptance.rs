//! Rust-only acceptance suite for the isolated NixOS VM.
//! Tokens stay inside captured process output and are never printed here.

mod authorization;
mod directories;
mod exact;
mod execution;
mod grants;
mod harness;
mod lifecycle;
mod prefix;
mod probe;
mod process;
mod storage;
mod sudo;
mod terminal;

use harness::{Harness, check};
use nix::unistd::Uid;
use std::error::Error;

pub(crate) type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn acceptance() -> Result<()> {
    check(
        Uid::effective().is_root(),
        "acceptance checks must run as root inside the isolated VM",
    )?;
    let harness = Harness {
        agent: process::Account::named("agent")?,
        admin: process::Account::named("admin")?,
    };
    storage::legacy_upgrade(&harness)?;
    println!("passed: on-disk legacy upgrade retires old tokens and preserves new named grants");
    storage::named_upgrade(&harness)?;
    println!("passed: named-grant directory upgrade preserves existing tokens and permissions");
    let main = harness.create("id,cat,delegated-sudo-check", "60m")?;
    grants::administration(&harness, &main)?;
    println!("passed: administrative authorization and inspection");
    sudo::sudo_boundary(&harness, &main)?;
    println!("passed: ordinary sudo password and delegation boundary");
    storage::private_state(&harness, &main)?;
    println!("passed: private root-owned storage in the configured VM");
    execution::execution(&harness, &main)?;
    println!(
        "passed: root identity, arguments, I/O, working directory, environment and exit status"
    );
    terminal::interactive_token(&harness, &main)?;
    println!("passed: default terminal token prompt hides credentials and executes as root");
    execution::denials(&harness, &main)?;
    println!("passed: invalid tokens, command restrictions and PATH spoofing");
    authorization::rejected_commands(&harness, &main)?;
    println!("passed: command-string injection and ungranted executable rejection");
    exact::commands(&harness)?;
    println!("passed: exact command arguments, order, empty values and pinned path");
    prefix::command(&harness)?;
    println!("passed: fixed argument prefixes with optional suffixes and shell-syntax rejection");
    directories::restrictions(&harness)?;
    println!("passed: exact/subtree working directories, path escapes, replacement and renewal");
    terminal::interactive_creation(&harness)?;
    println!(
        "passed: interactive creation preserves bare star and quoted arguments without glob expansion"
    );
    lifecycle::revoke_running_command(&harness)?;
    println!("passed: grant lock released at exec and existing command survives revocation");
    grants::expiration_and_extension(&harness)?;
    println!(
        "passed: active and expired renewal resets expiry and rotates tokens within thirty days"
    );
    grants::names_and_deletion(&harness)?;
    println!("passed: unique Unicode grant names, deletion and safe name reuse");
    grants::listing(&harness)?;
    println!("passed: complete listing of more than one hundred grants");
    Ok(())
}

fn run() -> Result<i32> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments
        .first()
        .is_some_and(|argument| argument == "--probe")
    {
        return probe::run(&arguments[1..]);
    }
    check(
        arguments.is_empty(),
        "unexpected acceptance-helper argument",
    )?;
    acceptance()?;
    Ok(0)
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("delegated-sudo acceptance: {error}");
            std::process::exit(1);
        }
    }
}
