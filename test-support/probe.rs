//! Harmless granted executable installed only inside the acceptance VM.

use crate::Result;
use nix::unistd::{Gid, Uid, getgroups};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::thread;
use std::time::Duration;

pub(crate) fn run(arguments: &[String]) -> Result<i32> {
    let environment: BTreeMap<_, _> = std::env::vars().collect();
    println!(
        "{}",
        json!({
            "uid": Uid::current().as_raw(),
            "gid": Gid::current().as_raw(),
            "groups": getgroups()?.iter().map(|group| group.as_raw()).collect::<Vec<_>>(),
            "cwd": std::env::current_dir()?,
            "env": environment,
            "args": arguments,
        })
    );
    eprintln!("probe stderr");
    if arguments.iter().any(|argument| argument == "--wait") {
        fs::write(
            "/run/delegated-sudo-probe.pid",
            std::process::id().to_string(),
        )?;
        thread::sleep(Duration::from_secs(60));
    }
    Ok(if arguments.iter().any(|argument| argument == "--fail") {
        37
    } else {
        0
    })
}
